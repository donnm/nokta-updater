#!/usr/bin/env python3
"""Nokta LEGEND device emulator v3 - consensus protocol per NOTES.md section 27.

Wire format (reversed from The_Legend_Update_Tool.exe v2.1.2, verified by
two-agent consensus + referee checks; see NOTES.md section 27):

HOST -> DEVICE frames:  [0x01][cmd][params][chk]
                        chk = 0xFF ^ XOR(cmd+params)   (0x01 marker excluded)
  id:      01 81 00 00 00 00 7E          (4 binary zero params)
  bl_ver:  01 11 30x8 EE
  ready:   01 4C v1 v2 v3 v4 chk      (v* = container header bytes [3][4][6][7])
  stp:     01 A3 <m> 30 <hi> <lo> chk (m = container byte[0xb])
  str:     01 A2 30 30 <hi> <lo> chk  (arg = block size, 0x200)
  tot_pkts:01 DA <hi> <lo> 30 30 chk  (16-bit count)
  data:    <512 raw bytes><chk>       513 bytes, no 0x01, no cmd byte

DEVICE -> HOST responses:
  ID phase:  91 F0 V1 V2 V3 V4 chk    chk = 0xFF ^ XOR([1..5])  (0x91 excluded)
  state 0:   7-byte frames [t][1..5][chk@6 over 1..5]:
             0x61 ready | 0x92 NACK | 0xF2 <1|2|3> error
  state 1/2: single bytes, no chk: 0x91 ack | 0x92 nack | 0x94 block-ok
             | 0x95 crc-fail
  state 3:   F1 xx xx xx xx chk      (6 bytes, chk over [0..4])
  state 4:   55 06 <brand> <coilID u32> <mc> <sum> <most> chk  (chk over [0..9])
             brand byte[2]: 1=Tianxie clone, 2=Gold Hunter clone, else genuine
  NACK:      bare 0x92 for unknown cmd / bad chk

Usage:
  python3 legend_emulator.py --pty              # wine COM1
  python3 legend_emulator.py /dev/ttyUSB0       # real serial port
  python3 legend_emulator.py --selftest         # off-line protocol selftest
"""
import os, sys, pty, select, time, argparse, subprocess, functools

WINEPREFIX = os.environ.get("WINEPREFIX", os.path.expanduser("~/.wine-nokta"))
LOG = os.environ.get("LEGEND_EMU_LOG", "")

MARKER = 0x01
CMD_ID, CMD_READY, CMD_BLVER, CMD_TOTPKT, CMD_STP, CMD_STR = 0x81, 0x4C, 0x11, 0xDA, 0xA3, 0xA2
BLOCK = 512

def fold(b):
    """check = 0xFF ^ XOR(bytes), seed 0xFF (NOTES section 27)."""
    return 0xFF ^ (functools.reduce(lambda a, x: a ^ x, b, 0) & 0xFF)

def log(m):
    line = f"{time.strftime('%H:%M:%S')} {m}"
    if LOG:
        with open(LOG, "a") as f:
            f.write(line + "\n")
    print(line, flush=True)


class Legend:
    """Device side of the consensus protocol."""

    def __init__(self, container=None):
        # container: the .bin firmware image we "install" (host streams it to us)
        self.container = bytearray(container) if container else bytearray()
        # ID response version bytes (arbitrary but stable; real device reports its own)
        self.version = (0x11, 0x00, 0x01, 0x00)   # V1..V4 in the 91 F0 frame
        self.blver = (1, 5)
        self.n_packets = 0
        self.residue = 0
        self.received = bytearray()
        self.session = "idle"      # idle -> ready -> flashing -> last -> crc -> info
        self.wait_block = None     # bytes expected after str/stp ACK
        self.last_m = 0x00         # container byte[0xb] once we learn it

    # ---------- response builders ----------

    def id_response(self):
        b = bytes([0xF0, *self.version])
        return bytes([0x91]) + b + bytes([fold(b)])

    def nack(self):
        return bytes([0x92])

    def ready7(self, t, p5):
        """state-0 7-byte frame: [t][1..5][chk over 1..5]"""
        return bytes([t]) + p5 + bytes([fold(p5)])

    def crc_frame(self):
        b = bytes([0xF1, 0, 0, 0, 0])
        return b + bytes([fold(b)])

    def info_frame(self, brand=0x00):
        coil_id = (0x74792021).to_bytes(4, "little")   # echoes FCC silkscreen :)
        b = bytes([0x55, 0x06, brand]) + coil_id + bytes([1, 2, 3])
        return b + bytes([fold(b)])

    # ---------- host-frame parsing ----------

    def parse(self, chunk):
        """Handle one received chunk. Returns (reply_bytes_or_None, note)."""
        if not chunk:
            return None, "empty"
        # DATA sub-state: after str/stp ACK we expect exactly one block.
        if self.wait_block is not None:
            need = self.wait_block
            if len(chunk) < need + 1:
                return None, f"data chunk short ({len(chunk)} < {need+1})"
            blk, chk = chunk[:need], chunk[need]
            if chk == fold(blk):
                self.received.extend(blk)
                self.wait_block = None
                if self.session == "last":
                    self.session = "crc"
                    return (bytes([0x94]) + self.crc_frame() + self.info_frame()), \
                           "residue ok -> 94 + F1 + 55 06"
                return bytes([0x94]), f"block {len(self.received)//BLOCK} ok -> 94"
            return bytes([0x95]), "block crc fail -> 95"
        if chunk[0] != MARKER:
            # no marker: either a 513-byte data block (no 0x01, no cmd) or garbage
            if len(chunk) >= BLOCK + 1 and self.session in ("flashing", "last"):
                blk, chk = chunk[:BLOCK], chunk[BLOCK]
                if self.session == "last":
                    blk, chk = chunk[:self.residue], chunk[self.residue] if len(chunk) > self.residue else 0
                    want = fold(blk)
                    if chk == want:
                        self.received.extend(blk)
                        # real device: 94, then F1 complete-frame, then 55 06 info
                        return (bytes([0x94]) + self.crc_frame() + self.info_frame()), \
                               f"residue block ok ({len(blk)} B) -> 94 + F1 + 55 06"
                    return bytes([0x95]), "residue crc fail -> 95"
                want = fold(blk)
                if chk == want:
                    self.received.extend(blk)
                    return bytes([0x94]), f"block {len(self.received)//BLOCK} ok -> 94"
                return bytes([0x95]), "block crc fail -> 95"
            return None, f"no marker, ignored ({len(chunk)} B)"

        cmd = chunk[1] if len(chunk) > 1 else None
        # frame = [0x01][cmd][params][chk]; chk covers cmd..end
        if len(chunk) < 4:
            return self.nack(), "short frame -> 92"
        chk = chunk[-1]
        want = fold(chunk[1:-1])
        if chk != want:
            return self.nack(), f"bad chk (got {chk:02x} want {want:02x}) -> 92"

        if cmd == CMD_ID and self.session == "idle":
            return self.id_response(), "ID -> 91 F0 response"

        if cmd == CMD_BLVER:
            return self.id_response(), "bl_ver -> version response"

        if cmd == CMD_READY and self.session in ("idle", "ready"):
            self.session = "ready"
            # real device: 0x91 ACK + 6-byte frame [61][4 data][chk over 5 bytes]
            body = bytes([0x61, 0x00, 0x00, 0x00, 0x00])
            return bytes([0x91]) + body + bytes([fold(body)]), "ready -> 91 + 61 frame"

        if cmd == CMD_TOTPKT:
            hi, lo = chunk[2], chunk[3]
            self.n_packets = (hi << 8) | lo
            # residue implicitly = whatever remains when str asks for the tail
            self.session = "ready"
            body = bytes([0x92, 0x00, 0x00, 0x00, 0x00])
            return bytes([0x91]) + body + bytes([fold(body)]), \
                   f"tot_pkts={self.n_packets} -> 91 + 92 frame"

        if cmd == CMD_STR:
            size = (chunk[4] << 8) | chunk[5]
            if self.session in ("ready", "flashing"):
                self.session = "flashing"
                self.expect = size
                self.wait_block = size
                return bytes([0x91]), f"str({size}) -> 91"
            if self.session == "last":
                self.wait_block = size
                return bytes([0x91]), "str(residue) -> 91"
            return self.nack(), "str in wrong state -> 92"

        if cmd == CMD_STP:
            self.last_m = chunk[2]
            size = (chunk[4] << 8) | chunk[5]
            self.session = "last"
            self.residue = size
            self.wait_block = size
            return bytes([0x91]), f"stp(m={chunk[2]:02x},{size}) -> 91"

        return self.nack(), f"unknown cmd {cmd:02x} -> 92"

    def block_ack(self):
        """After 0x94 for the final block, device sends the F1 frame."""
        if self.session == "last":
            self.session = "crc"
            return self.crc_frame()
        return None

    def info_after(self):
        if self.session == "crc":
            self.session = "info"
            return self.info_frame()
        return None


# ---------------- self-test (off-line, no serial) ----------------

def selftest():
    ok = True
    def t(name, cond):
        nonlocal ok
        print(("PASS " if cond else "FAIL ") + name)
        ok = ok and cond

    dev = Legend()
    t("id frame parse", True)

    # 1. host sends byte-exact id frame
    r, note = dev.parse(bytes.fromhex("01 81 00 00 00 00 7e".replace(" ", "")))
    t(f"ID -> 91 F0 response ({note})", r and r[0] == 0x91 and r[1] == 0xF0 and len(r) == 7)
    v = r
    t("ID chk = FF^XOR([1..5])", v[6] == fold(v[1:6]))

    # 2. ready frame with container version bytes (v1.17 container header: 89 01 00 01)
    vb = bytes([0x89, 0x01, 0x00, 0x01])
    frame = bytes([MARKER, 0x4C]) + vb + bytes([fold(bytes([0x4C]) + vb)])
    r, note = dev.parse(frame)
    t(f"ready -> 91 61 7-byte frame ({note})",
      r and r[0] == 0x91 and r[1] == 0x61 and len(r) == 7)
    t("ready chk over [1..5]", r[6] == fold(r[1:6]))

    # 3. tot_pkts = 582 (v1.17)
    n = 582
    p = bytes([0xDA, (n >> 8) & 0xFF, n & 0xFF, 0x30, 0x30])
    frame = bytes([MARKER]) + p + bytes([fold(p)])
    r, note = dev.parse(frame)
    t(f"tot_pkts({n}) -> 91 92 frame ({note})",
      r and r[0] == 0x91 and r[1] == 0x92 and len(r) == 7)

    # 4. str(512) -> 91
    p = bytes([0xA2, 0x30, 0x30, 0x02, 0x00])
    frame = bytes([MARKER]) + p + bytes([fold(p)])
    r, note = dev.parse(frame)
    t(f"str(512) -> 91 ({note})", r == b"\x91")

    # 5. 513-byte block, good chk -> 94
    blk = bytes((i * 7) & 0xFF for i in range(BLOCK))
    r, note = dev.parse(blk + bytes([fold(blk)]))
    t(f"block ok -> 94 ({note})", r == b"\x94")

    # 6. block, bad chk -> 95
    r, note = dev.parse(blk + bytes([fold(blk) ^ 0xFF]))
    t(f"block crc fail -> 95 ({note})", r == b"\x95")

    # 7. unknown cmd -> bare 92
    p = bytes([0x77, 0x30, 0x30])
    frame = bytes([MARKER]) + p + bytes([fold(p)])
    r, note = dev.parse(frame)
    t(f"unknown cmd -> bare 92 ({note})", r == b"\x92")

    # 8. stp -> 91, residue block -> 94 -> F1 frame
    p = bytes([0xA3, 0xF3, 0x30, 0x02, 0x10])   # m=0xF3, residue=0x210=528
    frame = bytes([MARKER]) + p + bytes([fold(p)])
    r, note = dev.parse(frame)
    t(f"stp -> 91 ({note})", r == b"\x91")
    res = bytes((i * 3) & 0xFF for i in range(528))
    r, note = dev.parse(res + bytes([fold(res)]))
    t(f"residue block -> 94+F1+5506 burst ({note})",
      r is not None and r[:1] == b"\x94" and len(r) == 1 + 6 + 11)
    f1 = r[1:7]; inf = r[7:18]
    t("burst F1 frame", f1[0] == 0xF1 and len(f1) == 6 and f1[5] == fold(f1[0:5]))
    t("burst 55 06 info frame", inf[0] == 0x55 and inf[1] == 0x06 and inf[10] == fold(inf[0:10]))

    # 9. non-marker garbage is ignored
    r, note = dev.parse(bytes([0xAB, 0xCD]))
    t("garbage ignored", r is None)

    print("\n" + ("ALL PASS" if ok else "SOME FAILED"))
    return 0 if ok else 1


# ---------------- serial / pty main ----------------

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pty", action="store_true")
    ap.add_argument("device", nargs="?", help="serial device (real PC mode)")
    ap.add_argument("--selftest", action="store_true")
    args = ap.parse_args()

    if args.selftest:
        sys.exit(selftest())

    if args.pty:
        master, slave = pty.openpty()
        os.set_blocking(master, False)
        import termios, tty
        tty.setraw(slave)
        env = dict(os.environ, WINEPREFIX=WINEPREFIX, WINEDEBUG="-all")
        subprocess.run(["wine", "reg", "add", "HKCU\\Software\\Wine\\Ports",
                        "/v", "COM1", "/t", "REG_SZ", "/d", os.ttyname(slave), "/f"],
                       env=env, capture_output=True, timeout=60)
        log(f"[*] PTY {os.ttyname(slave)} -> COM1")
        fd = master
    elif args.device:
        import termios, tty
        fd = os.open(args.device, os.O_RDWR | os.O_NOCTTY)
        tty.setraw(fd)
        log(f"[*] {args.device} opened")
    else:
        ap.error("need --pty, --selftest, or a device")

    dev = Legend()
    log("[*] running; consensus protocol (NOTES section 27)")
    while True:
        r, _, _ = select.select([fd], [], [], 0.5)
        if not r:
            continue
        try:
            data = os.read(fd, 8192)
        except OSError:
            continue
        if not data:
            continue
        log(f"RX {len(data):4d} {data[:64].hex(' ')}{'...' if len(data)>64 else ''}")
        resp, note = dev.parse(data)
        if resp:
            log(f"TX {len(resp):4d} {resp[:64].hex(' ')}  [{note}]")
            os.write(fd, resp)
        else:
            log(f"--      [{note}]")

if __name__ == "__main__":
    main()
