#!/usr/bin/env python3
"""Nokta The Legend firmware updater.

Protocol (reversed from a captured official update session):

  TX 01 81 00 00 00 00 7E            ID
  RX 91 F0 V1 V2 V3 V4 chk           (chk = 0xFF^XOR(F0,V1..V4), marker excluded)
  TX 01 4C <dev[2]> <dev[3]> <dev[4]> <minor> chk    ready
  RX 91 61 <4 data> chk              ACK + 6-byte frame, chk over [61..data]
  TX 01 DA hi lo 00 00 chk           tot_pkts = full blocks + residue packet
  RX 91 92 00 00 00 00 6D            status frame (chk over 92..data)
  repeat per full packet:
      TX 01 A2 00 00 02 00 5F        str(512)
      RX 0x91
      TX <512 bytes> <chk>           chk = 0xFF^XOR(block)
      RX 0x94 (block ok) / 0x95 (crc fail -> resend)
  TX 01 A3 <container[11]> 00 hi lo chk      stp(residue)
  RX 0x91
  TX <residue bytes> <chk>
  RX 0x94
  RX F1 00 00 00 00 chk              update complete
  RX 55 06 <brand> <coilID u32> <mc> <sum> <most> chk   device info

Usage:
  nokta_updater.py list
  nokta_updater.py download --version v1.17
  nokta_updater.py probe [--port /dev/ttyUSB0]
  nokta_updater.py flash --version v1.17 [--port /dev/ttyUSB0] --yes
"""
import argparse, functools, hashlib, http.client, os, re, select, shutil, sys, time
import urllib.error
import urllib.request

BLOCK = 512
MARKER = 0x01
SERVER_URL = "https://source.noktadetectors.com"

MODEL = {
    "name": "The Legend",
    "prefix": "_the_legend_customer_softwares",
    "list": "available_softwares_THE_LEGEND.txt",
    "softdir": "THE_LEGEND_software",
}


def list_url():
    return f"{SERVER_URL.rstrip('/')}/{MODEL['prefix']}/{MODEL['list']}"


def soft_url(ver):
    return f"{SERVER_URL.rstrip('/')}/{MODEL['prefix']}/{MODEL['softdir']}/{ver}.h"


def fold(b):
    return 0xFF ^ (functools.reduce(lambda a, x: a ^ x, b, 0) & 0xFF)


def log(m):
    print(m, flush=True)


def _fmt_rate(n):
    if n >= 1048576:
        return f"{n/1048576:.1f} MB/s"
    if n >= 1024:
        return f"{n/1024:.1f} kB/s"
    return f"{n:.0f} B/s"


def _fmt_bytes(n):
    if n >= 1048576:
        return f"{n/1048576:.1f} MiB"
    if n >= 1024:
        return f"{n/1024:.0f} KiB"
    return f"{n} B"


class Progress:
    """Console progress fitted to the terminal width (live bar on TTY)."""
    def __init__(self, label, total=None, logfn=log, step=5, max_bar=24):
        self.label = label
        self.total = total or 0
        self.logfn = logfn
        self.tty = sys.stdout.isatty()
        self.step = step
        self.max_bar = max_bar
        self.next_pct = 0
        self.done = 0
        self.start = time.time()

    def _render(self, done, suffix=""):
        cols = shutil.get_terminal_size(fallback=(80, 24)).columns
        pct = (done * 100.0 / self.total) if self.total else 100.0
        elapsed = max(time.time() - self.start, 1e-9)
        rate = done / elapsed
        eta = (self.total - done) / rate if rate > 0 and done < self.total else 0
        core = [f"{pct:5.1f}%"]
        if self.total:
            core.append(f"{done}/{self.total}")
        opts = []
        if suffix:
            opts.append(suffix)
        opts.append(_fmt_rate(rate))
        if done < self.total:
            opts.append(f"ETA {eta:.0f}s")
        prefix = f"{self.label}: ["
        while True:
            tail = "] " + "  ".join(core + opts)
            avail = (cols - 1) - len(prefix) - len(tail)
            if avail >= 10 or not opts:
                break
            opts.pop(0)
        bar_w = max(0, min(self.max_bar, avail))
        filled = int(bar_w * pct / 100.0)
        bar = "#" * filled + "-" * (bar_w - filled)
        line = prefix + bar + tail
        return line[:cols - 1]

    def update(self, done, suffix=""):
        self.done = done
        if not self.total:
            mb = done / 1048576.0
            line = f"{self.label}: {mb:6.1f} MB {suffix}".rstrip()
            if self.tty:
                cols = shutil.get_terminal_size(fallback=(80, 24)).columns
                print("\r" + line[:cols-1], end="", flush=True)
            else:
                self.logfn(line)
            return
        pct = done * 100.0 / self.total
        if self.tty:
            line = self._render(done, suffix)
            cols = shutil.get_terminal_size(fallback=(80, 24)).columns
            print("\r" + line + " " * max(0, (cols - 1) - len(line)), end="", flush=True)
            return
        if pct >= self.next_pct:
            self.logfn(self._render(done, suffix))
            self.next_pct = (int(pct) // self.step + 1) * self.step

    def finish(self, suffix=""):
        if self.total:
            self.update(self.total, suffix)
        if self.tty:
            print()
        elapsed = max(time.time() - self.start, 1e-9)
        size = _fmt_bytes(self.total or self.done)
        rate = _fmt_rate((self.total or self.done) / elapsed)
        self.logfn(f"{self.label}: complete - {size} in {elapsed:.1f}s ({rate})")


def parse_container(path):
    with open(path, "rb") as f:
        raw = f.read()
    m = re.search(rb"uint data_v(\d+)_(\d+)_length = (\d+);", raw)
    arr = re.search(rb"\{([^}]*)\}", raw, re.S)
    if not m or not arr:
        raise SystemExit(f"{path}: not a Legend .h container")
    data = bytes(int(x, 16) for x in re.findall(rb"0x([0-9a-fA-F]{2})", arr.group(1)))
    declared = int(m.group(3))
    if len(data) != declared:
        raise SystemExit(f"{path}: declared {declared} bytes, array has {len(data)}")
    if len(data) < 17:
        raise SystemExit(f"{path}: container too short ({len(data)} bytes)")
    if data[1:4] != b"\x52\x54\x89":
        raise SystemExit(f"{path}: bad container magic {data[1:4].hex()}")
    if functools.reduce(lambda a, x: a ^ x, data, 0) != 0:
        raise SystemExit(f"{path}: container XOR check failed")
    ver = (int(m.group(1)), int(m.group(2)))
    if ver[1] > 0xFF or data[8] != ver[1]:
        raise SystemExit(f"{path}: header minor 0x{data[8]:02x} != declared minor {ver[1]}")
    return data, ver


class Link:
    """read/write with exact-length framing (buffered)"""
    def __init__(self, fd):
        self.fd = fd
        self.buf = b""

    def write(self, b):
        view = memoryview(b)
        while view:
            try:
                n = os.write(self.fd, view)
            except BlockingIOError:
                select.select([], [self.fd], [], 0.1)
                continue
            if n <= 0:
                raise OSError("serial write failed")
            view = view[n:]

    def flush(self):
        self.buf = b""
        while True:
            r, _, _ = select.select([self.fd], [], [], 0)
            if not r:
                break
            try:
                if not os.read(self.fd, 4096):
                    break
            except OSError:
                break

    def read_exact(self, n, timeout=5.0):
        end = time.time() + timeout
        while len(self.buf) < n and time.time() < end:
            r, _, _ = select.select([self.fd], [], [], 0.1)
            if r:
                try:
                    chunk = os.read(self.fd, 4096)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


class SerialLink(Link):
    def __init__(self, ser):
        super().__init__(ser.fileno())
        self.ser = ser

    def write(self, b):
        while b:
            n = self.ser.write(b)
            if not n:
                raise OSError("serial write timed out")
            b = b[n:]

    def flush(self):
        self.buf = b""
        try:
            self.ser.reset_input_buffer()
        except (AttributeError, OSError):
            pass

    def read_exact(self, n, timeout=5.0):
        end = time.time() + timeout
        while len(self.buf) < n and time.time() < end:
            chunk = self.ser.read(max(1, n - len(self.buf)))
            if chunk:
                self.buf += chunk
        out, self.buf = self.buf[:n], self.buf[n:]
        return out


def cmd_frame(cmd, params):
    payload = bytes([cmd]) + params
    return bytes([MARKER]) + payload + bytes([fold(payload)])


def read_frame(link, typ, timeout=10.0):
    """Scan for a complete status frame: 0x91, type, 4 data bytes, checksum."""
    end = time.time() + timeout
    while True:
        remain = end - time.time()
        if remain <= 0:
            return None
        b = link.read_exact(1, timeout=remain)
        if not b:
            return None
        if b[0] != 0x91:
            continue
        remain = end - time.time()
        if remain <= 0:
            return None
        rest = link.read_exact(6, timeout=remain)
        if len(rest) < 6:
            return None
        fr = b + rest
        if fr[1] == typ and fr[6] == fold(fr[1:6]):
            return fr


def legend_handshake(link, attempts=10, timeout=2.0, logfn=log):
    for attempt in range(attempts):
        link.flush()
        link.write(bytes.fromhex("0181000000007e"))
        fr = read_frame(link, 0xF0, timeout=timeout)
        if fr:
            return fr
        logfn(f"ID attempt {attempt+1}: no response")
    return None


def do_update(link, container, ver=(1, 0), logfn=log, show_progress=False):
    stream = container[16:]
    n_full = len(stream) // BLOCK
    residue = len(stream) % BLOCK
    n_pkts = n_full + (1 if residue else 0)

    meta = {"device_ver": None, "brand": None, "coil": None, "mc": None,
            "sum": None, "most": None, "new_ver": ver,
            "f1_ok": False, "info_ok": False}
    # 1. ID
    logfn("Phase 1/3: checking device")
    r = legend_handshake(link, logfn=logfn)
    if not r:
        raise SystemExit("ID handshake failed")
    meta["device_ver"] = (r[4], r[5])
    logfn(f"ID ok: {' '.join('%02x'%x for x in r)}  device v{r[4]}.{r[5]}")

    logfn("Phase 2/3: preparing device for writing (erase)")
    # 2. ready: device ID bytes 2..4 + target version minor (capture-derived)
    ready = cmd_frame(0x4C, bytes([r[2], r[3], r[4], ver[1] & 0xFF]))
    for attempt in range(10):
        link.flush()
        link.write(ready)
        fr = read_frame(link, 0x61, timeout=10)
        if fr:
            logfn(f"ready ok: {fr.hex(' ')}")
            break
        logfn(f"ready attempt {attempt+1}: bad/missing 61 frame")
    else:
        raise SystemExit("ready failed")

    # 3. total packet number
    tot = cmd_frame(0xDA, bytes([(n_pkts >> 8) & 0xFF, n_pkts & 0xFF, 0x00, 0x00]))
    for attempt in range(10):
        link.flush()
        link.write(tot)
        fr = read_frame(link, 0x92, timeout=5)
        if fr:
            logfn(f"device ready: {n_pkts} packets, {len(stream)} bytes to write")
            break
        logfn(f"tot_pkts attempt {attempt+1}: bad/missing 92 frame")
    else:
        raise SystemExit("tot_pkts failed")

    # 4. data phase
    logfn(f"Phase 3/3: writing firmware ({n_full} full packets + {residue} B tail)")
    total_bytes = len(stream)
    prog = Progress("Writing firmware", total_bytes, logfn=logfn) if show_progress else None
    sent = 0
    str_frame = cmd_frame(0xA2, bytes([0x00, 0x00, 0x02, 0x00]))
    for i in range(n_full):
        block = stream[i*BLOCK:(i+1)*BLOCK]
        packet = block + bytes([fold(block)])
        ok = False
        for attempt in range(5):
            link.flush()
            link.write(str_frame)
            ack = link.read_exact(1, timeout=3)
            if ack != b"\x91":
                logfn(f"pkt {i}: str ack {ack.hex() if ack else '(silence)'} "
                      f"(attempt {attempt+1})")
                continue
            for resend in range(5):
                link.write(packet)
                ack = link.read_exact(1, timeout=5)
                if ack == b"\x94":
                    sent += 1
                    ok = True
                    break
                if ack == b"\x95":
                    logfn(f"pkt {i}: CRC fail, resending block ({resend+1})")
                    continue
                if ack == b"\x92":
                    logfn(f"pkt {i}: device wants str again")
                    break
                logfn(f"pkt {i}: {ack.hex() if ack else '(silence)'} "
                      f"(attempt {attempt+1})")
                break
            if ok:
                break
        if not ok:
            raise SystemExit(f"block {i} failed")
        if prog:
            done = sent * BLOCK
            prog.update(done, f"({sent}/{n_pkts} pkt, {done/1024:.0f} KiB)")
        elif (i + 1) % 50 == 0 or i == n_full - 1:
            logfn(f"  {i+1}/{n_full} blocks ok")

    # 5. stp + residue
    logfn(f"Finalizing: sending tail packet ({residue} B) and verifying")
    stp = cmd_frame(0xA3, bytes([container[11], 0x00, (residue >> 8) & 0xFF, residue & 0xFF]))
    tail = stream[n_full*BLOCK:]
    tail_packet = tail + bytes([fold(tail)]) if residue else b""
    ok = False
    for attempt in range(10):
        link.flush()
        link.write(stp)
        if link.read_exact(1, timeout=3) != b"\x91":
            logfn(f"stp attempt {attempt+1}: missing 91")
            continue
        logfn(f"stp(residue={residue}) ok (91)")
        if not residue:
            ok = True
            break
        for resend in range(5):
            link.write(tail_packet)
            ack = link.read_exact(1, timeout=5)
            if ack == b"\x94":
                logfn(f"tail packet accepted ({len(tail)} B)")
                if prog:
                    prog.update(total_bytes, f"({n_pkts}/{n_pkts} pkt, {total_bytes/1024:.0f} KiB)")
                ok = True
                break
            if ack == b"\x95":
                logfn(f"tail CRC fail, resending ({resend+1})")
                continue
            logfn(f"tail: {ack.hex() if ack else '(silence)'}")
            break
        if ok:
            break
    if not ok:
        raise SystemExit("final packet failed")
    if prog:
        prog.finish()

    # 6. completion frame F1
    fin = link.read_exact(6, timeout=15)
    if len(fin) == 6 and fin[0] == 0xF1 and fin[5] == fold(fin[0:5]):
        meta["f1_ok"] = True
        logfn("final verification: F1 completion frame received")
    else:
        logfn(f"warn: expected F1 frame, got {fin.hex(' ') if fin else '(silence)'}")

    # 7. device info 55 06
    info = link.read_exact(11, timeout=15)
    if len(info) == 11 and info[0] == 0x55 and info[1] == 0x06 and info[10] == fold(info[0:10]):
        brand = {0: "The Legend (genuine)", 1: "clone: Tianxie", 2: "clone: Gold Hunter"}.get(info[2], f"unknown({info[2]})")
        coil = int.from_bytes(info[3:7], "little")
        meta["brand"], meta["coil"], meta["mc"], meta["sum"], meta["most"] = info[2], coil, info[7], info[8], info[9]
        meta["info_ok"] = True
        logfn(f"device info: brand={brand} coilID={coil} mc={info[7]} sum={info[8]} most={info[9]}")
    else:
        logfn(f"warn: expected 55 06 frame, got {info.hex(' ') if info else '(silence)'}")

    return sent, n_full, residue, meta


# ---------------- server fetch & list ----------------

def http_get(url, timeout=30):
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


VERSION_RE = re.compile(r"v[0-9A-Za-z][0-9A-Za-z._-]{0,63}")


def is_safe_version(v):
    return bool(VERSION_RE.fullmatch(v)) and ".." not in v


def require_version(v):
    v = v.strip()
    if not is_safe_version(v):
        raise SystemExit(
            f"invalid version {v!r}: must start with 'v' and contain only "
            "letters, digits, '.', '_' or '-' (no path separators)")
    return v


def parse_version_list(text):
    return [v.strip() for v in text.split(";")
            if v.strip() and is_safe_version(v.strip())]


def version_key(v):
    return tuple(int(x) for x in re.findall(r"\d+", v)) or (0,)


def latest_version(versions):
    return max(versions, key=version_key)


def available_versions():
    return parse_version_list(http_get(list_url()).decode(errors="replace"))


def list_versions():
    versions = available_versions()
    latest = latest_version(versions) if versions else None
    log(f"model: {MODEL['name']}")
    for v in versions:
        tag = " (latest)" if v == latest else ""
        if os.path.exists(f"legend-{v}.h"):
            tag += " (downloaded)"
        log(f"{v}{tag}")
    return versions


def download_file(url, out, logfn=log, validate=None):
    logfn(f"downloading {url}")
    tmp = out + ".part"
    ok = False
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=30) as r:
            total = int(r.headers.get("Content-Length") or 0) or None
            prog = Progress("Downloading", total)
            h = hashlib.sha256()
            n = 0
            with open(tmp, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
                    h.update(chunk)
                    n += len(chunk)
                    prog.update(n, f"{n/1048576:.1f} MB")
            prog.finish()
            if total is not None and n != total:
                raise SystemExit(f"download truncated: got {n} of {total} bytes")
        if validate:
            validate(tmp)
        os.replace(tmp, out)
        ok = True
    except (urllib.error.URLError, OSError, http.client.HTTPException) as e:
        raise SystemExit(f"download failed: {e}")
    finally:
        if not ok:
            try:
                os.unlink(tmp)
            except OSError:
                pass
    logfn(f"downloaded {url} -> {out} ({n} B sha256={h.hexdigest()[:16]})")
    return n


def fetch_update(version=None):
    versions = available_versions()
    if not versions:
        raise SystemExit("no versions in server list")
    ver = require_version(version) if version else latest_version(versions)
    if ver not in versions:
        log(f"warn: {ver} not in server list {versions}; trying anyway")
    url = soft_url(ver)
    out = f"legend-{ver}.h"
    expected = version_key(ver)

    def check(path):
        _c, file_ver = parse_container(path)
        if file_ver != expected:
            raise SystemExit(f"{path}: version mismatch: requested {ver}, "
                             f"container is v{file_ver[0]}.{file_ver[1]:02d}")

    download_file(url, out, validate=check)
    _c, file_ver = parse_container(out)
    if file_ver != expected:
        raise SystemExit(f"{out}: version mismatch: requested {ver}, container is "
                         f"v{file_ver[0]}.{file_ver[1]:02d}")
    return out, ver


# ---------------- USB / serial helpers ----------------

USB_NAMES = {
    (0x10C4, 0xEA60): "Silicon Labs CP210x",
    (0x0403, 0x6001): "FTDI FT232R",
    (0x0403, 0x6010): "FTDI FT2232",
    (0x0403, 0x6011): "FTDI FT4232",
    (0x0403, 0x6014): "FTDI FT232H",
    (0x0403, 0x6015): "FTDI FT231X",
    (0x1A86, 0x7523): "QinHeng CH340",
}


def serial_ports():
    try:
        from serial.tools import list_ports
        return sorted(p.device for p in list_ports.comports())
    except Exception:
        return []


def usb_info(port):
    """USB identity of a serial port, e.g. chip name, VID:PID, serial, path."""
    try:
        from serial.tools import list_ports
        ports = list(list_ports.comports())
    except Exception:
        return None
    target = os.path.realpath(port)
    for p in ports:
        if p.device != port and os.path.realpath(p.device) != target:
            continue
        if not p.vid or not p.pid:
            return "unknown (no USB metadata)"
        name = USB_NAMES.get((p.vid, p.pid), "USB device")
        extra = []
        if p.serial_number:
            extra.append(f"serial={p.serial_number}")
        if p.location:
            extra.append(f"path={p.location}")
        suffix = (" " + " ".join(extra)) if extra else ""
        return f"{name} ({p.vid:04x}:{p.pid:04x}){suffix}"
    return None


def open_serial(port):
    try:
        import serial
    except ImportError:
        raise SystemExit("error: pyserial is required (pip install pyserial)")
    try:
        return serial.Serial(port=port, baudrate=115200, bytesize=8, parity="N",
                             stopbits=1, timeout=0.1, write_timeout=5,
                             xonxoff=False, rtscts=False)
    except (serial.SerialException, OSError) as e:
        ports = serial_ports()
        found = (f"ports found: {', '.join(ports)}" if ports
                 else "no serial ports found")
        raise SystemExit(
            f"error: {e} - is {port} correct?\n"
            f"{found}\n"
            "check that the detector is connected and in update mode and that you "
            "have permission to access it (e.g. dialout group)")


def probe_device(port):
    """Read-only identification of the connected Legend."""
    log(f"probing {port} ...")
    info = usb_info(port)
    if info:
        log(f"USB: {info}")
    ser = open_serial(port)
    try:
        link = SerialLink(ser)
        detail = legend_handshake(link, attempts=5, timeout=1.0)
        if not detail:
            ports = serial_ports()
            extra = (f"; ports found: {', '.join(ports)}" if ports else "")
            raise SystemExit(
                f"no Legend detected on {port}{extra} - put it in update mode "
                f"(hold UP at power-on) and check the cable/port")
        log(f"Detected: The Legend, firmware version {detail[4]}.{detail[5]:02d}")
        return 0
    except OSError as e:
        raise SystemExit(f"serial I/O failed on {port}: {e} - is {port} correct?")
    finally:
        ser.close()


def local_versions(ext):
    out = []
    try:
        names = os.listdir(".")
    except OSError:
        return out
    for name in names:
        if not name.startswith("legend-") or not name.endswith(ext):
            continue
        ver = name[len("legend-"):-len(ext)]
        if is_safe_version(ver):
            out.append(ver)
    return sorted(out, key=version_key)


def real_update(port, path, yes, allow_unverified=False):
    if not yes:
        raise SystemExit("refusing to write to a real device without --yes (FLASH WRITE)")
    container, ver = parse_container(path)
    log(f"container v{ver[0]}.{ver[1]}  -> {port}")
    ser = open_serial(port)
    try:
        ser.dtr = True
        ser.rts = True
    except (AttributeError, OSError) as e:
        log(f"warn: could not set DTR/RTS on {port}: {e}")
    link = SerialLink(ser)
    try:
        try:
            sent, n_full, residue, meta = do_update(link, container, ver,
                                                    show_progress=True)
        except OSError as e:
            raise SystemExit(f"serial I/O failed on {port}: {e} - is {port} correct?")
        verified = bool(meta.get("f1_ok") and meta.get("info_ok"))
        if verified:
            old = meta.get("device_ver")
            old_s = f"v{old[0]}.{old[1]:02d}" if old else "?"
            new = meta.get("new_ver") or ver
            log("")
            log(f"Update complete: The Legend {old_s} -> v{new[0]}.{new[1]:02d}.")
            log("Recommended: perform a factory reset on the detector after updating.")
            log("  The Legend: Settings -> User Profile, then hold Pinpoint until 'Fd' appears.")
        else:
            log("WARNING: update finished but completion frames were not fully verified; re-run the update.")
        if not verified and not allow_unverified:
            raise SystemExit("update could not be verified; re-run the update "
                             "(or pass --allow-unverified)")
        return 0
    finally:
        ser.close()


def cmd_list(a):
    list_versions()


def cmd_download(a):
    fetch_update(a.version)


def cmd_probe(a):
    probe_device(a.port)


def cmd_flash(a):
    ext = ".h"
    if a.version:
        ver = require_version(a.version)
    else:
        local = local_versions(ext)
        if local:
            ver = local[-1]
            log(f"using latest local version {ver}")
        else:
            versions = available_versions()
            if not versions:
                raise SystemExit("no versions in server list")
            ver = latest_version(versions)
    path = f"legend-{ver}{ext}"
    local_ok = False
    if os.path.exists(path):
        log(f"using local {path}")
        try:
            _c, file_ver = parse_container(path)
            if file_ver != version_key(ver):
                raise SystemExit(f"{path}: contains "
                                 f"v{file_ver[0]}.{file_ver[1]:02d}, expected {ver}")
            local_ok = True
        except SystemExit as e:
            log(f"local {path} is invalid ({e}); re-downloading")
    if not local_ok:
        log(f"{path} not usable; downloading")
        path, ver = fetch_update(ver)
    real_update(a.port, path, a.yes, a.allow_unverified)


def main(argv=None):
    ap = argparse.ArgumentParser(description="Nokta The Legend firmware updater")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sp = sub.add_parser("list", help="list firmware versions available on the server")
    sp.set_defaults(func=cmd_list)

    sp = sub.add_parser("download", help="download firmware to the current folder")
    sp.add_argument("--version", help="firmware version (default: latest)")
    sp.set_defaults(func=cmd_download)

    sp = sub.add_parser("probe", help="read-only identification of the connected Legend")
    sp.add_argument("--port", default="/dev/ttyUSB0",
                    help="serial device (default: /dev/ttyUSB0)")
    sp.set_defaults(func=cmd_probe)

    sp = sub.add_parser("flash", help="download (if needed) and write firmware to the Legend")
    sp.add_argument("--version", help="firmware version (default: latest)")
    sp.add_argument("--port", default="/dev/ttyUSB0",
                    help="serial device (default: /dev/ttyUSB0)")
    sp.add_argument("--allow-unverified", action="store_true",
                    help="exit 0 even if completion frames were not verified")
    sp.add_argument("--yes", action="store_true",
                    help="confirm writing firmware to a real device")
    sp.set_defaults(func=cmd_flash)

    a = ap.parse_args(argv)
    try:
        a.func(a)
    except KeyboardInterrupt:
        print()
        log("interrupted")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
