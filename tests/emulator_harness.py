"""PTY harness: run nokta_updater.do_update against tools/legend_emulator.Legend.

Relocated from the old --emulator-test CLI mode. Used by unit tests only.
"""
import os
import pty
import select
import sys
import threading
import time
import tty

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import nokta_updater as U
from legend_emulator import Legend


def run_against_emulator(path, logfn=U.log):
    """Returns dict: ok, sent, n_full, residue, received, expected_len."""
    container, ver = U.parse_container(path)
    master, slave = pty.openpty()
    tty.setraw(slave)
    os.set_blocking(master, False)
    dev = Legend()
    stop = threading.Event()

    def emu():
        buf = b""
        while not stop.is_set():
            r, _, _ = select.select([slave], [], [], 0.05)
            if not r:
                continue
            try:
                chunk = os.read(slave, 65536)
            except OSError:
                continue
            if not chunk:
                continue
            buf += chunk
            while buf:
                if dev.wait_block is not None:
                    need = dev.wait_block + 1
                    if len(buf) < need:
                        break
                    frame, buf = buf[:need], buf[need:]
                    resp, note = dev.parse(frame)
                    if os.environ.get("UPDBG"):
                        logfn(f"  [emu<-] data {len(frame)}B [{note}] resp={resp.hex() if resp else None}")
                    if resp:
                        os.write(slave, resp)
                    continue
                if buf[0] == U.MARKER:
                    if len(buf) < 4:
                        break
                    need = 7 if buf[1] in (0x81, 0x4C, 0xDA, 0xA2, 0xA3) else 4
                    if len(buf) < need:
                        break
                    frame, buf = buf[:need], buf[need:]
                else:
                    if len(buf) < U.BLOCK + 1:
                        r2, _, _ = select.select([slave], [], [], 0.05)
                        if not r2:
                            frame, buf = buf[:], b""
                        else:
                            continue
                    else:
                        frame, buf = buf[:U.BLOCK + 1], buf[U.BLOCK + 1:]
                resp, note = dev.parse(frame)
                if os.environ.get("UPDBG"):
                    logfn(f"  [emu<-] {frame[:8].hex(' ')}{'...' if len(frame) > 8 else ''} "
                          f"({len(frame)})  [{note}]  resp={resp.hex() if resp else None}")
                if resp:
                    os.write(slave, resp)

    t = threading.Thread(target=emu, daemon=True)
    t.start()
    try:
        sent, n_full, residue, meta = U.do_update(U.Link(master), container, ver, logfn=logfn)
    finally:
        stop.set()
        time.sleep(0.1)
        os.close(master)
        os.close(slave)

    received = bytes(dev.received)
    expected = bytes(container[16:])
    ok = sent == n_full and received == expected
    logfn(f"EMULATOR: blocks_sent={sent}/{n_full} residue={residue} "
          f"received={len(received)} expected={len(expected)} -> "
          f"{'PASS' if ok else 'FAIL'}")
    return {"ok": ok, "sent": sent, "n_full": n_full, "residue": residue,
            "received": received, "expected_len": len(expected), "meta": meta}
