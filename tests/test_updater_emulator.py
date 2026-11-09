"""End-to-end updater vs bootloader-emulator tests (PTY harness, no hardware)."""
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import emulator_harness
from emulator_harness import U
from test_protocol import make_container, write_h


class TestEmulatorE2E(unittest.TestCase):
    def test_small_container(self):
        stream = bytes((i * 7 + 3) & 0xFF for i in range(U.BLOCK))
        stream += bytes((i * 11 + 5) & 0xFF for i in range(U.BLOCK))
        stream += bytes(range(24))
        data = make_container(stream, major=9, minor=9)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v9.09.h")
            write_h(p, data, 9, 9)
            r = emulator_harness.run_against_emulator(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["sent"], 2)
        self.assertEqual(r["residue"], 24)
        self.assertEqual(r["received"], data[16:])

    @unittest.skipUnless(os.environ.get("NOKTA_SLOW_TESTS"),
                         "set NOKTA_SLOW_TESTS=1 for full-image e2e")
    def test_full_v113(self):
        root = os.path.dirname(HERE)
        p = os.path.join(root, "firmware", "legend", "legend-v1.13.h")
        r = emulator_harness.run_against_emulator(p)
        self.assertTrue(r["ok"])
        self.assertEqual(r["sent"], 560)
        self.assertEqual(r["residue"], 96)
        self.assertEqual(r["expected_len"], 286816)


if __name__ == "__main__":
    unittest.main()
