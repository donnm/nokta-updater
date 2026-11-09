"""Pure unit tests for the Legend update protocol helpers."""
import os
import sys
import tempfile
import unittest

TOOLS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tools")
if TOOLS not in sys.path:
    sys.path.insert(0, TOOLS)

import nokta_updater as U


def make_container(stream, major=9, minor=9):
    hdr = bytearray(16)
    hdr[0] = 0x5A
    hdr[1:4] = b"\x52\x54\x89"
    hdr[5] = 0x01
    hdr[7] = 0x01
    hdr[8] = minor
    hdr[10] = 0x01
    hdr[11] = 0x31
    data = bytes(hdr) + stream
    x = 0
    for b in data[:-1]:
        x ^= b
    return data[:-1] + bytes([x])


def write_h(path, data, major=9, minor=9):
    text = (f"uint data_v{major}_{minor}_length = {len(data)};\n\n"
            f"uint8_t data_v{major}_{minor}[] = {{\n"
            + ",".join(f"0x{b:02x}" for b in data) + "\n};\n")
    with open(path, "w") as f:
        f.write(text)


class TestFold(unittest.TestCase):
    def test_id_frame_check(self):
        self.assertEqual(U.fold(bytes([0x81, 0, 0, 0, 0])), 0x7E)

    def test_empty(self):
        self.assertEqual(U.fold(b""), 0xFF)


class TestCmdFrame(unittest.TestCase):
    def test_id_frame(self):
        self.assertEqual(U.cmd_frame(0x81, bytes(4)), bytes.fromhex("0181000000007e"))

    def test_str_frame(self):
        self.assertEqual(U.cmd_frame(0xA2, bytes([0, 0, 2, 0])), bytes.fromhex("01a2000002005f"))

    def test_stp_frame_shape(self):
        f = U.cmd_frame(0xA3, bytes([0x31, 0, 0, 0x60]))
        self.assertEqual(f[0], 0x01)
        self.assertEqual(f[1], 0xA3)
        self.assertEqual(f[-1], U.fold(f[1:-1]))


class TestContainer(unittest.TestCase):
    def test_roundtrip(self):
        stream = bytes(range(256)) * 4 + b"xyz"
        data = make_container(stream, 1, 13)
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "v1.13.h")
            write_h(p, data, 1, 13)
            parsed, ver = U.parse_container(p)
        self.assertEqual(ver, (1, 13))
        self.assertEqual(parsed, data)
        self.assertEqual(parsed[1:4], b"\x52\x54\x89")
        self.assertEqual(parsed[16:], data[16:])

    def test_bad_magic_rejected(self):
        data = bytearray(make_container(b"\x00" * 32))
        data[1] = 0x00
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "bad.h")
            write_h(p, bytes(data), 1, 1)
            with self.assertRaises(SystemExit):
                U.parse_container(p)


class TestVersionList(unittest.TestCase):
    def test_parse(self):
        text = "no;\nv1.09;\nv1.11;\nv1.13;\nv1.15;\nv1.17;"
        self.assertEqual(U.parse_version_list(text),
                         ["v1.09", "v1.11", "v1.13", "v1.15", "v1.17"])

    def test_parse_empty(self):
        self.assertEqual(U.parse_version_list("no;"), [])

    def test_latest_is_max_not_first(self):
        text = "no;\nv1.09;\nv1.11;\nv1.13;\nv1.15;\nv1.17;"
        self.assertEqual(U.latest_version(U.parse_version_list(text)), "v1.17")

    def test_latest_unsorted(self):
        versions = ["v1.13", "v1.05", "v1.19", "v1.09"]
        self.assertEqual(U.latest_version(versions), "v1.19")

    def test_version_key_ordering(self):
        self.assertGreater(U.version_key("v1.17"), U.version_key("v1.9"))


class TestModel(unittest.TestCase):
    def test_urls(self):
        self.assertEqual(
            U.list_url(),
            "https://source.noktadetectors.com/_the_legend_customer_softwares/"
            "available_softwares_THE_LEGEND.txt")
        self.assertEqual(
            U.soft_url("v1.13"),
            "https://source.noktadetectors.com/_the_legend_customer_softwares/"
            "THE_LEGEND_software/v1.13.h")


class TestPortOpenFailures(unittest.TestCase):
    def _container(self):
        data = make_container(bytes(range(64)))
        p = tempfile.NamedTemporaryFile(suffix=".h", delete=False)
        p.close()
        write_h(p.name, data)
        self.addCleanup(os.unlink, p.name)
        return p.name

    def test_missing_port_is_graceful(self):
        path = self._container()
        with self.assertRaises(SystemExit) as cm:
            U.real_update("/dev/definitely-not-a-port", path, yes=True)
        self.assertIn("error:", str(cm.exception))
        self.assertIn("/dev/definitely-not-a-port", str(cm.exception))

    def test_requires_yes_before_open(self):
        path = self._container()
        with self.assertRaises(SystemExit) as cm:
            U.real_update("/dev/definitely-not-a-port", path, yes=False)
        self.assertIn("without --yes", str(cm.exception))


if __name__ == "__main__":
    unittest.main()
