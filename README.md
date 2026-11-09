# Nokta The Legend firmware updater

Reverse-engineered firmware updater for **The Legend**. Other
Nokta models are not supported (yet).

## Status

| Model | list | download | probe | flash |
|---|---|---|---|---|
| The Legend (gen 1) | yes | yes | yes | yes |

`list` and `download` contact Nokta's update server. `probe` and `flash` work
with a locally connected detector.

## Install

- Python 3.10+
- `python3 -m pip install -r requirements.txt` (only `pyserial` is required)
- Linux: the user needs access to the serial device (usually the `dialout` group)

The default port is `/dev/ttyUSB0`; override with `--port`.

## Usage

```bash
python3 tools/nokta_updater.py list
python3 tools/nokta_updater.py download --version v1.17
python3 tools/nokta_updater.py probe
python3 tools/nokta_updater.py flash --version v1.17 --yes
```

`flash` refuses to write without `--yes`. After an update it expects the
device's completion frames (`F1` and `55 06`); if they are missing it exits
nonzero unless `--allow-unverified` is given for diagnostics. Ctrl-C exits
cleanly with status 130.

Put the detector in update mode (hold UP while powering on), connect the Nokta
USB data cable, and run `probe` first. After a successful update Nokta
recommends a factory reset: Settings -> User Profile, hold Pinpoint until `Fd`
appears.

## Firmware layout

```text
firmware/
  legend/
    legend-v1.05 ... v1.17 .h   vendor C-array firmware containers
    legend-v1.05 ... v1.17 .bin extracted encrypted payloads
    SHA256SUMS
```

- `.h` containers carry a 16-byte header (magic `52 54 89`, header minor equal
  to the declared version) and a whole-file XOR checksum of zero.
- `.bin` files are the extracted container payloads; they are byte-identical
  to the corresponding `.h` payload.
- These files are archival reference copies. The CLI still resolves local
  firmware from the current working directory (`legend-<version>.h`) and
  downloads into it.

## Notes

- USB serial bridge: Silicon Labs CP210x (`10c4:ea60`), 115200 8N1.
- Commands are 7-byte frames: `01 cmd params... chk`, where
  `chk = 0xFF ^ XOR(cmd + params)`.
- Flow: ID (`01 81 00 00 00 00 7E`) -> prepare/erase (`01 4C ...`) -> total packet
  count (`01 DA ...`) -> `str` (`01 A2 ...`) + 512-byte block + block checksum ->
  tail (`01 A3 ...`) -> `F1` completion frame -> `55 06` device-info frame.
- Device replies use `91` for an ACK, `94` for a good block, `95` to request a
  block retry, plus 7-byte status frames such as `91 61 ...` (ready) and
  `91 92 ...` (packet count).
- Firmware containers are C-array `.h` files. The update stream is the
  container after its 16-byte header, split into 512-byte blocks plus a
  residue tail.
- The ready frame is `0x91` followed by a 6-byte body (`0x61` + four data bytes
  + checksum); the total-count reply is `0x91 0x92 ...` with the same framing.
- `probe` and `flash` are read-only until a verified container is ready to
  write; `flash` checks the ID handshake and refuses without `--yes`.

## Official tool telemetry

The official Windows updater reports telemetry after a completed update. In
the captured v1.13 -> v1.17 session it sent one POST at the end of the update
(after the new/old firmware versions were known); no POST was observed on
launch, version listing, or download. It is sent automatically, without a
telemetry consent prompt, to:

`https://source.noktadetectors.com/analytics/log_flask_legend_client.php`

Exact captured JSON body:

```json
{
    "BL Version": "0.0",
    "Coil ID": "69110445",
    "Device Info": "The Legend",
    "HW Version": "1.1",
    "Ip": "",
    "Language": "english",
    "Match Counter": "0",
    "Most Match Device": "The Legend",
    "New SW Version": "v1.17",
    "Old SW Version": "v1.13",
    "Operating System": "windows 10",
    "Sum of Counter": "0",
    "Update Tool Version": "2.1.2"
}
```

`Operating System` is `windows 10` here because the official tool was captured
under Wine. This project does not send telemetry.

## Safety

- Never flash without a verified container and a known recovery path.
- Interrupted transfers can leave the detector in update mode; re-enter UP mode
  and re-run the update.
- A factory reset after flashing is recommended by Nokta.

## License

The original source code, tests, and documentation are licensed under the MIT
License (see LICENSE). The firmware files under firmware/ are proprietary Nokta
artifacts and are not covered by that license (see NOTICE).

## Tests

```bash
python3 -m unittest discover -s tests
NOKTA_SLOW_TESTS=1 python3 -m unittest tests.test_updater_emulator
```

The suite uses a PTY-based Legend bootloader emulator; it needs no detector and
no network. The slow test runs the full Legend v1.13 image byte-for-byte.
