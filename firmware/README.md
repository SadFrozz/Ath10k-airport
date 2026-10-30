# Firmware inputs

These are original firmware containers and board-calibration databases, not
build outputs. A firmware directory does not imply tested hardware support.

| Directory | Used by driver profile | Notes |
| --- | --- | --- |
| `QCA6174/hw3.2/` | QCA6174, PCI `168c:003e`, subsystem `1028:0310` | Previously stored anonymously at the root of this directory; bytes unchanged |
| `QCA9377/hw1.0/` | QCA9377 hw1.1, PCI `168c:0042` | Keeps the upstream container-directory name; contains `PROVENANCE.json` |

The QCA9377 profiles select separate exact board keys for Dell `1028:1810` and
Lunnen `1a3b:2b51`. The Lunnen calibration must not be substituted with another
subsystem's board data. WLAN/OTP images are shared where the existing profile
explicitly permits it; this layout change does not alter selection or fallback.

`python3 scripts/build/prepare-firmware.py` validates the inputs and produces:

- `build/generated/firmware/QCA6174/`
- `build/generated/firmware/QCA9377/`
- `build/generated/firmware/QCA9377-Lunnen/`
- `src/core/Ath10kPayload.hpp` (generated, ignored by Git)

Each generated profile contains the selected board, WLAN image, OTP and manifest.
The generated C++ payload remains outside the tracked source. Run the preparation
script through the normal build; do not edit generated outputs.

The shared redistribution license is [LICENSE.QualcommAtheros_ath10k](LICENSE.QualcommAtheros_ath10k).
Each chipset directory retains its firmware-specific notice. The QCA6174 folder
name identifies this driver's existing profile; a precise original upstream
revision for that older imported copy has not been established.
