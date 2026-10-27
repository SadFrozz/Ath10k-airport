# Ath10k-airport

Experimental Qualcomm Atheros driver development for the Lunnen LLL5DAW:
QCA9377 `168c:0042 / 1a3b:2b51`, macOS Sequoia 15.6.1, x86_64.

The current native adapter targets the stock macOS networking stack and the system
Wi-Fi UI. **The corrected controller diagnostic has been built and checked offline;
native enumeration, the Wi-Fi menu and connections have not been verified on hardware.**
WPA3/SAE and PMF are not implemented. AWDL and AirDrop are unsupported.

## Current change

- Adds the experimental Sequoia IO80211/Skywalk adapter and pinned private headers.
- Selects the exact Lunnen board-calibration profile and keeps existing radio/security work.
- Fixes stage 3 passing a NULL thread into the network controller: a real `IOWorkLoop`
  and a distinct `IO80211WorkQueue` now serve their respective controller paths.
- Keeps both queues alive through base-controller cleanup and adds startup checks.
- Provides complete Windows cross-compilation, Mach-O linking, ad-hoc signing and
  independent structural/hash verification, without running macOS.
- Builds a separate native stage-3 artifact in CI while preserving the legacy job.

See [the native adapter status](docs/native-sequoia.md),
[Windows build instructions](docs/windows-build.md), and
[historical legacy-driver background](docs/legacy-background.md).

## Build

On macOS with Xcode:

```sh
make NATIVE=1 DIAGNOSTIC_STAGE=3 -j2 kext
```

The result is `build/native/out/Ath10kMac.kext`. Stage 3 tests the base controller
start/stop path and returns before opening PCI, loading radio firmware or starting DMA.
`make` without `NATIVE=1` retains the legacy Ethernet-backed build.

On Windows, follow [the cross-build guide](docs/windows-build.md). Python, Zig,
the Cygwin Apple ld64 port and rcodesign produce a complete x86_64 kext locally.
No EFI install, rollback or reboot operation is part of these build scripts.

## Portable checks

```sh
python3 tests/run-development-tests.py
# Windows:
python tests/run-development-tests.py --zig path/to/zig.exe
```

These cover firmware/board selection, RSN policy, security vectors, native wire/status/
capture layouts and diagnostic privacy. They cannot establish hardware compatibility.
The read-only `Collect-macOS-diagnostics.command` gathers selected diagnostics without
Wi-Fi credentials, SSIDs, MAC addresses or machine serial numbers.

## Credits and licenses

Based on [jonasw8/Ath10kMac](https://github.com/jonasw8/Ath10kMac) and
[thekunalthakur/Ath10kMac](https://github.com/thekunalthakur/Ath10kMac).
Private declarations are pinned to laobamac/itlwm commit
`738d4c61b5a64433b27c1ab09dba94916ab77d8d`; provenance and license are in `vendor/itlwm`.
MacKernelSDK, firmware and regulatory sources retain their own notices and licenses.
See `LICENSE`, `firmware/` and `regulatory/`.
