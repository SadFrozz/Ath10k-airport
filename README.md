# Ath10k-airport

Experimental native Qualcomm Atheros Wi-Fi driver for macOS, loaded through
OpenCore. Networks are managed through the macOS Wi-Fi menu and System Settings.
No companion app, login agent, OpenCore Legacy Patcher or system-volume patches
are required.

[Documentation](docs/guides/native-sequoia.md) ·
[Compatibility](docs/compatibility/COMPATIBILITY.md) ·
[Releases](https://github.com/SadFrozz/Ath10k-airport/releases) ·
[Issues](https://github.com/SadFrozz/Ath10k-airport/issues) ·
[Changelog](CHANGELOG.md)

## Features and status

- Native network discovery, scanning, association and IPv4/IPv6 traffic.
- WPA2-Personal and experimental WPA3-Personal/SAE with PMF.
- Internal key updates, replay protection and protected management handling.
- Host-requested roaming implementation with local regression coverage.

**This is a development driver, not a stable general-purpose release.** The
hardware checkpoint is QCA9377 (`168c:0042`, subsystem `1a3b:2b51`) in a Lunnen
LLL5DAW on x86_64 macOS Sequoia 15.6.1 (24G90). Other cards and system versions
are not implied by the presence of firmware or headers in this repository.

| Area | Current limitation |
| --- | --- |
| Stability | Disconnects, transmission errors and latency remain under investigation |
| WPA3/PMF | SAE traffic and one protected SA Query exchange observed; full interoperability and AP-triggered rekey remain unverified |
| Roaming | Physical inter-AP handoff has not been tested |
| Sleep/wake | Possibly working at driver level; platform sleep investigation is deferred |
| macOS 11–26 | Broader support is a development target, not a supported-version range |
| AWDL/AirDrop | Not implemented |
| Enterprise / FT / SAE-PK | Not implemented or advertised |

See the [implementation and evidence map](docs/development/NATIVE-STATUS.md) for
precise scope. SAE is disabled in default builds and requires the explicit
experimental option below.

## Installation

Use only a build intended for your hardware and macOS version. Preserve a known
working EFI and another network connection before replacing the driver.

1. Copy the built `Ath10kMac.kext` to `EFI/OC/Kexts`.
2. Add or update its enabled entry in `Kernel → Add` in OpenCore's `config.plist`.
3. Check your OpenCore configuration, then reboot to load the new binary.
4. Select the network using the standard macOS Wi-Fi controls.

Install the kext bundle only; no application or additional system patch is part
of this driver. Do not treat controller-only or cryptography diagnostic builds
as functional Wi-Fi releases. See the [native guide](docs/guides/native-sequoia.md).

## Building

Clone the repository with its pinned dependencies:

```sh
git clone --recurse-submodules https://github.com/SadFrozz/Ath10k-airport.git
cd Ath10k-airport
# For an existing checkout:
git submodule update --init --recursive
make -j2 kext
```

Building on macOS requires the Apple command-line toolchain and Python 3.
The output is `build/native/out/Ath10kMac.kext`. For the experimental SAE build
on the validated kernel:

```sh
make -j2 NATIVE=1 NATIVE_SAE_EXPERIMENTAL=1 NATIVE_PMF_PROBE=0 DIAGNOSTIC_STAGE=0 kext
```

Run the consolidated regression suite with `make test-development`.
Local tests do not certify radio interoperability or additional macOS versions.
See [Windows build instructions](docs/guides/windows-build.md) for the separate
cross-compilation workflow.

## Development

- `src/core`: radio, firmware transport and data path.
- `src/security`: authentication, key exchange and protected management.
- `src/macos`: controller, native OS integration and ABI definitions.
- `tests`: matching test groups, fixtures and shared support.
- `scripts`: build, validation and diagnostics tooling.
- `packaging`: kext and Xcode project templates.
- `vendor`: pinned upstream submodules; generated headers belong in `build`.
- [`firmware`](firmware/README.md): chipset-specific inputs, provenance and licenses.
- `docs`: requirements, current development state, guides and historical evidence.

Read the [native contract](docs/contracts/NATIVE-CONTRACT.md),
[security contract](docs/contracts/WPA3-CONTRACT.md) and [agent instructions](AGENTS.md)
before changing implementation. Submit bug reports with the OS build, PCI IDs,
driver build/UUID, reproduction steps and relevant sanitized diagnostics. Never
include network passwords or key material.

## Credits and licensing

- [Acidanthera / MacKernelSDK](https://github.com/acidanthera/MacKernelSDK) for the kernel SDK.
- [OpenIntelWireless / itlwm](https://github.com/OpenIntelWireless/itlwm) and
  [laobamac's fork](https://github.com/laobamac/itlwm) for native Wi-Fi ABI references.
- Linux ath10k contributors and Qualcomm Atheros firmware authors for reference
  implementations and firmware; retain the notices shipped with these files.

Project licensing is recorded in [LICENSE](LICENSE). Dependencies and firmware
retain their own licenses. The [dependency guide](docs/guides/dependencies.md)
records pinned revisions and local ABI overrides. The [licensing review](docs/guides/license-audit.md)
records unresolved third-party compatibility questions; the root license does
not cover every bundled component.

See [CI and releases](docs/guides/ci.md) for triggers, Release/Debug packages and tag publication.
