# Ath10k-airport

Experimental native Qualcomm Atheros QCA9377 Wi-Fi kext for OpenCore, targeting
Lunnen LLL5DAW (`168c:0042 / 1a3b:2b51`) on x86_64 macOS Sequoia.
Wi-Fi is controlled through macOS system settings and the Wi-Fi menu.
There is no companion application, login agent or application bundle to install.
The driver does not require OpenCore Legacy Patcher or changes to system volumes.

## Status

Native discovery, scanning and WPA2 traffic have worked on the development laptop.
An explicit experimental build has also connected through native SAE on Sequoia
15.6.1 (24G90), carried interface-bound IPv4/IPv6 traffic and completed one protected
unicast SA Query round trip. This is a limited hardware checkpoint, not complete
WPA3/PMF interoperability or stability certification. Group BIP and rekey have host
coverage; AP-driven hardware rekey, reconnect timing and sleep/wake remain open.
Normal reboot without forced power-off has been reported by the user.

Default builds do not enable SAE. The experimental option is guarded for the
validated kernel; broader macOS 11–26 support remains planned. AWDL/AirDrop are
unsupported. Sequoia ABI declarations are not proof of compatibility with other
releases. See [the connection audit](NATIVE-CONNECTION-AUDIT.md),
[the native contract](NATIVE-CONTRACT.md), [compatibility](COMPATIBILITY.md) and
[WPA3 requirements](WPA3-CONTRACT.md).

## Build

```sh
make -j2 kext
# Explicit equivalent:
make NATIVE=1 DIAGNOSTIC_STAGE=0 -j2 kext
```

The opt-in SAE build for the currently validated kernel is:

```sh
make NATIVE=1 NATIVE_SAE_EXPERIMENTAL=1 NATIVE_PMF_PROBE=0 DIAGNOSTIC_STAGE=0 -j2 kext
```

This keeps the one-shot startup PMF hardware diagnostic disabled. Experimental
admission does not bypass the kernel/profile/key checks or downgrade a requested
SAE connection to WPA2. See [the WPA3 contract](WPA3-CONTRACT.md) for limitations.

Output: `build/native/out/Ath10kMac.kext`. Only this kext is the driver deliverable;
release archives also include documentation, licenses and checksums.
`DIAGNOSTIC_STAGE=3` explicitly selects the controller-only diagnostic, which stops
before radio startup. It is not the functional Wi-Fi driver.
`NATIVE=0` retains the historical Ethernet-backed implementation for development;
it is not the default or release configuration.

Build commands do not install into EFI or reboot the computer. For Windows
cross-compilation, see [the Windows guide](docs/windows-build.md).
Generated firmware headers and `firmware/prepared/` stay outside source control.

## Checks

```sh
python3 scripts/audit-native-callbacks.py --check
python3 tests/run-development-tests.py
```

Host models and successful compilation do not prove hardware stability. Offline
kernel binding requires exact candidate inclusion checks; see
[validation limits](OFFLINE-VALIDATION-ERRATUM.md).
The optional `Collect-macOS-diagnostics.command` reads diagnostics; it is not an
application or a requirement for native Wi-Fi operation.

## Provenance and licenses

Based on jonasw8/Ath10kMac and thekunalthakur/Ath10kMac. Private declarations and
local ABI amendments are recorded in `vendor/itlwm/SOURCE.json`. MacKernelSDK,
firmware and regulatory data retain their own notices. See `LICENSE`, `firmware/`,
`regulatory/` and `vendor/itlwm/`.
