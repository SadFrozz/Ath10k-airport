# Sequoia native adapter: current diagnostic stage

Target: Lunnen LLL5DAW, QCA9377 `168c:0042`, subsystem `1a3b:2b51`,
macOS Sequoia 15.6.1 (Darwin 24.6). The adapter accepts Darwin 24.2–24.x only.
Use the stock IO80211Family, IOSkywalkFamily, corecapture and corecrypto.
The private declarations are pinned in `vendor/itlwm/SOURCE.json`.

This is an experimental adapter, not a working native Wi-Fi release. Native
enumeration, joins, traffic, sleep/wake and the system Wi-Fi menu remain unverified.
SAE/WPA3 and PMF are not implemented. AWDL and AirDrop are unsupported.

## Stage-3 failure and correction

The previous driver returned one `IO80211WorkQueue` from both `getWorkLoop()` and
`getWorkQueue()`. In the installed Sequoia IO80211Family, that queue's `getThread()`
returns NULL. `IONetworkController::start()` compares its workloop with the
provider's, and, if different, passes its thread to `ml_thread_policy()`. The kernel
then accesses the thread's mutex without checking for NULL. The direct PCI provider
does not expose the newly allocated queue; the upstream itlwm provider wrapper does.

The driver now creates a regular `IOWorkLoop` for the legacy network controller and
a separate `IO80211WorkQueue` for WCL. It checks the ordinary thread and queue
separation before starting the base controller. Both queue references survive the
base controller's timer/gate cleanup. After `super::free()`, cleanup uses saved
local references only, never the destroyed driver's members.

The faulty call chain was established from the installed kext and kernel collection.
A failed-boot stack was not persisted; confirmation on hardware is still pending.

`make NATIVE=1` defaults to diagnostic stage 3. It starts and stops the base
controller, then exits before opening PCI, loading radio firmware or starting DMA.
Its success marker is `opencore-controller-passed`. Additional properties are
`Ath10kLegacyWorkLoopHasThread` and `Ath10kWorkQueuesSeparated`.
Stages 1 and 2 previously booted successfully on the target. The corrected stage 3
has been built and checked offline, but not boot-tested.

## Builds

macOS / Xcode:

```sh
make NATIVE=1 DIAGNOSTIC_STAGE=3 -j2 kext
codesign --force --sign - build/native/out/Ath10kMac.kext
```

Windows: see [the cross-build instructions](windows-build.md). No local macOS,
WSL or VM is needed. The native CI job builds a separate stage-3 artifact on an
Intel macOS runner. The existing legacy build/release job is preserved.

Portable regressions:

```sh
python3 tests/run-development-tests.py
# Windows:
python tests/run-development-tests.py --zig path/to/zig.exe
```

These builds and tests do not install into EFI, reboot, or establish radio/WPA3 support.
