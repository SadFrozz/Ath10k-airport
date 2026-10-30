# Native macOS integration requirements

This document defines required behavior, not implementation status. See
[docs/development/NATIVE-STATUS.md](../development/NATIVE-STATUS.md) for evidence and remaining work,
[docs/development/NATIVE-CALLBACK-MATRIX.json](../development/NATIVE-CALLBACK-MATRIX.json) for callback inventory,
and [the historical investigation](../history/NATIVE-CONTRACT.md) for recovered
addresses, ABI observations and chronological experiments.

## Required behavior

| Area | Required contract | Acceptance evidence |
| --- | --- | --- |
| Delivery | Kext injected through OpenCore; stock OS networking components; no companion app or system-volume patches | Build/package inspection and loaded kernel UUID |
| ABI | Validate the selected OS adapter before touching hardware; never infer cross-version support from a successful build | Recovered matching stock ABI, adapter tests and per-OS boot evidence |
| Queues | Enforce WCL → radio lock order; no synchronous reverse entry or wait under an owned gate; bound pending work | Production-path cancellation, contention and teardown regressions |
| Start/stop | Publish availability only after readiness; retire callbacks, DMA, peers and work before releasing owners; retain uncertain DMA ownership | Failure-injection lifecycle tests and hardware startup/shutdown |
| Scan | Honor SSID/channel/regulatory filters, publish discoveries promptly, complete or cancel each accepted request once | Consolidated scan regressions and relevant hardware regression |
| Association | Preserve requested security, credential lifetime, station identity and AP parameters; bound retry/abort; publish BSS/link/completion in stock order | Production dispatcher tests plus native association and traffic |
| Security | Follow [docs/contracts/WPA3-CONTRACT.md](WPA3-CONTRACT.md); never mix internal supplicant and external key ownership | Key/PMF/SAE regression group and separate radio evidence |
| Data | Admit only authorized traffic, handle backpressure, preserve DMA/packet ownership, validate RX replay and aggregation | TX/RX regression group and interface-bound traffic |
| Reconnect/roam | Retire old keys and firmware owners before reuse; generation-bind prepared profiles; send ordered Start/Prep/Reassoc/Complete; preserve carrier only during valid handoff | Production integration with failures and cancellation; physical handoff remains separately unverified on one router |
| Power | Quiesce asynchronously and fence old callbacks; restore only after hardware readiness | Local power regressions; platform sleep deferred, status “Possibly working” |
| Compatibility | Provide validated adapters for macOS 11–26; reject unsupported ABIs | Separate OS acceptance, not one Sequoia result |
| AWDL/AirDrop | Implement peer/interface/channel coordination and required OS contracts as a separate feature stage | Protocol, OS integration and interoperability evidence |

## Acceptance policy

Previously implemented behavior is covered by one consolidated entry point:
`python3 tests/run-development-tests.py --cxx clang++` (`make test-development`).
Run once after final changes in a related batch; repeat only for changed code,
a failure or a specific unresolved concern. Local passing tests do not certify
radio interoperability, all callbacks, other OS versions or platform sleep.

A callback returning Unsupported is not automatically optional. Its consumer,
required scope and alternative path must be investigated before classification.
Publication is batched. Installation requires a verified SD rollback; reboot
requires explicit user approval and a 10-second delay.
