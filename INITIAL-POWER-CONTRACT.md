# Initial power and recovery contract

Status: investigation plus cached-identity matching implemented, 2026-10-28.
Automatic wake recovery and early powered initialization are not implemented.
The separately staged e105f82 boot candidate remains frozen pending permission.

## Evidence from the matching kernel

Reference: Apple's [xnu-11417.140.69 IOServicePM.cpp](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/iokit/Kernel/IOServicePM.cpp), matching
this machine's xnu-11417.140.69 kernel. The inspected source stays local; line
numbers below identify the upstream revision rather than a vendored copy.

| Function | Source location | Consequence |
| --- | --- | --- |
| `addPowerChild2` | Around 1011 | Initial desired state is derived from the parent's supplied domain flags, not by polling its current-state index |
| `OurChangeStart` | Around 4755 | The initial transition is not discarded by the ordinary same-state fast path |
| `notifyControllingDriver` | Around 4470 | The normal initial `setPowerState` call is skipped only if the selected state has `kIOPMInitialDeviceState` |
| `initialPowerStateForDomainState` | Around 7670 | The inherited implementation maps domain flags to a permitted state |
| `IOService.h::getPowerState` | Local SDK around 1769 | A parent can still report its off index while powering up its child; polling that index is not an admission protocol |

Our two-state table does not set the initial-device-state skip flag (0x100).
This establishes the normal callback path, not an unconditional callback or
startup deadline: allocation failures and incomplete parent power information
must remain fail-closed. An early-PM implementation must not bypass admission
and initialize hardware merely because a timer expires.

## Matching while power is unavailable

The current PCI provider publishes `vendor-id`, `device-id`,
`subsystem-vendor-id` and `subsystem-id` as four-byte little-endian OSData values.
Read-only registry inspection confirmed 168c:0042 / 1a3b:2b51 on this machine.

`probe` now reads retained cached properties rather than configuration space.
It validates exact OSData width/value range, also accepts bounded OSNumber
values, and rejects absent, malformed or unsupported identity without hardware
access or changing the match score. Native matching retains the Sequoia ABI and
exact Lunnen subsystem restrictions. Before enabling bus mastering/BAR access,
`identifyDevice` rechecks the real configuration identity against the same native
profile predicate. An overridden cached property is not authority to boot a
foreign module's firmware.

Tests execute the production matching helper and method against a PCI mock with
no configuration, MMIO or open API. They cover retained property ownership,
number/data encoding, missing/wrong types, malformed lengths, null data, overflow,
wrong vendor/device/subsystem, unsupported ABI and probe-only diagnostics.

## Required startup integration, still pending

1. Allocate all producer/cancellation state before joining the power plane.
2. Establish controller PM before BAR/register access and firmware/DMA work.
   Current `start` still enables/maps PCI first and registers PM after firmware;
   cached matching alone does not repair this gap.
3. Start with power permission unknown. An actual admitted On callback can queue
   the first producer once; root/device Off must block it before MMIO starts.
4. Distinguish power loss before any hardware work from power loss after a probe
   began. Only the first case may resume a fresh first probe without full rematch.
   Never clear a block which includes a pending root/device suspend intent.
5. A producer aborted before entry must not lose a later On arriving before its
   completion flag clears. Queue/cancel ownership must cover that tail race.
6. Preserve producer bookkeeping locks until PM callbacks can no longer schedule
   work; draining a thread call alone does not make a scheduler's lock disposable.
7. Normal native external control is read-only and rejects the app Restart
   operation. Automatic native recovery therefore needs an internal, retained
   worker which prepares restart under radio and terminates outside all driver
   gates, initialization barriers and PM/root callbacks. It must not wait on its
   own cancellation, use stale DMA/keys, or restart while a new sleep is pending.
8. Only verified DMA release permits PCI rematch. A fresh instance must obey its
   parent's power domain even if it missed an earlier root sleep notification.

The first remaining implementation is early PM/first-probe admission, followed
by guarded recovery/rematch. Kernel callback delivery, initial-off matching,
sleep cancellation, repeated sleep/wake and traffic restoration require hardware
validation. macOS 11–26 support is not established by this Sequoia investigation.
