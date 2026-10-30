# Initial power and recovery contract

Status: cached matching and early powered-initialization candidate implemented,
2026-10-28. Automatic wake recovery is implemented as an offline candidate; kernel/hardware validation remains pending.
The current hardware-tested boot candidate is 5a5d69c. Initial startup and native
traffic work; this does not validate system sleep/wake or termination/rematch.

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

## Startup integration and remaining recovery work

1. Allocate all producer/cancellation state before joining the power plane.
2. Establish controller PM before BAR/register access and firmware/DMA work.
   The candidate now moves real identity/configuration, bus mastering, BAR mapping
   and target initialization into a producer admitted by the actual On callback.
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

Items 1–8 are implemented as an offline candidate and tested with production
entry, PCI preparation, scheduler/cancellation, power and recovery methods.
Internal recovery now retires the old instance before asynchronous rematch.
Kernel callback delivery, initial-off matching,
sleep cancellation, repeated sleep/wake and traffic restoration require hardware
validation. macOS 11–26 support is not established by this Sequoia investigation.

## Implemented first-probe sequence

Start opens the IOKit provider, initializes permission as unknown/off, allocates
the producer mutex/call and root interest, then registers the controller's PM
table and joins its parent's power tree. It performs no direct configuration
reads, bus-master enable or BAR access there. Allocation/registration/power-request
failure stops setup; there is no unadmitted synchronous initialization fallback.
The framework's IOPCIDevice open/PM machinery remains responsible for its own
provider operations; this claim concerns the driver's configuration/MMIO work.

An On/root-state action can restore exact blocked phase 1 to active phase 0 only
before the first powered hardware attempt, when root/device state permit it. A
pending suspend changes the atomic word and prevents that CAS; permanent stop
phase 3 also cannot be cleared. After a hardware attempt starts, the previous
full-restart requirement stays in force and old DMA/keys are never resumed.

The ONCE producer has separate pending/started/stopping state. Entry takes the
initialization mutex, verifies permission, and latches started before real PCI
configuration. Its tail checks permission again after an aborted run so an On
which arrived before pending clears is resubmitted rather than lost. Cancellation
closes scheduling and drains pending execution with public APIs. The scheduler
mutex survives until final controller free after PM closure, preventing late
callbacks from reaching a freed scheduling lock. PCI command restoration is
guarded by actual command ownership, avoiding a write of an unread default value
when setup stops before power admission.

Host tests execute the production entry guard and powered PCI preparation with
hardware-access traps while blocked, plus the actual queue/cancel/tail methods.
They cover coalescing, aborted-run/On tail ordering, dispatch-before-entry cancel,
wrong powered profile, failed BAR mapping and retained scheduler-lock lifetime.
Production power tests cover initial Off/On, root sleep/cancel before hardware,
pending suspend intent and permanent stop. These are models of kernel primitives,
not executed kernel initial-power transitions. The frozen e105f82 candidate
awaiting permission has not been replaced by this new build.


## 2026-10-28: automatic wake recovery candidate

The internal retained ONCE worker prepares retirement under the initialization
barrier and radio gate, then terminates outside both. A CAS from restart phase 2
to permanent retirement phase 3 arbitrates with new sleep/off intent. Recovery
requires verified inactive firmware, released DMA, retired interrupts and restored
PCIe state. Quarantine or failed verification leaves recovery blocked.

Repeated notifications coalesce. A generation counter preserves an eligible wake
arriving during an obsolete attempt without polling rejected hardware. The worker
hands cancellation ownership off before terminate can invoke stop; its final
self-release permits object destruction without accessing freed context. Rematch
is suppressed for an inactive PCI provider. The replacement must obtain its own
PM permission and recreate firmware, queues and keys.

ASPM restoration is idempotent after verified success. Unavailable PCI reads
(0xffff) cannot count as successful restoration. Stop after sleep/rematch leaves
verified bus mastering disabled instead of restoring a command after power loss.

Production-method host tests cover cancellation before entry and after dispatch,
coalescing, wake-tail generation, queued sleep before commit, sleep after commit,
rejected retirement states, failed terminate, inline stop from terminate and
destruction on final worker release. The full normal and ASAN/UBSAN suites pass,
as do native/non-native builds and exact binary inclusion in a local auxiliary
collection (UUID DC4B47B7-6C93-3FA3-A6E9-767266BB174C). Auxiliary validation uses
a separate selection-only Info.plist copy; this proves binary binding, not
OpenCore loading or runtime stability. Hardware sleep/wake is not verified.
The frozen e105f82 installation candidate has not been replaced or installed.
