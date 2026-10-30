# Native connection audit (2026-10-28)

Current feature state: [docs/development/NATIVE-STATUS.md](NATIVE-STATUS.md). The entries below are chronological evidence; early unsupported/uninstalled statements are superseded by later checkpoints. Requirements live in docs/contracts/NATIVE-CONTRACT.md and docs/contracts/WPA3-CONTRACT.md.

Current hardware checkpoint (2026-10-29): experimental native image
A3E38378-BAE6-346C-8E1D-88A192367DE1 booted on Sequoia 15.6.1/24G90.
macOS selected SAE (upper auth 4096, password cipher 10, zero flags/index).
The opt-in PMF diagnostic started and completed one authenticated SA Query:
TX submitted 1, RX verified 1, successful exchange 1, RX/TX drops 0.
These counters are controller-lifetime totals. An en1-bound IPv4 HTTPS request
completed with HTTP 200 and successful TLS verification. All twenty en1-bound
ICMP requests received replies over 60.31 seconds; all thirteen observations
remained authorized/connected-sae, with no new disconnect or TX watchdog.
The station returned to requested PS after the query. A prior initial failure
is recorded as association-rejected; it is not a PMF timeout.
This establishes a short native SAE data-path and protected unicast-management
round trip. Group BIP, rekey PN/IPN behavior, long-term stability, sleep/wake,
and cross-version certification remain separate open checks. The older entries
below are chronological and do not supersede this checkpoint.

Hardware-confirmed: firmware starts, macOS creates en1 and shows scanned networks.
Earlier e2b8293 hardware testing confirmed association and bidirectional traffic,
but later watchdogs/stalls prevent a current stability claim. Initially WCLJoinManager aborted
on unsupported WCL_LOW_LATENCY_INFO before dispatching the association callback.

This revision answers that query with the actual zero session mask, applies scan
away-time settings, keeps a bounded 30-second candidate cache, and adds PSK-SHA256
(AKM 6, descriptor 3) without changing a requested AKM to PSK/SHA1. Required PMF,
SAE and enterprise authentication remain explicitly unsupported. Optional offloads
are not falsely marked implemented.

The next hardware run confirmed LOW_LATENCY_INFO no longer blocks the attempt.
WCL now aborts on SET_MAC_ADDRESS before association dispatch. This revision adds
disconnected station MAC changes through VDEV_DELETE, ECHO, VDEV_CREATE with the
requested address, and a second distinct ECHO. Publication to BSD and the native
address query happens only after both firmware barriers. Invalid/multicast/zero
addresses are rejected; an active link, outstanding scan/DMA, or another address
request returns busy. The WCL caller sleeps with the network gate released;
runtime commands are isolated during the transaction. A five-second transaction
limit and six-second caller deadline stop/reset the radio on failure instead of
claiming an address change. This does not implement MAC rotation on an active link.
The final connection-stage BSS lookup now also uses the fresh candidate cache.

Host tests cover native wire layouts, association RSN, cache freshness, regulatory
bounds, SHA1 legacy behavior and independent SHA256 four-way/rekey fixtures. SHA256
fixtures use hashlib plus cryptography; regenerating them requires
`tests/fixtures/requirements-fixtures.txt`. The committed fixtures use only public test keys.
The macOS SHA256 test uses CommonCrypto, while the kernel uses corecrypto. Hardware
validation, DHCP and live traffic are still necessary.

KDF reference: https://w1.fi/hostapd/devel/sha256_8c_source.html
AES-CMAC reference: https://www.rfc-editor.org/rfc/rfc4493
Current adapter and private ABI: pinned upstream in scripts/build/native-headers.json.

WPA3-Personal (SAE plus mandatory PMF/BIP) is a required next development target.
PSK-SHA256 support must not be described as WPA3.

AWDL and AirDrop are explicit planned features; they require a separate AWDL
interface/data path and Bluetooth integration, not only AP connectivity.

MAC host tests execute the production runtime method with mocked DMA/MMIO seams,
including both barriers, wrong ECHO cookies, pending credits/DMA, timeout,
invalid ring state, sync failure and BSD publication failure. These tests do not
prove that QCA9377 firmware accepts a live delete/recreate cycle; hardware
verification is still required. Firmware command reference:
https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireless/ath/ath10k/wmi-tlv.c


## First association and post-association watchdog (2026-10-28)

The e2b8293 hardware run confirmed station MAC recreation, association on DFS
channel 52, completed PSK-SHA256 protection, DHCP IPv4, IPv6 configuration and
bidirectional traffic on the native interface. This is a functional milestone,
not a stability claim: a subsequent system watchdog captured a lock cycle.

The 03:08:31 configd stackshot records kernel threads 345 and 13561 waiting for
mutexes owned by each other. Symbolication against the matching stock
IO80211Family UUID identifies setLQM + 0x49 in the radio-side thread and
reportDataPathEvents + 0x69, InfraInterface::postMessage and
PostOffice::outForDelivery in the WCL-side thread. configd's IP configuration
queue waits on the same cycle. No new kernel panic is required for this failure.

The fix removes synchronous LQM/link-state calls from the radio worker and
moves native service into one coalesced thread call. It enters the WCL gate,
then the network/radio gate. PostOffice enqueue/delivery and native requests now
use WCL -> network ordering. The runtime timer only schedules work and never
waits for WCL. Reset/availability/join-abort notifications are routed through
the same bridge. The queued callback uses THREAD_CALL_OPTIONS_ONCE, so
invocations cannot execute concurrently. Stop marks requests stopped under the
network gate, releases that gate, cancels/waits and frees the callback, then
releases interfaces/radio resources. MAC firmware progress stays on the radio
timer, allowing a WCL MAC callback to sleep without blocking its completion.

Host regressions execute the production bridge callbacks with mocked gates and
verify ordering, coalescing, inactive/stopped behavior and cancellation outside
gates. Architecture guards reject synchronous WCL interface updates in the
radio worker and direct PostOffice use outside the bridge. Hardware stability
of this correction is not yet confirmed. Continue auditing reconnect, scans
while associated, IP/multicast handling, key renewal, shutdown and sleep/wake;
do not treat host tests as proof for those scenarios.

Thread-call cancellation/ONCE semantics checked against Apple's Sequoia-era XNU:
https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/osfmk/kern/thread_call.c

Startup guard: do not schedule the WCL bridge until the native protocol has
started and BSD binding has requested readiness. This prevents the new bridge
from overlapping the initial synchronous BSD/WCL binding in the opposite order.

Runtime-failure audit: after IRQ/DMA quiescence, a pending native scan is marked
failed/completed and a terminal WCL service is queued even with the radio timer
stopped. The bridge permits this inactive-radio failure notification when a
scan/join/link needs completion, while suppressing new availability announcements.
MAC failure wakeups schedule terminal delivery after releasing their wait state.


## Repeated watchdog and normal-mode overhead (2026-10-28)

The next hardware run still hung. A second configd watchdog at 03:44:08
shows a different cycle: IOServiceTerminateThread (111), in
IO80211APIUserClient::stop +0x125, and thread-call worker 17044, in nested
IOCommandGate::runAction. WCLTimerSource::serialAction and CCLogPipe are also
blocked behind it. Matching kernel and IO80211 UUIDs were checked locally;
raw reports are deliberately excluded because they contain private process data.
This rules out treating the previous queue order as a complete stability fix.

The native notification bridge now attempts both gates without waiting.
Contention retains the coalesced pending notification and schedules one delayed
retry after 10 ms; it never waits for the network gate while holding WCL.
This removes that blocking edge even when an Apple user-client termination
holds the network workloop and waits for WCL. Production-method host tests cover
contention at either gate, delayed retry, successful delivery and stop ordering.
The stackshot alone does not establish that every observed disconnect has this
cause; repeat hardware verification is required.

Normal builds now omit 220 detailed bring-up/event console messages while
keeping error/rejection/quarantine messages. Build with DIAGNOSTICS=1 to restore
them and the idle whole-pool DMA audit. Per-packet ownership, DMA sync, refill and
completion checks remain enabled. The full idle audit walked 1023 mappings once
per second; it is diagnostic work rather than a prerequisite for packet delivery.
Neither boot-time improvement nor stable reconnection has yet been measured on
this candidate. WPA3/PMF, Tahoe, AWDL and AirDrop remain incomplete.


## Post-1333 hardware run: background scan disconnect (2026-10-28)

The quieter nonblocking candidate booted; the user reports visibly faster system
startup and no new configd watchdog was present during this short observation.
This is not a stability pass: two driver disconnects were recorded. At 04:16:47
WCL explicitly logged GET WCL_BSS_INFO (433) returning NotReady, updateBss failing,
and an involuntary leave with reason Update Bss fail. Scan completion had cleared
_nativeBSSBytes after using the same scratch buffer for unrelated BSS records.

The current-BSS query now rebuilds its reply from the associated connection AP
while connected, independently of scan buffer lifetime. Visible beacon SSID IEs
are passed without an unnecessary metadata SSID override; a hidden advertisement
keeps the override path. The connection hiddenSSID flag now follows the selected
AP instead of remaining unconditionally true. UI hidden-network classification
still needs verification after reboot; a previously saved hidden flag can persist.

Measured timeline: kernel boot 04:13:29, interface named 04:13:54, user autojoin
04:15:02, link active 04:15:33.876, DHCP BOUND 04:15:34.939. The pre-login interval
must not be attributed entirely to driver connection latency. About 32 seconds
remain between user autojoin and DHCP; repeated scan failures were observed.
Scan requests still collect the full regulatory plan before filtering requested
channels, so optimizing directed/subset scans remains open. No router change is
required. A 45-packet source-bound gateway test had zero loss (average 3.77 ms),
and interface-bound direct HTTPS succeeded. An earlier bound-interface ping
returned routing errors and is not a driver packet-loss measurement.


## API user-client provider workloop (2026-10-28)

7a17e7f still hung, with no usable DHCP address before the stall. At 04:30:37
configd's watchdog captured IOServiceTerminateThread 111 holding the inherited
controller workloop while waiting in IO80211APIUserClient::stop. Airportd thread
8587 held WCL and waited on a command gate in apple80211RouteExternal. CCLogPipe,
network ioctl and WCL timer threads queued behind these owners. Kernel UUID and
IO80211 symbols match the captured report. The report includes threads from all
processes: the owner 8587 is in airportd, not kernel pid 0.

Ath10kNativeInterface now overrides getWorkLoop to return the WCL workqueue.
IOService's documented provider-chain workloop inheritance otherwise reaches
Ath10kPCIDevice::getWorkLoop, which intentionally returns the separate threaded
BSD/radio workloop. API user-client termination must serialize on WCL itself;
it must not hold the radio gate while entering WCL. The controller keeps its
thread-backed network workloop and the existing nonblocking notification bridge.
Host contract tests enforce both sides of this separation. Hardware verification
is still required and the observed stall is not attributed to WPA keys solely
because the exposed port-authorized property stayed true.

The saved macOS known-network profile also contains Hidden=true for the tested
visible AP. This is separate from current beacon parsing and has not been edited
or deleted. Current-BSS scratch-lifetime fix is retained. Visible-network UI and
usable traffic remain pending; zero disconnects on a stalled driver is not a
stability pass. No manual kext load or further reboot was performed.

The attached BSD interface presents the Wi-Fi protocol as its provider. It therefore also overrides getWorkLoop explicitly, in the opposite direction: it retains the controller network workloop for Ethernet operations. This prevents the Wi-Fi provider correction from accidentally moving BSD operations onto a threadless WCL queue. Both provider-chain endpoints are checked.


## Requested-channel scan contract (2026-10-28)

Native channel subsets now restrict firmware START_SCAN itself, intersecting the physical channel plan and regulatory policy. Unknown/6 GHz channels cannot turn into unrestricted scans; an empty intersection fails before submission. An accepted request cancelled before the first firmware submission completes locally without START/STOP or DMA ownership. Legacy full-plan wire format and passive DFS behavior remain unchanged. Native decode-to-command fixtures, extracted production provider getters, ASan/UBSan and mocked radio cancellation/credit/event regressions cover these changes. Hardware autojoin timing remains unverified. Event enqueue errors discovered in matching PostOffice assembly are tracked as an open P0 task in docs/contracts/NATIVE-CONTRACT.md.


## Checked event acceptance and rekey continuity (2026-10-28)

The notification emitter now checks PostOffice enqueue results. It retains
accepted-prefix markers/cursors and retries a failed suffix through the
coalesced ONCE worker after 10 ms. ScanDone and ConnectComplete are not marked
sent on allocation failure. Disconnect events preserve the old BSSID across
radio cleanup, and pending terminal notifications block incompatible new
transactions. Real associated beacon data remains queryable even if the
FirstBeacon message is still waiting for memory. Supplicant progress runs
before notification attempts.

The same production-emitter tests found and cover false link-down during
legitimate key replacement and the contradictory success/failure outcome at a
join deadline. Deadline failure now wins and performs data-port/crypto cleanup
once even if its notification must retry. Hardware validation is pending; these
source-level corrections are not a claim that all prior hangs are resolved.


### Control-worker teardown ordering (2026-10-28)

The deferred probe can create the native interface and service thread call while cancellation waits for it. Both stop() and partial-initialization free() now drain that producer first, then stop/drain native requests, before releasing power notifications, runtime, IRQ or DMA resources. This closes late-worker creation after cancellation and access to already released radio resources. A host test executes the production drain helper with an in-flight producer; source guards check both resource-release call sites. Full host tests, ASan/UBSan and the native build pass. This is an offline candidate, not a verified fix for the observed hardware freeze.

Wake remains incomplete: the current power path blocks I/O after wake pending a full restart, and sleep notification registration happens after deferred firmware initialization. Automatic native recovery must coordinate in-progress initialization, sleep acknowledgement, DMA quiescence and provider rematch; simply clearing the block or replaying notifications is unsafe. No automatic recovery is claimed here.


### Sleep during initialization: barrier and ordering (2026-10-28)

This candidate supersedes the late-notifier-registration gap described above. The priority root sleep notifier is now registered before the deferred firmware/DMA producer is queued. A dedicated initialization mutex covers firmware probing and interface construction. The sleep/off path first raises the atomic I/O block, then waits for this producer barrier, and only then enters the radio workloop to quiesce the device. A producer which starts after the block is raised exits without booting firmware. Before WMI has a workloop, the power action uses the already-created controller workloop. Controller PM registration runs after releasing the initialization barrier, and runtime timer/IRQ startup rejects a pending power block. The mutex remains alive through base-controller destruction, after notifier removal, PMstop and worker draining.

The first suspend verifies bootstrap/runtime DMA release even when WMI never became active, retaining quarantine on failure. Repeated root/device suspend notices do not repeat PCI accesses after the first quiescence. DeviceOn or unsolicited wake before the pending suspend action records its state must not clear the atomic block: that case remains `suspend-pending`. An ordinary wake following a recorded suspend still requires a clean restart; automatic rematch is not implemented by this change.

Host tests execute the production power methods with real host threads and a mutex: a sleep callback raises the I/O block immediately, cannot acknowledge while initialization owns the barrier, and acknowledges after the producer leaves and the fallback controller gate verifies DMA. They also cover pending-suspend/DeviceOn ordering, partial-bootstrap quarantine, repeated notices, device/root wake ordering and cancelled sleep. Initialization and destruction boundaries are source guards, not an execution of the full kernel firmware probe. Physical sleep and freedom from all framework lock cycles remain unverified.

Framework evidence: the installed IO80211Family `IO80211SkywalkInterface::start` (UUID 0D5AC570-04D4-38B6-8577-9F21350CDD50, entry ffffff80022616d6) performs interface PM setup at ffffff8002261bb0–ffffff8002261bfa. Therefore interface construction itself must be included in further PM lock analysis; it cannot be treated as a plain allocation. The matching public [XNU IOServicePM implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/iokit/Kernel/IOServicePM.cpp) submits power-driver registration as an asynchronous request; PMstop inhibits new driver callbacks and waits for prior driver callbacks before asynchronous power-plane detach. This is evidence about those operations, not proof that every call made during interface construction is nonblocking. Targeted disassembly is retained locally; Apple binaries are not redistributed.

Shutdown now uses the same power-event barrier before the base controller shutdown callback, so a queued probe cannot boot firmware after shutdown quiescence. This path is covered by an ordering guard and the existing DeviceOff power-method tests; physical shutdown remains untested.


### Native admission and security lifetime across power transitions (2026-10-28)

Native requests now check the atomic power I/O block both before waiting for the radio gate and inside that gate. This closes the interval where a request passed the initial check but entered after a sleep/off caller raised the block. The event bridge does not run radio/crypto progress or publish join success while power is blocked and WMI is still active. Once the power action has quiesced WMI, the bridge still delivers pending terminal scan/join/link events; blocking those would leave system transactions unfinished.

A radio-gated `discardNativeSecurity()` resets the supplicant (including PMK/PTK/replay state), pending reply/key buffers and the retained join key without discarding nonsecret association-event metadata. Runtime end, native worker stop and radio-off call it directly. Radio-side cancel/failure/disconnect cleanup also drops a live security context before notification delivery. Thus a failed PostOffice allocation cannot retain software credentials until Deauth/LinkDown eventually succeeds. DMA-owned connection/command buffers retain their existing hardware-quiescence ordering; this helper does not write into them.

Portable tests execute the exact production dispatcher/action and the gated admission prefix with a gate-entry power/stop/runtime transition seam. They count acceptance, not firmware side effects, across scan, associate, MAC and power-query requests. The bridge test executes its production methods to prove that pending-suspend work is suppressed while inactive-runtime terminal delivery remains available. A separate test executes the production NativeSecurity class and discard method: it initializes a fixture PMK/nonce, dirties pending key/reply buffers, and verifies byte-for-byte supplicant reset and buffer wiping while retaining the BSSID/event metadata. Source guards check call sites; those guards do not execute a kernel stop. Full host suite, sanitizers and native build are required before packaging. This remains an offline candidate, not hardware validation or automatic wake recovery.

Additional local teardown evidence: IO80211Controller::detachInterface (ffffff8002227be8) validates the object and clears its primary-interface pointer; its analyzed body does not itself stop the interface. IO80211SkywalkInterface::stop (ffffff8002264772) includes PM-stop dispatch and resource cleanup, and IOSkywalkNetworkInterface::stop (ffffff8002980b2e) calls deregisterNetworkInterface before the base stop. These entry points are from the image UUIDs above. Their whole transitive call graphs and asynchronous teardown still require review; no full absence-of-deadlock claim follows from these three bodies.


### Pending suspend intent cannot become restart readiness (2026-10-28)

A second suspend could raise the atomic block to 1 while an older DeviceOn/wake action still held the initialization/radio gate. The older action, with `needsRestart` from the first sleep, could then promote that same 1 to 2 and temporarily advertise clean-restart readiness before the new suspend recorded its root/device state. Native traffic stayed blocked, but a recovery caller could mistake this for a valid restart window.

The atomic word now combines phase (low two bits) and pending-suspend count (upper bits). Queueing a root/device suspend increments that count and blocks I/O in one compare-and-swap. The gated suspend action consumes one count only after recording its root/device state. Wake can promote exactly 1 to 2; a pending count changes the word and prevents that CAS from succeeding. Saturation is fail-closed, not a wrap to active. Existing `powerIOBlocked` and `powerRestartAllowed` accept only exact 0 and 2 respectively. This is a prerequisite for automatic recovery, not its implementation.

The production power-method test holds the initialization barrier as an older DeviceOn would, starts simultaneous root-sleep and device-off threads, verifies both pending intents, executes the older gated DeviceOn, and checks that neither pending intent nor I/O blocking/restart exclusion was lost. After both suspend actions finish, root/device wake must both be recorded before readiness returns. Earlier power, partial-DMA and notification tests remain enabled.

Wake-recovery design constraint: the local SDK `getPowerState` documentation explicitly says that a power parent's current state can remain the off-state while its child is being powered up. A polling check of PCI `getPowerState()` is therefore not the recovery readiness contract. The implementation must rely on device/root power callbacks and their queued intent. Before enabling automatic terminate/rematch, move controller PM setup before initial firmware scheduling, queue the first probe only when the new instance is permitted on, and handle callbacks arriving during registration. A fresh rematched instance must also obey parent DeviceOff even if it missed an earlier root sleep notification. The recovery worker must run outside WCL/radio/initialization gates and PM callouts, own retained lifetime references, and transfer its cancellation ownership before termination so stop cannot wait for its own callback. New pending sleep must invalidate readiness; old DMA rings and keys must never be rearmed. These integration steps and their kernel/hardware validation remain incomplete.


### Registration allocation ownership and inherited cleanup (2026-10-28)

The previous bridge allocated two generic IOMalloc(0x130) buffers and placed them in framework-owned registration slots. Matching IOSkywalkFamily assembly shows a different contract: Network registration copies a 0x108 prefix using IOMallocTypeImpl; Ethernet copyRegistrationInfo copies 0x130 with its own typed allocation; Network deregistration and Ethernet destruction use IOFreeTypeImpl. The linked kernel identifies those calls, while IOMalloc_external uses KHEAP_DEFAULT/kalloc_ext. This is an allocator/type/size mismatch in the old implementation; its causal connection to the recorded hardware freeze has not been proven.

The bridge now calls the stock nonvirtual IOSkywalkEthernetInterface::copyRegistrationInfo factory. The Ethernet slot owns that single allocation, including partial factory failure after MAC property publication fails. The Network slot temporarily borrows its common 0x108 prefix. stop(), free() and virtual deregisterLogicalLink() detach only that loan before the inherited cleanup executes; another owner's slot is left for its own cleanup. The Ethernet owner survives stop/deregistration and releases the buffer in final base free, so a reader which already obtained the prefix does not lose storage at detach. There is no generic allocation handed to a typed free, and no second owner of the same pointer. Preexisting registrations reject setup rather than being overwritten. The bridge does not call the full Nexus/logical-link registration method with fabricated packet pools or null links.

The local macOS15 Network RegistrationInfo declaration is corrected to 0x108, the Ethernet factory signature is added as IOReturn, and these deviations from the pinned vendor snapshot are recorded in scripts/build/native-headers.json. Static assertions retain the existing class layouts and verify both registration sizes. The stock addresses are Network registration ffffff8002980ebc, Ethernet factory ffffff8002986fec, Network deregistration ffffff8002980b64, Ethernet free ffffff8002986e5a, and virtual deregisterLogicalLink ffffff800298115e. Direct deregistration references identified in the analyzed families belong to base stop/free, virtual deregisterLogicalLink and full Ethernet registration failure cleanup. The latter registration entry is not called by this bridge.

Compiled parent dispatch was checked against the actual IO80211InfraProtocol vtable: offset 0xa0 resolves to IO80211InfraInterface::free (ffffff80022d3ae0), 0x5d8 to IO80211InfraInterface::stop (ffffff80022d3a04), and 0x8e8 to IOSkywalkNetworkInterface::deregisterLogicalLink (ffffff800298115e). That verifies the three inherited calls added here, not all framework vtables. Native compilation, signature verification and offline kernel linking confirm that the factory import is resolvable on the installed system.

Portable tests execute the exact production setup/detach/stop/free/deregister methods with a typed-owner seam that rejects freeing the Ethernet object as Network memory. Coverage includes success, stop then destruction, destruction without stop, virtual deregistration and error forwarding, repeat detachment, factory failure before allocation and after allocation, missing factory output/expansion, preexisting owners and a replacement Network owner. A saved reader is checked while the Ethernet owner is still alive after stop/deregister. The mock base is intentionally repeatable; these tests do not establish that every stock stop routine is idempotent, nor execute the kernel's typed allocator. Hardware teardown and the full asynchronous framework lifecycle remain to be verified.

Address normalization correction: the matching standalone kernel and the kernel embedded in BootKernelExtensions.kc share UUID E999BA1A-CC26-3685-A2DB-AB7085F6F12A but have different VM header bases (ffffff8000200000 versus ffffff80002e8000). Cross-image call targets must use linked-cache symbols; for example IOMallocTypeImpl is ffffff8000ab6770 and IOFreeTypeImpl is ffffff8000ab68a0 there. Standalone kernel function-body analysis and image-relative stackshot symbolization remain valid when normalized to the standalone image. Mixing standalone VM symbols with cache cross-image targets is invalid. No Apple binary or disassembly is redistributed with the source or package.


### Leaf interface stop precedes controller cleanup (2026-10-28)

The matching [XNU IOService implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/iokit/Kernel/IOService.cpp) defers a terminated service's stop until its leaf clients are finalized, invokes client stop on the provider workloop, and then detaches it. The driver's cached `_nativeStarted`/`_nativeAttached` flags could therefore remain true even after the framework had already stopped and detached the native interface. Controller cleanup previously called stop/detach again unconditionally from those flags. It now checks that the native interface still names this controller as its provider before performing the manual fallback. Controller-primary bookkeeping and the driver's retained reference are still released.

There was also a lifetime interval between framework interface stop and later controller stop where the native event worker could still address the interface's managers. Ath10kNativeInterface::stop now retires the matching controller-side protocol before detaching registration metadata or invoking inherited stop. A radio-gated action marks native requests stopped, clears `_nativeStarted`, wipes pending software security and ends WMI runtime. An executing radio action cannot overlap retirement; accepted waiters are woken or aborted by the existing stop/runtime path. Later requests and event callbacks cannot use the retired interface. Identity checking prevents an unrelated interface from stopping the current one. The stop hook does not cancel/wait for the service thread while IOService may hold the radio gate. Controller stop/free later perform the existing outside-gate drain. Interface construction installs the native gate before creating the interface; a gate-less partial teardown only marks protocol state and avoids hardware calls.

The production controller-release method is executed with framework-already-stopped/detached, manually owned started, attached-but-unstarted, unattached partial, foreign-provider and repeated-cleanup states. The seam rejects a second child stop. It verifies BSD detachment first, retained references/security release and interface release before gate removal. Bridge tests execute the production leaf-stop hook to check radio-gated retirement without thread-call waits, suppression of subsequent services, deferred controller drain, identity rejection and the partial fallback. Registration tests execute the production interface stop wrapper including its controller hook. These are host lifetime/ordering seams, not execution of XNU's termination worker or proof that every stock stop routine is idempotent.

Remaining PM stop audit: stock IO80211InfraInterface::setPowerState (ffffff80022dbfe8) synchronously enters its WCL queue through IOWorkLoop::runActionBlock (linked kernel ffffff8000afb580); stock IO80211SkywalkInterface::stop calls PMstop. XNU PMstop waits for outstanding driver callouts. Native leaf stop can run under its controller/provider radio loop, so PM callout/WCL/radio ordering must be resolved before automatic terminate/rematch is enabled. This candidate does not yet implement that deferred PM-callout drain or automatic wake recovery. IOSkywalkInterface::didTerminate (ffffff8002973036) delegates through the base termination callbacks rather than providing such a PM drain.


### Pre-stop PM drain outside WCL/radio gates (2026-10-28)

This candidate moves the PMstop request outside driver workloop gates; explicit proof/guarding of callout completion is still incomplete. Native interface initialization installs a supported gIOWillTerminateNotification handler before attachment/start. The matching dictionary names Ath10kNativeInterface and the callback checks the exact target object; other instances do nothing. Using an entry-ID dictionary before attachment would be wrong: the ordinary IORegistryEntry dictionary-init path has not assigned that ID yet. The [matching XNU registry implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/iokit/Kernel/IORegistryEntry.cpp) assigns it when attached. Class matching plus identity filtering avoids that pre-attachment gap. Failure to allocate the matching dictionary/notifier fails setup; the caller still owns and releases its dictionary reference.

In the matching [XNU service implementation](https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/iokit/Kernel/IOService.cpp), this notification type has no immediate existing-object delivery at installation. terminateWorker invokes it outside service workloop actions, after dropping its job/arbitration locks. invokeNotifier drops the global notification lock before invoking the handler, and records the invocation so remove synchronizes against outstanding callbacks. The running kernel reports xnu-11417.140.69~1, matching the inspected release source; cache symbol addresses are normalized separately as recorded above.

The handler first asks the matching controller to make I/O permanently blocked (atomic low phase 3), waits for the firmware/interface-construction barrier outside workloop gates, and retires protocol/radio through the existing hardware-gated stop action. It releases the construction barrier and radio gate before PMstop, allowing outstanding WCL PM callouts to finish. Later inherited interface stop sees PMstop already requested. The platform implementation uses a 15-second deadline per wait and can return while a callback is still running; this requires an additional completion/lifetime guard before cleanup can be considered safe. The notification is removed synchronously before final base free. Runtime-owned controller and workqueue references retained by stock interface start remain in force; no new controller/interface retain cycle is added. Diagnostic properties mark draining-power and pm-stop-returned without claiming verified completion or adding console log traffic.

The production notifier/setup/removal, controller preparation and atomic termination-block methods are executed in a threaded host seam. It holds the construction barrier to prove immediate I/O exclusion before waiting, then models a PM callout blocked on WCL which subsequently needs radio. PMstop asserts that construction/radio locks are released, waits for that callout, and completes after WCL is released. Tests also cover operation before registry ID assignment, other instances/wrong targets, missing controller, both allocation failures, notifier removal before base free, and permanent blocking with pending suspend intents. Existing bridge, registration, release, power, notification and crypto suites remain enabled. The seam models queue/PM primitives; it does not execute the kernel's notifier delivery or establish hardware freeze freedom.

Automatic wake recovery remains incomplete. The next integration step is early controller PM scheduling so a fresh rematched instance boots firmware only when its parent permits it, followed by a retained recovery worker outside all driver/framework gates. A terminated native instance remains fail-closed rather than reusing old rings/keys. Physical notification delivery, restart, sleep/wake and sustained traffic require explicit-authorized hardware tests.

The final timeout seam models PMstop returning with an unfinished callout; it verifies that diagnostics do not call this drained. This does not fix the remaining cleanup race. The next required P0 step is an admitted/in-flight PM wrapper plus delayed base cleanup with retained resource lifetime until all admitted calls have actually exited. In particular, inspect the borrowed BSD ifnet/manager lifetime before detaching the legacy interface; simply retaining the native object is not a sufficient general proof. This candidate remains unsuitable for a boot test until that completion/lifetime guard is finished.

### Public worker drain (2026-10-28)

Replaced the event bridge's private `thread_call_cancel_wait` import with public
cancellation and explicit queued/running ownership. Actual auxiliary binding and
exact executable UUID inclusion now pass; this is not a hardware stability test.
The termination notifier is still incomplete because stock PMstop may return
without all admitted power callbacks exiting. BSD detach also needs a paired,
properly ordered finalize of the borrowed ifnet binding. Do not install this WIP.

### BSD reference ownership (2026-10-28)

Matching networking detach calls ifnet_detach and waits; final BSD free releases
its ifnet owner. Native prepare now acquires an independent reference and keeps
it through inherited native free, including failed preparation. Model tests
cover legacy release first, parent free ordering, failed acquisition, duplicate
bind and partial initialization. This protects resource storage only; actual
PM completion and properly ordered finalize remain required before installation.

### BSD softc context ownership (2026-10-28)

ifnet callbacks resolve the legacy object through ifnet_softc. Native prepare
now retains that exact controller-owned BSD object as well as the ifnet, and
releases them after inherited native free. Failed reference acquisition balances
the object retain; foreign/null owners are rejected. This protects allocation
lifetime, not attachment or already retired controller resources. A future PM
completion guard must coordinate controller gate/WMI cleanup as well as native
managers; deferring only native parent stop is insufficient.

### Native PM/framework stop synchronization (2026-10-28)

Stock native power-body admission is counted; didTerminate and finalize defer
inherited stop scheduling until real body exit and a WCL fence. PMstop runs on
a preallocated worker outside WCL/radio and the global termination worker; a
platform timeout parks the job without detaching the native child or allowing
controller cleanup. WCL then finalizes BSD before parent completion. Direct
partial-start cleanup drains actual native bodies before event-worker/resources.
A distinct native parent-start flag preserves mandatory parent stop after early
radio retirement and avoids double stop. Host/threaded and sanitizer tests pass;
kernel lifecycle/hardware not verified. Next audit is the PCI-controller's own
setPowerState/root callback closure and resource-release barrier, then wake recovery.

### Controller PM closure and quiescence (2026-10-28)

Stop/free now permanently block I/O, drain producers/native calls, quiesce through
the DeviceOff action under the shared producer/radio barrier, and only then close
power admission. Root notifier removal, PMstop and an actual barrier rendezvous
precede resource release. Entry and inside-barrier checks reject late controller
callbacks without touching retired state. Quiescence must precede closure so a
late root sleep acknowledgement remains valid. Threaded host cases cover both
pre-barrier and executing-body races, powered-off PCI and repeated cleanup.
Kernel/hardware delivery still requires a boot test; automatic wake recovery
and the broad native callback/connection audit are not complete.

### Initial power/matching evidence (2026-10-28)

Matching now reads cached PCI IDs; real configuration identity is rechecked before
any bus-master/BAR enable. XNU's initial-transition path preserves a normal initial
setPowerState call when the table lacks kIOPMInitialDeviceState; this is not a
guarantee on allocation failure. Parent current-state polling is invalid during
child power-up. Early PM registration, first-probe admission/tail races and the
internal native recovery worker remain pending (docs/contracts/INITIAL-POWER-CONTRACT.md).

### Early PM and admitted hardware start (2026-10-28)

Controller PM setup moved before the driver's real PCI configuration/BAR/firmware
work. Unknown/off admission blocks the first producer until On; pre-hardware
sleep/cancellation can resume a first probe without reusing old state. The queue
tail preserves On after an aborted attempt, and cancellation keeps scheduler
storage alive until final PM-closed free. Command restore is ownership-guarded.
Production host entry/PCI/queue/power methods and targeted race tests pass; kernel
delivery and automatic recovery/rematch after initialized sleep remain pending.


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


## AP disconnect cause and continuous reconnect regressions (2026-10-28)

The native Deauth event previously always used IEEE reason 3 and left its
subtype byte zero, even after a validated AP frame carried another reason
and subtype. ConnectionState now retains the first AP terminal reason, subtype
and BSSID independently of cumulative diagnostics. Radio resetDisconnected keeps
this nonsecret event metadata while wiping old keys/rings state; successful
candidate selection clears it for the next association. A repeated terminal frame
cannot replace the first cause. Native delivery uses the retained record only
for the BSSID whose LinkUp was published; absent/mismatched AP metadata retains
the existing local reason 3. Enqueue failure does not consume the record.

Production receive/reset/notification tests inject AP deauthentication and
disassociation with reason 15, a subsequent conflicting reason/subtype, complete
radio cleanup and a failed first enqueue. They check the exact native event,
BSSID and single terminal delivery. A separate selection assertion verifies
that the next accepted candidate cannot inherit the old cause. This does not
implement protected management frames or prove hardware disconnect handling.

The normal development runner now includes the existing connection, reconnect,
station/AP maintenance, channel switch, runtime power and WMI notification tests.
The production extractor bounds DMA release before the separate control-drain
method and excludes controller PM-drain from the single-thread runtime seam;
actual controller/PM concurrency stays covered by test_power. The runtime seam
uses production atomic admission/power actions and counts recovery scheduling,
while test_wake_recovery separately executes the actual retained worker.


Sequoia subtype ABI was checked against the matching local IO80211Family image,
UUID 0D5AC570-04D4-38B6-8577-9F21350CDD50. The dispatch at
0xffffff80021f4b10 reads payload byte 0x10: nonzero calls handleDeauth at
0xffffff80021f4b9e; zero calls handleDisassoc at 0xffffff80021f52bc.
The main handler reads the reason word at offset 8 (0xffffff80021f45b1).
The imported header named byte 0x10 `disassociation`, reversing its meaning.
It is now named `deauthentication`, with a fixed offset assertion; AP subtype
0xc0 and local reason-3 fallback set it to 1, subtype 0xa0 sets it to 0.
These are manually reconstructed observations of the Sequoia binary, not
recovered Apple C source or a claim for other macOS adapters.


## Association lifetime in current-AP queries and WCL link updates (2026-10-28)

A queued WCL LinkUp acknowledgement could previously set the AP/link after
radio cancellation or disconnect began, provided its BSSID still matched.
WCL_BSS_INFO also accepted Connected while cancel/disconnect were active, unlike
BEACON_INFO and EXTENDED_BSS_INFO. ConnectionState::connectionAssociated now
expresses the common lifetime: Connected, no cancel intent and no disconnect
stage. It intentionally does not require an authorized controlled port: initial
key exchange and live rekey must not be confused with loss of association.

The three current-AP queries share one admission method; rejected requests leave
output untouched. Current BSS is still rebuilt from the associated AP independently
of scan scratch. WCL LinkUp uses the same admission and requires the current
BSSID before either interface mutation. LinkUpDone additionally requires port
authorization. WCL Down remains idempotent during/after teardown, accepts its
zero BSSID and preserves debounce duration. It is not rejected merely because
the association is already gone. Power/stop/runtime admission remains in the
outer radio-gated dispatcher, before these methods. Notification and crypto
workers now use the same association predicate.

Matching Sequoia WCLNetManager::updateLinkState at 0xffffff8002125516 builds
a 16-byte command: BSSID bytes 0..5 initially zero, up at 6, flags at 7/8,
debounce word at 12; the BSSID is populated only on up. cmdIouc at
0xffffff80021255de receives command 0x1c6 and length 0x10. The local analysis
uses the already recorded IO80211Family UUID; no Apple binary/assembly is
exported. These observations do not validate another OS adapter.

The new host test executes production query/link-update methods with real
ConnectionState and wire builders. Its table covers disabled, scan, association
in progress, failed, cancel, drain, final disconnect barrier, live rekey and
authorized connection. It verifies no stale AP mutation/output on rejection,
correct BSSID after poisoned scan scratch, independent AP/link flags, zero-BSSID
down with/without debounce, null inputs and absent interface. LinkUpDone's
association/port combination has a source guard; it is not an execution of that
full dispatcher branch. Kernel WCL delivery/rekey/disconnect behavior remains
unverified; this is an offline candidate.


## Configured channel width and native link metrics (2026-10-28)

getCHANNEL previously always returned a 20MHz width flag even when the configured
home definition was HT40/VHT80. nativeChannelFlags now validates the existing
physical channel geometry and emits exactly one width, the correct band,
extension-above for HT40, and the known primary-channel DFS flag. Supported
channel entries use the same builder for their 20MHz definitions. Regulatory
selection remains in the existing policy layer; the flag builder neither adds
physical channels nor authorizes transmission. Channel 14/6GHz/160/80+80 remain
outside this adapter's physical/width support.

Local Sequoia channelFlagsFromIEEEOperatingClass at 0xffffff8002135b1e confirms
the bit assignments: classes 81/82 -> 0x0a, 83 -> 0x20c, 84 -> 0x0c,
115 -> 0x12, 116 -> 0x214, 117 -> 0x14, 118 -> 0x112, 119 -> 0x314,
120 -> 0x114 and 128 -> 0x410. The jump table at 0xffffff8002135bb4 was decoded
against the matching IO80211Family UUID recorded above. Class 128 alone cannot
identify DFS, so the actual primary-channel DFS property is added explicitly.
This is manual binary analysis, not recovered Apple C or cross-version proof.

getCHANNEL, getRSSI and getRATE now share lifecycle admission: cancel, disconnect,
disabled or failed state reject without publishing old data. During join the
channel is the selected home definition, not a measurement of instantaneous RF
during a scan. RSSI/rate require a live association, including a rekey whose
controlled port is temporarily closed. Missing RSSI, missing/zero/unrepresentable
or out-of-decoder-range firmware rate return NotReady. The existing rate unit
conversion (kbps/500) is preserved; rates remain the last observed firmware
measurement, with age diagnostics, not an invented instantaneous MCS/SGI value.
MCS/guard-interval queries remain unsupported pending suitable evidence/data.

Host tests execute the production query method and actual channel builder.
Independent expected flags cover 18 valid 20/40/80 definitions across 2.4/5GHz,
DFS and both HT40 extension directions; 11 invalid definitions are rejected.
Tests check exact reply flags, write boundary, unchanged output on rejection,
join versus disconnect/failure/rekey state, measured RSSI, firmware rate units,
missing/out-of-range rates, null output and unknown operation. Kernel/UI
channel-width reporting and live performance remain unverified.


## HT/VHT capability query implementation and callback inventory (2026-10-28)

The adapter previously rejected getHT_CAPABILITY and getVHT_CAPABILITY while
its association request advertised HT/VHT IEs. These existing virtual slots now
forward through the normal WCL -> radio dispatcher. Replies describe local
firmware/host capabilities independently of the current AP and are available
after SERVICE_READY, before association. The native personality is restricted
to the verified single-chain QCA9377; it does not inherit extra NSS, STBC,
beamforming or 160/80+80 features from broad firmware capability bits.

Matching IO80211Family/IO80211PeerManager::getHtCapabilityIE at
0xffffff80021e7220 issues ioctl selector 0x9a at 0xffffff80021e7252.
Failure clears its cached HT capability length at 0xffffff80021e729f.
Success copies 28 IE bytes from reply offset 4 (0xffffff80021e72ec..7310).
getVHtCapabilityIE at 0xffffff80021e7452 issues selector 0xd6 at
0xffffff80021e7484. Failure clears its VHT-capable flag at
0xffffff80021e74a3; success copies 14 IE bytes from offset 4 at
0xffffff80021e7529..7546. This identifies a stock consumer and ABI; it does
not prove these calls were the cause of this laptop's slow autojoin.

HT reply is 32 bytes (version plus IE 45/26); VHT reply is 20 bytes
(version plus IE 191/12 and two zero reserved bytes). Static assertions bind
the adapter headers to these layouts. The generic policy/IE writers are now
shared by association and native queries, preserving the existing supported
features and rate-map negotiation. HT uses one RX MCS0..7 mask per enabled
stream, disabled SMPS, the host width ceiling, supported SGI bits, 64KiB A-MPDU
and 8us spacing. VHT keeps existing 3895-byte MPDU/64KiB A-MPDU policy and
SGI80 only when reported by firmware; unknown highest-rate fields stay zero.
These are capabilities, not an instantaneous transmit MCS or guard interval.

Primary ath10k reference (local masks remain narrower than full Linux support):
https://github.com/torvalds/linux/blob/v6.12/drivers/net/wireless/ath/ath10k/mac.c
See ath10k_create_ht_cap and ath10k_create_vht_cap for firmware enablement,
per-chain MCS masks and TX/RX capability encoding. No Linux driver code or
Apple assembly was copied into this adapter by this change.

Production-method tests cover readiness/disabled support, exact byte layouts,
write boundaries, single-chain masks, masked optional firmware features, missing
SGI bits, unknown operation/null outputs and undersized/invalid IE writers.
The actual association request is parsed and its local HT/VHT IEs compared
with the native replies. Width20/40 and globally disabled build profiles are
checked separately from the default suite. Kernel consumers and real reconnect
performance still require hardware validation.

docs/development/NATIVE-CALLBACK-MATRIX.json now inventories all 190 inline protocol overrides:
31 forward and 159 return Unsupported. scripts/validation/audit-native-callbacks.py
checks the snapshot against the actual header, explicit aliases, enum and
main dispatcher branches; CI runs --check. Negative probes verify stale
snapshots, unfamiliar/nested bodies and missing enum/dispatch entries are
rejected. Unsupported callbacks remain explicitly marked as requiring caller
evidence; this inventory does not prove they are optional. Lifecycle and
non-inline overrides remain in the separate contract matrix above.


## Sequoia credential slot / WPA3 prerequisite (2026-10-28)

WCLJoinRequest's stock validator permits key_len 0..64, not only 32. The native
key envelope and imported apple80211_key now preserve all 64 bytes while retaining
the 148-byte key structure and RSC/WoW offsets. Join decoding also retains flags
and index. A shared native authentication policy keeps decoding separate from
support: only existing open and exact WPA2-PSK/PSK-SHA256 with 32-byte PMK/PMKSA
are accepted; password, SAE/FT-SAE/mixed masks and enterprise cannot fall back
to PSK or truncate a password into a PMK. SAE failure is identified explicitly,
and the full temporary request is wiped.

Tests execute the actual decoder/policy across 0/1/31/32/33/63/64-byte credentials,
embedded zeros, PMK/PMKSA/MSK/password ciphers, exact and mixed auth masks, full
candidate counts, all truncated lengths, >64/overflow lengths, malformed SSID/RSN
lengths, invalid BSSIDs and null input. Canaries and unchanged output on rejected
lengths check bounds; existing production security-lifecycle tests now wipe the
expanded retained key slot. Native compiler assertions check 148-byte ABI, key
offset 16, RSC length 80 and WoW length offsets 100/120.

docs/contracts/WPA3-CONTRACT.md records the matching stock validation/copy addresses and all
remaining SAE/PMF implementation gates. No SAE/PMF success or capability is
claimed; live WPA3 credential delivery and hardware security behavior are still
unverified. The broader native lifecycle/compatibility goal remains open.


Build integrity: Makefile now enables compiler-generated -MMD/-MP dependencies
and includes object .d files, so nested vendor/SDK ABI edits cannot silently
leave old object layouts. The current candidate already rebuilt all seven
native C++ objects because a local native header also changed; this does not
identify stale objects as the cause of any historical freeze. A real incremental
build test verifies seven C++ compilations after initial Makefile update, zero
for an unchanged build, seven after touching only the nested credential header,
and six in the non-native build. All eight native objects emit .d files, and
each C++ dependency file contains the credential header. Final native UUID is
unchanged and is rechecked against the existing local auxiliary collection.


## SAE backend symbol availability (2026-10-28)

The separate Sequoia CoreCrypto image contains P-256 entries not visible in the
earlier kernel-only search. docs/contracts/SAE-CRYPTO-BACKEND.md records image UUIDs, twelve
strong imports, exact auxiliary probe inclusion and a missing-export negative
control. The isolated make target is built in CI, never loads and does not alter
the normal Wi-Fi binary. Manual import/validation disassembly identifies heap
workspace allocation, reinforcing outside-gate crypto-worker requirements.
This establishes symbol availability for this image, not callable context ABI,
P-256 correctness, actual SAE/PMF or macOS 11–26 support. Those original goal
requirements remain incomplete. No Apple binary/header/assembly is redistributed.

## Pairwise candidate expiry ordering (2026-10-28)

A delayed native service tick previously submitted an outstanding M2 or consumed
a queued M3 before checking the pairwise-candidate deadline. Cancellation also
left the native reply buffer pending. This could send a response belonging to a
retired candidate. Expiry now runs before transmit/receive progress, restores the
established supplicant context and clears the candidate response in both queues.
Authenticated established M3/M4 retry state and committed key operations remain
intact. Focused production-class and actual supplicant tests exercise clearing
and a successful authenticated group rekey after candidate cancellation. This
is a confirmed ordering defect, not proof of the cause of a hardware hang.

## Deferred BSD transmit wakeup (2026-10-28)

The output path stalled during EAPOL holds, but serviceConnection consumed a
firmware WAKE notification without checking that hold or even the presence of
an output queue. Clearing the hold later did not guarantee another completion
event. The queue could therefore remain stopped while the association stayed up.

A shared dataTXAdmissionOpen predicate now gates BSD admission, direct data
submission and deferred wakeup. It includes controlled-port, cancellation,
EAPOL, management/radio/firmware pause and slot-capacity checks. Service keeps
wakeup intent until an output queue exists and all blockers clear; an existing
BSD stall also triggers reconsideration without a new hardware event. Production
connection tests exercise overlapping EAPOL/WAKE, a temporarily absent queue,
direct submission during the hold and recovery with no new completion event.
The development/CI runner now also includes the pre-existing TX watchdog,
security-disconnect and RX-security diagnostic scenarios. Hardware diagnosis
remains outstanding; this source-level defect is not proof of a hang cause.

## Retained payload and disconnect clock (2026-10-28)

The data watchdog used a payload's original submission age as the teardown
timeout as soon as the controlled port closed. A legitimate, firmware-retained
payload older than five seconds could therefore fail the first disconnect tick,
without receiving a drain interval. The transport CE deadline still uses command
age. The teardown deadline now uses the existing disconnect-stage clock, matching
serviceDisconnect. Closing the controlled port alone is not evidence of a DMA
completion failure. No payload is freed or its ID reused before both CE and HTT
completion; actual stuck drains remain bounded at five seconds. Tests cover a
minute-old payload completing after disconnect and an identical payload that
never completes, with the latter retaining ownership at the exact deadline.
This is source/test evidence, not a verified explanation of a hardware hang.

## Late abort during teardown (2026-10-28 hardware follow-up)

Loaded d653974/B1A4D518 stopped its runtime with cancel-security-response-timeout.
The captured registry showed disconnect stage 5, security phase 0 and a repeated
cancel request after AP deauthentication. A host reproduction injects that late
abort during DELETE_PEER after software key retirement; the old implementation
fails to finish teardown. Cancellation waits for installation/CSA replies now
apply only before teardown begins. DELETE/STOP/barrier keep their own command
ownership and completion rules. The regression also requires successful
reassociation through the same live runtime. This addresses the recovery failure;
the original AP disconnect remains a separate unresolved issue.

## Idle leave before association (2026-10-28)

Current-boot airportd logs show pre-association disassociation followed by two
10-second association timeouts. The native handler accepted the join, while
runtime remained active with Disabled and cancelRequested=true, without a key
generation. LEAVE_NETWORK unconditionally latched cancellation even when idle;
serviceConnection returns immediately in Disabled, leaving that latch to cancel
the next accepted join. Cancellation now applies only to a live connection stage
or pending teardown. Abort completion and security reset remain unchanged.

The regression executes the extracted production LEAVE/JOIN_ABORT cases: idle
and repeated idle requests, active scan/connected cancellation, teardown, scan
abort and JOIN_ABORT completion scheduling. It failed on the old idle latch and
passes with the fix. Focused native_leave, connection, security_disconnect,
native_notifications and native_scan tests pass under ASan/UBSan; native kext
build and symbol checks pass. Hardware reconnect remains unverified.

Open: approximately 30 seconds until first networks, reported on the same boot.
Measure startup readiness, requested channel masks/dwell, first-result delivery
and scan completion separately before attributing this to dwell alone. A later
two-channel scan with zero results does not prove the startup scan was empty.

## Incremental native scan results (2026-10-28)

Captured airportd settings requests took 9.213 seconds initially and about 4.44
seconds on later sweeps. This does not explain the entire user-reported 30-second
wait. The driver previously held every ScanResult until firmware scan completion.
It now submits discoveries as the cache grows, retaining firmware ownership and
withholding ScanDone until actual completion. A final full snapshot refreshes
entries whose SSID or beacon data changed after initial delivery. Failed queue
submissions retain their index; cancellation/failure suppresses further results
and reports its terminal status only after firmware completion.

The actual production notification method is extracted for host regressions.
Tests cover early discovery, newly appended BSS, retry on queue failure, updated
final records, final-pass retry without duplication, cancellation, firmware
failure and terminal-event retry. The early-discovery test fails on the old code.
Focused native_notifications, native_scan and native_leave pass with ASan/UBSan.
Native kext build/symbol checks pass. No hardware latency improvement is claimed
until reboot testing; initial unsolicited sweep and system scan scheduling remain
under investigation.

## Reassociation contract investigation (local batch, 2026-10-28)

Matching local IO80211Family image UUID: 0D5AC570-04D4-38B6-8577-9F21350CDD50.
`WCLNetManager::sendReassocCommand` at 0xffffff800212933e sends command 0x1aa
through cmdIouc with a 0xbc-byte input (call at 0xffffff80021294f4). Before
dispatch it obtains the current SSID into offset 0x99 and its length at 0xb9.
It reads a 32-bit count at 0x94 and modifies bit zero at offset 0x98.
`remove6GChannels` at 0xffffff8002217f1c iterates at most 50 16-bit channel
specifications from offset zero, removes entries with (value & 0xc000)==0x4000,
and writes the compacted count back at 0x94. These offsets are observations,
not a complete structure declaration: the intervening fields remain unknown.

The sender issues bulletin-board messages before cmdIouc, and sends a compensating
message when the command returns an error. Their full state/event semantics and
the completion path still require reconstruction. Current setWCL_REASSOC remains
explicitly unsupported. Mapping the request directly to the 0x2cc-byte join
decoder would use the wrong envelope and skip roaming state/ownership handling.
No driver behavior has been changed by this investigation. Raw Apple disassembly
remains local, outside repository and SD release packages.

Roaming event consumers were also inspected in the same image. RoamStart
(0xffffff800214412e) and RoamPrep (0xffffff80021441b6) require nonnull
12-byte payloads and dispatch internal FSM events 2 and 4 respectively.
Reassoc (0xffffff8002144230) requires an 8-byte payload; only a zero first
32-bit word dispatches internal event 5, with a null FSM payload. RoamDone
(0xffffff80021442b2) requires a nonnull 0xa8-byte payload and dispatches
internal event 6. These internal FSM numbers are NOT PostOffice message IDs.
Invalid envelopes are logged/ignored and these handlers return zero, so a
successful enqueue/handler return cannot establish that roaming progressed.
Message registration, complete field meanings and the FSM transitions remain
open; no guessed event IDs or success-only reassociation stub is installed.
The generated callback inventory now records the confirmed setWCL_REASSOC
caller and its exact input envelope while keeping implementation unsupported.

The init method references gROAM_MANAGERCallBackArray at 0xffffff80023f3070
and passes a count of 25. Its first four 24-byte records match the independently
located handler symbols: registration words 0x00890002 (RoamStart), 0x008b0002
(RoamPrep), 0x00490002 (Reassoc), 0x00500002 (RoamDone). These are raw
registration words, not yet verified public postMessage IDs. Each record's
encoded function pointer matches its handler and its adjustment word is zero.
The table narrows the remaining translation work to bulletin-board registration
and the PostOffice driver-message mapping; treating the high half as a public
message ID without that mapping is not justified.

Routing evidence: IO80211PostOffice::deliverMessage at 0xffffff80022b2746
forwards the original message arguments through interface slot 0xb10.
IO80211Glue::sendEvent at 0xffffff800212acc8 constructs a CommonGlueMessage
with the input event number at offset zero and command flag zero at offset 4.
WCLGlue::receiveMessageInternal at 0xffffff8002122ef0 maps event envelopes
to bulletin-board words `(received_number << 16) | 2`, preserving input
length/pointer, then calls sendMessage with manager argument 12. Thus the
registration high-half interpretation is confirmed at the WCL receiver.
The object invoked through slot 0x118 in CommonGlue::receiveMessage
(0xffffff800211ecf1/0xffffff800211ed05) is a buffer pool, not an event
translator. IO80211Glue::initWithOptions stores IO80211BufferPool::withOptions'
result in context+0x10, then places it in CommonGlueOptions+8 at
0xffffff800212a2a8..0xffffff800212a2ac. The IO80211BufferPool vtable at
0xffffff80023d6ba8, address-point offset 16 plus slot 0x118, resolves to
IO80211BufferPool::getBuffer (0xffffff800227f7ce). The receive path copies
all 0x30 bytes of the message to a local envelope, including the original
number/flags at 0xffffff800211ec44..0xffffff800211ec4f. Buffer allocation
is conditional on envelope byte 6 being one; sendEvent sets it to zero.
This branch changes payload pointers for copying, not event numbering.
Therefore no event-number translation is present in this inspected CommonGlue
receive segment. This corrects the earlier translator hypothesis; remaining
upstream queue/interface dispatch and filtering must still be verified before
promoting registration high halves to public driver-event constants. Payload
field semantics, lifetime and roaming FSM ordering also remain unimplemented.

The queued Glue path was inspected through complete function boundaries:
addEventToPendingQueue (0xffffff800212aecc) stores the unmodified event number
at entry+0x10, the length at +0x14, and copies payload bytes into entry+0x20.
It appends at the tail; processPendingEventQueue (0xffffff800212ae38) removes
from the head, invokes sendEventAndFilter, then frees the entry. The latter
(0xffffff800212aba2) constructs the same event envelope without renumbering.
Its byte-0x28 delivery/filter flag controls subsequent postMessageSync fallback;
a successful queue insertion alone does not establish WCL consumption.
WCLGlue::isMsgNeeded (0xffffff8002123072) passes type 2 and the unchanged
number to WCLBulletinBoard::isMsgNeeded for event envelopes. Registration
availability is therefore distinct from payload validation and FSM acceptance.
These findings establish FIFO/copy behavior only for this inspected Glue queue,
not all producer queues or asynchronous consumers.

Independent symbolic cross-check: the same image's gAppleMIndexToString table
at 0xffffff80023ed360 names indices 0x89 APPLE80211_M_ROAM_SCAN_START,
0x8b APPLE80211_M_ROAM_PREP, 0x49 APPLE80211_M_REASSOC,
0x50 APPLE80211_M_ROAM_STATUS, and 0x8a APPLE80211_M_ROAM_SCAN_END.
This corroborates the registration high halves as Apple message numbers.
In particular, WCL's handleRoamStart consumes ROAM_SCAN_START; its name must
not be interpreted as an association-start notification. The inspected Glue
route preserves these IDs. Full InfraInterface/PostOffice dispatch coverage,
payload fields and FSM ordering are still required before implementing roaming.

Roaming action-level evidence (same image, no implemented driver behavior):
handleRoamScanEnd at 0xffffff8002144330 requires a nonnull 0x4c-byte
payload and sends internal FSM event 3. Like the other envelope handlers,
invalid input is logged/ignored while returning zero.
roamPrep at 0xffffff80021450d6 obtains the current associated SSID and uses
payload+4 as an ether_addr in getCachedBeacon. It reads a signed 16-bit value
at payload+0xa, stores it in manager context+0x74 and cached-beacon context+0x27c,
and updates a cached-beacon timestamp. The signed value's units/meaning are
not yet proven; it must not be assigned a public field name based on guessing.
The first four payload bytes remain unclassified here.

roamDone at 0xffffff80021451a4 reads payload word zero: nonzero is copied
to manager context+0x50, whereas zero invokes buildRoamCompletionStatus.
Both branches clear force-roam flags and timestamp (context+0x34/+0x38)
and can invoke WCLAdaptiveRoam::handleRoamEventConfiguration. The action
also reads payload byte 0x68; when it or context byte 0x48 is nonzero,
it copies 0x68 bytes FROM manager context+0x50 TO the event payload and
then prints the result. Thus this consumer can mutate the supplied payload;
a future delivery path must supply writable owned memory, not a const or
shared immutable status blob. This evidence does not yet establish which
values denote terminal failures or which FSM states admit this action.
The reassoc action at 0xffffff800214519c itself is a zero-return no-op;
its state transition and other message subscribers must be examined before
concluding that the reassociation notification has no effects.

### Reconstructed roaming FSM (local Sequoia image only)

The static initializer at 0xffffff80021459c4 populates configuration pointers
for 6 states, 10 events and 11 actions. CommonFsmManager::processEvent at
0xffffff800211e8d4 indexes two-byte entries by state*10+event; byte zero
is the next state (0xff preserves it), byte one indexes the action table.
It writes the next state BEFORE invoking the action. The following complete
60-entry matrix records decoded facts, not implemented driver support.
Rows give next state / action. Names below omit common ROAM_MANAGER prefixes.

| State | Event | Next state | Action |
|---|---|---|---|
| LINK_DOWN | CONNECT_COMPLEATE | LINK_UP | connectCompleate |
| LINK_DOWN | LINK_DOWN | LINK_DOWN | ignore |
| LINK_DOWN | ROAM_START | LINK_DOWN | unhandledEvent |
| LINK_DOWN | ROAM_SCAN_END | LINK_DOWN | unhandledEvent |
| LINK_DOWN | ROAM_PREP | LINK_DOWN | unhandledEvent |
| LINK_DOWN | REASSOC | LINK_DOWN | unhandledEvent |
| LINK_DOWN | ROAM_DONE | LINK_DOWN | unhandledEvent |
| LINK_DOWN | SLEEP | LINK_DOWN | unhandledEvent |
| LINK_DOWN | WAKE | LINK_DOWN | unhandledEvent |
| LINK_DOWN | TIMEOUT | LINK_DOWN | unhandledEvent |
| LINK_UP | CONNECT_COMPLEATE | LINK_UP | unhandledEvent |
| LINK_UP | LINK_DOWN | LINK_DOWN | linkDown |
| LINK_UP | ROAM_START | ROAM_SCAN | roamStart |
| LINK_UP | ROAM_SCAN_END | LINK_UP | unhandledEvent |
| LINK_UP | ROAM_PREP | LINK_UP | roamPrep |
| LINK_UP | REASSOC | LINK_UP | ignore |
| LINK_UP | ROAM_DONE | LINK_UP | ignore |
| LINK_UP | SLEEP | SLEEP | sleep |
| LINK_UP | WAKE | LINK_UP | unhandledEvent |
| LINK_UP | TIMEOUT | LINK_UP | unhandledEvent |
| ROAM_SCAN | CONNECT_COMPLEATE | ROAM_SCAN | unhandledEvent |
| ROAM_SCAN | LINK_DOWN | LINK_DOWN | linkDown |
| ROAM_SCAN | ROAM_START | ROAM_SCAN | roamStart |
| ROAM_SCAN | ROAM_SCAN_END | ROAM_SCAN | roamScanEnd |
| ROAM_SCAN | ROAM_PREP | ROAM_REASSOC | roamPrep |
| ROAM_SCAN | REASSOC | ROAM_SCAN | unhandledEvent |
| ROAM_SCAN | ROAM_DONE | LINK_UP | roamDone |
| ROAM_SCAN | SLEEP | SLEEP | sleep |
| ROAM_SCAN | WAKE | ROAM_SCAN | unhandledEvent |
| ROAM_SCAN | TIMEOUT | LINK_UP | ignore |
| ROAM_REASSOC | CONNECT_COMPLEATE | ROAM_REASSOC | unhandledEvent |
| ROAM_REASSOC | LINK_DOWN | LINK_DOWN | linkDown |
| ROAM_REASSOC | ROAM_START | ROAM_REASSOC | unhandledEvent |
| ROAM_REASSOC | ROAM_SCAN_END | ROAM_REASSOC | roamScanEnd |
| ROAM_REASSOC | ROAM_PREP | ROAM_REASSOC | roamPrep |
| ROAM_REASSOC | REASSOC | WAIT_ROAM_DONE | ignore |
| ROAM_REASSOC | ROAM_DONE | LINK_UP | roamDone |
| ROAM_REASSOC | SLEEP | SLEEP | sleep |
| ROAM_REASSOC | WAKE | ROAM_REASSOC | unhandledEvent |
| ROAM_REASSOC | TIMEOUT | LINK_UP | ignore |
| WAIT_ROAM_DONE | CONNECT_COMPLEATE | WAIT_ROAM_DONE | unhandledEvent |
| WAIT_ROAM_DONE | LINK_DOWN | LINK_DOWN | linkDown |
| WAIT_ROAM_DONE | ROAM_START | WAIT_ROAM_DONE | unhandledEvent |
| WAIT_ROAM_DONE | ROAM_SCAN_END | WAIT_ROAM_DONE | roamScanEnd |
| WAIT_ROAM_DONE | ROAM_PREP | WAIT_ROAM_DONE | unhandledEvent |
| WAIT_ROAM_DONE | REASSOC | WAIT_ROAM_DONE | unhandledEvent |
| WAIT_ROAM_DONE | ROAM_DONE | LINK_UP | roamDone |
| WAIT_ROAM_DONE | SLEEP | SLEEP | sleep |
| WAIT_ROAM_DONE | WAKE | WAIT_ROAM_DONE | unhandledEvent |
| WAIT_ROAM_DONE | TIMEOUT | LINK_UP | ignore |
| SLEEP | CONNECT_COMPLEATE | SLEEP | unhandledEvent |
| SLEEP | LINK_DOWN | LINK_DOWN | linkDown |
| SLEEP | ROAM_START | SLEEP | ignore |
| SLEEP | ROAM_SCAN_END | SLEEP | ignore |
| SLEEP | ROAM_PREP | SLEEP | ignore |
| SLEEP | REASSOC | SLEEP | ignore |
| SLEEP | ROAM_DONE | SLEEP | ignore |
| SLEEP | SLEEP | SLEEP | unhandledEvent |
| SLEEP | WAKE | LINK_UP | wake |
| SLEEP | TIMEOUT | SLEEP | unhandledEvent |

Implementation implications: REASSOC in ROAM_REASSOC transitions to
WAIT_ROAM_DONE despite using the ignore action; omitting it because its action
is empty would lose a real transition. ROAM_SCAN_END does not by itself exit
a roaming state. ROAM_DONE from any of the three active roaming states returns
to LINK_UP, while LINK_DOWN terminates the roaming state. TIMEOUT also returns
to LINK_UP but uses ignore, so it does not substitute for the roamDone cleanup
or establish successful radio association. SLEEP discards roaming events;
WAKE from SLEEP returns to LINK_UP. These are WCL bookkeeping transitions,
not proof that firmware or keys survived sleep. Full action side effects,
request cancellation and other message subscribers remain open.

Action-side continuation: roamStart (0xffffff8002144bc4) requires both its
payload and an associated beacon before initializing its 0x68-byte status
area. It snapshots the current BSSID/channel/authentication information,
copies payload words at +0/+4 into status words +0/+4, then calls timer
slot 0x1d0 with argument 10000 (milliseconds, verified below).
linkDown (0xffffff8002144b5c), sleep (0xffffff80021457ac), and roamDone
all invoke slot 0x218 on the same timer object. linkDown also updates roam
locks, removes a roam offset and reinitializes the roaming profile. wake
(0xffffff8002145776) removes roam offset 8 and invokes the adaptive-roam
sleep-exit configuration; it does not itself restore firmware association.

Current source comparison: Ath10kNativeInterface.hpp still explicitly rejects
setWCL_REASSOC, roam profile/cache updates and roam locks. Consequently these
reconstructed flows are implementation requirements, not claims that current
roaming follows them. Ath10kRecovery.cpp uses driver retirement/rematching for
wake recovery; WCL's bookkeeping return to LINK_UP cannot validate that path.

Timer binding is now verified against both IO80211TimerSource and
WCLTimerSource vtables (0xffffff80023c5768 / 0xffffff80023c9f58): slot
0x1d0 resolves to IOTimerEventSource::setTimeoutMS at 0xffffff8000b00fd0;
slot 0x218 resolves to cancelTimeout at 0xffffff8000b01130. The roaming
protection timeout is therefore 10 seconds, and linkDown, sleep and roamDone
cancel it. protectionTimer at 0xffffff8002143fd4 dispatches internal event
9 (TIMEOUT) with null payload, confirming the table's timeout path directly.

Entry/exit admission was also checked: linkStateUpdate at 0xffffff8002143fe6
accepts exactly two payload bytes and emits LINK_DOWN only when byte zero is
zero. A link-up indication here does not enter LINK_UP. joinDone at
0xffffff8002144010 instead requires exactly 16 nonnull payload bytes and a
zero first word before emitting CONNECT_COMPLEATE. It is registered under
bulletin-board word 0x000c0003, not driver message type 2. Thus emitting a
physical link-up event alone cannot initialize the roam manager; successful
join completion through WCL is a separate prerequisite. These constraints
must be retained when adding native reassociation and wake recovery.

Production notification regression coverage: test_native_notifications now
injects one enqueue failure separately at AssociationComplete, join BSS,
LinkStatus-up, FirstBeacon and ConnectComplete, then cancels the connection
before retry. All five paths emit exactly one failed ConnectComplete, no new
association/beacon/up notification, close the controlled port and do not repeat
completion on the next service call. The focused native_notifications run
passed using the extracted production serviceNativeNotifications method.
This validates host-side cancellation/retry ordering, not WCL execution,
firmware roaming or physical sleep/wake. No driver behavior change was needed
for these cases.

The focused notification suite also now holds portAuthorized false after
association, LinkUp and FirstBeacon: no ConnectComplete is emitted across
repeated service calls until authorization becomes true; then exactly one
successful completion is delivered. The complete native_notifications test
passed with clang AddressSanitizer and UndefinedBehaviorSanitizer enabled.
This covers notification gating, not proof of correct firmware key installation.

Key/authorization path source audit: serviceConnection in Ath10kNetwork.cpp
waits for matching HTT security indications for phases 1/2, drains command DMA
ownership and WMI credits, requires authorizeRequested at phase 3, and waits
for the WMI ECHO reply at phase 4 before opening portAuthorized. Rekey also
waits for pendingMPDUs to drain before discarding RX reorder/fragment batches
and updating replay counters. This is stronger than merely enqueueing keys.
The HTT validator ties non-NONE install acknowledgements to mapped peer,
expected cipher/cast and install phase. NONE indications have a separate
clear/teardown path and cannot acknowledge an install.

A remaining correlation audit item: initial-association and security ECHO
cookies are constants (0xa7100047 and 0xa7100057). Serialization and teardown
may prevent reuse ambiguity, but cross-generation delayed replies have not
yet been proved impossible across every cancellation/recovery path. Do not
claim generation-safe correlation solely from the existing phase/peer checks;
trace reply routing and retirement before changing cookies or accepting stale
responses. No observed runtime failure is attributed to this hypothesis yet.

Focused connection and security_disconnect suites passed with clang ASan/UBSan
on this source state. This is simulated firmware evidence, not a hardware
validation of key installation or stale-response exclusion.

ECHO correlation follow-up: parseWMIInitResponse rejects a reply unless an
ECHO is submitted and not already completed/replied; it also compares the
payload cookie. An explicitly tracked rollback ECHO is separately recognized
by rollback.echoCookie and does not acknowledge the current ECHO. Cancellation
of an active security install/barrier waits for the outstanding semantic reply
before teardown (bounded by cancel-security-response-timeout); association
barrier cancellation instead records its cookie for rollback handling. The
ordinary path therefore does not simply abandon an outstanding ECHO and reuse
its cookie in the next join. A duplicate reply arriving during a later command
with the same cookie is not distinguished by the parser, but production of
such a duplicate has not been demonstrated. Treat this as defense-in-depth
work pending lifecycle proof, not a confirmed disconnect cause. Any cookie
change must update both command construction and expected reply state, and
must preserve rollback consumption and transactional credit validation.

Runtime snapshot 2026-10-28 10:34 UTC, same boot UUID as the 5a5d69c
verification: DisconnectCount remained 1 (previously user-confirmed manual
switch), ConnectionError none, WMIRuntimeRejected 0, DataTxErrors 0. Default
route remained en1 and interface-bound HTTPS returned 200 in 0.146 seconds.
These sampled counters do not prove uninterrupted traffic throughout the gap.
The snapshot exposed an obsolete WMIRuntimeMode label claiming fixed 1/10 ms
polling while the adaptive timer reported 100 ms. Source now describes the
IRQ-worker/adaptive-watchdog or adaptive-polling mode; numeric interval telemetry
remains authoritative. This diagnostic-only change does not alter scheduling
and is not installed in the running kext.

Reassociation pre-command messages partly resolved by callback registration:
word 0x00070003 dispatches getRoamState; word 0x00040003 dispatches
setForceRoamMsg (0xffffff800214472a). The latter consumes two bytes, stores
byte 1 as the force-roam flag and byte 0 as the secondary flag, and clears
the secondary flag/timestamp unless byte 1 equals one. This is an internal
bulletin-board operation performed before the driver reassociation command,
not an additional public driver event to synthesize. Word 0x00060003 and
failure-compensation subscribers still require tracing. The decoder is not
wired until request semantics, completion and cancellation are sufficient.

The local native kext build after the diagnostic mode-label correction passed
compilation, linking and check-kext-symbols. No new kext was installed, loaded,
or tested on hardware; firmware/roaming behavior remains unchanged.

Reassociation failure compensation is now identified: after cmdIouc(0x1aa)
returns nonzero, sendReassocCommand clears the second byte of its two-byte
force-roam message and sends 0x00040003 again. The setForceRoamMsg consumer
therefore clears force-roam flags/timestamp. This is synchronous admission-error
compensation, not asynchronous radio failure completion. Returning success from
an unimplemented reassociation handler would bypass it and leave WCL expecting
a real operation; keep explicit unsupported until the operation is implemented.

Pre-command word 0x00060003 has matching callback records at
0xffffff80023f05d8 (GAS scanAbortNotificationHandler), 0xffffff80023f2910
(ScanManager scanAbortRequestHandler) and 0xffffff80023f47a0 (nearby-device
abort). These addresses lie within their named callback arrays; registration
counts for all three still need cross-checking. Direct inspection of
scanAbortRequestHandler (0xffffff8002137986) confirms a nonnull four-byte
payload is dispatched as scan FSM event 2. The reassociation sender supplies
four-byte value 1. Therefore request admission occurs after a scan-abort request
has already been issued; do not assume an idle radio or restart a scan solely
because setWCL_REASSOC is called. Completion ordering between the scan abort
and reassociation still needs the scan FSM and driver-side ownership checks.

Scan-abort timing contract: WCLScanManager::abortScan at 0xffffff8002139a4e
calls cmdIouc(0x1b3) with no payload. A successful return arms timer slot
0x1d0 with 1000 ms and returns; there is no synchronous completion wait in
this action. An immediate error sends scan FSM event 4 with 0xe00002eb.
handleTimeoutAbort at 0xffffff800213a1fc sends the same event/status.
Thus accepting the abort command is distinct from completing it, and the
normal completion window is one second. Whether the caller's scan state
admits the abort action still follows the scan FSM table.

Current driver comparison: setWCL_SCAN_ABORT only sets cancelRequested for
an outstanding native scan. serviceWMIScan waits for original command TX and
credits, submits STOP_SCAN when the command ring is idle, then requires a
terminal firmware event, stop consumption and returned credits before setting
completed. serviceNativeNotifications emits aborted ScanDone only afterward.
This ownership discipline must not be weakened to meet WCL's deadline by
pretending that radio cancellation completed. A targeted abort-latency and
late-ScanDone test remains required, especially before admitting reassociation
while the previous scan is retiring.

Confirmed parser ordering bug and local fix: parseWMIInitResponse previously
rejected every scan event when the current scan was terminal, before decoding
the event's scan ID. A delayed prior-generation completion was therefore
reported as scan-event-after-terminal even though stale-event handling already
exists. A regression test reproduced this with current ID 0xa037, terminal and
completed, and an old completion for 0xa036. It failed on the original code.
The terminal guard now runs after ID classification and applies only to the
current scan. Old valid events retain normal stale-event handling; a duplicate
terminal event for the current ID remains an error. native_scan and
native_notifications passed with ASan/UBSan after the change. This is a
reproduced parser bug, not yet a hardware-confirmed cause of user disconnects.

Boundary coverage for the stale-scan fix passed with ASan/UBSan: every
truncation of the 40-byte event, malformed fixed TLV, multi-bit event type,
wrong requestor and wrong vdev are rejected without changing scan state,
command credits or last-event metadata. A valid stale completion remains
accepted without advancing the current scan; a same-ID duplicate terminal
completion remains rejected. This exercises transactional parser behavior,
not firmware abort timing or scan-ID wraparound.

Transport-credit coverage for the stale completion passed with ASan/UBSan:
a stale event carrying a valid HTC credit returns that credit without changing
the current scan. An excessive credit return is rejected without partial
changes to scan state, available/outstanding credits or event metadata. This
confirms that ignoring the old scan event does not discard valid transport
accounting attached to it. No additional production change was required.

Request producer evidence: forceRoamUsingNeighborCache at
0xffffff8002217100 passes the reassociation buffer itself to getNeighborCache
with capacity 50 AppleChannelSpec_t entries. On a nonzero result it stores
that count at +0x94, writes six 0xff bytes at +0x64..+0x69, stores 32-bit
value 1 at +0x90, and calls sendReassocCommand with its boolean argument true.
This independently confirms the 50-channel area ends at +0x64. The six-byte
all-ones field is consistent with a broadcast BSSID, but its full field/list
semantics and the +0x90 discriminator still require other producers/consumers;
no guessed struct layout or runnable reassociation decoder has been added.

Target address field confirmed by a second producer: setROAMDefault at
0xffffff800221738e copies six bytes from apple80211_sta_roam_data+8 into
reassoc+0x64. It passes that SAME source address as ether_addr to
getCachedBeacon with the associated SSID. Thus +0x64 is a target BSSID,
not an opaque six-byte token. This producer also writes 1 at +0x90; when a
matching beacon exists it writes its chanspec at +0 and channel count 1 at
+0x94. A missing cache entry still reaches sendReassocCommand with its boolean
argument false, so the request decoder must not assume every valid request
contains at least one channel. The meaning/capacity of any additional BSSID
entries and the +0x90 value still require confirmation before accepting lists.

The local full-image disassembly identified ten direct sendReassocCommand call
sites, including forced roaming, neighbor-cache roaming, band selection,
setROAMDefault, setROAMWithChannel and startRoamScan. This is a direct-call
inventory, not proof that indirect callers or other OS versions are covered.
Raw disassembly remains local and is excluded from repository/SD artifacts.

Explicit-channel producer: setROAMWithChannel (0xffffff80022175c2)
confirms the same target-BSSID copy to +0x64 and value 1 at +0x90. It takes
an 8-bit channel from sta_roam_data+7, constructs band bits (0xc000 for
selector 2; 0x4000 for selector 3 when the corresponding capability is set),
then applies `(spec & 0xc0ff) | 0x1000` and stores a single 16-bit chanspec
at request+0 with channel count 1 at +0x94. Default selector 0 chooses
0xc000 when the channel number is at least 15. These are concrete producer
encodings; band/width interpretation must stay consistent with the existing
chanspec conversion, not be inferred from the low channel byte alone.
Vendor macOS15/macOS26 headers only forward-declare apple80211_reassoc,
so they do not independently establish the missing BSSID-list fields.

Unconstrained roaming producer: startRoamScan at 0xffffff8002217af4
allocates 0xbc bytes through 0xffffff8000ab7060, independently resolved in
the matching kernel symbol inventory as IOMallocZeroData. On its send path
it writes only the broadcast target at +0x64 and value 1 at +0x90 before
calling sendReassocCommand(false, 0). Thus channel count +0x94 is genuinely
zero, not an uninitialized field; no individual target or channel is supplied.
This confirms that REASSOC admission must support a request for candidate
discovery, not merely a preselected-BSSID join. A future implementation must
retain the current connection while discovering/selecting a candidate and
report the roaming event sequence, rather than translating every such request
into a disconnect and ordinary join. The callback remains unsupported until
that lifecycle is implemented; request decoding alone is insufficient.
The source boolean controls whether this send path is reached; it is not
forwarded as the sendReassocCommand boolean on this path.

Connected-scan source audit: native admission permits Connected plus authorized
port; buildWMIScan caps connected passive dwell at 100 ms and sets minimum
home-channel rest to 150 ms. submitDataPacket/dataTXAdmissionOpen do not
globally close data admission for the whole scan. serviceDataTX uses scan
activity to defer its queue-stall watchdog, not as a transmission prohibition.
These are source properties, not measured latency or roaming success.

Follow-up race identified: native setWCL_SCAN_REQ lacks the non-Idle CSA
check already present in the diagnostic scan entry point. serviceChannelSwitch
cancels scans in Announced and Drain, but later Down/Restart/Barrier/Confirm
phases do not repeat that cancellation. serviceWMIScan also lacks a CSA
phase gate. A new request accepted between CSA commands can therefore
start a scan during channel transition. Reproduce admission for these phases
and reject it before resetting scan state; also check a CSA announcement
arriving after admission but before firmware submission. This finding does
not yet establish a cause of the observed physical disconnects.

CSA/scan race regression and fix: a test executes the extracted production
serviceWMIScan pre-submission path, replacing only the later hardware section
with a counter. Before the fix, the first non-Idle CSA phase reached that
section and failed the assertion. Native scan admission now reports busy
bit 512 for non-Idle CSA. The service also marks cancellation on observing
any non-Idle phase, covering announcements after admission. Unattempted scans
finish via the existing local cancellation path; submitted scans retain the
existing STOP_SCAN and DMA/credit completion path. All ten non-Idle phases
and normal Idle submission passed with ASan/UBSan, together with the existing
channel_switch suite. This does not simulate firmware STOP timing or prove
that the user's disconnects were caused by this race.

CSA guard ownership checks also passed with ASan/UBSan for every non-Idle
phase: an already submitted scan retains txOwned and does not become terminal
or completed at the guard; a previously completed scan remains byte-for-byte
unchanged. The test seam stops before hardware processing, so it proves guard
behavior only, not STOP_SCAN completion. Native build and import checks passed.

CSA scan-drain integration coverage: the actual serviceChannelSwitch path
now has a regression that starts with an active scan and owned DMA, verifies
scan cancellation and zero channel-switch commands, supplies scan completion
while retaining DMA and verifies it still waits, then releases ownership.
The transition subsequently reaches Confirm and requires the new-channel
beacon before Idle. Passed with ASan/UBSan. Scan acknowledgements are injected
by the test, so firmware stop latency remains unmeasured.

Next scheduling concern: serviceAPMaintenance starts its 5-second drain
deadline before waiting for _wmiScan.completed, while a connected scan can
legitimately span multiple home-channel rests. It neither cancels that scan
nor waits to start the deadline. Native scan admission also lacks a draining
maintenance check. Reproduce a WMM/ERP update during a long scan before
choosing cancellation versus revised timeout accounting; do not assume this
is a confirmed observed hardware failure.

AP maintenance/scan deadline reproduced and fixed: a WMM update while scan
is incomplete failed at serviceAPMaintenance(8500) after starting the drain
clock at 2500. The service now requests scan cancellation before arming its
independent DMA drain deadline. The scan service retains its 35-second host
bound; a stuck scan is not treated as completed. Native admission reports
busy bit 1024 while AP maintenance is blocked, draining or executing.
ASan/UBSan regression verifies a six-second scan wait produces no AP drain
timeout, no maintenance command, and a cancellation request; after scan
completion it retains the exact five-second deadline for stuck data DMA.
ap_maintenance and native_scan suites passed; native build/import checks
passed. Firmware cancellation latency and physical stability remain untested.

AP drain cancellation follow-up: the combined regression run passed connection,
security_disconnect and channel_switch, then reproduced stale maintenance.draining
when a WMM update reverted to the applied configuration before command submission.
The regression failed on the production methods extracted before the fix.
The no-change and cancellation exits now clear draining along with blocked.
This prevents native scan busy bit 1024 persisting after an abandoned update
and gives a later update a fresh drain deadline. Follow-up ASan/UBSan suites ap_maintenance, runtime_power, native_scan and
native_notifications passed, and the native rebuild/import check passed.
This remains local validation, not hardware confirmation.

Roaming implementation dependency, confirmed against source at 1a5a0c3:
setWCL_ASSOCIATE consumes the PMK into Supplicant::begin and wipes both the
local JoinRequest and _nativeJoin.key. Supplicant retains PMK only in the
live session; NativeSecurity::reset wipes it. serviceNativeRequests discards
security on cancellation, Disabled/Failed or any disconnect stage, before
waiting for WCL notifications. The recovered 0xbc-byte REASSOC envelope
contains no new credential slot. Thus routing roaming through normal LEAVE
and ASSOCIATE would destroy the only retained PMK and cannot implement the
contract. Do not weaken normal leave/forget-network zeroization. A roaming
transaction needs bounded ownership of reusable authentication context,
separate fresh per-BSSID handshake/nonces and explicit wipe on cancellation,
failure, user leave, power-off and completion. Candidate discovery must not
mutate the live ConnectionState until a candidate is selected; the existing
selectOpenBSS path writes that state. These are implementation requirements,
not a claim that a roaming credential transfer or candidate switch exists.

Candidate rate rejection was reproduced as non-transactional: a matching
BSSID advertising unsupported basic rate 0xff changed selected AP/channel
before returning unsupported-basic-rate. The regression compares the whole
ConnectionState before/after rejection and failed before the fix. Common-rate
and mandatory-rate checks now precede AP/channel mutation. This addresses
rate rejection only; HT negotiation and power validation still mutate state
and require a separate candidate configuration for complete roaming isolation.
Follow-up connection ASan/UBSan suite and native build/import checks passed.
Hardware validation remains pending.

Candidate isolation design constraint: ConnectionState includes installed key
bytes, replay state, EAPOL queues, data TX slots and firmware ownership flags.
Do not make a whole-state kernel-stack copy or copy it back to commit a
candidate. The PHY preparation helpers depend on AP metadata, regulatory
policy, firmware HT/VHT capabilities and RF chains; their outputs are channel,
width/center, common rates/maps, PHY flags/reason and negotiated rate ceilings.
Power validation additionally reads candidate country and power constraints.
Use a dedicated configuration without keys or transport ownership, and commit
only these fields after all validation succeeds. Existing association-response
callers of the PHY helpers must retain their current negotiated-rate semantics.
No such isolated configuration has been implemented yet. Reboot remains
deferred at the user's explicit request; do not install the prepared candidate
as part of this source refactor.

Candidate configuration isolation implemented locally: selectOpenBSS now
prepares AP/PHY/rate/power fields in CandidateConfiguration, statically bounded
to 2048 bytes, with no credentials, packet queues or firmware ownership fields.
PHY negotiation and regulatory power helpers accept this configuration as
well as existing ConnectionState callers. Only after all checks succeed are
explicit configuration fields committed. A rejection caused by AP power
constraint 255 leaves the whole ConnectionState byte-identical in the new
regression. Connection ASan/UBSan and native build/import checks passed;
channel_switch and ap_maintenance ASan/UBSan suites also passed.
This does not implement candidate ranking, reassociation or roaming keys.
Published 1a5a0c3 separately passed both GitHub workflow runs 40677155025
and 40677154974; those results do not cover this later local refactor.

Preparation/application split now implemented locally: prepareBSSCandidate
accepts a const ConnectionState and one AP, checks SSID/security, rates and
regulatory power, and produces configuration without changing the connection.
BSSID ranking is intentionally a caller responsibility. applyBSSCandidate
commits only configuration fields; it does not switch the firmware peer,
replace connection BSSID or transfer credentials. Existing selectOpenBSS
retains its exact-BSSID search behavior and uses these two stages. A test
prepares another BSSID on channel 6, checks its prepared identity/channel and
byte-identical live state, then verifies SSID mismatch also leaves live state
unchanged. Connection ASan/UBSan and native build/import checks passed.
This enables candidate evaluation; it is not a functioning roaming controller.

Candidate boundary regression passed with ASan/UBSan: all SSID/rate counts
33..255 reject before array access, protected AP rejects for open policy, and
live ConnectionState remains byte-identical. Applying validated configuration
preserves seeded pairwise key byte, replay counter, BSSID and WMI/TX ownership
flags. This checks selective assignment, not firmware roaming or key transfer.

Reassociation producer inventory completed for the ten direct callers in the
local Sequoia image: all write value 1 at +0x90. The previously unclassified
callers are triggerNeighborCacheSteering (0xffffff8002215e60) and
triggerBSSIDSteering (0xffffff8002216690). The latter copies a chosen six-byte
BSSID to +0x64, obtains a chanspec through its beacon object's slot 0x1e8,
writes it at +0, then stores 64-bit 0x0000000100000001 at +0x90 (therefore
+0x90=1 and +0x94=1) before sendReassocCommand(true,0). This confirms the
single-target/single-channel shape used by BSSID steering. It does not prove
that +0x90 is a BSSID count or establish multi-target capacity: all observed
producers use the same value, so a decoder must not infer an arbitrary list
layout from the unused bytes. The ten-call inventory covers direct callers
in this image only, not future versions or indirect invocations.

A local nativeDecodeReassoc now decodes the observed single-target request
shape: exact 0xbc bytes, +0x90 fixed to 1, <=50 channel specs, byte flags
limited to observed bit 0 and SSID length <=32. It preserves channel specs
without interpreting their radio legality, and permits the confirmed zero-
channel broadcast request. Unsupported layouts reject without changing output.
ASan/UBSan native_wire tests cover zero/50 channels, every truncated buffer,
null/oversized input and invalid selector/count/flags/SSID length. The native
setWCL_REASSOC callback remains unsupported: this parser is not admission,
firmware roaming, key transfer or completion-event implementation.

Channel constraint comparison resolved from Sequoia helpers:
ChanSpecGetPrimaryChannel (0xffffff8002135823) derives width index from
(spec>>11)&7 and uses widths [5,10,20,40,80,160,160]. For width index 7,
zero low byte or width below 20 it returns the low byte. Otherwise it computes
primary = center - width/10 + 2 + 4*((spec>>8)&7), rejecting under/overflow.
For band bits 0xc000, width index 6 and nonzero low byte <=5, center is
looked up in [42,58,106,122,138,155] and width becomes 80 before that calculation.
The zero-byte early exit happens BEFORE this lookup.
ChanSpecGetPrimarySpec (0xffffff80021358e3) combines the resulting primary
with (spec&0xc000)|0x1000. IO80211_channelSpecMatches
(0xffffff8002135f83) compares derived primary bytes AND equal upper two band
bits (xor <0x4000); it does not require raw chanspec equality. Therefore a
20MHz primary constraint can match the same primary in a wider AP definition,
but an equal numeric primary in another band cannot match. These functions
normalize/compare representations; they are not regulatory or capability
validation and even retain some invalid encodings. A driver must still apply
its supported-band/channel-width and domain checks separately.

Channel normalization/comparison is now implemented in nativePrimaryChannel,
nativeChannelSpecsMatch and nativeReassocChannelMatches. Tests passed with
ASan/UBSan for every primary position in 40/80/160 MHz examples, 20-to-80 MHz
matching, different-band rejection, the special width-index-6 center lookup,
zero-center early return, arithmetic under/overflow, zero-channel requests and
invalid channel-count bounds. These helpers deliberately mirror representation
comparison, not channel authorization: invalid encodings can normalize to zero
and still compare equal just as in the recovered helper. A caller must perform
capability/domain validation before admitting or choosing a candidate. No
roaming callback has been enabled by this change.

Local prepareRoamCandidate now combines the decoded request constraints with
read-only candidate preparation: exact current SSID, broadcast or valid unicast
target, target BSSID match, supported primary and normalized band/channel
constraint, then existing security/PHY/regulatory validation. No ranking or
firmware state transition occurs. ASan/UBSan native_wire tests pass for
broadcast discovery and exact target, reject mismatched band/target/SSID and
zero target, and verify byte-identical live state. Request flag bit 0 is
preserved/shape-checked but its roaming policy semantics remain unimplemented.
The callback remains unsupported until the complete transaction exists.

Local chooseRoamCandidate ranks only fresh, request-compatible observations
that pass prepareRoamCandidate. It ignores entries older than the cache's
existing 30-second limit or timestamped after now, then prefers higher signed
SNR, newer observation, and lexicographically lower BSSID as a stable tie break.
No eligible candidate leaves the output unchanged; live state and cache are
read-only. ASan/UBSan native_wire tests cover stronger but incompatible SSID,
expired stronger candidate, all-expired cache and backwards observation time.
This ranking is a local initial policy, not a recovered Apple scoring formula.
It does not decide when to roam, exclude the current AP, implement flag policy,
provide hysteresis or trigger firmware changes. Those remain caller duties.

Candidate ranking tie regressions passed with ASan/UBSan: equal signal and
observation time select the same BSSID under reversed cache insertion order;
a fresher observation wins an equal-signal tie; an explicit requested BSSID
filters other choices; count 65 rejects without changing output.


### Grouped reassociation: successful completion dependencies (24G90)

The complete `WCLRoamManager::roamDone` (0xffffff80021451a4) and
`buildRoamCompletionStatus` (0xffffff8002145256) consumers establish that
a successful roam is resolved against the current associated BSS, current BSSID,
channel, authentication and AKMs. Nonzero input status instead takes the failure
branch. Therefore an accepted reassociation request cannot be completed by
replaying ordinary ConnectComplete while retaining the previous BSS state.

The 0xa8-byte roam status payload is writable: under the manager/payload flag
condition the handler copies 0x68 bytes of constructed status into it. It also
clears its active state fields and invokes the adaptive-roam consumer. These
are consumer facts, not proof of the producer layout or all notification IDs.
Raw function boundaries and structured findings are retained locally in
`NATIVE-roam-contract-batch-20261030/stock-roam-completion*`. Runtime REASSOC
remains unsupported pending the complete profile/key/notification transaction.


### Direct producer cross-check: reassociation notifications (24G90)

The BCM producers now independently confirm three driver message IDs. Their
common call target 0xffffff800222b4a8 resolves in IO80211Family to
`IO80211Controller::postMessage(IO80211SkywalkInterface*, unsigned, void*,
unsigned long, bool)`, eliminating the remaining numeric-ID ambiguity for
these calls (not for every roaming message).

- `handleReassocEvent` at 0xffffff80015cc4fe posts ID 0x49, eight bytes
  at 0xffffff80015cc5b0. Words are mapped firmware status and reason, both
  preserving zero. Firmware status 6 bypasses this producer. Broadcom numeric
  statuses are not portable Ath10k status values.
- `handleRoamPrepEvent` at 0xffffff80015cd426 posts ID 0x8b, twelve bytes
  at 0xffffff80015cd6d4. Word zero comes from firmware reason; bytes 4..9
  are the address; signed value at +10 defaults to zero or comes from the
  supported extended event. Its physical meaning remains unproven.
- `postRoamCompletionStatus` at 0xffffff80015e6f3a posts ID 0x50 with
  0xa8 bytes at 0xffffff80015e6fc4, but another interface receives four
  bytes at 0xffffff80015e6ff7. RoamPrep likewise has an alternate null/zero
  payload path. The version/interface-specific envelope must not be collapsed.

The complete producer functions, resolved controller wrapper and structured
findings are retained in the local roam evidence packet and verified on SD.
This advances the grouped transaction contract; it does not enable REASSOC
or establish the entire writable status structure.


### Reassociation group: admission requires retired transport owners

Extracted production nativeJoinRequest accepted a valid SAE request when the
software connection was Disabled but still owned a WMI command. The added
fixture fails against the prior source at the admission assertion. Admission
now rejects pending WMI TX, management TX, data TX, AP peers, PMF TX, scan TX
and outstanding WMI credits before changing connection or security state.
The seven cases run for both SAE password preparation modes and confirm no
new worker/session is created by the rejected attempt. This is a demonstrated
missing admission guard, not proof that a particular hardware disconnect was
caused by this interleaving.

Five focused groups (native_sae_radio, native_profile, native_wire,
security_disconnect, native_security_lifecycle) and shared checks pass. Full
batch acceptance/build and hardware validation remain pending. The grouped
profile/roaming helpers are still not instantiated by the runtime.


### Roam BSS publication dependency (24G90)

`WCLNetManager::linkStatusInd` (0xffffff8002127b78) reads payload byte6
to dispatch link-up/down FSM events. Its linkUp action (0xffffff8002123ff0)
calls updateBss(true,true,false,reason) before subsequent notifications.
`updateBss` (0xffffff8002124586) queries cmdIouc0x1b1 into a 0x840-byte
buffer, checks BSSID at +0x29, passes beacon metadata and bytes at +0x40 to
updateOrAddBeacon, then invokes setCurrentBSS. A failing update can trigger
leaveNetworkCommand under the caller's leave-on-error flag.

Thus future roaming must expose the new associated AP and beacon through
queries before link-up delivery, and final successful roam status must follow
the new BSS publication. Tests of extracted current query/link-update methods
now exercise three consecutive AP identities, delayed old-address updates and
stale scan scratch. These pass together with native_notifications and
native_profile. They validate these boundaries, not a complete firmware roam.


### Shared native association admission

The wire entry now decodes then delegates to nativeBeginJoin, a radio-gated
consumer of JoinRequest. The common path independently validates fixed-array
bounds and station AP identity, checks old transport ownership, and uses the
same candidate/security/SAE preparation as ordinary macOS joins. It wipes the
provided credential copy on every return, including stopped/busy/bounds errors.

The extracted-production SAE test now passes alternate password scenarios
through ProfileCredentials -> prepareRoamJoin -> nativeBeginJoin, with a
different former AP identity and the expected selected AP. Both H2E and legacy
preparation paths are exercised. Clearing the profile before admission proves
the prepared request is independent; the existing worker tests continue after
the caller copy is wiped. This is local preparation/admission/crypto coverage,
not evidence of a real firmware roaming transaction or its WCL completion.
Five focused groups and shared checks passed. Live REASSOC and profile retention
remain disabled pending old-owner retirement and notification integration.


### Roaming start must precede retiring the old BSS

BCM handleRoamScanStartEvent at 0xffffff80015cc7ba calls the independently
resolved controller postMessage at 0xffffff80015ccace with ID0x89 and twelve
bytes (mapped status, mapped roam reason, extended signed16 value plus zero
padding). WCLRoamManager::roamStart at 0xffffff8002144bc4 requires a current
BSS as well as a payload, clears its completion state and snapshots the current
BSSID as the old AP. This establishes an additional ordering boundary: do not
retire the current BSS before the start notification is consumed. Enqueue
success is not proof of consumption. No synthetic scan-start is enabled.

The current shared-admission implementation compiles and links as a native
kext; the symbol check passes (UUID FB08EAEC-3200-370B-9D0E-07DCBF9773AC).
This intermediate build has not passed final full-suite/dependency-collection
acceptance and is not installed. The live roaming transaction remains pending.


### Roaming delivery return values and allocation boundary

The full stock reportDataPathEventsGated (0xffffff8002264c28) calls
the object at interface ivars+0x28 through slot0x288. A false result
skips postMessageInternal; the gated function still returns zero. When
forwarding, it also discards postMessageInternal's return. The outer
reportDataPathEvents (0xffffff8002264cd2) returns a boolean nonzero test
of its workqueue action result, not a consumer acknowledgement. The
concrete filter receiver and its roam-ID behavior remain to be resolved.

Glue addEventToPendingQueue (0xffffff800212aecc) copies payload bytes into
its own allocation and appends at the tail. Its allocation-failure branch
calls _panic (0xffffff8000bd13ec, independently resolved in the local
kernel-cache symbol table), rather than returning a recoverable error.
routeEventToWcl returns zero after queuing/scheduling. Consequently,
PostOffice enqueue retry can cover only failure before that queue accepts
its copy; it cannot guarantee downstream allocation or event consumption.
Do not replay accepted events blindly: duplicate roam FSM transitions are
not an acknowledgement protocol. Preserve the old WCL BSS until start and
publish the new BSS before completion using the verified ordered path.
Evidence: stock-roam-delivery-gates.asm/json in the roaming batch packet.
No runtime notification path is enabled by this finding.


### Infrastructure roam event filter resolved

Binary vtables independently resolve InfraInterface slot0xb00 to inherited
Skywalk createPeerManager (0xffffff8002263aee), and slot0xb18 to
reportDataPathEvents (0xffffff8002264cd2). Creation stores the manager in
interface ivars+0x28. PeerManager slot0x288 resolves to reportDataPathEvents
(0xffffff80021e14f4), slot0x290 to recordDataPathEventsProcessing.

For IDs0x49,0x50,0x89,0x8a,0x8b the full InfraInterface dispatch reaches
0xffffff80022d6240 unchanged. The base PeerManager takes its default path
with edx=0, r12b=1, r13b=0; its common epilogue returns true after recording
counters. These roam payloads are not read by this filter. The ordinary
infrastructure path therefore needs no filter override or bypass for these
events. The general non-acknowledgement and downstream allocation limits
above still apply. This conclusion does not cover AWDL/NAN managers.
Evidence: stock-roam-filter-resolved.asm/json.


### Runtime profile owner integration

NativeSecurity now retains a bounded credential profile after successful
common join admission. An admitted replacement clears the old generation
before candidate/security setup; busy requests do not overwrite it. Reset
clears the profile together with association security. Accepted MAC changes
invalidate it before vdev recreation. Authenticated transition-disable updates
restrict the retained profile and retire prepared generations; unsupported
policy clears it without silently downgrading authentication.

Terminal service now checks profile ownership itself, including Open networks
which have no supplicant or PMF session. Local production-extraction tests cover
all four terminal conditions, preservation across pairwise-attempt cancellation,
SAE credential retention and reset on failed H2E/legacy preparation paths, and
notification-driven policy restriction/unsupported-policy invalidation. Five
focused groups passed, followed by the added policy-notification test.
Native build CD040286-296B-361F-B0D9-7E713D497AFD compiled/linked and passed
the symbol check. Full batch acceptance and dependency checks remain pending.
Prepared handoff ownership transfer and roam notifications are not yet wired;
REASSOC stays unsupported and this intermediate build is not installed.


### Software retirement boundary for the handoff

NativeSecurity resetAssociation is private and shared by full reset and the
explicit retireForRoam(expectedProfile) operation. Full reset always invalidates
credentials first. Roam retirement requires the current nonzero profile
generation; a stale/zero token returns without touching current keys. It
cancels SAE/PSK jobs, PMF sessions/inbox/query/TX owners, pending management
keys, supplicant state and replies while retaining the profile. Existing SAE
generation counters are not recycled. This API is not yet invoked by live REASSOC.

The extracted-production lifecycle test verifies stale-token noninterference,
key/reply clearing, retained exact binary PMK, and subsequent terminal profile
invalidation. Five affected test groups passed. Firmware retirement is separate:
serviceDisconnect waits for CE3 and credits, key completion/peer disappearance,
optional PEER_DELETE_RESP, STOP_RESP, final ECHO and pending-MPDU drain before
resetDisconnected. Software retirement alone does not satisfy those barriers.


### Prepared handoff credential transfer

PreparedRoam owns one bounded request, bound to the concrete ProfileCredentials
object, its generation and station MAC. Preparation carries the selected cache
observation time through chooseRoamCandidate/prepareRoamJoin. Consumption checks
that original observation age (not a renewed preparation-age window), backwards
time, owner identity and generation, then wipes the private copy. Failure leaves
the caller output unchanged and retires the pending secret. Replacement and
destruction also wipe it; the owner is noncopyable.

Local tests cover four auth profiles, successful one-shot transfer, clear,
same-profile replacement, MAC mismatch, expired observation, backwards time,
explicit cancellation, another owner with the same numeric generation, failed
preparation, and backing-storage secret removal after consumption/destruction.
The production SAE preparation test now runs prepare -> retireForRoam -> take
-> nativeBeginJoin for both H2E and legacy paths. Five affected groups passed.
This is software ownership/admission coverage: PreparedRoam is not yet created
by live REASSOC, and no inter-AP radio or macOS completion is claimed.


### Roam scan-end is telemetry, not completion

The exact-length handler at 0xffffff8002144330 accepts 76 bytes and dispatches
FSM event3. All six state transitions preserve their input state. SCAN,
REASSOC and WAIT_ROAM_DONE invoke roamScanEnd (0xffffff8002144f1e); it requires
a current BSS, clamps candidate count at byte1 to three in the writable
payload, logs scan/candidate metrics, and stores nonzero signed byte0 into
context+0x70. The embedded strings independently identify byte0 as current
BSS RSSI, byte3 scan count, words4/8/12 reason/status/age. Three 20-byte
candidate records begin at16 (BSSID, channel byte6, RSSI byte7, age word8,
load word12, flags halfword16). Unread bytes remain unspecified.

This event must not substitute for RoamDone or acknowledge old-radio retirement.
There is no scan-end success/failure transition out of ROAM_SCAN in this FSM.
The current BCMCore immediate-ID search did not find a producer; absence from
that search is not proof that stock never emits it. Consumer layout and FSM
behavior are established independently. Evidence saved in
stock-roam-scan-end-consumer.asm and stock-roam-scan-end-facts.json.


### Repeated link-up updates BSS without a link-down

Decoded all 77 WCLNetManager transitions from context0xffffff80023f1f60,
using initializer0xffffff8002129cf4 (11 events, 7 states, 22 actions) and
CommonFsmManager's verified two-byte next-state/action entries. In LINK_UP,
LINK_UP remains LINK_UP and calls linkUp, rather than ignoring it. That action
executes the previously recovered updateBss path. Thus new-BSS publication
during roaming need not send LinkDown first; preserving the old WCL BSS through
RoamStart and posting repeated LinkStatus(up) before RoamDone is consistent
with both FSMs. This does not by itself verify the other completion consumers.
Full matrix: stock-network-fsm-derived.json.

NativeRoamEvents now constructs recovered Start/Prep/Reassoc/Complete
envelopes with fixed IDs and byte layouts. The completion is always a mutable
168-byte envelope; opaque bytes are zero. Invalid preparation addresses leave
the output unchanged. Golden-wire and mutation-boundary tests passed alongside
existing notification/profile regressions. These encoders are not yet connected
to the live roaming dispatcher; mapped failure policy remains to be integrated.


### Successful roaming triggers a currently unsupported cache request

WCLAdaptiveRoam::handleRoamEventConfiguration (0xffffff80022dec70) returns
immediately for nonzero status. On success it calls configureUserRoamCache
(0xffffff80022dee46), which emits command0x1af with a 128-byte envelope. This
call uses zero channels, clear=1 and updateOverride=1 with override=0. Native
setWCL_ROAM_USER_CACHE still returns unsupported. This is an explicit remaining
post-completion contract, not an optional hardware roaming test.

The producer copies up to ten 12-byte channel records and stores count at0x78,
override at0x7a, clear at0x7b, updateOverride at0x7c. BCM cmdROAM_USER_CACHE
(0xffffff800155a4f0) independently confirms clear/add/override operations and
read flags0x7d/0x7e when output is supplied. The unused byte0x7f is unresolved.
Implement real channel-cache/override state and its scan effect before
acknowledging arbitrary requests; a no-op success would violate this contract.
Evidence: stock-roam-postcompletion-cache.asm/json.


### User roam-cache parsing and state

Added decodeRoamCache for the recovered fixed 128-byte envelope, ten channel
records and the five operation flags. It rejects truncated/oversized frames,
negative/oversized count representations, nonboolean flags and the unresolved
byte0x7f; failed decoding leaves output unchanged. UserRoamCache commits only
after validating every entry through the caller's validator. Clear/list update
and override update are independent; a failed channel replacement leaves the
previous complete state intact. Read flags preserve state when no mutations
are requested. No output serialization is implemented yet.

native_wire, native_profile and native_scan passed. The live callback remains
unsupported until real channel/regulatory validation, query serialization and
roam-only scheduling are wired; normal user scans must not be narrowed by a
roaming hint. BCM maps override into firmware user_roamcache operation4, but
that alone does not prove how it should affect every ordinary scan request.


### Roam-cache atomic readback and channel validation

BCM readback independently writes override at0x7a (0xffffff800155abec)
and count at0x78 (0xffffff800155ad5b); channel conversion fills 12-byte entries.
UserRoamCache::exchange now applies validated operations to a private candidate,
serializes requested reads from that resulting state, then commits state/output.
Invalid input or rejected channel leaves both unchanged. Unused returned channel
records are zeroed rather than echoing stale caller bytes.

The channel validator checks the known 2.4/5GHz band, 20/40/80MHz geometry,
firmware scan-plan primary channel and current regulatoryPower policy (passive
scan eligibility). Unsupported widths/unknown flag bits and inconsistent band
or extension flags are rejected. Tests cover read-after-write, read-only,
clear/override reset, malformed/short transaction preservation and a restricted
firmware band range. native_wire, regulatory and native_scan passed.
This completes local cache exchange, not live callback/roam scheduling; those
remain unwired. Evidence: stock-roam-cache-readback.asm.

### Roaming acceptance with one router

Physical inter-AP handoff is unavailable on the user's setup. This must not
block implementation of the native contract or trigger requests for a second
AP. Keep four distinct evidence levels: recovered stock macOS contract,
production-path local integration, ordinary single-AP hardware regression, and
unverified physical inter-AP handoff. Same-AP reconnect does not establish the
last level. Recovered private ABI is tied to the examined OS build.

For local integration acceptance, exercise the actual handoff dispatcher through
success, cancellation, stale completions and firmware retirement failures.
Profile helpers and event-layout tests alone do not close that gate. Check that
old keys and transport ownership retire before the new join, the old BSS survives
the start notification, the new BSS is queryable before successful completion,
and failures leave neither pending credentials nor an unfinished system request.
Live REASSOC remains disabled until this production-path integration is complete.

### Prepared handoff now follows controller credential lifetime

NativeSecurity owns PreparedRoam. Terminal reset wipes it before clearing the
profile and association; admitted profile replacement and accepted MAC change
also clear it. An authenticated policy update clears it if the profile token
changes. Software retirement alone preserves it for the explicit handoff.
The extracted production SAE fixture now uses this owned object and exercises
terminal cancellation before preparing again and entering common join admission.
Four affected integration groups and the final SAE cancellation fixture passed.
The earlier full 63-test result predates these production edits; final full-suite
and native-build acceptance remain pending. Live REASSOC is still disabled.

### Transport retirement before exposing Disabled

Production serviceDisconnect previously waited for ECHO reply and pending RX
MPDUs at its final barrier. Earlier stages had drained other owners, but final
reset did not independently establish they stayed retired. It now checks the
expected disconnect ECHO cookie, scan completion/TX ownership, serial/data/PMF
TX, WMI ownership/credits and peer count before wiping ConnectionState. Drain
also waits for scan TX ownership even after a scan completion arrived.

The extracted production routine was exercised with nine independently held
barrier conditions and a completed-scan/owned-TX drain case. Each held case
preserves association keys/state; releasing it permits exactly one reset.
Existing end-to-end simulated CLEAR/DELETE/STOP/ECHO/reconnect and native join
admission tests also pass. This is preventive ownership hardening, not evidence
that every injected state has occurred on hardware. Live roam remains pending.

### Production prepared-join continuation

Added nativeContinueRoam beneath the radio/WCL gate contract. It validates
profile ownership, MAC and original scan age before waiting on shared join
admission. Busy retains the prepared request; invalid work is wiped; an
admitted request is consumed once into nativeBeginJoin. Common admission now
also checks pending RX MPDUs and unretired vdev/peer creation flags.

The production SAE fixture exercises eight held transport/publication conditions,
then actual H2E/legacy preparation through the continuation, and rejects a second
consumption. Profile/security tests and native compile/link/symbol checks passed.
This function is not yet called by a live REASSOC dispatcher. The dispatcher
must still handle old-BSS notification ordering and intentional teardown
without ordinary terminal cleanup discarding the retained profile. Tests
explicitly prepare the retirement/publication boundary; they do not prove that
missing live orchestration. No installation or physical roaming test occurred.

### Roam notification enqueue progress

RoamEvents::Delivery now tracks one noncopyable transaction: Start, Prep,
Reassoc, then Complete. Only successful queue acceptance advances progress.
Rejected posts leave the original metadata intact, even when the receiver
mutates its writable payload. Successful completion requires Reassoc acceptance
and an explicit new-BSS publication prerequisite; nonzero failure completion
is permitted after any accepted Start. Completed events cannot be replayed.

Tests inject rejection at each step and failure completion from all three
started phases, check invalid ordering, mutated-payload retries, double sends
and transaction reuse. The native_wire group passed. This is local delivery
state, not a WCL-consumption acknowledgement and not yet bound to the live
controller dispatcher. The previously built kext predates this header addition.

### Stale notification attempts cannot advance a new roam

Delivery now assigns a nonzero monotonically increasing generation at begin
and requires it on every send. Reusing a completed owner cannot let an old
callback emit Start, Prep, Reassoc or Complete for the new attempt. Generation
exhaustion refuses another begin. Invalid begin leaves the previous token and
phase intact. Tests pass for stale transitions at every phase, alongside the
previous enqueue-failure, mutation and single-completion cases. This remains
local delivery state awaiting live dispatcher integration.

### Intentional retirement integrated with production terminal cleanup

NativeSecurity now owns delivery progress and a retirement token. Beginning
retirement requires a matching prepared profile and an accepted Start/Prep
sequence. The production serviceNative cleanup preserves that profile only
while its delivery token, MAC and original observation age remain valid and
no explicit cancellation or failed link state exists. Full reset always clears
the retirement token and pending credentials. The cleanup predicate includes
orphaned pending/retirement owners even if the profile was already cleared.

Extracted production tests cover retention across Drain and Disabled, explicit
cancellation, failed link, expiry, MAC replacement, profile replacement/clear
and failure completion. The SAE fixture runs accepted Start/Prep -> retirement
-> shared continuation -> H2E/legacy preparation and confirms consumption clears
the retirement marker. Controller-level request admission, firmware disconnect
initiation and intentional LinkDown suppression are still not wired; no live
REASSOC support is claimed. Final full-suite acceptance remains pending.

### Controller disconnect and retained-link publication

The controller now admits nativeDisconnectForRoam only with a valid prepared
profile, accepted Prep, established published link, and idle scan/TX/WMI owners.
It queues the existing requestDisconnect Drain, retires software association
keys, and closes the data path without discarding old WCL publication flags.
serviceNativeNotifications suppresses ordinary Deauth/LinkDown only while the
retirement remains valid. Cancellation/expiry restores the ordinary terminal
path. Common continuation may bypass those retained publication flags only
after validating the intentional retirement, while keeping all transport checks.
It resets publication flags on new admission and restores them on failure.

Production SAE integration tests exercise busy TX/scan rejection before port
closure, Drain admission, continuation blocked until retirement, then H2E/legacy
SAE preparation. Firmware completion is modelled there by resetDisconnected;
separate reconnect tests cover actual production teardown sequencing. Production
notification tests verify suppression and return to exactly one ordinary
Deauth/LinkDown with the old BSSID. The macOS REASSOC entrypoint and overall
service dispatcher are still unsupported/unwired; no live roaming claim.

## Integrated host-requested roaming candidate (supersedes earlier unwired notes)

The current source connects setWCL_REASSOC through the radio-gated request
handler and existing WCL/radio service bridge. It validates the fixed 188-byte
request, selects a fresh eligible cached BSS, snapshots the admitted profile,
and queues Start/Prep before initiating the existing asynchronous disconnect.
Admission rejects overlapping joins/scans/rekeys and terminal/power states.
There is no companion app, root patch, or private synchronous queue wait.

The same transaction continues only after the firmware/CE/HTT/RX retirement
boundary. It uses the ordinary join/security path with fresh association keys.
Notifications use Reassoc, new BSS/LinkStatus/FirstBeacon, then writable 168-byte
RoamComplete. Success requires publication of the new BSS; failure/cancellation
completes the accepted roam, and JoinAbortComplete waits until that completion.
Queue acceptance is tracked without claiming consumer acknowledgement.

Both WCL link-down publication and BSD carrier-down are deferred during a valid
handoff while data admission/queues close. Failed/cancelled retirement releases
the deferred carrier even when the internal data-link flag is already down.
Authenticated transition-disable received after request acceptance is applied
before teardown, so a newly restricted profile cannot use an older snapshot.
Late key/rekey work blocks retirement until it is resolved.

The WCL post-success user-cache clear/override-disable and empty readback are
implemented. Nonempty autonomous firmware roam-cache updates and override enable
return unsupported; no ignored request is reported successful. Host-directed
roaming uses the fresh observation cache and performs full authentication;
FT/SAE-PK, independent firmware roam offload, and inter-AP interoperability are
not claimed. No eligible cached BSS causes an immediate not-ready response;
this request does not invent or widen a foreground scan.

Validation covers the actual request/retirement/common SAE code plus extracted
notification dispatch with controlled firmware hooks. Separate production
reconnect tests exercise CLEAR/DELETE/STOP/ECHO and held owners. The notification
fixture tests every enqueue-failure position, before/after-join cancellation,
late policy, BSS publication and one terminal result. These are local tests,
not a physical inter-AP roam. Only one router is available. Installed EFI and
the loaded driver remain unchanged until explicit installation/reboot approval.

Integrated candidate AF185664-F6A2-3EE4-B3D6-723E5CB4C1BD passed the final
63-test suite, callback matrix, native compile/link/symbol checks, strict ad-hoc
signature and exact-UUID offline dependency inclusion. The offline probe omits
only OSBundleRequired from its plist; executable program sections match the
normal signed candidate. Installed EFI is unchanged; rollback is verified on SD.

## Documentation reconciliation — 2026-10-30

The previous leading WPA3 status was stale: SAE/PMF are implemented, with an
earlier protected SA Query hardware checkpoint. Current requirements now live
in the two normative contracts; original investigation text is preserved in
docs/history. docs/development/NATIVE-STATUS.md records implementation, local coverage and
hardware evidence separately. CHANGELOG.md and AGENTS.md establish batch-level
maintenance and one consolidated regression for implemented functionality.
The installed AF185664 image remains unchanged; ordinary SAE traffic was
observed after boot. AP-triggered key updates are a missing radio observation,
not an absent PMF implementation. No new driver feature is claimed by this
documentation reconciliation.

## External key dispatch evidence — 2026-10-30

Examined local AppleBCMWLANCoreMac UUID
4C3822FC-8902-3AF6-A791-DD4A8D9E9C66, matching Sequoia 24G90.
Core setCIPHER_KEY at 0xffffff800160dc76 forwards the input to JoinAdapter
setKey at 0xffffff8001586450 with true and null auxiliary data. Decoded the
11 signed-relative jump entries at 0xffffff8001586ad4 from the Mach-O segment:

| Cipher selector | Target | Observed path |
| --- | --- | --- |
| 0 | 0xffffff80015865a3 | Return path after initial owner lookup |
| 1–5, 8 | 0xffffff80015865cc | mapAppleKeyToBcomKey then firmware programming |
| 6, 9 | 0xffffff80015864c0 | PMK/MSK path; programPMK, optional supplicant events and 6000 ms timeout |
| 7 | 0xffffff8001586682 | Separate PMKSA path; detailed semantics pending |
| 10 | 0xffffff80015866f4 | Separate password path; detailed semantics pending |

Ordinary key mapping at 0xffffff8001652189 reads index at +0x0e, length
at +4, cipher at +8, bytes at +0x10, flags at +0x0c, peer address at +0x5c.
It bounds copied key material to 32 bytes, requires at least 32 for TKIP and
swaps its two MIC halves. This is evidence about Broadcom translation, not a
policy to truncate external input in Ath10k. Program dispatch selects
programKeyAsync (0xffffff800158998a) or programKeySync (0xffffff8001589abe)
after a runtime virtual query; callback return cannot alone establish the
actual firmware/key authorization barrier.

Conclusion: the external callback is a discriminated credential/key operation,
not an alias for internal PTK/GTK installation. Before enabling it, recover
PMKSA/password handling, owning interface/session selection, completion and
controlled-port transitions, and define mutually exclusive internal/external
supplicant ownership. Existing internal SAE/PMF implementation is unaffected.
No new capability or hardware certification is claimed by this investigation.

### External-key PMKSA/password/completion follow-up — 2026-10-30

Same matching BCM image as above. PMKSA selector 7 at 0xffffff8001586682
returns zero after a feature-flag check and optional logging: no firmware key
programming occurs in this branch. It is not evidence of a working PMKSA cache.
Password selector 10 at 0xffffff80015866f4 bounds its copy to 64 bytes, builds
wsec_pmk with flag 1, optionally enables supplicant events and 6000 ms timeout,
then calls programPMK. Core setCIPHER_KEY supplies null auxiliary data, so it
skips the subsequent auxiliary-data command path. Ath10k must validate its
accepted password contract, not copy Broadcom truncation behavior.

programPMK (0xffffff8001589840) uses runIOCtlSet command 0x10c.
programKeySync (0xffffff8001589abe) uses runIOCtlSet command 0x2d.
programKeyAsync (0xffffff800158998a) submits 0x2d with 0xa4-byte payload through
issueCommand and returns that submission result. Its callback at
0xffffff8001589bb0 immediately returns on success; on failure it optionally
logs. It neither publishes WCL link success nor authorizes the controlled port.
Therefore a separate handshake/port event path must be recovered before
external owner support can be considered integrated. These callbacks do not
justify inventing a WCL key-complete event or authorizing on submission.

### Firmware supplicant completion is separate from external key submission — 2026-10-30

BCM handleSupplicantEvent at 0xffffff800158af00 consumes event status at +8
and reason at +0x0c; it matches event peer +0x18 against retained records.
The mapping at 0xffffff8001652463 returns success only for status 6 with
reason 0 or 21. The reason mask 0xcace maps to 0x3f6; status 5 with reason
0/21 maps to 0x35; other reasons/statuses use failure/unknown values.
The handler stores status at context+0x280, reason at +0x282 and invokes
sendConnectComplete (0xffffff800158abce) on its terminal branches. It is
distinct from the logging-only programKeyAsyncCallback.

This traces the firmware-supplicant completion path, not the externally owned
802.1X controlled-port path. It corroborates the existing internal-supplicant
design: completion follows the authenticated exchange rather than key-command
submission. Do not map raw Broadcom status numbers onto Ath10k firmware, nor
claim external enterprise ownership resolved by this finding. Next unresolved
contract is the OS-owned EAPOL/controlled-port path and its profile admission.

### STA_AUTHORIZE scope and EAPOL ownership — 2026-10-30

IO80211Family setSTA_Authorize ioctl wrapper at 0xffffff80022cb8ac requires
exactly 20 input bytes, attempts WCL command 0x4a and falls back to
apple80211setSTA_AUTHORIZE at 0xffffff80021fbf2a. The fallback casts to
IO80211SapProtocol before invoking vtable slot 0x1020, rejecting an interface
that does not satisfy that cast. BCM implements this on APSTAInterface at
0xffffff800169be42. Therefore this inspected fallback cannot be treated as
the infrastructure client's controlled-port authorization callback. The WCL
handled route is a separate unresolved path; this observation is not a proof
that every route for command 0x4a is SAP-only.

Current Ath10k releaseRXBatch consumes secure EtherType 0x888e into its internal
four-frame queue, rejects lengths above 512 and checks source BSSID. Ordinary
outputPacket requires dataTXAdmissionOpen; there is no external EAPOL bypass
for a closed controlled port. These are intentional internal-supplicant
constraints, not sufficient transport for general OS-owned 802.1X/EAP frames.
External support must integrate RX/TX ownership, bounded frame validation and
controlled-port state alongside key commands. Enabling setCIPHER_KEY alone
would advertise an unusable path. No internal WPA3 regression is inferred.

### Apple EAP client boundary corrects the external-owner plan — 2026-10-30

Primary source inspected: apple-oss-distributions/eap8021x, main on 2026-10-30:
- [EAPOLSocket.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/EAPOLSocket.c), blob a82591c5bd96afe2bf98057b261c225759596577.
- [Supplicant.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/Supplicant.c), blob 552c261964a5eee7382a0e54bba952a29731bb47.
- [InterestNotification.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/InterestNotification.c), blob 5f3767c8a74d942d77f904940b58e04a6354d8de.

Supplicant set_wpa_key_info exports MSK and calls EAPOLSocketSetWPAKey; clear
passes NULL/zero. EAPOLSocketSetWPAKey requires wireless WPA-enterprise. For
the primary supplicant it uses null BSSID and registers completion interest
when MSK is nonempty; preauthentication uses a specific BSSID. It calls
wireless_set_wpa_msk. Handshake completion can renew configuration or recover
a lost EAP Success, then unregisters the interest. InterestNotification listens
for kIOMessageServicePropertyChange on the interface's selected parent object.
The public wireless implementation is omitted, so exact private ioctl mapping
and compatibility with installed 24G90 userspace still require local recovery.

Architectural correction: OS-owned EAP does not imply OS-owned PTK/GTK install.
An enterprise mode may route EAP to the OS, accept MSK, and retain the existing
internal four-way/PMF implementation. Explicit EAP versus EAPOL-Key ownership,
MSK admission, peer/generation cancellation and completion notification must
be integrated together. Prior notes requiring a wholly external handshake
owner are superseded by this split, not a reason to duplicate working crypto.

### Installed EAPOL client MSK ABI — 2026-10-30

Read-only disassembly of installed eapolclient x86_64 UUID
FAC5670D-77C2-3A38-9DE9-37B8A150A96B (Sequoia 15.6.1).
The set_msk logging path calls 0x10000c324 at 0x100009111. The callee
accepts lengths only 0 or 64 (test ecx against 0xffffffbf), constructs a
zeroed 0x94-byte apple80211_key record with version 1, length +4, cipher +8,
key bytes +0x10. Null BSSID selects MSK cipher 9; explicit BSSID selects
PMKSA cipher 7 and copies its six bytes to +0x5c. It invokes Apple80211Set
at 0x10000c3ee with selector 3, zero second selector and size 0x94; return
zero maps to true. This confirms the public source architecture on the local
binary, including zero-length clearing. It does not yet prove the private
framework's translation or native kernel completion behavior.

The same executable imports Apple80211Set/Get and IOKit interest registration.
At 0x10000f00c it registers IOGeneralInterest after selecting a parent object.
Disassembly is local analysis only, not distributed Apple code. No driver
capability was enabled or key material accessed in this inspection.

### Kernel MSK transformation and completion notification — 2026-10-30

Matched IO80211Family setCipherKey at 0xffffff80022c9dbe validates a 0x94-byte
request and calls checkValidationForApple80211Key. For interface type 1 it
queries auth via WCL command 2 (fallback getAUTH_TYPE). Cipher mask 0x340
selects 6/8/9: auth 0x4000 or 0x8000 clamps length to 48, other auth clamps
to 32. Auth 0x80 with a nonempty key copies the next 32-byte source portion
over the outgoing key start. It then sends WCL command 3, size 0x94, with
apple80211setCIPHER_KEY fallback. Thus the observed userspace 64-byte MSK is
NOT the expected native callback length; consumer validation must use the
post-translation association profile. Meaning of every auth mask remains to
be checked before enabling broader profiles.

IO80211InfraInterface::handleKeyDone at 0xffffff80022d4d9c emits
kIOMessageServicePropertyChange (0xe0000130) on its interface after success
and property update, for interface type 1. setLinkStateInternal invokes it
for link states 1/2, with success true for state 2. postMessage also invokes
it with true/true for ID 0x4c when payload+4 equals 0xe0822c15. These are
stock notification producers, not grounds to send arbitrary duplicate
property-change messages from Ath10k. The existing native link publication
may already traverse the correct initial completion route; verify its exact
link state mapping before adding another event. Rekey notification is distinct.

### Existing native LinkUp already reaches initial key-done — 2026-10-30

Ath10k nativeLinkStateUpdate invokes the stock interface setLinkState with
kIO80211NetworkLinkUp when WCL byte7 requests the link update. The included
ABI enum assigns Down=1 and Up=2. The recovered stock setLinkStateInternal
path invokes handleKeyDone(true,false) for state2 on type1 interfaces. Thus
initial EAP completion has an existing stock notification route; adding an
unconditional messageClients(property-change) would duplicate it. This is
source/ABI path evidence, not a new enterprise radio test.

Native key replacement deliberately retains carrier and does not republish
LinkUp. The separately recovered stock postMessage branch ID0x4c/reason
0xe0822c15 invokes handleKeyDone(true,true). Before adding any such event,
recover its producer payload and WCL routing and determine which enterprise
reauthentication scenarios require it. Do not confuse it with the already
implemented 40-byte transition-disable SupplicantEvent.

### Rekey event shares the existing supplicant wire record — 2026-10-30

Resolved producer AppleBCMWLANCore::handlePSKEvent at 0xffffff80015cdd46:
it builds the 40-byte record and posts ID0x4c at 0xffffff80015cdf71, then
invokes JoinAdapter::handleSupplicantEvent. Firmware status6 maps to
0xe0820406; reason21 maps to 0xe0822c15. This is the SAME SupplicantEvent
wire record already declared in build/generated/itlwm/WCL.hpp (enum76), not a new
event type. Earlier wording about a separate event refers only to different
reason/semantics and must not be read as a separate payload or event ID.
Current completedSupplicantPolicy emits reason0 (0xe0822c00), so it does not
enter Infra's reason21 key-done notification branch. The policy delivery
mechanism must not be repurposed into unconditional rekey notification.

Implementation decision pending: tie reason21 publication to a successfully
completed applicable key exchange and its association generation, with
one accepted enqueue and cancellation handling. Do not synthesize it for
IGTK-only updates or every security counter increment without confirming
stock reason21 semantics and distinguishing pairwise from group exchanges.

### Reason21 identified as PTK update — 2026-10-30

The maintained Broadcom driver header
[bcmevent.h](https://github.com/StreamUnlimited/broadcom-bcmdhd-4359/blob/master/include/bcmevent.h)
defines WLC_E_SUP_PTK_UPDATE=21, separately from GTK_UPDATE=23. Its PTK
update payload describes the PN when M4 was sent. This explains the locally
recovered Infra reason0xe0822c15 key-done branch: it is pairwise replacement,
not a blanket GTK/IGTK completion signal. Header version is independent of
Apple 24G90; numeric mapping is corroborated by the local producer/consumer,
not evidence that all newer Broadcom event extensions exist on this Mac.

Next implementation boundary: preserve a pairwise-update completion ticket
from authenticated PairKeys through firmware PTK acknowledgement, PMF epoch,
ECHO/RX retirement and M4 transport completion, then post the existing
40-byte SupplicantEvent with success/reason21 once. Cancel the ticket on
leave/failure/profile retirement; retry failed enqueue without replaying an
accepted event. Do not trigger on initial keys, GTK-only or IGTK-only changes.
No runtime implementation has been added in this investigation yet.

## 2026-10-30 — native EAPOL completion ownership gap

Source review confirms that `serviceNative` sets `authorizePending` only when
submitting at security phase 3. Rekey replies are submitted at phase 5, so the
existing native completion branch does not inspect their failure. The serial
retirement path in `serviceConnection` sets `eapolTxFailed`, but does not itself
cancel that native rekey. Moreover, `serviceConnection` can submit a management
frame later in the same invocation, and `serviceNativePMF` runs before native
reply processing. Therefore reading the shared latest `txStatus`/`txId` from a
later native tick cannot identify M4 reliably.

The implementation batch must capture completion at retirement and cover reply
ownership, every EAPOL failure, pairwise-only notification, duplicate replies,
cancellation and enqueue retry together. This is a source-confirmed integration
gap, not evidence of a particular observed radio failure. No driver changes or
new hardware test have been made at this checkpoint.

## 2026-10-30 — integrated EAPOL/PTK completion candidate

Implemented durable EAPOL completion at serial DMA retirement and failure
handling for every native reply. A PairKeys export binds the expected security
generation; only successful M4 completion after the phase-5 key/PMF/ECHO barrier
creates the pending PTK event. While pending, the next EAPOL exchange is not
consumed. Event 76/reason 0xe0822c15 preserves policy flags and is consumed only
on accepted enqueue. Association retirement clears its owner. Initial keys,
group-only updates and duplicate replies do not arm this event.

Consolidated 64-test suite passed, including production-fragment completion,
notification and reset tests. Candidate D2D48A34-9F25-327E-A916-7C7D4C297822
built and signed; exact UUID included in isolated auxiliary linking after
removing OSBundleRequired only from its validation copy. The successful command
uses repository selection (-r probe -b br.com.jonasw8.driver.ath10kmac), explicit
aux output, existing boot/system collections and --allow-missing-kdk. Earlier
bundle-path-only attempts supplied no binaries and are not counted as passes.
No EFI change, live loading or hardware rekey validation performed.

## 2026-10-30 — EAP receive preflight and OS startup boundary

Reviewed Apple EAPOLSocket.c (public main; source snapshot hash retained in local evidence).
Wireless link activity is inferred from a valid AP MAC, and ordinary wireless
EAP transmission targets the BSSID; AF_NDRV carries the packet. This supports
publishing association identity before controlled-port completion. It does not
prove the installed IO80211 input path accepts pre-link packets or starts the
system EAP client; those remain separate local-stack checks.
Source: https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/EAPOLSocket.c

Found releaseRXBatch's earlier preflight still imposed the internal four-way
512-byte limit and queue capacity on every EAPOL frame, before native routing.
Validated current-owner system EAP now bypasses only that internal slot budget;
peer validation, secure RX checks and controlled-port blocking remain in place.
An extracted production preflight/packet test covers 1024-byte EAP with a full
internal key queue and rejects the same bypass for personal profiles. Sanitized
fixture passed; native enterprise admission remains disabled/unimplemented.

## 2026-10-30 — installed EAP client auth discriminator

Re-read installed eapolclient, x86_64 UUID FAC5670D-77C2-3A38-9DE9-37B8A150A96B.
At 0x10000c223 it requests Apple80211CopyValue selector 2, reads AUTH_UPPER,
and at 0x10000c2ca–0x10000c2f2 recognizes exactly 1, 4, 0x80, 0x800, 0x4000,
0x8000 as enterprise values. The ordinary AKM1 admission's upper-auth 4 therefore
matches the installed client discriminator. Other values are not admission
permission: this driver still rejects their distinct derivation/roam contracts.
This proves the consumer's expected value, not current WCL getAUTH_TYPE output,
EAP client startup or pre-link RX delivery. Fresh disassembly excerpt and hash
are retained in NATIVE-eap-integration-20261030.


## 2026-10-30 — EAP queue lifecycle and stock input boundary

The installed 1.0.106 checkpoint is preserved; development resumed on the current
branch without another hardware test. Auditing the integrated EAP path found that
networkLink starts the BSD output queue only after authorization, while EAP needs
that queue to transmit before authorization. The new separate EAP queue owner
starts it without changing carrier, stops/flushes it on retirement while carrier
is down, and hands queue ownership to ordinary data after authorization. Link-down
handles the EAP-only running state before the old same-carrier early return.

EAPOwner enqueue previously checked clock reversal but not the MSK wait deadline;
RX routing likewise relied on later cleanup and did not check association retirement.
Ingress now enforces these boundaries. Service does not submit EAP while interface,
runtime or power admission is disabled, but timeout still retires the owner.

Installed IONetworkingFamily was read from BootKC, UUID
5D3F11B8-802B-3860-8A36-E9334980A117. inputPacket at ffffff800262fa96 checks
attached ifnet (+0x90); pushInputPacket at ffffff800262f9be reaches
ifnet_input_extended at ffffff800064a480 (confirmed against original KC symbols).
Neither inspected method gates on carrier. IOBasicOutputQueue::start at
ffffff80026361c0 sets running state and invokes dequeue. These are static boundary
facts, not evidence of enterprise radio operation or complete system-client startup.
Excerpts and image hash: outputs/NATIVE-eap-port-lifecycle-20261030/stock-evidence.json.
No Apple implementation was copied into driver source.

The separate setEAP_FILTER_CONFIG callback was also examined instead of treating
its name as an ordinary EAP prerequisite. Stock Core setter at ffffff8001643cfa
stores the first u32 in context +0x4c90; its diagnostic names WoWEapolFilterEnable.
It does not start EAP or deliver packets in that setter. Wake-filter consumers and
failure handling remain unverified. The callback matrix records this narrow
finding; the driver continues to reject unsupported configuration, without fake
success. Evidence: stock-eap-filter.asm in the same directory.


Publication/version rule clarified by user: advance the build number only after
successful push, not while changes are local or merely committed. Source metadata
has been restored to 1.0.106. The prepublication FA99080C candidate labelled
1.0.107 is superseded and must not be installed. Pending release notes for this
batch are the queue-start/stop, expired ingress and disabled-runtime transmission
changes described above; add them to the versioned changelog after publication.


## 2026-10-30 — initial EAP key-clear and system startup audit

Public Apple source identifies a concrete integration error: the EAP client clears
WPA key state on entry to Authenticating, before the first MSK. Our zero-length
MSK handler previously retired the association unconditionally. A current owner
with no accepted PMK now reports Empty without changing its generation, packet
queue or deadline. Accepted/consumed PMK clear still cancels and closes the port.
The extracted callback, owner and combined join→initial clear→MSK→M1–M4→receipt
fixtures pass ASan/UBSan; expired/reset/conflicting paths remain distinct.

ControllerStart opens the system EAPOL socket and launches eapolclient; its
interface-type gate accepts IEEE80211. Wi-Fi is not automatically started by the
Ethernet autodetection flag. The driver must not add a companion launcher. The
installed manager's start/join sequencing remains an exact consumer evidence gap.

The public link-down path delays transition to inactive, so an accepted LinkDown
message cannot be treated as an acknowledgement draining old OS MSK callbacks.
No one-second delay was added: source defaults are configurable and not a fence.
Late zero-BSSID MSK isolation and Enterprise reauthentication remain open.
See NATIVE-EAP-CONTRACT.md for exact source blob identities and references.


## 2026-10-30 — installed Enterprise start-before-associate ordering

Read-only installed airportd/loaded CoreWLAN inspection recovered the actual
user-mode caller sequence: WiFiAgent start request with bounded acknowledgement
precedes common association, which receives is8021X=true. UUIDs, call addresses,
selector-decoded bounded disassembly and restart-loop facts are saved under
startup-contract and summarized in NATIVE-EAP-CONTRACT.md. No live system client
was started and no connection settings were changed. Stop/restart polling does
not establish a universal old-key drain: same-process autoreconnect remains an
unproven boundary. Do not add a guessed delay or claim full late-key isolation.


## 2026-10-30 — EAP retirement across callback and service

Expiry detected inside the MSK callback clears the owner before the periodic
service can see its deadline. The callback now explicitly records timeout,
cancels association, closes the controlled port and schedules cleanup when that
expiry retired the owner. A stale identity with a still-live owner remains a
rejected request, without cancelling that owner. Service also releases EAP-only
queue ownership when security/profile/association has already been retired; it
preserves a running authorized data queue. Extracted callback, service and combined
production handshake fixtures passed ASan/UBSan for these paths.

These changes follow the initial empty-key reset fix. Final consolidated regression
and native build are being rerun for the combined batch; earlier full-suite and
image evidence must not be treated as validation of these final edits. No install,
push or build-number advancement has occurred.


Final combined checkpoint: all 68 C++ tests plus runner checks passed with explicit
ASan/UBSan, assertions enabled. Native compilation/symbol check passed for UUID
9CB4F564-2283-3261-A46A-3A27CBC19C87 at unchanged version 1.0.106. An isolated
copy, with OSBundleRequired removed only there, passed strict ad-hoc signature
verification and auxiliary linking; exact UUID inclusion was verified. No EFI or
system collection modification, installation or Enterprise hardware claim.
Evidence: final-regression.log, final-regression-summary.json, latest-build.json
and final-inclusion.json in NATIVE-eap-port-lifecycle-20261030.


Publication checkpoint: functional batch 862ed1f0bba3df83732eb68860ad95edcd72ce69
was published to native-sequoia-development and its tree matched the local files.
Only then were plist/kmod versions advanced to 1.0.107 and code-only changelog
notes assigned. These metadata edits await the next publication; no second
per-fix push was made. The validated binary is still the prepublication 1.0.106
image; a versioned build must be generated before any installation.


## 2026-10-30 — reauthentication PMK-clear boundary

Recovered stock cipher9 switch target and programPMK zero-length path. Stock
forwards empty PMK to firmware without direct disassociation in inspected methods;
public EAP client emits that clear both on Authenticating and Held. This rules out
using the callback alone as a unique restart/failure signal. Firmware active-key
semantics and replacement-handshake ownership must be recovered as one group
before replacing current default-disabled cancellation behavior. No driver edits
or repeated Personal tests for this evidence-only step. See EAP contract and
NATIVE-eap-reauth-contract-20261030 facts/disassembly.


Wrong-PMK authorization boundary: added one scenario to the combined production
Enterprise join/callback/handshake fixture. A deliberately different PMK is
accepted by the tokenless current-owner callback, but valid AP M3 then returns
Fatal without key export or authorization intent. The fixture passed ASan/UBSan.
This distinguishes a tested cryptographic barrier from unresolved late-callback
provenance/availability; it does not close reauthentication or hardware delivery.
No production code change, whole-suite rerun, publication or build-number change.


Reauthentication group review: upstream-derived PMK setter and cache-replacement
behavior separate PMK lifetime from established PTK/link lifetime. Local review
identified four coupled integration points: reset() loses replay/GTK history,
phase5 replacement admission requires an authorized port, old EAPOL receipts
have independent consumers, and the OS needs initial/update completion ordering.
Recorded a transition table in the EAP contract; no speculative port policy or
partial production implementation was enabled. Reference blob and limitations
saved as reference-pmk-lifecycle.json.


## 2026-10-30 — Enterprise master replacement primitive

Added replaceEAPMaster to the cryptographic supplicant: only established AKM1,
current station/BSSID, no pending pairwise exchange. It replaces PMK without
resetting established keys, replay floors, GTK history or cached responses. The
next M1 derives a candidate using the fresh nonce path. Security fixture passed
ASan/UBSan: old M1 rejected, old M3 acknowledged without reinstall, next M2
matches independent fresh derivation under replacement PMK, pending exchange
rejects replacement, cancellation preserves established key material.

This primitive is NOT called by the native callback yet. It is incomplete local
work for the larger reauthentication group, not advertised support or a deployable
candidate. Next integration must serialize EAP/firmware receipt ownership and
resolve port/restart/failure policy together. Existing native clear behavior is
unchanged; full regression waits for the completed related batch.


Replacement crypto acceptance expanded to independent Python hashlib/HMAC and
cryptography RFC3394 AP vectors (public fixture keys only). New PMK M1/M2/M3/M4
completes with PairKeys, exact expected TK/M4, rejects old M3 and damaged MIC,
and returns Reply rather than key export for duplicate new M3. ASan/UBSan
security test passed. Original Enterprise fixture regenerates byte-for-byte
unchanged after generator extension. Native orchestration remains unintegrated;
these are cryptographic results, not firmware/radio reauthentication evidence.


Replacement lifetime owner now provides explicit begin/finish transitions. Begin
requires the current consumed owner, no queued EAP, matching station/peer, valid
clock and a future deadline; it creates a new generation. Consuming replacement
PMK does not remove that deadline. Finish requires matching generation/identity,
consumed PMK and time strictly before expiry. Restart cannot extend a pending
replacement. Sanitized owner tests cover queued packets, retired generations,
wrong peer, no key, deadline equality, completion and timeout.

These APIs remain unconnected to native service pending the single orchestration
group. The caller must still drain firmware/TX ownership and supply actual key
completion evidence; finishReplacement alone cannot establish those facts.


Native EAP service now consumes a pending replacement PMK through
replaceEAPMaster only when EAP TX, reply, key export, authorization receipt,
PTK notification, pairwise candidate, serial/data/WMI TX, submitted command and
rekey owners are idle. Waiting for handoff does not return before ordinary EAP
receipt processing, avoiding a self-blocked drain. Initial admission keeps its
existing begin/bind path. Replacement remains bounded after PMK consumption.
The service fixture passed ASan/UBSan for all eleven guards, single consumption,
no full supplicant reset and timeout; combined native fixture also passed ASan/UBSan.
Callback restart admission, port policy and completion integration remain pending.


Replacement completion is now tied to accepted macOS pairwise-update publication.
Before publishing, the replacement must match station/peer/generation, have a
consumed PMK and remain before its deadline. Failure cancels and closes the port
without false success. Failed post retains the pending deadline; successful post
finishes the replacement. Actual extracted notification fixture passed ASan/UBSan
for retry, successful completion, deadline equality, no consumed PMK and changed
peer. Native callback restart admission remains unconnected, so no full
reauthentication support is claimed and no installation candidate is ready.


Idle-link reauthentication startup connected to the actual MSK callback. Stable
phase5 authorized Enterprise clear begins replacement; old outstanding owners
fail explicitly with cancellation/Busy instead of silently overwriting state.
Repeated initial empty reset does not extend the deadline. Actual combined
join/callback/new PMK/M1/M3/PairKeys/M4 receipt fixture passed ASan/UBSan; wrong
receipt ID cannot complete the replacement. An additional guard now defers queued
key-frame consumption until new PMK handoff. Affected group and native build passed for the combined source. Default gate remains off. No install or push.


Phase5 restart now tolerates outstanding prior owners. beginReplacement preserves
queued same-association EAP frames while replacing only PMK owner/deadline. Service
drains queued/in-flight EAP and existing key/notification owners before consuming
new PMK. A prior PTK notification may complete during that wait but cannot finish
the replacement; only post-handoff completion may do so. Updated five-test group
passed ASan/UBSan. Added queue→TX→receipt→PMK fixture also passed ASan/UBSan.
The first interrupted edit attempt left old test expectations; that run failed
and is not acceptance evidence. Updated tests passed after reconciliation.
Mid-install phase1–3 restart semantics remain separate from this phase5 path.
Latest source has not yet received final native rebuild/full regression.


Restart admission now includes an existing pair/group firmware rekey in phases1–4
(rekeyKind1/2), without opening its controlled port. Initial installation remains
a distinct cancel path. Service drains the existing operation and notification
before replacement PMK handoff. Callback tests cover each phase and the initial
versus rekey distinction. The combined native fixture now uses extracted actual
key-RX service to prove queued early M1 is retained until replacement PMK, then
consumed to generate new M2. All three affected fixtures passed ASan/UBSan.
Full consolidated regression and native build started for final group acceptance;
no installation, push or additional version change.


Final reauthentication batch checkpoint: all 68 tests plus runner checks passed
with explicit ASan/UBSan and assertions. Native 1.0.107 build UUID
94767F02-6D18-31C1-986F-C7CEC401A0C6 passed symbol validation; isolated strict
ad-hoc signature and exact-UUID auxiliary inclusion passed. Evidence is under
NATIVE-eap-reauth-contract-20261030. No installed image change or live Enterprise
claim. Pending post-publication release notes: bounded same-association restart,
queued-owner drain, replay-preserving PMK replacement, early key RX admission,
existing firmware rekey coordination and accepted macOS completion.
