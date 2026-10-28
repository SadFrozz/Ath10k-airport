# Native macOS integration contract

Status: active investigation, 2026-10-28. Current hardware stability is not
established. Offline checks do not establish a working network interface.

## Evidence and scope

Analyze the system modules actually loaded on this machine, rather than assume
that an older third-party adapter header describes the complete current ABI.

| Component | Matching local image UUID | Role |
| --- | --- | --- |
| XNU kernel, Sequoia 24G90 | E999BA1A-CC26-3685-A2DB-AB7085F6F12A | IOService provider inheritance and termination |
| IO80211Family | 0D5AC570-04D4-38B6-8577-9F21350CDD50 | WCL clients, commands, scans, association and messages |
| IONetworkingFamily | 5D3F11B8-802B-3860-8A36-E9334980A117 | Legacy BSD detach and ifnet ownership |
| IOSkywalkFamily | 50C44C84-1166-387F-8ECE-02E931E2405B | Interface/data-path integration |

Local images were extracted as analysis containers from BootKernelExtensions.kc.
No Apple binary or raw private stackshot is committed. The current environment
provides LLVM disassembly, not an installed C decompiler. The pseudocode below is
manually reconstructed from matching assembly and is not recovered Apple source.
The local kernel collections contain the two listed networking families; no
separate Broadcom Wi-Fi module has yet been identified in those collections.

## Reconstructed provider and termination contract

Relevant Sequoia assembly entry points:

* `IOService::getWorkLoop` at standalone `0xffffff80009ddaa0` (linked cache `0xffffff8000ac5aa0`) obtains `getProvider()`,
  then tail-calls that provider's virtual `getWorkLoop()`; null provider returns
  null. This also matches the local SDK's documented provider-chain inheritance.
* `IO80211SkywalkInterface::newUserClient` at `0xffffff80022627c6` allocates an
  IO80211APIUserClient for type zero, initializes it, and attaches/starts it with
  the Skywalk interface as provider. Unsupported client types are rejected.
* `IO80211APIUserClient::stop` at `0xffffff80022c65a6` invokes stopGated directly
  when already in the appropriate queue, otherwise synchronously routes a block
  through its WCL workloop. It does not make holding an unrelated radio gate safe.
* `IO80211Controller::getWorkLoop` at `0xffffff800222b028` dispatches through a
  separate virtual workqueue accessor. Our BSD controller override intentionally
  differs because legacy IONetworkController paths need a threaded workloop.

```text
IOService.getWorkLoop():
    provider = getProvider()
    return provider ? provider.getWorkLoop() : null

nativeWifiInterface.getWorkLoop():
    return controller.getWorkQueue()       # WCL queue

nativeBSDInterface.getWorkLoop():
    return controller.getWorkLoop()        # threaded radio/BSD queue

notificationWorker():
    try WCL gate
        try radio gate
            publish queued native events
    if contention: retry later without holding either gate
```

The 04:30:37 watchdog identifies the radio/WCL inversion through API-client
termination and an airportd request. Giving the Wi-Fi provider the WCL queue
removes the inherited radio gate from that termination route. The BSD interface
also needs an explicit override because its public provider becomes the Wi-Fi
protocol after attachment. This candidate still requires hardware validation.

## Work and validation matrix

| Priority | Path | Evidence/status | Completion condition |
| --- | --- | --- | --- |
| P0 | Registration ownership | Candidate uses the stock typed factory, a borrowed Network prefix and cleanup hooks; host ownership and parent-vtable checks pass | Hardware stop/recovery retains one owner and no stale borrower |
| P0 | Framework leaf termination | Candidate counts admitted stock power bodies, defers didTerminate/finalize, then fences WCL and finalizes BSD before inherited completion; PCI-controller power path still needs its own audit | No PMstop/WCL/radio cycle during controller/interface termination and recovery |
| P0 | Event delivery errors | Candidate checks enqueue returns, keeps phase/cursors and retries with 10 ms backoff; host injection covers every stage | Verify system behavior during scan, rekey and failures on hardware |
| P0 | Provider queues and API client close | New provider overrides; existing nonblocking event bridge | No cyclic waits during repeated query/close/scan; useful traffic continues |
| P0 | Current BSS reply | Fixed scratch lifetime after WCL's confirmed Update Bss fail | Repeated background scans retain correct AP reply and connection |
| P0 | Data path after authorization | Last boot had authorized port but no DHCP and stalled worker | DHCP, ARP, IPv4, IPv6 and bound HTTPS pass while worker advances |
| P1 | Scan request semantics | Candidate passes requested physical channel subset to firmware; rejects empty regulatory intersection; pre-submit cancellation completes locally | Hardware confirms subset timing, SSID matching, cancel and completion ordering |
| P1 | Autojoin | About 32 seconds after login on previous boot | Trace and reduce avoidable retries without router changes |
| P1 | Visibility | Beacon metadata adjusted; saved profile still has Hidden=true | Compare fresh beacon, WCL current BSS and saved profile/UI independently |
| P1 | Join and keys | PSK/SHA256 fixtures and first traffic previously passed | Initial/rekey/abort/failure paths retain ordering and replay protections |
| P1 | Power and lifecycle | Early PM/first-producer admission, native/controller stop fences and security cleanup are candidates; automatic wake recovery missing | Off/on, sleep/wake and teardown have finite completion and safe DMA ownership |
| P2 | Queries and capabilities | 190 inline callbacks: 29 forward, 161 reject | Classify every rejection by actual system caller; implement mandatory contracts |
| P2 | IPv6/multicast and statistics | Partial implementation | Multicast filter and counters reflect delivered traffic; no fabricated metrics |
| P2 | WPA3/PMF | SAE and mandatory PMF/BIP not implemented | Implement and test complete authentication/protection, not an AKM label change |
| P3 | macOS 11–26 | Current adapter is Darwin 24 only | Versioned adapters with per-version ABI and hardware validation |
| P3 | AWDL/AirDrop | Planned only | AWDL interface/scheduling/IPv6 and Bluetooth integration validated |

For each required callback, record input layout and bounds, caller queue,
permitted state, action ownership, result/error semantics, event ordering,
timeout/cancellation, teardown dependencies, and independent test evidence.
An Unsupported response is not automatically a bug; a Success response without
the promised operation is not an acceptable replacement.

## Offline validation correction (2026-10-28)

Several prior `kmutil create -n boot ... -p candidate` runs returned success
but generated a collection containing only `com.apple.kernel`. Their metadata
`offline_kernel_link=true` does **not** prove candidate inclusion or successful
symbol binding. Preserve the historical packages and attach a correction;
do not silently replace their verified manifests. An older local
`native-validation.kc` does include Ath10k, but that alone does not identify it
as the current candidate.

Every future link check must additionally run
`scripts/verify-kernel-collection.py COLLECTION KEXT_EXECUTABLE` and match both
bundle identifier and executable UUID. This is necessary, not sufficient, for
hardware correctness. The verifier rejects missing/duplicate entries, stale
UUIDs and malformed command bounds.

A separate explicit auxiliary-collection experiment reached actual symbol
binding and rejected `_thread_call_cancel_wait` as an unavailable kext export.
That experiment used a separate validation copy with `OSBundleRequired` removed;
it does not prove the original OpenCore-injected bundle cannot boot and is not
proof that this import caused the hardware hang. Replace this private API with
public cancellation plus independently tracked queued/running callback lifetime.
The unchanged candidate auxiliary control run was rejected before linking
("No binaries or codeless kexts were provided"); it is not a passing control.
No OS collection, EFI driver or active network was changed by these checks.

## Public thread-call drain candidate

The event bridge now owns a short bookkeeping lock and separate queued/running
flags. Scheduling and delayed retries publish queued ownership before entering
the kernel. Callback entry transfers it to running ownership; callback exit
publishes completion, wakes drainers and never dereferences the controller again.
Controller stop closes admission, calls public `thread_call_cancel` and sleeps
outside WCL/radio while either flag remains set. A false cancel cannot erase an
already dispatched callback's queued ownership. Repeated stop preserves the lock
until final cleanup; allocation failures also take the same partial cleanup path.
`THREAD_CALL_OPTIONS_ONCE` prevents overlapping invocations. The SDK explicitly
allows freeing a thread call from its own callback, so kernel return bookkeeping
after the last driver access does not require the private wait export.

Production-method host tests cover cancellation before dispatch, dispatch before
callback entry, an executing callback, gate contention, allocation retry and
repeated stop. Native build and an explicit auxiliary link now pass; the linked
entry's UUID matches `CFD4467C-3B91-3855-92DD-C60872675CB2`. This experiment used
a separate copy with `OSBundleRequired` removed only for auxiliary inclusion;
the actual executable was unchanged. It validates binary binding against this
local kernel, not the original bundle's OpenCore load or hardware stability.

The outside-gate termination notifier remains preparatory work: `PMstop` returning
does not prove all stock power callbacks exited. **Not ready for installation.**
A completion/lifetime guard and BSD binding cleanup are still required. The
matching Skywalk base prepare method stores the ifnet pointer and calls
`ifnet_set_mtu`, not `ifnet_reference`; finalize clears that pointer. Our BSD
detach currently lacks a paired finalize call. Retaining the native interface
alone therefore does not establish safety of a deferred power callback after BSD
detach. Resolve ownership and queue ordering before deferring inherited stop.

## Borrowed BSD resource lifetime candidate

Matching IONetworkingFamily detach (`0xffffff8002631eae`) halts output, calls
`ifnet_detach` and waits for detach completion; it does not call the native
Skywalk finalize method. Its free (`0xffffff800262f074`, call at
`0xffffff800262f14d`) releases the ifnet through `ifnet_release`. Skywalk base
prepare stores the pointer without a direct reference acquisition. The native
finalize slot `0x858` resolves to `IO80211SkywalkInterface::disable`, which forwards
to `IOSkywalkNetworkInterface::disable`; the latter can set running state and
report link status. Finalize therefore must not be treated as a harmless pointer
clear or added under an unverified gate order.

The native interface now takes its own public `ifnet_reference` before invoking
stock prepare, retains it even on preparation failure (the parent may already
have stored it), and releases it only after inherited native free returns. A
null interface, failed reference acquisition or duplicate binding is rejected
without pretending preparation succeeded. Host tests execute these production
methods with legacy BSD release occurring first, then verify parent free still
sees a live resource and the final reference is released exactly once afterward.
This prevents reclamation of the borrowed ifnet storage; it does not preserve
attachment, make arbitrary operations on a detached interface valid, synchronize
power callbacks, or finish the pending finalize/PM ordering repair.

## BSD callback context lifetime candidate

Matching `IONetworkInterface::if_detach` (`0xffffff800262f540`) obtains its owner
through `ifnet_softc`, retains it for that callback, updates detach state and
releases it. `if_input_ctl` (`0xffffff8002631a0e`) also calls `ifnet_softc` then
loads the owner's controller and expansion state. Retaining ifnet storage alone
does not independently retain that object for later native access.

Native prepare now verifies the supplied ifnet is the controller's actual legacy
interface, retains that BSD object before acquiring the ifnet reference, and
balances the object retain on failed reference acquisition. Both references
survive inherited prepare failure and are released after native parent free,
with ifnet first and its callback owner last. The owner still has its own ifnet
reference until its final free. Production-method tests drop the framework's BSD
object ownership first, verify both the resource and softc context remain live,
then check complete balanced cleanup, including failed reference acquisition and
foreign/missing owner rejection. This adds no new native self-reference; the
controller release path still drops its BSD and native ownership in that order.

This retains allocated context; it does not preserve network attachment or
permit callbacks to use controller state already retired by stop. In particular,
retaining a controller object for deferred native stop would not prevent its
normal stop from removing gates and WMI resources. Actual PM callback completion
must coordinate that resource teardown too; a deferred native stop alone is
insufficient. Current candidate remains **not ready for installation**.

## Delivery gates

Run relevant production-method/packet tests, sanitizers, native build/import and
signature checks, then offline kernel linking. Preserve the candidate, source
revision and previous installed version with verified SD copies. Keep development
on `native-sequoia-development`. Do not modify the OS/root volume or manually
load the experimental kext. Reboots require explicit user authorization.


## Confirmed message-buffer ownership

`IO80211PostOffice::sendMail` at `0xffffff80022b261e` allocates `length+0x38`,
copies the caller payload into that allocation, then appends it to an intrusive
queue without acquiring a workloop gate itself. Thus stack payloads are copied
before return, but the caller must serialize PostOffice access. The boolean
argument is stored with the message; it is not a choice to borrow the payload.
Allocation failure returns `0xe00002bd` (NoMemory). The event-delivery candidate
checks this return and commits only the accepted phase. This proves enqueue
acceptance, not that WCL has already processed the asynchronous notification.
Hardware verification remains required.

The last pre-hang WCL log also records rejected FW_HOT_CHANNELS (424),
SET_ROAM_LOCK (428) and QOS_PARAMS (443). The join proceeded past these responses,
so this log alone does not make them the cause of the recorded lock inversion.
Their actual semantics/callers must be reviewed before adding success responses.

## Scan subset candidate

A native channel bitmap now becomes a mask over the physical plan, then
intersects the regulatory scan policy before START_SCAN is serialized. Duplicate
channels collapse; unrecognized/6 GHz channels cannot alias supported 2.4 GHz
channels. Empty intersections return Unsupported before starting firmware work.
Legacy/unrestricted scans keep the full regulatory plan. Requested SSID/BSSID
matching still filters delivered results; this change does not add active probes
or claim full hidden-network discovery.

The host suite covers native decode through firmware TLVs (literal 2437/5260 MHz
expectations, lengths, DFS passive policy, US channel-13 rejection and connected
home-rest timing), exact-capacity guards, and extracted production getters for
both provider workloops. The mocked radio suite exercises the real scan method's
pre-submit cancellation without DMA, START_SCAN or firmware credits, plus existing
STARTED/COMPLETED/STOP and stale-generation failure cases. Hardware timing and
stability on this candidate remain unverified.


## Notification acceptance, failure and ordering candidate

Security processing runs before the notification emitter. An allocation error
therefore cannot skip supplicant processing merely because an earlier event was
not accepted. The emitter stops attempting later messages in that pass after
any failed enqueue; the existing coalesced worker retries after 10 ms. It does
not enter a tight retry loop or add an unbounded private message queue. Stopping
cancels and waits for the same ONCE thread call, including delayed retries.

Separate phase markers track ResetInterface/DriverAvailable, scan-result cursor
and count, association, current-BSS scan result, link-up and first beacon,
ConnectComplete, abort completion, and Deauth/link-down. An accepted prefix is
not repeated after a later allocation failure. The old BSSID survives radio
state cleanup until both disconnect notifications have been accepted. New
MAC/scan/join transactions wait for pending abort/link-down events. Current BSS
availability follows real associated beacon data, not whether FirstBeacon has
already been enqueued successfully.

A hard join deadline takes precedence over success. Its cleanup closes the data
port and cancels the attempt once, even if the failure notification cannot yet
be allocated. Connection-event metadata remains available for the retry. A
healthy group/pair key replacement temporarily closes the controlled port; the
emitter preserves the existing link while associated and in a known rekey, and
still tears down on a real cancel/disconnect. These were source-level defects;
no claim is made that every previous hardware disconnect had either cause.

Host regressions execute the exact production emitter with a failing PostOffice
seam: repeated failure at each of 11 ordered boot/scan/join/RSSI messages,
byte-for-byte accepted payload comparison, scan cancellation during retry,
inactive-radio abort retry, failure at either disconnect message after radio
state reset, partial-link failed join, persistent allocation pressure, and hard
deadline cleanup. Bridge tests check retry coalescing and stop cancellation.
Full controller teardown and automatic wake/restart remain separate audit work;
this acceptance test does not prove the absence of all kernel lock cycles.


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

The local macOS15 Network RegistrationInfo declaration is corrected to 0x108, the Ethernet factory signature is added as IOReturn, and these deviations from the pinned vendor snapshot are recorded in vendor/itlwm/SOURCE.json. Static assertions retain the existing class layouts and verify both registration sizes. The stock addresses are Network registration ffffff8002980ebc, Ethernet factory ffffff8002986fec, Network deregistration ffffff8002980b64, Ethernet free ffffff8002986e5a, and virtual deregisterLogicalLink ffffff800298115e. Direct deregistration references identified in the analyzed families belong to base stop/free, virtual deregisterLogicalLink and full Ethernet registration failure cleanup. The latter registration entry is not called by this bridge.

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

## Native PM completion and framework deferral candidate (current)

This supersedes the preparatory outside-gate PMstop notifier described above.
The native interface now counts entry/exit around the unmodified inherited
setPowerState body. Closing admission rejects new bodies with Aborted; the short
bookkeeping mutex is never held while calling a parent method or workloop gate.
The notifier closes admission and retires radio but performs no PMstop wait on
the global termination worker.

The matching SDK documents didTerminate deferral for pending I/O. Matching XNU
IOService::didTerminate schedules stop only when inherited completion is invoked;
terminationWorker leaves a parent unfinalized while its child remains attached.
The candidate defers inherited completion and retains the interface/provider
while a preallocated ONCE thread call runs PMstop outside WCL/radio. If PMstop
returns with an admitted body still running, that job parks with its references
and attachment intact. The last real body exit queues it again. Thus controller
gates/WMI resources and native managers remain available together, instead of
merely keeping their enclosing allocations alive after an early controller stop.

IOService::finalize has a second scheduling path when only this interface is
terminated and its provider remains active; finalize is also deferred. Once
admitted bodies have exited, the worker enters WCL, finalizes the matching BSD
binding and only then marks completion and resumes inherited finalize/didTerminate.
The WCL fence also drains earlier callers which might have passed native request
admission before radio retirement. Completion cannot become visible while this
worker is still waiting for WCL. A mismatched borrowed BSD binding parks without
parent cleanup and reports a diagnostic instead of touching an unknown owner.

Direct controller cleanup after partial startup closes native PM admission,
retires radio, invokes PMstop and waits for the actual native body count outside
WCL/radio, then finalizes BSD under WCL before draining the event bridge. Native
parent-start ownership is tracked separately from radio readiness: early radio
retirement must not suppress a still-required parent stop. Framework stop clears
that ownership, preventing a second manual parent stop.

Tests execute the production methods with a real blocked host power body,
timeout-returning PMstop, a worker waiting for WCL, finalize arriving during
that wait, repeated completion, direct cleanup, allocation failures and final
self-release/free of the running call. References and parent return values are
checked. Full host tests, ASan/UBSan, native build and exact-UUID auxiliary binary
linking pass (8D6BC124-79CA-3194-A116-50482BEA2D39). Auxiliary input selection
uses an isolated OSBundleRequired-removed copy; original OpenCore loading and
actual kernel termination delivery remain untested.

Still not ready for installation: the separate PCI-controller setPowerState and
root power notification path needs terminal admission/barrier verification before
its own PMstop/resource release. Automatic wake recovery also remains missing.
No hardware stability or full-stack completion is established by these host tests.

## PCI-controller power admission/resource fence candidate (current)

The stop/free path now raises the permanent I/O block before draining firmware
creation. That block does not by itself reject root sleep notifications: a sleep
acknowledgement must still follow hardware quiescence. A separate atomic
controller-power admission flag closes only after the existing DeviceOff action
has run under the initialization barrier and radio gate. The action stops WMI
and checks partial-bootstrap DMA ownership; an already-suspended device avoids
a second powered-off PCI access. With the producer drained and I/O permanently
blocked, no new firmware/runtime work can rearm the device in this handoff.

After quiescence and closure, root notifier removal synchronizes outstanding
handlers, controller PMstop inhibits further platform callbacks, and a final
initialization-barrier rendezvous precedes WMI/resource release. requestPowerEvent
checks the separate closure flag both before and after acquiring that barrier.
An already-dispatched callback which passed its first check therefore cannot
access a retired workloop, PCI pointer, runtime state or property publisher after
resources are released. A callback entering later returns at its first check.
Late root sleep notifications can acknowledge immediately because closure is
published only after quiescence. Repeated stop/free and early partial setup
share this sequence.

Threaded production-method tests pause a callback between its first check and
barrier acquisition, close/quiesce the controller, mark resources unavailable
and then resume it. They also hold an executing callback inside the barrier to
prove cleanup cannot overtake it, verify root sleep still quiesces with the
permanent I/O block, exercise late root acknowledgement, already-powered-off PCI
and repeated cleanup. Native/partial producer tests remain enabled.

This closes the specific controller power-admission/resource race found in this
audit. It is not kernel/hardware proof. Automatic wake/rematch recovery remains
unimplemented, and the broader native callback/traffic audit remains incomplete.
A boot/connection stability test of the accumulated fixes is the next hardware
gate; it requires a fresh explicit reboot authorization.

Current controller-power candidate executable UUID: `8C9FAF40-3A5D-36D8-8D82-F685EDF20FBB`; full portable and ASan/UBSan suites, native build/import check and exact-UUID auxiliary binding passed. Original OpenCore boot and actual hardware termination remain unverified.

## Cached matching and initial PM evidence

`probe` now uses retained cached PCI identity properties, with strict length/type/
range checking, and does not issue PCI configuration reads. Powered startup still
revalidates the actual native hardware profile before bus mastering/BAR access.
The current machine's cached ID encodings were verified read-only. Production
matching tests use a PCI mock without hardware APIs. INITIAL-POWER-CONTRACT.md
records the matching XNU initial-callback conditions and the remaining early-PM/
producer-tail integration. Automatic wake recovery remains incomplete; this
matching change alone does not make a rematch while powered off safe end to end.
The e105f82 candidate awaiting explicit boot authorization is unchanged.

## Early PM and first powered producer (current)

Superseding the late-registration gap above: controller PM is now registered
before direct configuration/MMIO/firmware work. Start initializes unknown/off
permission and allocates all probe scheduling state before joining the parent.
Only an admitted On can queue the initial producer; real identity, PCI command
ownership, bus-master enable and BAR mapping occur behind its power/barrier check.
The initial-device-state skip flag is absent and failed allocation/registration/
power request has no unguarded synchronous probe fallback.

Before the first hardware attempt, initial Off/root sleep does not create stale
firmware state requiring rematch. Root/device readiness can clear only exact
phase 1, not another callback's queued suspend or permanent termination. Once
started is latched, the previous restart requirement remains unchanged. An On
arriving between aborted producer exit and completion publication is preserved
by ONCE rescheduling in the tail. Cancellation retains its scheduler lock until
final free, after power closure, and restores PCI commands only when owned.

Production-method host tests cover entry/configuration traps, queue/tail/cancel
races and initial power actions. INITIAL-POWER-CONTRACT.md records the source
evidence and implementation. Automatic native recovery after an initialized
sleep remains unimplemented; kernel delivery and physical startup remain untested.
The separate e105f82 candidate awaiting install/reboot authorization is unchanged.

Initial-power candidate validation: full portable and ASan/UBSan suites, native and non-native builds/import checks, plus exact-UUID native auxiliary binding passed (`9C3C9AAF-8F26-3259-B2D7-534CE243EC40`). Kernel initial callback delivery, traffic and sleep/wake recovery are not established by these checks.
