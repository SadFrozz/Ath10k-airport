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
| P0 | Framework leaf termination | Candidate counts admitted stock power bodies, defers didTerminate/finalize, then fences WCL and finalizes BSD before inherited completion; controller power closure/quiescence barrier and internal wake worker are candidates | No PMstop/WCL/radio cycle during controller/interface termination and recovery |
| P0 | Event delivery errors | Candidate checks enqueue returns, keeps phase/cursors and retries with 10 ms backoff; host injection covers every stage | Verify system behavior during scan, rekey and failures on hardware |
| P0 | Provider queues and API client close | New provider overrides; existing nonblocking event bridge | No cyclic waits during repeated query/close/scan; useful traffic continues |
| P0 | Current BSS reply | Fixed scratch lifetime after WCL's confirmed Update Bss fail | Repeated background scans retain correct AP reply and connection |
| P0 | Association lifetime in queries/link acknowledgements | Candidate shares association admission across AP queries, notifications and WCL up; host state table executes query/link methods | Hardware rejects stale up/BSS while rekey preserves association |
| P0 | Data path after authorization | 5a5d69c: native WPA2/DHCP and en1-bound IPv4/IPv6 HTTPS passed; sustained traffic remains under observation | DHCP, ARP, IPv4, IPv6 and bound HTTPS pass while worker advances |
| P1 | Scan request semantics | Candidate passes requested physical channel subset to firmware; rejects empty regulatory intersection; pre-submit cancellation completes locally | Hardware confirms subset timing, SSID matching, cancel and completion ordering |
| P1 | Autojoin | 5a5d69c: user reports first networks in a few seconds; autojoin after manual power toggle passed; cold-login timing still needs separate measurement | Trace and reduce avoidable retries without router changes |
| P1 | Visibility | Beacon metadata adjusted; latest airportd autojoin lists zero hidden SSIDs; fresh profile/UI consistency still needs explicit verification | Compare fresh beacon, WCL current BSS and saved profile/UI independently |
| P1 | Join and keys | PSK/SHA256 fixtures and first traffic previously passed | Initial/rekey/abort/failure paths retain ordering and replay protections |
| P1 | Power and lifecycle | Early PM/first-producer admission, native/controller stop fences, security cleanup and guarded automatic wake rematch are candidates | Off/on, sleep/wake and teardown have finite completion and safe DMA ownership |
| P2 | Queries and capabilities | 190 inline callbacks: 32 forward, 158 reject; source-checked inventory in NATIVE-CALLBACK-MATRIX.json | Classify every rejection by actual system caller; implement mandatory contracts |
| P2 | IPv6/multicast and statistics | Partial implementation | Multicast filter and counters reflect delivered traffic; no fabricated metrics |
| P1 | WPA3/PMF | Opt-in image 9A07D3C3 auto-associated with AKM8/required PMF on 24G90 and passed en1-bound ICMP/HTTPS; protected management counters initially zero | Validate protected unicast/group management, replay, firmware PN, rekey, reconnect and sleep/wake on hardware |
| P1 | WPA3 policy notification | Local candidate uses stock event76/40-byte successful exchange format; seven affected sanitizer tests and 72 actual userland parser/decoder cases pass; enqueue retries and connection binding implemented | Verify real kernel delivery and saved-profile persistence with an authenticated AP policy update; broader bitmap octets remain unmapped |
| P1 | Protected management hardware exchange | Explicit NATIVE_PMF_PROBE mode reuses the production SA Query/CCMP/replay path; five affected sanitizer tests and readiness/one-shot checks pass | On an approved hardware boot observe submitted protected TX, authenticated matching response and successful SA Query; then cover group BIP and rekey/sleep PN behavior separately |
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

NATIVE-CALLBACK-MATRIX.json now inventories all 190 inline protocol overrides:
31 forward and 159 return Unsupported. scripts/audit-native-callbacks.py
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

WPA3-CONTRACT.md records the matching stock validation/copy addresses and all
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
earlier kernel-only search. SAE-CRYPTO-BACKEND.md records image UUIDs, twelve
strong imports, exact auxiliary probe inclusion and a missing-export negative
control. The isolated make target is built in CI, never loads and does not alter
the normal Wi-Fi binary. Manual import/validation disassembly identifies heap
workspace allocation, reinforcing outside-gate crypto-worker requirements.
This establishes symbol availability for this image, not callable context ABI,
P-256 correctness, actual SAE/PMF or macOS 11–26 support. Those original goal
requirements remain incomplete. No Apple binary/header/assembly is redistributed.


## Runtime link-loss incident and PS wake/drain fix (2026-10-28)

The live 0.0.98 / UUID 808674DF-53D8-3742-A2ED-689680AAC259 driver stopped with
ConnectionError=data-tx-completion-timeout. The saved registry shows 64 pending
payloads, 424355 CE observations versus 424291 HTT completions, one watchdog
failure, applied station PS, no explicit TX-pause mask, no active scan and no
recorded AP deauth/disassoc. Runtime and controlled port were stopped; en1 was
inactive. macOS's 20:31 diagnostic capture records WCL deauth handling. Local
registry, kernel/airport logs and the pre-fix regression are saved separately;
no credentials or packet payloads are included in this public contract.

This establishes a retained full queue and a host watchdog stop, not the physical
reason firmware stopped completing payloads. A source regression independently
reproduced a real cycle: PS disable waited for dataPending to reach zero, although
firmware-retained data could require that PS disable to complete. Its unchanged
public-API assertion failed before the fix and passes after it.

The fix permits a wake-only PS-disable transaction on CE3 while CE4 payloads remain
owned. It sends PS disable followed by the existing ECHO/credit barrier, skipping
power/timing writes until their ordinary data drain is possible. A lower/forbidden
power limit is not bypassed by this exception. Source payload IDs, DMA buffers
and completion ownership are unchanged; only actual HTT plus CE completion can
release them.

For a full queue with no progress while station PS is applied, the driver requests
this bounded wake after one second without progress. It does not trigger for one
old retained frame or an explicit firmware/scan pause. The original five-second
full-queue/CE timeout and pause/teardown deadlines remain unchanged. If firmware
still never completes, normal failure/reset safety still applies. After the queue
drains, PS is held off for one second before the user's requested idle PS can
resume; power saving is not globally disabled. Persistent registry watchdog
reason/slot/ID/age and wake-request counters make the next incident diagnosable
even when IOLog is absent from the unified log store.

Tests drive the real radio-command/credit/ECHO path while all 64 payloads remain
owned, then deliver their real HTT completions and check queue release, the idle
hold and PS re-entry. They also preserve the original timeout on failed recovery
and verify pause/resume and safe DMA ownership. The new test build is 0.0.99,
with matching kmod/bundle versions and the existing compatible-version floor.
This fix has software-model evidence; installation/boot and physical stability
validation must be recorded separately. It does not revive the already stopped
0.0.98 runtime or implement complete automatic firmware restart after every fault.

RSNXE query/setter contract audit (2026-10-29, Sequoia only):
- Exact stock AppleBCMWLANCoreMac UUID
  4C3822FC-8902-3AF6-A791-DD4A8D9E9C66 implements getRSN_XE at
  0xffffff80015f462e and setRSN_XE at 0xffffff8001610d64. Both use
  a 16-bit length at offset 4 and element bytes at offset 6. Getter capacity
  is 257 bytes; setter rejects lengths above 257. Zero-length setter clears
  the outgoing cache. Stock feature gates may reject both operations.
- These access JoinAdapter's outgoing association RSNXE cache (length offset
  0x68, bytes 0x70), distinct from its firmware-associated cache at 0x171.
  Returning the AP beacon RSNXE would implement a different contract.
- Both current native callbacks still explicitly reject. Their stock producer
  addresses and semantics are recorded in NATIVE-CALLBACK-MATRIX.json, separate
  from consumer evidence. Caller ordering, next-join binding, mid-association
  update rules and cancellation lifetime need reconstruction before a setter
  can safely affect the real association. A byte cache with no effect on the
  transmitted element must not report successful configuration. This audit
  adds evidence without claiming the callbacks are optional or implemented.

Read-only RSNXE callback candidate (2026-10-29):
- getRSN_XE now enters the existing WCL-to-radio gated dispatcher. The exact
  stock request wrapper at 0xffffff80022137d6 requires 264 bytes for operation
  457; the typed wrapper at 0xffffff80021faca3 invokes protocol slot 0x1068.
  That corroborates the independently recovered length/data offsets.
- The candidate exports the production association/M2 encoder's own station
  RSNXE: H2E is f4 01 20, while legacy SAE and PSK-SHA256 have no station
  extension. It never returns the AP's different advertised capabilities.
  The output record is initialized completely, including unused bytes.
- A prepared pending association or live association is required. Stop, power
  block, cancellation, teardown, unbound/reset supplicant and retired joins
  return not-ready without writing output. Port closure during rekey preserves
  the associated profile. No crypto, wait, I/O or allocation is added.
- Four affected ASAN/UBSAN regressions pass (native_rsnxe_query,
  native_pmf_receive, native_key_stage, native_sae_radio); the final expanded
  query regression also covers PSK-SHA256 and an absent security owner.
  The regenerated callback inventory is 190 total, 32 forwarded, 158 rejected.
- setRSN_XE remains unsupported until its association-binding and update
  semantics can be honored. The read-only candidate is not installed; the
  hardware-confirmed A3E38378 build remains loaded. Earlier audit wording
  describing both callbacks as rejected refers to the initial checkpoint.

PMF receive/key-update ordering checkpoint (2026-10-29):
The retained BIP worker and native dispatch path now have explicit tests for
same-key retransmission, independent slot rotation, same-slot replacement and
cancellation while crypto is executing. The old epoch cannot commit into a new
slot or disconnect after replacement. Native staging and final dispatch also
pass with a mocked firmware key-completion barrier. These passing host checks
reduce the remaining matrix to actual AP-driven group BIP and rekey behavior;
they do not close hardware, long-duration or sleep/wake requirements. See
WPA3-CONTRACT.md for the exact evidence boundary. Production code is unchanged
from the pending D1E2649F package during this follow-up.

PCIe idle admission versus native management work (2026-10-29):
- A production runtime-power regression reproduces SOC/PCIe target idle sleep
  at the 60 ms threshold while pmfTXPending is already set and station PS is
  still applied. WCL/native work can set that reservation between radio ticks.
  The old permitted predicate omitted the flag. The pre-fix test fails at its
  explicit awake assertion; no hardware hang is inferred from that host failure.
- Idle admission now also requires no pending PMF TX, no pending spectrum
  response and no spectrum frame in flight. These reservations use the existing
  radio wake/drain/retirement paths. Removing a reservation permits ordinary
  target idle again; system suspend retains its independent quiescence path.
- Three regression cases individually exercise these reservations and idle
  resumption. Eight affected ASAN/UBSAN tests pass: runtime_power,
  station_maintenance, wake_recovery, native_termination,
  native_security_lifecycle, power, native_bridge and native_rsnxe_query.
  The RSNXE test extraction is separated from key hooks so broader security
  lifecycle mocks do not acquire an unrelated query implementation.
- Live A3E38378 has zero PCIe wake failures, zero TX watchdogs and the same one
  initial association rejection at observation. Its system sleep/wake counts
  are both zero: PCIe runtime idle is not a tested laptop suspend/resume cycle.
  The installed source does not contain this new idle predicate yet.

Full candidate regression and IPv6 checkpoint (2026-10-29):
- All 59 selected C++ tests pass in the complete development runner with
  assertions enabled and ASAN/UBSAN, together with its Python/source/config
  prerequisites. This includes the expanded in-flight BIP rotation checks,
  isolated RSNXE query, native request/lifecycle/termination/recovery tests and
  the new three PCIe idle-reservation cases. This is host validation, not a
  full completion claim for the hardware/ABI matrix.
- Native candidate 785EFF7A-E357-337E-9F90-A343A3168FD0 passes build, strict
  signature/import checks and exact-UUID inclusion in a work-local auxiliary
  collection. It combines the read-only RSNXE reply and PCIe idle admission
  correction. The one-shot startup PMF diagnostic is disabled. It is not yet
  installed. The current A3E38378 EFI driver/configuration has a new
  byte-verified SD rollback. No system collection is modified.
- On the still-loaded A3E38378 SAE connection, en1 has IPv6 addresses and a
  default route scoped to en1. An explicitly en1-bound IPv6 HTTPS request
  returns HTTP 200, 577 bytes and TLS verification result 0. Five IPv6 ICMP
  requests sent through en1 to its scoped default router all receive replies.
  Only redacted address-count/route summaries are retained. The DNS resolver
  is not separately interface-bound by this HTTPS check.
- IPv6 observations extend the existing IPv4/SAE data-path checkpoint; they
  do not certify all DHCPv6, multicast, roaming, PMF group rekey or sleep/wake
  behavior. AWDL/AirDrop and other macOS versions remain separate open stages.

User-observed normal reboot recovery (2026-10-29):
The user reports that normal reboot now completes without holding the power
button and manually powering the laptop back on. The user identifies the
penultimate build as the apparent turning point; the exact first-fixing image
is not established. Treat this as a positive hardware checkpoint and retain
normal reboot without forced power intervention as an explicit regression
gate. It does not by itself certify repeated shutdowns or sleep/wake, and
causality must not be assigned to one queue/worker change without stronger
evidence. The report was received while candidate 785EFF7A was loaded.

Normal-mode candidate hardware checkpoint (2026-10-29):
Boot B629655E-4CCD-4811-844E-CF2BFD504AB9 loaded UUID
785EFF7A-E357-337E-9F90-A343A3168FD0 through OpenCore. macOS selected SAE/AKM8,
the controlled port is authorized, and startup diagnostic query properties
are absent. Both IPv4 and IPv6 HTTPS transfers explicitly bound to en1
complete with exit 0, HTTP 200 and successful TLS verification. All twenty
en1-bound ICMP requests receive replies over 60.38 seconds; all thirteen
samples remain connected-sae/authorized, with no new disconnect or TX watchdog.
The one initial association-rejected event remains unexplained; the live
status code was overwritten by successful association. The current kernel
message ring no longer contains the early rejection. Do not assign its cause
without a retained failure-status observation. No new protected-management
round trip was requested in normal mode. The earlier A3E38378 protected-query
proof remains a separate checkpoint. Actual sleep/wake is still untested.

Association identifier and retained rejection diagnostics (local source
follow-up after 785EFF7A, 2026-10-29):
- The parser masked AID with 0x3fff and could reject a valid lower-eleven-bit
  identifier when reserved bits 11..13 were set. Linux v6.12 mac80211
  ieee80211_rx_mgmt_assoc_resp uses 0x7ff and cites IEEE 802.11-2016 9.4.1.8
  (all five high bits reserved). The candidate now uses 0x07ff and retains
  the existing nonzero/maximum-2007 checks.
  Reference: https://github.com/torvalds/linux/blob/v6.12/net/mac80211/mlme.c
- The independent field regression fails before the fix and passes afterward
  across all 32 high-bit combinations. Invalid low-bit values remain rejected.
- Association rejection count, last received status and raw AID now survive
  reset and a later successful join in existing ConnectionDiagnostics. The
  registry publishes the raw and masked identifier separately. Status zero
  with an invalid AID is distinguishable from an AP-denied status. Foreign
  transmitter input cannot replace this diagnostic. No identity or key is
  exported. The read-only collector whitelists these numeric fields.
- Four affected ASAN/UBSAN tests pass: connection, security_disconnect,
  native_join and native_sae_radio. This is a source-only follow-up, not a new
  installed kext or a repeat of the prior 59-test release checkpoint.
- The current boot's initial rejection cannot be attributed to this AID bug: its
  status/raw AID were not retained. Upstream also handles temporary status 30
  plus an association-comeback Timeout Interval IE; that retry/timer contract
  is still a separate open implementation item. The loaded 785EFF7A driver
  is unchanged. No reboot, commit or push accompanies this checkpoint.

Association comeback request handling (local source follow-up, 2026-10-29):
- A status-30 association response with one valid Timeout Interval IE (56,
  length 5, type 3) now requests a timed retry. All IE lengths are validated
  before accepting the interval. Missing, wrong-type, malformed or duplicate
  timeout elements retain explicit rejection. Constants and upstream behavior
  are checked against Linux v6.12 ieee80211.h and mac80211/mlme.c.
  https://github.com/torvalds/linux/blob/v6.12/net/mac80211/mlme.c
  https://github.com/torvalds/linux/blob/v6.12/include/linux/ieee80211.h
- The radio service converts TU to milliseconds with a ceiling, waits without
  sending early, drains existing packet ownership and resubmits association
  within the same selected security profile. No open-auth/SAE restart, peer
  recreation, authorized port or success notification occurs during the wait.
- Native waits are bound to the original _nativeJoinDeadline. They can exceed
  the ordinary five-second response timer while remaining within the actual
  OS request lifetime. Non-native control uses a fixed thirty-second fallback
  from association-stage entry. The original three-transmission limit remains.
  A duplicate cannot renew either wait or request deadline. Clock reversal,
  exhausted attempts or an interval exceeding the remaining request fail
  explicitly. Caller cancellation/teardown removes the pending wait.
- A fully accepted association response becomes immutable during firmware
  completion; a delayed temporary failure cannot overwrite its AID/profile.
  Durable comeback count and last TU complement retained rejection status/AID.
- Four affected ASAN/UBSAN tests pass: connection, security_disconnect,
  native_join, native_sae_radio. Expanded tests cover zero/one TU rounding,
  malformed/duplicate IEs, cancellation, owned-packet drain, large values,
  overflow/clock reversal, fixed native deadline and a >10-second wait through
  the real radio service. The SAE fixture preserves its verified session,
  PMF owner/generation and exact association RSNE/PMKID through the retry.
- The complete development suite is running after these source changes; its
  result is not yet claimed. No new kext has been built/installed. Current
  hardware 785EFF7A remains unchanged. The initial real rejection is still
  unattributed until its actual retained status is observed on a future boot.

Association-comeback build checkpoint (2026-10-29):
All 59 C++ tests in the complete development runner pass with assertions and
ASAN/UBSAN, together with Python/source/config prerequisites. The normal-mode
native image UUID 0E9AA8BE-EF2E-393A-A9DA-58AEA243E6E5 builds and passes strict
signature/import checks plus exact-UUID inclusion in a work-local auxiliary
collection. It includes the AID mask correction, durable rejection/comeback
metadata and request-deadline-bound association retry. Startup PMF probing is
disabled. Current hardware remains on 785EFF7A; this new image has not booted.
A fresh current EFI driver/configuration copy is byte-verified on SD.

A separate read-only direct BSD socket ioctl probe (operation 457, modern SDK
request size) returns EOPNOTSUPP with the sentinel output unmodified. This is
not proof that getRSN_XE was reached or failed. Correct native userland transport
and actual callback-read coverage remain open; no fabricated success or BSD
forwarding change is introduced on the strength of this probe.

Association-comeback hardware checkpoint (2026-10-29, supersedes unbooted status above):
The approved installation booted UUID 0E9AA8BE-EF2E-393A-A9DA-58AEA243E6E5
in a new boot session C58D33F8-487B-41F8-B09D-786D9F103B12. The native
SAE connection is authorized. Durable fields retain one actual AP temporary
association refusal (status 30), raw AID 49157 / masked AID 5, and one valid
comeback request of 1000 TU. The wait is no longer pending and connection
succeeded. This confirms the real comeback path; the AID masking correction
was not exercised by this AP's ordinary 0xc005 value. Total time from system
boot to authorization has not been measured by this checkpoint.
All 20 en1-bound ICMP requests received replies over 59.16 seconds; all 13
samples remained authorized, with no disconnect increment or TX watchdog
increment. IPv4 and IPv6 HTTPS sockets bound to en1 both returned HTTP 200
with certificate verification successful. Startup PMF probing is absent.
This bounded observation does not close long-duration stability, group PMF,
rekey, sleep/wake, RSNXE userland callback coverage or other macOS versions.
No additional reboot, commit or push was performed. Hardware evidence and
installation receipt are copied with SHA-256 verification to SD.
