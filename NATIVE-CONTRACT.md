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
| IOSkywalkFamily | 50C44C84-1166-387F-8ECE-02E931E2405B | Interface/data-path integration |

Local images were extracted as analysis containers from BootKernelExtensions.kc.
No Apple binary or raw private stackshot is committed. The current environment
provides LLVM disassembly, not an installed C decompiler. The pseudocode below is
manually reconstructed from matching assembly and is not recovered Apple source.
The local kernel collections contain the two listed networking families; no
separate Broadcom Wi-Fi module has yet been identified in those collections.

## Reconstructed provider and termination contract

Relevant Sequoia assembly entry points:

* `IOService::getWorkLoop` at `0xffffff80009ddaa0` obtains `getProvider()`,
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
| P0 | Event delivery errors | PostOffice copies payload but can return NoMemory; current flags advance without checking | Preserve event order and retry/terminate honestly on enqueue failure |
| P0 | Provider queues and API client close | New provider overrides; existing nonblocking event bridge | No cyclic waits during repeated query/close/scan; useful traffic continues |
| P0 | Current BSS reply | Fixed scratch lifetime after WCL's confirmed Update Bss fail | Repeated background scans retain correct AP reply and connection |
| P0 | Data path after authorization | Last boot had authorized port but no DHCP and stalled worker | DHCP, ARP, IPv4, IPv6 and bound HTTPS pass while worker advances |
| P1 | Scan request semantics | Candidate passes requested physical channel subset to firmware; rejects empty regulatory intersection; pre-submit cancellation completes locally | Hardware confirms subset timing, SSID matching, cancel and completion ordering |
| P1 | Autojoin | About 32 seconds after login on previous boot | Trace and reduce avoidable retries without router changes |
| P1 | Visibility | Beacon metadata adjusted; saved profile still has Hidden=true | Compare fresh beacon, WCL current BSS and saved profile/UI independently |
| P1 | Join and keys | PSK/SHA256 fixtures and first traffic previously passed | Initial/rekey/abort/failure paths retain ordering and replay protections |
| P1 | Power and lifecycle | Radio stop paths partially audited | Off/on, sleep/wake and teardown have finite completion and safe DMA ownership |
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
Allocation failure returns `0xe00002bd` (NoMemory). The current driver's event
lambda discards this result. Reliable phase advancement after event enqueue is
therefore still an open P0 task, not a completed robustness claim.

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
