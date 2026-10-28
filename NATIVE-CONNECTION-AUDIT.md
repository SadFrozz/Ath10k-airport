# Native connection audit (2026-10-28)

Hardware-confirmed: firmware starts, macOS creates en1 and shows scanned networks.
Association/data traffic are not yet confirmed. WCLJoinManager was observed aborting
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
`tests/requirements-fixtures.txt`. The committed fixtures use only public test keys.
The macOS SHA256 test uses CommonCrypto, while the kernel uses corecrypto. Hardware
validation, DHCP and live traffic are still necessary.

KDF reference: https://w1.fi/hostapd/devel/sha256_8c_source.html
AES-CMAC reference: https://www.rfc-editor.org/rfc/rfc4493
Current adapter and private ABI: pinned upstream in vendor/itlwm/SOURCE.json.

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

Native channel subsets now restrict firmware START_SCAN itself, intersecting the physical channel plan and regulatory policy. Unknown/6 GHz channels cannot turn into unrestricted scans; an empty intersection fails before submission. An accepted request cancelled before the first firmware submission completes locally without START/STOP or DMA ownership. Legacy full-plan wire format and passive DFS behavior remain unchanged. Native decode-to-command fixtures, extracted production provider getters, ASan/UBSan and mocked radio cancellation/credit/event regressions cover these changes. Hardware autojoin timing remains unverified. Event enqueue errors discovered in matching PostOffice assembly are tracked as an open P0 task in NATIVE-CONTRACT.md.


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
