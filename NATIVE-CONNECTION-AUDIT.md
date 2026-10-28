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
