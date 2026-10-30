# Native macOS EAP integration contract

Status: local experimental integration, disabled by default and not hardware verified. This is separate from implemented
WPA3-Personal SAE/PMF and from the local PTK-notification timeout correction.

## One implementation and validation group

| Boundary | Required behavior | Current source evidence |
| --- | --- | --- |
| Native join | Admit only explicitly supported enterprise auth, with no password/PSK reinterpretation or mixed-AKM downgrade | Opt-in ordinary WPA2-Enterprise AKM1; mixed, FT, SHA256 enterprise and supplied key material rejected |
| Association RSN | Select the requested enterprise suite consistently in AP validation, association and M2 | AKM1/CCMP supported consistently; PMF-required enterprise remains unsupported |
| EAP owner | System eapolclient owns EAP, driver owns the four-way handshake and PMF | Existing source/disassembly audit establishes MSK handoff architecture |
| Uncontrolled port RX | Route EAP to macOS before controlled-port authorization; preserve peer, bounds and one packet owner | Current-owner EAP routes to the system; internal-key queue remains separate, including preflight |
| Uncontrolled port TX | Admit only valid current-peer EAP while ordinary traffic remains blocked; bound ownership and drain | Bounded current-owner EAP bypass before normal controlled-port admission |
| EAPOL-Key RX | Retain internal handling and separate it from general EAP transport | Existing internal supplicant is operational for personal profiles |
| MSK callback | Validate the actual kernel-translated request, profile, station, peer and generation; wipe rejected/retired copies | MSK-only callback accepts translated 32-byte current-owner key; personal profiles and preauthentication rejected |
| Key derivation | Support only validated enterprise AKM derivation/MIC/RSN rules; do not relabel PSK vectors as enterprise proof | Ordinary AKM1 four-way integrated with one-shot PMK consumption; unsupported enterprise variants rejected |
| Ordering | Publish association/BSS events needed by the OS EAP client before controlled-port completion; no premature ordinary traffic | Existing notifications publish association before port authorization and gate final success on authorization |
| Completion | Preserve stock initial key-done path and separate rekey event; avoid duplicate property-change messages | Recovered Up=2 path reaches handleKeyDone; pairwise update uses ID76/reason0xe0822c15 |
| Cancellation | Forget, leave, radio-off, roam, timeout and stop retire packet/key work and reject late MSK callbacks | Existing personal lifecycle must remain intact |
| Evidence | Test admission through EAP routing, MSK acceptance, internal handshake, firmware barriers and cancellation together | Enterprise radio interoperability needs separate EAP infrastructure |

## ABI constraints

Included ABI headers name upper-auth bits 2 and 11 as WPA2 and SHA256-8021X,
respectively, and bits 14/15 as WPA3 enterprise/FT enterprise. These names alone
do not establish interoperability or authorize enabling the profiles.
The recovered local IO80211Family path clamps MSK/PMK callback key material to
32 bytes for ordinary auth or 48 bytes for auth 0x4000/0x8000; auth 0x80 selects
a different source portion. Do not accept all these variants through one
32-byte PMK branch. FT, Suite-B/192-bit, preauthentication and PMKSA cache
operations need their own validated contracts, not success placeholders.

## Acceptance

Implement the complete admitted EAP profile before advertising it. Tests must
exercise real production dispatch/routing and ownership, including malformed
lengths, EAP versus EAPOL-Key discrimination, stale peer/generation, duplicate
MSK, clear-key operations, queue pressure, timeout, reset and completion retry.
The full development test entry point remains the single regression gate for
previously implemented behavior. Hardware evidence for SAE does not establish
enterprise support; one available personal router cannot prove it.

## Local experimental admission

`Ath10kNativeEAPExperimental=true` is an explicit property gate, absent by
default. It additionally checks the examined 24G90 kernel. Ordinary upper-auth
bit 2, lower-auth 1 and an empty cipher-0/key envelope are the currently admitted
subset; acceptance of that envelope is locally tested, not an observed enterprise
request from the installed OS. No password is retained by the driver.

EAP owner waits at most 30 seconds from admission for MSK. The normal 15-second
four-way timer starts on successful PMK consumption; the existing overall native
join deadline still bounds the complete join. No extension or perpetual retry is
introduced. Same-association reauthentication is integrated locally as described below.
Enterprise host roaming remains unimplemented. A different MSK without the preceding
clear/restart transaction returns Busy rather than overwriting current material.

Production admission, native key callback, PMK binding, M1–M4 exports and M4
completion have a combined sanitized fixture. Firmware key acknowledgements are
emulated, and it checks authorization intent rather than actual radio port opening.
Failed completion cancels without authorizing. Clear-key behavior depends on whether
the owner is empty, initially installing keys, established, or already replacing keys.

Still required: end-to-end pre-link delivery/system-client startup evidence,
late MSK serialization, Enterprise roaming and radio reauthentication evidence. The 68-test sanitized suite and offline
dependencies passed. Local validation is not
enterprise interoperability or supported macOS 11–26 coverage.

The zero-BSSID MSK callback carries no association transaction token. Checking
current internal generation prevents reuse of our retired owner but cannot prove
that a delayed OS callback originated in the current association. Cross-association
serialization must be established before claiming stale-OS-key isolation.

## Uncontrolled output queue and ingress lifetime

Starting EAP is independent of controlled-port authorization and BSD carrier.
The shared output queue must run during an admitted current EAP association;
ordinary data remains rejected by outputPacket until its existing data gate opens.
An EAP-only queue must stop/flush on cancellation, interface disable and runtime
retirement even if carrier was already down. Retiring the EAP owner after successful
port authorization must not stop the authorized data queue. Queue mutation is
performed from service/cleanup, never synchronously from outputPacket.

Packet ingress validates association and owner deadline independently of service
scheduling. Expired transmission is Invalid, including when the queue is full;
it must not stall a caller waiting for space in an expired authentication. Expired
or retired EAP receive is consumed/dropped, not passed to the internal key parser.
Initial PMK consumption ends only the initial EAP wait budget, not four-way/join
deadlines. A replacement retains its 30-second deadline through accepted key-update
notification; consuming replacement PMK does not end that budget.

Read-only examination of installed IONetworkingFamily UUID
5D3F11B8-802B-3860-8A36-E9334980A117 establishes that inputPacket/pushInputPacket
require an attached ifnet and reach ifnet_input_extended without a carrier check
in these methods. The actual native data interface uses this IONetworkInterface
path, not an assumed IO80211 input override. Downstream AF_NDRV delivery and
system EAP client startup still require their own evidence.

## System-client startup and empty-key reset

Apple eap8021x controller.c (blob d51d67828162a9fecff7fede3ba2377f83a1f4de)
starts the system process from ControllerStart after accepting an Ethernet or
IEEE80211 interface and opening its EAPOL socket. Wi-Fi is excluded from the
Ethernet automatic-start flag. A driver must provide the native interface and
association contracts, not launch a private client or infer that one received
EAP frame starts the system process. The installed user-mode manager ordering is recovered below; other startup modes
and actual kernel join delivery remain unverified.

Supplicant.c (blob 552c261964a5eee7382a0e54bba952a29731bb47) enters
Supplicant_authenticating by clearing WPA key state before enabling reception.
EAPOLSocket.c (blob a82591c5bd96afe2bf98057b261c225759596577) maps an ordinary
client clear to zero-length MSK with no BSSID. Thus a valid current EAP owner
without an accepted key treats that request as idempotent empty-key reset:
preserve association, queued packets, generation and the original deadline.
Never authorize or extend the deadline. On an established link, or its ongoing
pair/group rekey, the first clear starts bounded replacement without bypassing
firmware key barriers. Clearing accepted replacement material cancels; clearing
accepted material during initial installation also cancels.

The public client's link-down handler schedules inactivity after a configurable
delay (default one second). It is not a synchronous driver-visible callback drain.
Neither observing link-down nor waiting a guessed interval proves that an MSK
from a retired session cannot arrive after a replacement association. No arbitrary
sleep or inferred generation token may be used to claim that isolation.

Sources: [controller.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/EAPOLController.bproj/controller.c),
[Supplicant.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/Supplicant.c),
[EAPOLSocket.c](https://github.com/apple-oss-distributions/eap8021x/blob/main/eapolclient.tproj/EAPOLSocket.c).
These are source-supported wire/lifecycle requirements, not a claim that the
installed private Wi-Fi manager and Enterprise radio path have been observed.

## Installed user-mode startup sequence (24G90)

The x86_64 airportd UUID 4C5133D4-CEF3-3D88-8E93-273EF886B93E
user-mode Enterprise entry calls __startUserMode8021XWithSSID at 0x10001be59;
a false result takes the failure branch. Only success reaches the common
association call at 0x10001bee0, with is8021X=true in r9d. The startup helper
calls internal_startUserMode8021X...reply: at 0x100006847 and waits for a
WiFiAgent reply, bounded to 20 seconds. Thus this actual installed entry starts
the system client before requesting radio association. It is not a reason to
publish controlled-port success early or create a separate userland launcher.

Installed CoreWLAN UUID A13906EE-B783-37F8-B44B-3DF90DF7EC8B, method
CWEAPOLClient::startEAPOLWithClientItemID:authenticationInfo:error: (image offset
0x4d8c6), queries EAPOLControlCopyStateAndStatus. Its running-client path calls
EAPOLControlStop, polls state at 200 ms intervals up to 50 iterations, and then
calls EAPOLControlStartWithClientItemID. The public ControllerStart additionally
rejects non-idle clients. This is bounded process orchestration; it is not a
per-association token supplied to the kext. Same-process autoreconnect and queued
old key requests remain outside the proven boundary.

Static evidence: outputs/NATIVE-eap-port-lifecycle-20261030/startup-contract.
The user-mode ordering is recovered; system/login-window modes, the precise
kernel enterprise join envelope and actual AF_NDRV/radio delivery remain unverified.

## Reauthentication clear is not a unique state transition

Public Supplicant.c blob 552c261964a5eee7382a0e54bba952a29731bb47 routes
a new method request from Authenticated into Authenticating (around lines
1284–1302), which clears the MSK. Held also clears it (around line 3052).
Thus zero-length cipher9 alone identifies neither successful reauthentication
nor failure. An EAP Success frame cannot be required before key handoff: the
client attempts set_wpa_key_info while its method is still Authenticating.

Stock CoreMac UUID 4C3822FC-8902-3AF6-A791-DD4A8D9E9C66 dispatches cipher9
through the PMK branch at 0xffffff80015864c0 (jump table 0xffffff8001586ad4).
Zero key length skips event-enable/timeout setup but still calls programPMK at
0xffffff8001586574. programPMK issues WLC_SET_WSEC_PMK (0x10c), with a
0x108-byte payload. These inspected functions contain no direct disassociation
on zero length. Firmware effects on existing PTK/controlled-port state remain
unrecovered; do not infer that it is safe to retain or discard those keys.

The local replacement policy below separates master-key and established-link
lifetimes, using independent supplicant reference behavior and existing driver
key barriers. It is not proof of stock firmware internals or radio interoperability.
Evidence: outputs/NATIVE-eap-reauth-contract-20261030.

## Late-key provenance versus cryptographic authorization

A tokenless MSK callback cannot identify the EAP session that produced its bytes.
That provenance gap is distinct from controlled-port authorization: the current
supplicant derives a PTK from PMK, both MACs and nonces, then verifies current M3
MIC before publishing Keys. A wrong old PMK must fail that check; acceptance by
nativeSetCipherKey alone must never open the port. A combined production-path
fixture now exercises admitted Enterprise join, empty reset, wrong MSK, M1 and
valid AP M3, asserting Fatal with no key export or authorization intent.
Its execution result is tracked in the audit; the test does not prove callback
serialization, retry availability, firmware behavior or real Enterprise delivery.
An old PMK equal to the current PMK is not distinguishable by key bytes alone.

## Replacement transaction requirements

The upstream-derived supplicant in FreeBSD, wpa.c blob
adf88ebdf829cf7d83f6925c65f417e6574bda0f, separates wpa_sm_set_pmk from
established PTK state. Its PMKSA_REPLACE path avoids deauthentication; cache
expiration is handled separately. This supports separate master-key and link
lifetimes, not assumptions about Broadcom firmware behavior.
Source: https://github.com/freebsd/freebsd-src/blob/main/contrib/wpa/src/rsn_supp/wpa.c

The current local group covers these linked transitions:

| Transition | Required rule | Local implementation / remaining evidence |
| --- | --- | --- |
| Established or ongoing rekey → EAP restart | Preserve link identity and prior owners; bounded deadline | Clear starts a new 30-second owner; initial key installation remains cancellation |
| New MSK while prior work is pending | Drain prior EAP queue, TX, key and notification owners before PMK handoff | Deferred service with original deadline; old PTK notification cannot finish new owner |
| New PMK → M1/M3 | Fresh nonce, replay retention, authenticate before key export | replaceEAPMaster preserves established keys/replay; early M1 waits for handoff |
| New keys → firmware barrier → M4 | Match generation and receipt, then notify macOS | Existing PairKeys path and durable receipt; replacement ends only after accepted update notification |
| Failure / timeout / leave | No indefinite wait or retained retired secrets | Owner expiry cancels; terminal security reset clears replacement state; hardware evidence remains open |

## Current local integration and evidence

The initial empty reset is idempotent. A clear on an established authorized phase5
link, or its existing pair/group rekey in phases1–4, starts replacement. Queued EAP
frames keep their bytes and timestamps; transport owners are not reset. New PMK
waits for queue, EAP TX, reply, key-install, authorization receipt, PTK notification,
pairwise candidate and serial/data/WMI/rekey owners to drain. Timeout still runs.

Existing installed keys remain until authenticated new M3 requests their update.
The restart itself never opens a port closed by an ongoing firmware update. The
existing pairwise key-install path closes/reopens the port at its firmware barriers.
An old pairwise notification delivered before new PMK handoff cannot finish the
replacement; after handoff, completion checks identity, generation and deadline.

Independent AP vectors and production-fragment fixtures cover PMK replacement,
M1–M4, retained replay/GTK state, wrong PMK/MIC, duplicate M3 without reinstall,
early queued M1, deferred owners, queue/TX/receipt drain, restart during firmware
rekey, terminal timeout and accepted/rejected macOS notification. Affected tests
passed ASan/UBSan. Final consolidated 68-test regression passed with ASan/UBSan; native compilation
and symbol validation passed. Firmware acknowledgements are emulated in fixtures.

Enterprise remains default-disabled. Precise live kernel join envelope, downstream
AF_NDRV delivery, stale OS callback provenance, system/login-window startup,
Enterprise roaming and radio interoperability remain open. Source integration and
local tests do not advertise support or establish native operation on other OSes.

## Enterprise roam boundary

EAPOLSocket.c blob a82591c5bd96afe2bf98057b261c225759596577 retains cached BSSID
on a non-RX wireless-info update while it remains valid. RX from a new source can
update it, but the inspected update method does not clear the cached EAP response.
Receive may retransmit that cached response on matching request identifier; the
inactive-link notification explicitly clears it. Therefore current Personal
retained-link roaming cannot simply admit AKM1: establish system EAP cache/session
retirement before new-BSS EAP, without claiming a guessed delay drains callbacks.
This is a public-source boundary, not installed consumer or radio evidence.

Roam admission and teardown must wait for pending PTK notification, EAP TX/queue
and replacement authentication as well as existing firmware/key owners. Local
production-path tests cover the added pending reply/PTK/EAP-TX guards. Enterprise
candidate selection remains rejected until the complete OS handoff is implemented.

A complete source call-site review also found cache clearing on socket destruction,
non-EAP packet transmission, and receipt that does not match the cached request
identifier. These are alternative causes, not guaranteed roam acknowledgements.
The ordinary RX path updates the new BSSID before comparing only the EAP request
identifier against the prior response. Therefore a new-BSS RX alone is not a cache
retirement fence. Do not synthesize EAP traffic or rely on a timed link-down pulse
to force an assumed userspace restart. The installed-client notification path and
its relationship to new association admission still require evidence.

Installed 24G90 eapolclient x86_64 UUID FAC5670D-77C2-3A38-9DE9-37B8A150A96B
now corroborates that boundary: RX updates wireless information at 0x10000a42c;
0x10000a6ba–0x10000a6dd compares cached response by packet type/request code/ID;
0x10000a75e retransmits. The link callback returns without notifying the supplicant
if refreshed active state is unchanged (0x10000a0d7–0x10000a0e1). Observed inactive
state frees the cached packet before invoking the supplicant (0x10000a1ee–0x10000a220).
Consequently posting Down then immediately making the next BSSID visible does not
prove userspace processed the inactive association. The next integration must
establish an observable session transition, not just accepted kernel event enqueue.
Initial and pairwise-update key-done producers are already recovered in the audit;
this finding does not require duplicate property-change notification.
Evidence: outputs/NATIVE-enterprise-roam-contract-20261030/installed-eap-roam-cache.json.
