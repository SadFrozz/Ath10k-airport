# Native macOS EAP integration contract

Status: local experimental integration, disabled by default and not hardware verified. This is separate from implemented
WPA3-Personal SAE/PMF and from the local PTK-notification timeout correction.

## One implementation and validation group

| Boundary | Required behavior | Current source evidence |
| --- | --- | --- |
| Native join | Admit only explicitly supported enterprise auth, with no password/PSK reinterpretation or mixed-AKM downgrade | Opt-in AKM1 and SHA256 AKM5 with CCMP/PMF; mixed, FT, Suite-B and supplied key material rejected |
| Association RSN | Select the requested enterprise suite consistently in AP validation, association and M2 | AKM1 plus explicit AKM5/CCMP/PMF source integration; hardware acceptance remains open |
| EAP owner | System eapolclient owns EAP, driver owns the four-way handshake and PMF | Existing source/disassembly audit establishes MSK handoff architecture |
| Uncontrolled port RX | Route EAP to macOS before controlled-port authorization; preserve peer, bounds and one packet owner | Current-owner EAP routes to the system; internal-key queue remains separate, including preflight |
| Uncontrolled port TX | Admit only valid current-peer EAP while ordinary traffic remains blocked; bound ownership and drain | Bounded current-owner EAP bypass before normal controlled-port admission |
| EAPOL-Key RX | Retain internal handling and separate it from general EAP transport | Existing internal supplicant is operational for personal profiles |
| MSK callback | Validate the actual kernel-translated request, profile, station, peer and generation; wipe rejected/retired copies | MSK-only callback accepts translated 32-byte current-owner key; personal profiles and preauthentication rejected |
| Key derivation | Support only validated enterprise AKM derivation/MIC/RSN rules; do not relabel PSK vectors as enterprise proof | AKM1 and AKM5 four-way with one-shot PMK consumption; AKM5 uses SHA256 KDF, descriptor 3 CMAC and IGTK barriers; FT/Suite-B rejected |
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

## Requested legacy Enterprise compatibility

The required compatibility scope also includes WPA1-Enterprise/TKIP and dynamic
WEP/802.1X, alongside WPA2-Enterprise. This is not a support claim. Recover native
authentication, credential and key-delivery contracts separately for each profile.
Dynamic WEP needs its own EAPOL-Key descriptor and key-index/install lifecycle;
it must not be sent through the RSN four-way owner. Distinguish EAP methods
provided by the stock macOS client from link-layer cipher support in this driver.
Only advertise a mode after its complete admitted path is implemented and tested;
legacy Enterprise radio interoperability remains separately unverified.


### Legacy EAP method inventory and acceptance

Audit EAP-TLS, PEAP (including EAP-MSCHAPv2), EAP-TTLS (including
PAP/CHAP/MSCHAP/MSCHAPv2), EAP-MD5, LEAP and EAP-FAST against each targeted
stock macOS client. This is the requested compatibility inventory, not a claim
that any listed method is present or usable on the installed OS. Record outer
and inner method availability separately, including credential/profile setup,
server trust and exported key material. Do not implement EAP methods inside
the kext merely because a particular stock client lacks them.

For each method/profile combination, establish whether it provides the key
material required by that link mode; a completed EAP exchange alone must never
open the controlled port. In particular, do not assume every historical EAP
method provides an MSK suitable for WPA or dynamic WEP. Preserve the distinction
between authentication success, key delivery and firmware installation.

The grouped compatibility matrix must cover WPA1-Enterprise TKIP/CCMP,
WPA2-Enterprise TKIP/CCMP and dynamic WEP-40/104 with 802.1X. Record each cell as
required, implemented, locally tested, hardware observed or unavailable in the
stock OS. Exercise authentication rejection, certificate/trust rejection where
applicable, reauthentication, key replacement, replay, timeout, cancellation and
late callbacks together. Never silently fall back to a weaker link profile or
bypass the system client's trust decision. If a stock OS cannot supply a method,
report that precise native-platform limitation rather than advertising support.


Installed 24G90 evidence: the eapolclient registration loop at
0x100000c6f–0x100000c97 walks ten 16-byte entries at 0x100013840 and calls
EAPClientModuleAddBuiltinModule, stopping on an error. Bound introspection
functions are md5, leap, eaptls, eapttls, peap, eapmschapv2, eapgtc, eapfast,
eapsim and eapaka in EAP8021X. This proves static registration intent on this
installed image, not successful runtime initialization, inner TTLS methods,
key-export suitability or radio interoperability. Evidence with image SHA-256:
outputs/NATIVE-security-compatibility-20261030/stock-eap-method-registration.json.


### Dynamic WEP owner recovered on installed 24G90

The installed eapolclient owns descriptor-1 key authentication/decryption:
0x100005227 selects descriptor 1; SessionKey/ServerKey callbacks feed its
signature check and RC4 decryption. It then routes through 0x10000891f to
0x10000c0e0, which accepts 5/13-byte keys and sends Apple80211Set operation 3
with a 148-byte version-1 key record. Offsets are length4, cipher8, flags12,
index14 and key16; cipher is 1/2 for lengths5/13. Do not mistake this userspace
record for the final kernel callback ABI.

Consequently dynamic-WEP EAPOL-Key must be delivered to the system EAP owner
under an explicitly admitted dynamic-WEP association, not processed by the
internal RSN supplicant or by a duplicate RC4 handshake in the kext. Default RSN/WPA1
classifier rejects descriptor1; enabling native WEP admission alone would be incorrect because
routing, native WEP callbacks, firmware slots and controlled-port completion
are not integrated. Recover replay/session retirement and translated callback
ownership before enabling this route. Evidence: stock-dynamic-wep-owner.json
and .asm under outputs/NATIVE-security-compatibility-20261030.


The inspected IO80211Family 24G90 kernel entry at 0xffffff80022c9dbe
copies the 148-byte record and validates key/RSC/WoW lengths (64/8/16/16).
Cipher values 1/2 take the WEP path without PMK/MSK length truncation. The
record is forwarded to sendIOUCToWcl operation 3, or unchanged through
apple80211setCIPHER_KEY and Infra virtual slot 0x10c0. The alternate entry
0xffffff8002218330 has the same WEP bypass. This establishes the outer kernel
record, not the still-untraced WCL inner driver dispatch/completion. Current
nativeSetCipherKey only admits the existing MSK owner; do not interpret a WEP
record as that owner's PMK. Evidence: stock-wep-kernel-dispatch.json/.asm.


### Observer, submission and completion are separate

Installed WCLNetManager::setKey (0xffffff8002129250) is an observer: after
checking a 148-byte message, a nonempty key on the current EAP join may arm
set4wayHsTimeout(6000). Its zero return does not establish firmware installation.
Stock Infra setCIPHER_KEY forwards the record to Core, whose handler invokes
JoinAdapter::setKey(record, true, nullptr, 0). The inspected asynchronous
programKey callback returns on success and logs failures; it does not itself
publish port authorization. Preserve separate callback acceptance, firmware
receipt and controlled-port completion in our implementation. Evidence:
stock-key-observer-versus-install.json/.asm in the security output directory.

### WPA1 initial key barriers (Personal and Enterprise)

The authenticated WPA1 M3 publishes PTK only. Its firmware acknowledgement
permits M4 transmission, but neither acknowledgement authorizes the controlled
port. Keep a bounded first-GTK wait and reject premature peer authorization.
The separate authenticated group exchange installs GTK, preserves its RSC and
transmits its ACK under the installed PTK. Only that ACK's own successful TX
receipt may request peer authorization; the firmware/RX barrier still precedes
ordinary traffic. Wrong or retired TX IDs cannot complete either exchange.
Cancellation must retire staged replies and both initial-group markers along
with the association; installed PTK still requires normal firmware teardown.
Exact authenticated retransmissions must not reinstall keys or reset PN/TSC.
These requirements apply after either PSK or the native Enterprise EAP owner
supplies the master key; they do not establish availability of an EAP method.


### Inner WEP routing checkpoint (24G90)

Read-only BootKernelExtensions pointer inspection resolves IO80211Glue's
virtual slot0x120 to CommonGlue::sendMessage (0xffffff800211ebd0), not
directly to receiveMessageInternal. WCLGlue converts the request into a
bulletin-board message and sends it to manager12. Its return-to-driver method
preserves the payload pointers/lengths; IO80211Glue routes IOUC messages into
apple80211RouteInternal. The internal SET table entry for operation3 resolves
to apple80211setCIPHER_KEY (0xffffff80021fb67c).

This narrows the remaining trace to bulletin-board operation3 dispatch and
WEP install/authorization semantics; it does not prove that every request
reaches the driver or that an accepted key opens the port. Evidence:
stock-wep-inner-routing.json/.asm in the security compatibility output directory.


### WCL dispatch result and handled ownership (24G90)

The NET_MANAGER callback array entry at 0xffffff80023f2650 binds SET
operation3 (message0x30001) to WCLNetManager::setKey, with zero this adjustment.
The bulletin board routes manager12 ingress through its subscriber bitmap.
routeMsg visits enabled manager bits0..10 in ascending order, retains the first
nonzero callback result, and ORs the separate handled byte at message offset40.
An empty subscriber set returns zero without claiming the request. The inspected
setKey observer does not set that byte. Other subscribers and the live bitmap
are not yet established by this static inspection.

The outer setCipherKey at 0xffffff80022c9fb1 invokes apple80211setCIPHER_KEY
when handled is not1, or when the handled result equals0xe082280f; otherwise
it returns the WCL result. Therefore a zero observer result must not suppress
driver submission. Driver acceptance, firmware installation and port authorization
remain separate requirements. This closes the generic dispatch/fallback policy,
not WEP key-slot semantics or runtime acceptance. Evidence:
stock-wep-bulletin-dispatch.json/.asm in the security compatibility output directory.


### WEP key envelope and QCA installation boundaries

Stock BCM mapAppleKeyToBcomKey (0xffffff8001652189) preserves key index,
maps Apple cipher separately from firmware cipher, translates TX flag bit4,
and normalizes a broadcast address to its default key address. Do not copy
BCM firmware structures into QCA commands. The inspected Linux ath10k station
path installs non-sta WEP in both group and pairwise slots, rolling back the
first installation if the second fails. Dynamic default-TX selection and static
WEP default-index selection differ. Our generic WMI serializer already supports
WEP lengths; the required lifecycle is still missing.

Ath10kNativeWEPKey.hpp now decodes the observed system dynamic-WEP envelope
without retaining/copying secrets: exact148 bytes, version1, Apple cipher1/5
bytes or2/13 bytes, index0..3, flags1/2/5/9, no advertised RSC/WoW extension,
and zero/broadcast/current-peer address. It resets its borrowed view on failure.
The caller must own and wipe the record; the view must not be queued. This is
not wired to nativeSetCipherKey yet and does not admit WEP or empty key removal.
Affected native_wire tests passed with ASan/UBSan. Evidence: wep-envelope/ under
the security compatibility output directory, byte-verified on SD.


### Explicit dynamic-WEP system packet ownership

The EAP owner now has an explicit beginDynamicWEP entry point. Descriptor1
RX is routed only to the system client, for the current station/peer/generation;
RSN/WPA1 descriptors are rejected in that mode, and default RSN/WPA1 owners
continue rejecting descriptor1. The decoder bounds the44-byte fixed body,
5/13-byte key size, index0..3 and either absent or exact-length encrypted key
data. It performs no MIC/decryption/replay authentication: that belongs to the
stock EAP client. System TX key frames remain rejected.

Dynamic-WEP owners reject MSK handoff and cannot consume a PMK. Their deadline
remains bounded; successful key installation/reauthentication completion is not
yet implemented. The native receive copy now uses the owner's selected envelope
instead of re-decoding every frame as RSN; this prevents zero-length delivery
after descriptor1 routing. Production-path fixtures cover padding, truncation,
wrong descriptors/peer/index/length, expiry, cancellation, stale generations and
RSN reuse, plus unchanged MSK callback/owner tests with ASan/UBSan. Native build
and symbol check passed. No native join calls beginDynamicWEP yet, so no WEP
capability is advertised. Evidence: wep-system-routing/ under the security output.


### WEP firmware receipt identity

Linux htt.h and wmi.h use different cipher enumerations. Selected WEP40(1)
programs WMI1 but receives HTT3; selected WEP104(5) programs WMI1 but receives
HTT2. Key sizes are5/13. TKIP uses selected2/WMI2/HTT4/32bytes; CCMP uses
selected4/WMI4/HTT6/16bytes. Pairwise receipts add bit0x80. HTT does not carry
the key index or a host transaction ticket, so a peer/cipher/cast match alone
cannot establish ownership across successive same-type slot operations.

firmwareKeyCipher centralizes these mappings and is used by existing TKIP/CCMP
serialization and receipt expectations. WEP receipts remain rejected by the
RSN phase machine; a dedicated serialized slot/fence owner is still required.
Affected connection tests passed ASan/UBSan and native build/symbol check passed.
Evidence: wep-firmware-ciphers/ in the security compatibility output directory.


### Key transaction fence requirement

A matching HTT security indication must retain slot-operation ownership until
an ordered firmware fence and retirement of prior RX work are established.
KeyTransaction now records Acknowledged separately from Idle, and permits reuse
only through completeAfterFence with the same ticket before the original
deadline. Submission checks that deadline too. Cancellation, expiry or clock
rollback after submission/acknowledgement makes the operation Uncertain; a
proven firmware retirement is required before reuse. A host ticket cannot
identify a wire response by itself. This helper is not yet integrated into
native WEP installation; do not treat its host tests as a firmware ordering
proof. Evidence: key-transaction-fence/ in the security compatibility output.


### Native WEP callback ownership

For an explicitly selected dynamic-WEP EAP owner, nativeSetCipherKey now
validates/copies the148-byte request through the recovered decoder and queues
owned5/13-byte material. The bounded eight-entry queue covers four slots with
group/unicast requests. Each entry has a monotonic host ticket; it is not a wire
identifier. Duplicate suppression compares only the latest request for a slot/cast
so A,B,A retains ordering. Full queue returns Busy before mutation.

Only the current generation/peer and head ticket can retire an entry; retirement
must follow the future firmware/fence consumer. Finish, owner clear, cancellation
and expiry wipe stored material. Expiry observed inside the native callback
cancels the link and schedules cleanup. No WEP queue entry grants port access,
consumes an MSK, or proves EAP replay provenance. Native admission and the
firmware queue consumer/authorization remain unfinished. Three affected tests
passed ASan/UBSan, plus native build/symbol check. Evidence: wep-key-owner/.


### Confirmed WEP slot ownership

The EAP owner retains completed key material for each of four group/unicast
slots separately from the pending queue. Completion must still be backed by
the future firmware/fence consumer. An identical request matching the latest
queued slot, or the completed slot when no replacement is queued, does not
schedule reprogramming. Installed A, queued B, requested A preserves B,A.
Completed material is wiped on replacement, clear and expiry alongside queued
secrets. Lookup requires current generation/identity and deadline.

This is not full WEP reinstallation protection: changed flags on identical
material must be separated into default-TX metadata updates by the firmware
consumer, which remains unfinished. No hardware completion is implied by host
fixtures. Affected callback/owner ASan/UBSan and native build passed; evidence
is wep-confirmed-slots/ in the security compatibility output directory.


### WEP default transmit selection

The owner now distinguishes a new key installation from selection of an already
installed TX slot and a metadata-only flag change. Duplicate detection accounts
for the effective TX index after all queued requests: A,B,A must end on A even
when the bytes of A are already installed. Completion updates confirmed TX
selection; clear resets it. Unchanged bytes must not be reprogrammed merely
to change default TX index.

Linux ath10k set_default_unicast_key uses VDEV_PARAM_DEF_KEYID; the inspected
TLV enum assigns0x21. buildWEPTransmitIndexWMI encodes command0x5008/tag95,
vdev0 and slot0..3 in28 bytes, without key material. Its caller must validate
installed-slot ownership and provide firmware completion/fencing. That consumer
is not implemented yet. Callback/connection ASan/UBSan tests and native build
passed; evidence: wep-transmit-selection/ in the security output directory.


### QCA group/pair WEP slot aliasing

The inspected Linux station WEP path mirrors a non-sta/group installation into
the same-index pairwise slot. Owner bookkeeping must reflect both physical
writes: a subsequent individual replacement can invalidate that mirror even
when the retained group bytes are unchanged. WEP action planning now accounts
for current and queued writes to both casts at the same index.

New group material with an already identical pair slot needs InstallGroupOnly;
an unchanged group with a different pair slot needs RepairPairMirror; otherwise
a new group install needs both writes. Group completion records the pair mirror
as unicast metadata and preserves the existing TX index. It must only be called
after every planned operation and fence succeeds; the firmware consumer and
partial-failure rollback remain unfinished. This host-state model does not prove
radio behavior. Callback/owner sanitized tests and native build passed; evidence:
wep-pair-mirror/ in the security compatibility output directory.


### Static and dynamic WEP admission requirements

Static association keys and dynamic EAP key callbacks are different envelopes.
Preserve explicitly selected Open System versus Shared Key authentication;
never treat a supplied WEP key as a plaintext Open profile. Require exact
WEP40/104 key length/cipher consistency and bounded key index. Shared Key
requires its challenge-response exchange before association. A decoded static
request, EAP Success alone or a queued key is not controlled-port authorization.
Only completion of the selected authentication plus all required firmware key
and default-TX barriers may release ordinary data. Cancellation must retain
uncertain DMA/key ownership until confirmed firmware retirement. Dynamic WEP
additionally requires current system EAP-session provenance; it must not consume
an RSN PMK or inherit an unrelated association's authorization.

Earlier checkpoint paragraphs describe implementation at their recorded stage,
not the current inventory. Static native join admission, Shared Key exchange,
firmware slot execution, controlled-port barriers, RX reassembly and prepared
roam credentials are now integrated and locally tested behind the default-off
WEP gate. Dynamic WEP system-session admission/authorization and hardware
interoperability remain unfinished. See the status map and batch plan for
per-stage evidence; local tests do not establish radio interoperability.


### Dynamic-WEP session/replay authorization boundary

System EAP authentication, descriptor signature verification, key callback,
firmware receipt and controlled-port authorization are distinct events. Bind
accepted keys to the current admitted system session; EAP Success and receipt
of an unauthenticated descriptor cannot establish authenticated replay progress.
Do not infer absence of OS replay handling from one public function. Require
observed callback/session ownership before enabling dynamic admission.
WEP RX reassembly must retain cipher, slot and key-set generation across all
fragments, reject mixed/corrupt continuations, and preserve normal port checks.
WEP IVs do not provide CCMP's sequential packet-number semantics.


### Stock WEP key dispatch is distinct from PMK startup

Installed 24G90 BCM JoinAdapter::setKey table0xffffff8001586ad4 maps Apple
cipher1/2 to conversion at0xffffff80015865cc, then programKeyAsync/Sync.
It bypasses the PMK branch's supplicant-event setup and6s handshake timer.
Preserve this separation in native dynamic WEP: system EAP key installation
must not start a WPA four-way handshake. Firmware command acceptance remains
separate from completed key installation and controlled-port authorization.
Evidence: stock-wep-key-dispatch in the security compatibility output directory.


The installed BssManager isEAPJoin predicate accepts only upper-auth values
1,4,128,2048,16384,32768; it excludes32/64. Its conditional setKey6s timer
must not serve as dynamic-WEP authorization evidence. This predicate's scope
is narrower than system EAP method availability. Evidence: stock-wep-eap-predicate.

## Enterprise SHA256 transition restrictions

The explicit AKM5/CCMP/required-PMF profile must remain admissible when macOS
supplies the Enterprise Transition Disable flag. That policy requires stronger
protection; it is not a blanket prohibition on Enterprise. Legacy AKM1 without
negotiated PMF and WPA1 remain rejected under this flag.
Authenticated Transition Disable KDEs from the selected PMF association must
pass MIC, unwrap, RSN and key validation before retention. Publish only after
key/port completion, bind delivery to the PMF owner and invalidate pending
profile/roam copies when restrictions tighten. OWE uses the same ownership
rules for Enhanced Open. Reset/cancellation cannot update the next profile.

Reference behavior inspected: wpa_supplicant wpas_glue.c, commit
59fa4b44b84301ac01b937a6a0e687cf5dd3593a, transition-disable consumer; Enterprise
sets required PMF and removes legacy protection. No upstream source copied.
