# Implementation and verification map

Updated 2026-10-30 after user resumed development. Requirements are in
[Native contract](../contracts/NATIVE-CONTRACT.md), [WPA3 contract](../contracts/WPA3-CONTRACT.md)
and [EAP contract](../contracts/NATIVE-EAP-CONTRACT.md). Historical checkpoints are
preserved in [the previous map](../history/NATIVE-STATUS-through-1.0.106.md);
its dated candidate/install statements are historical, not current state.

## Installed checkpoint

Ath10kMac **1.0.110**, UUID **E39009FE-C6F8-385B-8B0C-B6DC48AED01A**,
functional source **add6acf41627edc4d7158a31db7bec597c752d08**. Boot verified on
CF493E4E-E6A4-406D-85DA-C5DDA4C4D505. Interface en1 has IPv4 and three IPv6
addresses; native SAE/PMF remains ready. 45/45 gateway probes returned, but TX NoAck
rose 0→12, mean RTT 99.094 ms and max 1012.305 ms. Disconnect/watchdog/replay/security
counters stayed zero. This is bounded connectivity evidence, not stability acceptance
or proof of individual address callback invocation. Latency/NoAck correlation is
under investigation; do not infer that the host-address change caused it.
Evidence: outputs/NATIVE-installed-1.0.110-runtime-20261030 (workspace and SD).
69 sanitized tests and offline candidate checks passed before installation.
Follow-up correlation interval: 120/120 replies, mean RTT 9.444 ms, one sample
above the descriptive 100 ms cutoff (595.887 ms, 0.83%); NoAck remained 12→12.
No scan generation/event change around that spike. This interval fits the user's
<=1% rare-spike allowance; no targeted latency fix justified by this sample.
Earlier startup interval remains recorded; prolonged stability is not certified.

## Current implementation

| Area | Implementation / evidence | Open requirements |
| --- | --- | --- |
| Native interface, scan, association, traffic | Implemented; hardware observed on 15.6.1/24G90 | Prolonged stability, earlier latency/NoAck |
| WPA3-Personal SAE | Implemented experimental gate; native traffic observed | Both password modes not fully certified |
| PMF | Implemented; protected SA Query round trip observed in earlier image | Group BIP and AP-driven rekey radio evidence |
| PTK/GTK/IGTK and completion | Implemented firmware barriers, receipt ownership and bounded macOS notification | AP-triggered updates on hardware |
| Host-requested roaming | Integrated and covered by production-path fixtures | Physical inter-AP test unavailable with one router |
| Autonomous roam cache/offload | Enable/nonempty requests rejected | Implementation remains |
| Legacy Enterprise and EAP inventory | Local default-off WPA1 and WPA2 TKIP/CCMP admission, EAP/MSK routing and firmware key lifecycle integrated | Dynamic WEP native session/authorization unfinished; per-method OS and AP interoperability unverified |
| WPA2-Enterprise / SHA256 | Local default-off AKM1 and AKM5/CCMP/required-PMF; EAP transport, MSK, initial/replacement keys and authenticated transition policy integrated | System profile/method startup and radio evidence; FT/Suite-B unfinished |
| Enterprise reauthentication/roaming | Same-association replacement published in 45335d8; sanitized regression and native/offline build passed; Enterprise roaming unimplemented | OS provenance, roam session handoff and radio evidence |
| Static WEP Open/Shared | Local default-off authentication, slot programs, firmware barriers and data-port completion integrated | AP interoperability; dynamic WEP uses a distinct system session and remains unadmitted |
| WPA1 / TKIP | Local default-off initial group exchange, retained key slots, MIC report/countermeasures and cancellation integrated | AP interoperability and final package acceptance |
| OWE | Local default-off group19 worker, association, four-way/PMF and capability96 integrated | Stock protected-transition selection and AP interoperability |
| Sleep/wake | Lifecycle implemented; possibly working | Platform sleep deferred by user |
| macOS 11–14, 15.0–15.1, 26 | Separate adapters unfinished | ABI recovery, implementation and per-OS verification |
| AWDL/AirDrop | Not implemented | Separate protocol/interface/channel integration stage |

## Published and local checkpoints

Uncontrolled EAP port lifecycle was published as
862ed1f0bba3df83732eb68860ad95edcd72ce69. Its 68-test sanitized regression and
exact-UUID offline linking are saved under NATIVE-eap-port-lifecycle-20261030.
Only after publication was source version advanced to 1.0.107. Version 1.0.107 metadata was included in 45335d8. After that publication was
verified, source metadata advanced to 1.0.108; that next metadata/changelog edit
remains local.

Published batch 45335d8 adds same-association Enterprise reauthentication: bounded
restart, retained queue and old transport ownership, deferred PMK replacement
without wiping established key/replay history, early key-frame admission, and
completion after firmware/M4/macOS notification barriers. Restart during an existing
pair/group key installation preserves that operation's port policy. Affected
sanitized fixtures passed; final full 68-test regression passed with ASan/UBSan, native build and offline inclusion passed.
Evidence: outputs/NATIVE-eap-reauth-contract-20261030. No new image installed.

Enterprise remains off. Static installed user-mode startup ordering is recovered;
actual Enterprise delivery and other startup modes remain unverified. A tokenless
MSK callback cannot prove EAP session provenance. Wrong PMK cannot pass the tested
M3 authentication boundary, but stale requests can still affect availability.

## Evidence and work policy

Use the consolidated suite once after final batch changes. Do not repeat accepted
manual scan/boot/Personal traffic checks without a changed affected path or new
failure. Keep intermediate edits local and publish a reviewed batch. Pending
OpenCore/APST changes and platform sleep are outside this driver batch; do not
infer their runtime state from the historical pre-reboot checkpoint.

The installed user-mode client starts before radio association, as recovered from
exact-UUID airportd/CoreWLAN. Initial empty MSK reset preserves the current empty
owner and original deadline. Expiry in a key callback explicitly cancels; service
retires orphaned EAP queue ownership without stopping authorized data. See the
EAP contract and audit for precise evidence and unresolved boundaries.

## Published roam ownership batch

Published admission/teardown guards retain pending PTK notification, EAP TX/queue and
replacement-authentication owners. Dispatcher waits allow the old link's key
completion to progress instead of returning before its producer. Added fixtures
cover residual EAP owners and notification retry ordering. The full 68-test regression passed with ASan/UBSan; native compilation, strict
isolated signature and exact-UUID offline inclusion passed. Candidate UUID
CB30D84D-5AAB-3595-AFD4-F259BD9CB5AA, source version 1.0.108. Published as a88bbed after exact remote-tree verification.
Only after that publication, local metadata advanced to 1.0.109. The metadata-only 1.0.109 candidate was subsequently rebuilt, validated, installed
and boot-verified; its metadata update is not yet published. Enterprise
roam admission is still unsupported until the OS session handoff is implemented.

## Published address-notification group

Four host notifications now reach the stock interface cache: IPV4_PARAMS,
IPV6_PARAMS, legacy OFFLOAD_ARP and OFFLOAD_NDP. These are synchronous gated
copies, not firmware-offload activation. Invalid counts fail before mutation;
unused bytes are zeroed; empty IPv6 lists clear the cached list. Legacy ARP
preserves the old local IPv4 when its replacement word is zero and always updates
gateway/MAC. Explicit replacement with zero clears the gateway as stock does.
No separate retained pointer or asynchronous address owner is introduced, and
radio roam does not clear OS-owned L3 state. Existing stop/power/MAC admission
applies to all four requests. The added getter bridge preserves upstream headers.

Focused production dispatch and request admission checks passed; final expanded
69-test regression passed with ASan/UBSan. The current native build, strict
isolated signature and exact-UUID offline inclusion passed, including the getter
bridge (UUID F1A75ABE-5C9E-3570-9DF7-0C62A3422E9C). DHCP sleep hint, conditional traffic
engineering and radio ARP/NS offload remain unfinished; no capability advertised.
Published as add6acf41627edc4d7158a31db7bec597c752d08 after exact remote-tree
verification. Only then metadata advanced locally to 1.0.110; metadata is not yet
published. Installed image is now boot-verified 1.0.110.

Hardware candidate 1.0.110 is ready, UUID E39009FE-C6F8-385B-8B0C-B6DC48AED01A.
The metadata-only rebuild passed strict signature and exact-UUID offline inclusion;
current EFI 1.0.109/config and new candidate copies were hash-verified on SD.
Installation/reboot explicitly authorized and executed; loaded UUID verified.
Evidence: outputs/NATIVE-1.0.110-hardware-candidate-20261030/READY.json.

## Published traffic-policy package

Host mbuf traffic class now survives admission and HTT descriptor generation; AP ACM downgrade remains enforced. Native host Fastlane marking is applied synchronously within WCL after releasing radio, protected by the existing termination fence; link-down clears it. Enabled ACM override remains unsupported. All 71 tests passed with ASan/UBSan. Native build, strict isolated signature and exact-UUID offline inclusion passed (9A28E4F5-FD99-3724-9599-3B470EFC47AE). Hardware verification remains pending. This code is not in the installed 1.0.110 UUID listed above. Congestion-monitor and battery-policy integration remain open.

Published as 8235cbda431a4a7b90fbce09c9f70014c925a746; remote tree exactly matched the reviewed index. Only then metadata advanced locally to 1.0.111. Candidate rebuild/installation remains pending; installed 1.0.110 is unchanged.


## Local security batch: receive compatibility checkpoint

Raw decrypted group TKIP now normalizes IV/Michael/ICV/FCS before the existing
batch integrity and TSC checks. MIC attention is classified as Integrity.
Original-MPDU A-MSDU admission rejects group receivers and encrypted non-CCMP
ciphers before replay publication. RX pipeline/security diagnostics and actual
controller delivery fragments passed ASan/UBSan with mocked system delivery.
These edits remain unpublished/uninstalled. Pairwise TKIP, WPA1 join/handshake
and WEP/dynamic-WEP admission remain incomplete. Current group-TKIP MIC handling
is locally integrated as described below; this is not complete legacy compatibility.

## Local group-TKIP MIC lifecycle

Qualified raw/native RX failures now reach the native owner, bound to the active
profile and acknowledged GTK slot epoch. Duplicates do not create new reports.
The established KCK authenticates reports; separate TX receipts cannot authorize
M4. A second failure within 60 seconds blocks ordinary traffic without disabling
the encryption needed for reports. Existing key/EAP work drains, new key input
waits, and radio wake/scan cancellation remains bounded.

The native notification path emits event 6 with a six-byte BSSID and discards
stale events. The driver attempts reason-14 deauthentication after report completion
or failure before normal key/DMA teardown. The original six-second bound remains.
Group-TKIP rejoin exclusion survives association cleanup; stop persists nonsecret
timing on the PCI provider for rematch, and suppresses automatic rematch if saving
fails. No key, frame or old completion ticket is restored.

Focused production-method fixtures and native compilation have passed; physical
MIC injection, AP interpretation and runtime rematch have not been tested. This
path covers the current RSN/CCMP-pairwise/TKIP-group profile only. WPA1, pairwise
TKIP and legacy Enterprise must extend these contracts before being advertised.
Final package validation, signing and installation remain pending.

## Legacy Enterprise scope in the active security package

Required profiles include WPA1-Enterprise/TKIP, WPA2-Enterprise TKIP/CCMP
and dynamic WEP-40/104 with 802.1X. The EAP contract tracks EAP-TLS,
PEAP/MSCHAPv2, TTLS inner methods, EAP-MD5, LEAP and EAP-FAST separately
from link cipher support. Installed-client static registration evidence is
available; it does not prove usable key export or end-to-end compatibility.
Dynamic-WEP descriptor-1 authentication belongs to the stock system client;
routing, native key admission and firmware completion remain incomplete.
Enterprise remains disabled by default. These requirements belong to the same
security batch, not a separate per-method publication or reboot series.

### Local WPA1 raw GTK decoder

Descriptor-version-1 raw group-key decoding now validates role, replay, configured
key length, RSC and MIC before publishing output. Two affected sanitized fixtures
pass; snapshot verified on SD (wpa1-group-decode). Not yet wired to the native
supplicant: PTK lifecycle, retransmission acknowledgements and legacy admission
remain unfinished. This does not establish WPA1 interoperability.


## Local RSN pairwise TKIP handshake

Local opt-in RSN pairwise-TKIP handshake integration

Supplicant now owns a complete 64-byte PTK and retains/restores it across
pairwise rekey cancellation. Explicit compile-time AND selected-cipher opt-in
admits RSN AKM1/2 TKIP without required PMF, unsupported nonce modes or implicit
downgrade. Descriptor-version1 HMAC-MD5/RC4 uses RSN KDEs; it is distinct from
WPA1 descriptor254/raw GTK. Association and M2 carry the same selected suites.
Key export expands 56->72 bytes, preserving old offsets and appending Michael
subkeys in authenticator order. Native staged buffers use the shared size;
admission checks selected pair cipher and firmware handoff preserves all32
bytes. Firmware adapter remains sole MIC-subkey swap owner.

Tests: sanitized security, wpa1_key_auth, native_security_lifecycle,
native_eapol_completion, native_eap_service, native_pmf_receive, native_sae_radio
passed. Pairwise fixture covers M1/M2/M3/M4, bad MIC, exact/incremented retry,
rekey cancellation, completed pairwise rekey with unchanged GTK, group rekey,
Enterprise admission and required-PMF rejection. Existing CCMP vectors pass.
Native build and symbol check passed; unsigned development image only.

Native AllowTKIP remains false. Pairwise MIC error/report/countermeasures,
HT/VHT restrictions, full WPA1 association and dynamic WEP/Enterprise owner
integration remain incomplete. No physical legacy interoperability claim.
No full suite, final signature/offline KC verification, install, version bump,
commit, push or reboot. All edits belong to the same unpublished security batch.

Evidence: outputs/NATIVE-security-compatibility-20261030/rsn-pairwise-tkip; identical SD copy verified.


## Local pairwise/group MIC evidence

Local pairwise/group TKIP MIC integration

RX now qualifies unicast TKIP failures against local address, peer, key index0,
installed PTK epoch and TID replay floor. PTK epochs are published only at the
firmware key receipt; counters survive association reset, installed epochs clear.
Pairwise and GTK histories are separate in the MIC owner; shared exclusion and
transport/deauthentication policy is preserved. Reports select pairwise bit and
established-profile descriptor/HMAC (MD5 for TKIP pairwise, SHA1 for CCMP).
Native events queue exact type5/6 per failure, retaining order through delivery
failure, with six-byte BSSID. Rejoin exclusion covers either TKIP cipher.

ASan/UBSan affected tests passed: tkip_mic_owner, native_tkip_mic_service,
native_notifications, rx_security_diagnostics, security, wpa1_key_auth,
network_rx, connection, security_disconnect, native_security_lifecycle,
native_mic_persistence. Explicit new fixtures cover pair/group same-number
independence, shared exclusion, stale epoch, index/local address/PN rejection,
MD5-signed pair/group reports, native pair report selection and event5/6 ordering.
Firmware epoch commit and reset retention assertions passed. Native build and
symbol check passed; development image is not a signed/installable candidate.

Native TKIP admission remains off. Remaining: HT/VHT policy, legacy profile
selection/WPA1 association and handshake, dynamic WEP/Enterprise ownership,
full grouped regression and hardware candidate. No new physical MIC evidence.
No commit, push, version change, install or reboot.
Next radio policy reference:
https://wireless.docs.kernel.org/en/latest/en/developers/documentation/mac80211.html

Evidence: outputs/NATIVE-security-compatibility-20261030/pairwise-mic-integration; identical SD copy verified.


## Local legacy pairwise radio policy

Local legacy pairwise radio policy

Selected WEP40/TKIP/WEP104 pairwise cipher disables HT/VHT at common PHY
negotiation: 20 MHz, one stream, no SGI/MCS. Candidate preparation carries the
selected pair cipher into that same negotiation. Group TKIP with pairwise CCMP
retains HT/VHT. Association/firmware serialization rejects stale incompatible
HT/VHT/width state without modifying the output. peerRateSet clamps maintenance
NSS/width overrides for legacy pairwise mode, preventing fast PHY flag revival.

ASan/UBSan connection, channel_switch and ap_maintenance passed. New production
serialization fixtures inspect absent HT/VHT/operating-mode IEs and firmware
flags even under a requested 2-stream/80-MHz override; all three legacy ciphers
and CCMP+TKIP-group contrast covered. Native build and symbol checks passed.
Unsigned development image only; no final offline KC/signature acceptance.
Reference: https://wireless.docs.kernel.org/en/latest/en/developers/documentation/mac80211.html

Still incomplete: native legacy profile admission and matching association IE,
WPA1 complete handshake/native selection, dynamic WEP/Enterprise lifecycle and
full grouped regression/hardware validation. No native TKIP capability enabled.
No publication, version change, install or reboot.

Evidence: outputs/NATIVE-security-compatibility-20261030/legacy-radio-policy; identical SD copy verified.


## Local selected-profile RSN encoding

Shared selected-profile RSN encoding

Association frame and supplicant EAPOL M2 now use buildSelectedStationRSN.
Explicit pair/group TKIP/CCMP and ordinary AKM1/2 are encoded without fallback;
AKM6 remains CCMP-only. SAE/PMKID encoder is unchanged. Native profile admission
remains separate and legacy-disabled; encoding support is not radio support.
This fixes the previously divergent association encoder that always advertised
CCMP even when the opt-in supplicant selected pairwise TKIP.

ASan/UBSan connection wire tests inspect each pair/group/AKM1/2 combination.
RSN policy tests cover legal combinations, unknown selectors, short/null outputs
and transactional rejection. security, wpa1_key_auth, sha256_supplicant and
sae_eapol passed. SAE first exposed an old fixture initializing only56 of the
now72-byte key export. Fixture now checks the whole payload, plus zero TKIP
extension for CCMP; final SAE regression passed. Native build/symbol check pass.
Full suite not run; no signature/offline KC/install acceptance claimed.

Remaining: native explicit legacy profile selection and AP compatibility,
WPA1 descriptor254 handshake/association integration, dynamic WEP/Enterprise
ownership, final grouped validation and hardware candidate.
No commit/push/version increment/install/reboot.

Evidence: outputs/NATIVE-security-compatibility-20261030/selected-rsn-encoding; identical SD copy verified.


## Local exact RSN profile admission

Shared exact RSN profile admission

Core candidate/association-response checks and the supplicant now share
supportsSelectedRSN. A requested pairwise cipher must be present in the AP
advertisement, with the exact AKM, supported group cipher and capabilities.
Legacy core gate defaults false; opt-in enables ordinary AKM1/2 TKIP pair/group
profiles, while SHA256 remains CCMP-only and SAE retains its CCMP/PMF path.
This removes core's prior CCMP-only lookup that ignored selected pairCipher.
No native request sets the new legacy gate yet; native supplicant AllowTKIP
also remains false. Native selection/reconnect-profile binding remains needed.

Six affected ASan/UBSan tests passed: connection, rsn_policy, security,
wpa1_key_auth, sha256_supplicant, sae_eapol. Production-path fixtures cover exact
suite/AKM matches, wrong selected suite/AKM rejection, legacy gate, PMF-required
and unsupported capabilities. Native build and symbol check pass.
Local corecrypto symbol inventory contains external _ccmd5_di; this is static
evidence only, not a kernel MD5 execution test or all-OS ABI certification.

Remaining: explicit macOS legacy request decoding and stored-profile binding,
WPA1 complete descriptor254 handshake/native selection, dynamic WEP/Enterprise
lifecycle, final grouped regression/signature/offline dependencies/hardware.
No commit, push, version increment, install or reboot.

Evidence: outputs/NATIVE-security-compatibility-20261030/selected-rsn-admission; identical SD copy verified.


## Static stock join profile evidence

Recovered installed join security path (static evidence)

WCLJoinRequest::fillAssocCandidatesList at ffffff8002231cbe copies the key
structure from request+0x64 into candidate+0x40 (0x94 bytes), separately from
RSN/WPA IE at request+0xfa -> candidate+0xd6 (257-byte slot). Length at
candidate+0xd4 is produced by trimRsnIeLen, ffffff8002231c12: bounded to257 and
retained only for recognized authentication values. Thus keyCipher is key
material metadata, not an independent proof of the selected radio cipher.

AppleBCMWLANJoinAdapter::performJoin calls getBcomPropertiesFromWPARSN at
ffffff8001584f5b with length from candidate+0xd4. Nonzero return branches to
failure handling. Parser entry ffffff800165190c dispatches RSN element48 and
WPA vendor element221. RSN branch maps group selector at+4, reads pairwise count
at+8, maps first pairwise selector at+10 and then proceeds from+14. This is
consistent with a selected association IE, not a general AP list negotiation;
this local excerpt alone does not establish every upstream normalization rule.
setAssocRSNIE at ffffff8001586ca0 also passes the IE as a separate commander
payload. No password/key material or live credential dumps were collected.

Implementation consequence: recover/validate explicit request RSN/WPA profile
separately from PMK/password envelope; bind selected pair/group/AKM to stored
profile and carry it through prepareRoamJoin. Current prepareRoamJoin overwrites
request.rsn with the target AP advertisement, while ProfileCredentials stores
only auth plus raw request; this needs explicit selection preservation before
native legacy enablement. Do not infer TKIP from PMK/password keyCipher, and do
not copy a multi-suite AP advertisement as proof of a single selected cipher.

No production edits/build/tests/publication/installation/reboot in this pass.
Native legacy admission remains disabled. Next work is selected request profile
ownership and native binding, then full WPA1/dynamic-WEP lifecycle.

Evidence: outputs/NATIVE-security-compatibility-20261030/stock-join-security-contract; SD copy verified.


## Local selected cipher profile ownership

Stored profile cipher ownership and selected roam IE

ProfileCredentials now retains the selected pairwise cipher and legacy gate
alongside credential/auth generation; replacement validates combinations and
clear retires them. prepareRoamJoin requires an exact live/profile binding before
candidate selection. It emits one station RSNE from the stored cipher/current
AKM and validated target group cipher, not the target AP multi-suite IE. SAE
emits its selected PMF RSNE without copying an old AP PMKID. Open emits no RSNE.
Profile policy restriction preserves selected cipher while changing generation.
Native join explicitly establishes the currently admitted CCMP/nonlegacy mode,
and retains those actual selected values instead of inheriting retired state.

ASan/UBSan native_profile, native_leave and native_sae_radio passed. Added owner
retirement/policy-generation/mismatch rejection and multi-suite target tests;
failed preparation preserves outputs, target AP capability list stays intact,
selected request carries only CCMP/PSK in that fixture. Existing cache freshness
and secret lifecycle tests passed. Native build and symbol check passed.

Remaining: native incoming selected RSN/WPA decoding and legacy admission,
carry that explicit choice through the final join/crypto path, WPA1 complete
handshake, dynamic WEP/Enterprise lifecycle and final batch/hardware acceptance.
Core legacy profile ownership is not a claim of native TKIP roam support.
No full suite, signature/offline KC check, publication/version bump/install/reboot.

Evidence: outputs/NATIVE-security-compatibility-20261030/profile-cipher-binding; identical SD copy verified.


## Local native selected RSNE input

Native selected RSNE decoding and join binding

nativeSelectedRSN decodes one explicitly selected pairwise suite/AKM independently
of PMK/password keyCipher. Empty override keeps supported CCMP default; nonempty
RSNE must be well formed, contain one pairwise and one AKM, match native upperAuth
and pass existing profile policy. NativeBeginJoin binds the result to connection
and retained profile, then checks selected group against target AP before starting
crypto/radio. Malformed/multi-suite/contradictory or unsupported legacy selection
is rejected without publishing a profile; input key is wiped.

ASan/UBSan native_wire, native_profile, native_sae_radio pass. Added real native
join fixtures for exact/empty selection success, group mismatch, pairwise TKIP
while disabled, AKM conflict and malformed length; failures leave no radio work
or retained profile. Helper tests cover explicit legacy opt-in separately;
production passes false. Native build and symbol check pass.

Runtime compatibility of nonempty macOS override remains unverified; static
stock evidence and fixtures are not hardware proof. WPA1 vendor IE remains
unsupported pending descriptor254 handshake integration; dynamic WEP/Enterprise
and final native legacy crypto/admission enablement remain incomplete.
No full suite, final signature/offline KC, publication/version bump/install/reboot.

Evidence: outputs/NATIVE-security-compatibility-20261030/native-selected-request; identical SD copy verified.

## Local WPA1 handshake checkpoint — 2026-10-30

WPA1 software exchange now distinguishes initial PTK and initial GTK completion; authenticated retries and pair/group rekey are covered for TKIP/CCMP. RSNXE binding is rejected for WPA1. Affected wpa1_key_auth, sha256_supplicant and sae_eapol tests passed with ASan/UBSan; native compilation and symbol check passed. This does not establish native WPA1 admission or kernel MD5 execution: InitialPairKeys/InitialGroupKeys still require native install/receipt barriers before enablement. No installation, publication or version change. Evidence and hashed source snapshot: outputs/NATIVE-security-compatibility-20261030/wpa1-handshake, verified on SD.

## Local WPA1 native key barriers — 2026-10-30

InitialPairKeys and InitialGroupKeys now enter distinct native installation
stages. PTK ACK skips the absent GTK, M4 receipt leaves the port closed, and
first GTK ACK clears the pending-install marker. Its EAPOL reply is protected
under PTK before port authorization; only its matching successful TX receipt
requests authorization. Firmware/RX barriers remain; terminal secret cleanup
clears both initial-group markers. The existing 15-second handshake timeout
bounds first-GTK waiting. No native WPA1 profile has been enabled yet.

Affected sanitized tests: native_eapol_completion, connection,
security_disconnect, native_key_stage passed. Earlier affected lifecycle and
SAE-radio tests passed before the final group-ACK protection edit. Tests cover
actual extracted staging/completion and firmware service code, but inject
WPA1 key exports: they do not prove stock WPA1 association or radio operation.
Native compilation and symbol check passed; this is not final signing/KC
acceptance. Evidence: outputs/NATIVE-security-compatibility-20261030/wpa1-native-install.
No commit, push, version change, installation or reboot.

## Local WPA1 profile and association — 2026-10-30

Added explicit opt-in WPA1PSK/WPA1EAP decoding and selected WPA vendor-IE
validation. Mixed upper-auth requests, disabled-transition profiles, contradictory
AKMs and incomplete selected IEs are rejected. Empty WPA1 selection uses TKIP;
nonempty requests explicitly select TKIP/CCMP and matching group/AKM.
Core candidate selection now follows wpa1Selected instead of accepting RSNE as
a substitute; association emits selected WPA IE, and any WPA IE in the response
is validated against the chosen cipher/group/AKM. PMF is not admitted for WPA1.
Existing WMI NEED_GTK_2_WAY handling remains consistent with inspected Linux
ath10k_peer_assoc_h_crypto; it was not reinterpreted as host port authorization.

ASan/UBSan native_wire, connection, native_profile and native_sae_radio passed;
connection was rerun after adding mixed-AP candidate tests and passed. Native
build/symbol check passed. No WPA1 native join is enabled: nativeBeginJoin still
uses the default-disabled decoder gate; stored credentials, EAP/PSK handoff and
kernel crypto execution remain integration gates. No installed or radio claim.
Evidence: outputs/NATIVE-security-compatibility-20261030/wpa1-profile-association,
with hashed source/log copies on SD. No publication, version change or reboot.

## Local WPA1 saved-profile ownership — 2026-10-30

ProfileCredentials now admits explicitly opted-in WPA1 Personal/Enterprise,
binds protocol as well as pair cipher/legacy gate, and rejects contradictory
selected WPA IE. Authenticated transition-disable invalidates a now-forbidden
WPA1 profile and retires its credential generation. Personal handoff rebuilds
the selected WPA IE from the validated target observation and preserves the
credential owner; a WPA1/WPA2 state mismatch rejects without changing output.
Enterprise host roaming remains rejected pending native EAP session handoff.

Sanitized native_profile, native_security_lifecycle and native_sae_radio tests
passed; native compilation and symbol check passed. Native join startup still
does not opt into WPA1, so this is local ownership integration, not radio
support. Evidence: outputs/NATIVE-security-compatibility-20261030/wpa1-profile-owner.
Source/log hashes verified on SD; no commit, push, installation or version bump.

## Local legacy password-job ownership — 2026-10-30

The asynchronous PSK preparation owner can explicitly opt into legacy profiles;
it binds WPA1/WPA2, selected pair/group ciphers and the matching AP security IE.
AP suites and explicit selected-group agreement are validated before scheduling.
Collection rejects changed protocol, pair/group cipher, AP WPA IE, generation,
cancelled association and expired work. PBKDF2 remains outside the radio gate.
The initial cancellation fixture incorrectly invoked a cancelled queued callback;
it was corrected to cancel a dispatched callback and prove its retired PMK is
not returned. The final sanitized native_sae_radio suite passed, including existing
SAE/EAP/PSK paths and nine legacy-owner scenarios. Native build and symbols passed.

The native caller still uses the default-disabled legacy gate. Remaining work:
common native PMK-to-supplicant startup, WPA1 EAP master handoff, and kernel legacy
crypto/admission validation. During inspection the direct PMK branch was found to
ignore random(nonce) failure; fix and inject that failure with the startup work.
No publication, version bump, installation or reboot. Evidence:
outputs/NATIVE-security-compatibility-20261030/legacy-password-owner, verified on SD.

## Local common master-key startup — 2026-10-30

Direct PMK, completed PSK password job and initial system EAP PMK now use the
same beginMasterKey adapter. It preserves selected pair cipher, binds the AP
group cipher and routes WPA1 to its own handshake without RSNXE; RSN keeps its
RSNXE binding. SAE remains on its separate session/PMKID owner. Native compile
gates still leave legacy handshake disabled until the remaining runtime gates.
The direct PMK branch now requires successful nonce randomness before any
supplicant startup; a real nativeBeginJoin failure-injection fixture verifies no
ready state, retained profile or radio submission. EAP failure tests still pass.

Full WPA1 software handshakes now run for AKM1 (Enterprise) and AKM2 (Personal),
all supported TKIP/CCMP pair/group combinations and CCMP/TKIP descriptor-version
compatibility. This proves key exchange after a supplied PMK, not stock EAP
method availability or RADIUS interoperability. ASan/UBSan native_eap_service,
native_sae_radio, wpa1_key_auth and native_key_stage passed. Native build/symbol
check passed. Evidence: outputs/NATIVE-security-compatibility-20261030/native-master-key-handoff.
No commit/push, version bump, installation or reboot; evidence verified on SD.

## Local legacy crypto admission check — 2026-10-30

Explicitly compiled WPA1 and RSN pairwise-TKIP startup now requires the RFC2202
HMAC-MD5 known answer. A failed primitive or successful return with a corrupt
result refuses initialization. No readiness is cached across provider changes.
The kernel provider wrapper validates digest output/state/block sizes and
required callbacks before cchmac, bounding its fixed output and scratch layout.

ASan/UBSan wpa1_key_auth and native_sae_radio passed; native compilation and
symbol check passed. An additional production-wrapper extraction test passed
12 missing/malformed descriptor and invalid-input cases, with no primitive call
or output mutation on rejection. This test simulates the descriptor and uses
CommonCrypto for the primitive; it does not prove kernel MD5 execution. WPA1
native join remains disabled pending integrated runtime admission/routing.
Evidence: outputs/NATIVE-security-compatibility-20261030/legacy-crypto-gate.
No commit/push, version change, installation or reboot. Verified SD copy.

## Local integrated native legacy startup — 2026-10-30

EAPOL routing binds exactly descriptor 2 (RSN) or 254 (WPA1) to the active EAP
association, preserves it during reauthentication and retires it on reset.
Descriptor 1 remains rejected pending the separate dynamic-WEP system owner.
Neither internal key descriptor is accepted on the system EAP TX path.
Native join now wires explicit legacy selection into AP admission, retained
profile, password worker, EAP owner and common master-key startup. The production
supplicant compiles TKIP/WPA1; nativeLegacyEnabled requires the explicit property
Ath10kNativeLegacyExperimental and the existing 24G90 identity gate. Enterprise
additionally requires Ath10kNativeEAPExperimental. Neither option was enabled in
EFI or the installed driver. MD5 known-answer checks gate actual legacy startup.

Sanitized EAP routing/owner/service and existing native lifecycle/key-stage/SAE
fixtures passed. A new production-method fixture passed 12 combinations of raw
PMK/password/EAP and TKIP/CCMP pair/group suites through nativeBeginJoin to ready
WPA1 supplicant; disabled admission rejects before retaining credentials. This is
simulated transport/system key delivery, not radio/EAP server interoperability.
The first routing fixture called before replacement start; its clock was fixed
and the complete affected routing selection passed. Native build and symbols
passed; actual MD5 kernel execution, KC admission and stock capability discovery
remain unverified. Evidence: outputs/NATIVE-security-compatibility-20261030/legacy-native-startup.
No commit/push, version change, installation or reboot; SD hashes verified.

## Local legacy capability/library alignment — 2026-10-30

getCARD_CAPABILITIES now advertises WPA1 bit13 only under the same
nativeLegacyEnabled gate used by join admission. It does not set the aggregate
WPA bit15 or WEP. Existing TKIP/TKIPMIC advertisement remains for the already
supported WPA2 CCMP-pair/TKIP-group path. Extracted production capability tests
cover all four legacy/SAE switch combinations, unchanged bits and buffer guards;
sanitized native_join and native_sae_radio passed. Native build/symbol check passed.

Read-only kmutil libraries against current BootKernelExtensions.kc resolved all
958 nm undefined imports, including _ccmd5_di in com.apple.kec.corecrypto. Every
resolved provider is present in candidate OSBundleLibraries. This is export and
dependency declaration evidence only, not candidate KC inclusion, signature
acceptance, runtime execution or all-OS compatibility. No system collection was
rebuilt or changed. Evidence: outputs/NATIVE-security-compatibility-20261030/legacy-capabilities-libraries.
No commit/push, version change, installation or reboot; SD hashes verified.


Local WEP contract checkpoint: stock SET operation3 is bound to the NET_MANAGER
observer; recovered separate handled/result aggregation and outer fallback to
driver. Evidence: stock-wep-bulletin-dispatch.json/.asm. WEP installation and
controlled-port ownership remain unfinished; no runtime capability enabled.


Local WEP envelope decoder implemented and native_wire ASan/UBSan matrix passed.
Not integrated into native callback, firmware or controlled port; no WEP support
claim. Source/log/reference snapshot: NATIVE-security-compatibility-20261030/wep-envelope.


Dynamic-WEP packet routing now exists behind explicit EAP-owner selection,
with descriptor isolation and owner-based native copy length. Three affected
sanitized tests passed (ASan/UBSan); native build/symbol check passed. Native
WEP admission, key lifecycle and controlled port remain unimplemented.
Evidence: NATIVE-security-compatibility-20261030/wep-system-routing.


Local firmware cipher mapping is explicit and shared by existing TKIP/CCMP
serialization/receipt checks; WEP40/104 mappings covered without enabling WEP
receipts in the RSN machine. Connection ASan/UBSan and native build passed.
Evidence: NATIVE-security-compatibility-20261030/wep-firmware-ciphers.


Local KeyTransaction helper now retains acknowledged-operation ownership until
explicit firmware/RX fence retirement and bounds submission/fence deadlines.
Affected ASan/UBSan tests passed. Not yet integrated into native key service.
Evidence: NATIVE-security-compatibility-20261030/key-transaction-fence.


Local native WEP key callback now copies requests into the explicit EAP owner
with bounded queue, monotonic tickets, ordered duplicate handling and secret
retirement. Three affected sanitized tests/native build passed. Native admission,
firmware consumption and controlled port remain unfinished; WEP not enabled.
Evidence: NATIVE-security-compatibility-20261030/wep-key-owner.


Local WEP owner retains confirmed slots and suppresses identical reprogramming
requests, preserving queued replacement order. Clear/expiry wipe both stores.
Two affected sanitized tests and native build passed; completion is simulated,
firmware consumer/native admission/port authorization remain unfinished.
Evidence: NATIVE-security-compatibility-20261030/wep-confirmed-slots.


Local WEP planner distinguishes key installation, default-TX selection and
metadata-only changes; queued TX choices are included in duplicate detection.
Added bounded DEF_KEYID serializer. Callback/connection ASan/UBSan and native
build passed; firmware consumer/native admission/port completion still pending.
Evidence: NATIVE-security-compatibility-20261030/wep-transmit-selection.


Local WEP planner/owner now reflects group-to-pair same-index mirroring and
avoids unnecessary rewrite of unchanged halves. Queued individual replacements
prevent incorrect duplicate suppression. Two affected ASan/UBSan tests and
native build passed; firmware consumer/rollback/admission/port remain unfinished.
Evidence: NATIVE-security-compatibility-20261030/wep-pair-mirror.

## Passwordless hardware priority — 2026-10-30

Installed1.0.110: A10_Open eventually appears after directed scan, but Open and OWE Transition UI joins fail with0xe0822402 in stock candidate selection. Pure OWE is recognized as AKM18 and fails with-3900; no native OWE implementation claimed. No DHCP/traffic success on test APs. Evidence and stock disassembly: outputs/NATIVE-passwordless-tests-20261030. Next work is candidate matching and complete OWE path, ahead of credentialed lab profiles.

## 2026-10-30 — preserve OWE transition advertisements (local)

The management decoder and native BSS serializer now retain the WFA vendor IE
50:6f:9a:1c byte-for-byte, including opaque payload extensions. Duplicate
transition IEs and truncated TLVs reject the beacon; an update without the IE
clears the previous value. Serializer validates the vendor envelope and total
capacity before modifying output. This transports AP metadata only: no OWE
capability is enabled, no transition target is trusted for association, and no
plaintext downgrade is added. Native OWE crypto/admission/key lifecycle remains
unimplemented. This omission is confirmed in source, but is NOT established as
the cause of A10_Open's candidate-selection failure.

Vendor ID primary reference: hostap ieee802_11_defs.h at commit
c4ca476ad224fd376ee52a70dbb5b0f9f7f82408 (OWE_IE_VENDOR_TYPE=0x506f9a1c).

## 2026-10-31 — whole-AP UI inventory, installed 1.0.110 unchanged

The native Settings pass supersedes broad conclusions from CLI candidate lookup failures.
Open now has verified DHCP, 3/3 gateway replies and HTTPS HTTP/2 200 bound to en1
following the user's router correction. Open Transition associates as plaintext;
its traffic still fails. Pure OWE UI rejects (-3900); no secure transition implemented.
All five WEP profiles, WPA1 PSK TKIP/CCMP and WPA2 TKIP were attempted with supplied
credentials through native UI and rejected. Captured airportd records confirm
0xe00002c7 for WEP40 Open, both WPA1 modes and WPA2 TKIP. WPA1 UI incorrectly calls
the credential WEP. Remaining WEP failures are UI-observed, not assigned an inferred code.
Mixed WPA2 TKIP/CCMP associates (AKM2/phase5); this is not proof of TKIP cipher use.
After repeated joins, SAE and mixed WPA2 reached link-local without a DHCP gateway;
router configuration changed during the pass, so ownership of the DHCP failure is
unresolved. Early address-less snapshots are not final failures.
Seven EAP SSIDs are visible; EAP192 UI asks account/password, cancelled without
submission. TLS system identity/profile and the loaded EAP admission gate remain
barriers; no RADIUS success claimed. Wrong hidden-network UI labeling reappeared.
Evidence: outputs/NATIVE-all-AP-matrix-20261030/MATRIX.md, ui-runtime and
airportd-ui-errors.txt. USB en0 remains primary for the ongoing test campaign.
No driver edits, installation, version bump, commit or reboot in this pass.
Next: finish outstanding TLS-profile/admission and packet-path inventory, correlate
failures by stage, then implement one grouped security package.

### 2026-10-31 — DHCP and installed-code correlation

Controlled DHCP renewal on en1 (WPA2, same peer52, phase5) captured five requests
and no replies over25 seconds. TX completions increased84→134, NoAck/errors and
RX/security/drop counters stayed unchanged. Link-local address remained. This
narrows investigation to AP delivery/response and the receive path; completion
is not proof of DHCP delivery to server. AP-side DHCP evidence requested for the
observed private station MAC. Earlier passive20s window had no packets and cannot
support a traffic conclusion. Evidence: dhcp-renew-window.json in all-AP bundle.
Verified installed source add6acf nativeBSSMessage omits WPA vendor IE, consistent
with WPA1 networks being presented as WEP. Existing local source already preserves
WPA IE; no new driver change made. Loaded EAP experimental property absent, while
SAE property is true; Enterprise admission is an actual installed barrier.

### 2026-10-31 — AP-side DHCP evidence supersedes uncertainty

Via authorized LuCI terminal, br-a10lab5 captured five DHCP requests from the
Mac station during controlled renewal, no responses. Hostapd confirms RSN
pairwise handshake; a historical .188 lease exists. Both br-a10lab and
br-a10lab5 have172.29.77.1/24 and equal-subnet routes; DHCP configuration has
only a10lab section. Open is on br-a10lab, WPA2/SAE/Transition on br-a10lab5.
This proves client DHCP reaches the AP after decryption; absence of server
responses is an AP-side issue in this interval, not evidence of driver RX loss.
No router changes. Evidence: openwrt-observation.json.

### AP follow-up correction: separate DHCP exists; firewall rules missing

Runtime-v5 dnsmasq PID21470 is bound to br-a10lab5. The earlier claim that
DHCP was configured only for the first bridge described UCI incompletely and
is superseded. a10lab5_input/forward are empty and unreferenced by main
input/forward chains; saved rules allow DHCP/DNS/WAN and retain isolation.
Selected inet fw4 rules passed nft check-only, not applied; user approval
requested because restoring them changes network access. Duplicate-subnet
routes remain a separate topology concern, not proved the immediate cause.

## 2026-10-31 — router restored, native traffic matrix advanced

User approved restoration. Applied saved inet fw4 rules only; verified input/forward
chains, parent jumps and isolation drops. Backup /tmp/a10-before-restore.nft on router.
DHCP immediately recovered (.188 WPA2). Route lookup sent replies through wrong
br-a10lab; added temporary per-station /32 routes via br-a10lab5 for .188,.141,.129,.122.
After correction, en1-bound HTTPS HTTP/2 200 passed for WPA2 PSK, plaintext OWE
Transition (AKM0), SAE (AKM8/phase5), and mixed WPA2 (AKM2/phase5). Native-source
DNS through test router also passed on mixed WPA2. Open was verified earlier.
These are bounded traffic results, not prolonged stability or TKIP cipher proof.
Ping to gateway is intentionally blocked on br-a10lab5 and must not be used as
acceptance failure. No driver edits/install/reboot. Remaining router issues:
duplicate subnet topology, runtime rule persistence, eventual cleanup of /32 routes.
Evidence: outputs/NATIVE-all-AP-matrix-20261030/ui-runtime/*after-router-repair.json
and openwrt-observation.json. Legacy/OWE/Enterprise acceptance remains open.

## 2026-10-31 — grouped security continuation: queued WEP mirror ordering

Whole-AP inventory now separates successful native traffic on Open, plaintext
Transition, WPA2, SAE and mixed WPA2 from legacy UI failures and Enterprise/OWE
admission barriers. Active plan moved from historical Fast Lane to the complete
security compatibility package; no hardware success inferred for blocked profiles.

Source review found reverse WEP aliasing: installed (or queued) individual A,
queued group B, then individual A could suppress the final request as a duplicate,
although QCA group programming also overwrites the pair slot. Duplicate lookup
now treats a queued same-index group write as an individual-slot replacement.
Production nativeSetCipherKey fixtures cover installed and queued history with
individual flags1/5, retaining group B and final individual A separately. Focused
callback test passed with assertions enabled; this run used no sanitizers and
is not full batch acceptance or firmware/hardware evidence. WEP firmware
consumer, rollback, admission and controlled-port integration remain unfinished.
No installation, reboot, commit, push or build-number change.
Evidence: outputs/NATIVE-security-compatibility-20261030/wep-queued-mirror-order.

### 2026-10-31 — complete WEP operation planning (local, not firmware execution)

The queued key owner now exports an immutable, secret-free program bound to
its generation and head ticket. New group material schedules group then pair;
already matching halves are omitted. A new individual key may require pair
installation followed by default-TX selection. Retained-key selection never
rewrites key material; metadata-only updates produce a valid empty program.
Expired/stale owners and empty queues produce no valid program.

Reference inspected: local ath10k-pmf-reference/mac.c, ath10k_set_key lines
6612–6652 and WMI_KEY_* definitions in wmi.h (pairwise0, group1, TX usage2).
The serializer's existing flag mask already permits these values; no guessed
Apple-to-WMI flag copy or firmware capability change was made.

This is the full operation plan consumed by the future serialized firmware
executor, not that executor itself. Confirmed slot completion must still wait
for every operation and its fence; partial failures require teardown/rollback.
Native admission, WEP RX/TX and controlled-port integration remain open.

Validation: four affected tests passed ASan/UBSan with assertions enabled;
full batch regression deferred until final integration. Evidence and source
snapshots: outputs/NATIVE-security-compatibility-20261030/wep-operation-program;
SD copy byte-verified. No install, commit, push or version change.

### 2026-10-31 — WEP key ownership across service and roam

EAPOwner::pending previously counted only outgoing EAP packets. A queued WEP
key could therefore be omitted from roam-retirement guards, scan cancellation
and ordinary-TX hold. Pending now covers both kinds, with keyPending exposing
the key-only case. Successful key enqueue asserts the ordinary-TX hold
immediately. EAP service preserves that hold even with no outgoing packet;
it still drains real EAP TX completions and allows system EAP transport.

Production-path fixtures cover a key-only owner, scan cancellation, EAP TX
with a pending key, completion retirement, expiration and rejection of a roam
without discarding the old key owner. native_eap_service, native_eap_callback
and native_sae_radio passed with ASan/UBSan and assertions. These changes
retain ownership; they do not install WEP keys, authorize data, or prove WEP
hardware support. Firmware executor and admission remain pending in this
same unpublished security package.

Native build/link and symbol check passed (warnings retained in build log).
Evidence: outputs/NATIVE-security-compatibility-20261030/wep-lifecycle-holds,
byte-verified on SD. No installation, commit, push, version bump or reboot.

### 2026-10-31 — WEP execution state machine (radio wiring pending)

Ath10kNativeWEPExecution now consumes the complete queued program and emits
actual existing WMI serializers for 5/13-byte group/pair installs and default
TX selection. It retains the association generation, queue ticket, peer ID,
index, size and whole-request deadline without copying key material. It
separates submission, matching HTT receipt, CE/credit retirement, ECHO/RX
fence and final queue commit. Default-index writes do not wait for a key HTT
receipt; they still require transport retirement and a fence.

Only final completion updates confirmed slots. Timeout, clock rollback, lost
owner or cancellation poisons the operation; only externally proven firmware
retirement permits reuse. The caller must provide actual transport/fence
evidence: the state machine cannot manufacture an ECHO or identify a delayed
wire response using its host ticket. It is not yet wired into radio service,
HTT dispatch, teardown or native admission; do not advertise WEP support.

The new native_wep_execution test runs command bytes and state transitions
for both lengths, group mirroring and individual/default-TX writes, wrong
receipts, early commit, timeout across operation phases, and owner retirement.
ASan/UBSan passed. Included in the consolidated test entry point; no full-suite
claim, install, publication or version increment.

### 2026-10-31 — separate WEP HTT receipt ownership

ConnectionState now contains a dedicated WEP receipt mailbox. Arming requires
a current mapped peer, a nonzero host generation/ticket, a connected explicit
WEP Enterprise association and no RSN/WPA install phase or prior mailbox.
Production HTT validation matches the selected receipt cipher/cast and exact
peer; duplicate, wrong-context and unexpected receipts are rejected. Commit
updates only the WEP mailbox and diagnostics, never securityAck or port access.
The mailbox remains armed after receipt until its consumer proves the firmware
and RX fence; retirement requires its original host generation/ticket. Normal
resetDisconnected clears it with the rest of retired association state.

The test exercises real validateConnectionHTT/commitConnectionHTT for WEP40/104
and both casts, plus early/wrong-ticket retirement and replayed indications.
This wires receipt classification, not the radio sender: WEPExecution still
needs the service-loop transport/ECHO adapter and teardown integration before
native admission or WEP support can be enabled.

Validation: native_wep_execution, connection and security_disconnect passed
ASan/UBSan; native build/link and symbol check passed (warnings retained).
Evidence: outputs/NATIVE-security-compatibility-20261030/wep-htt-owner, byte-verified
on SD. No hardware, full-suite, publication or installation claim.

### 2026-10-31 — native WEP service and cancellation integrated locally

serviceNativeWEP now runs from the native service loop. It consumes queued
programs through the shared CE3 command buffer, arms the dedicated HTT mailbox,
drains CE/credit ownership, submits uniquely correlated ECHO commands and waits
for pending RX work before advancing. The radio connection worker defers other
maintenance while this owner is active, but still drains data/packet completion
and processes cancellation. Scan cancellation and EAP packet ownership remain
independent. Complete programs update the EAP owner's confirmed slots only;
no controlled port is opened. Whole-program deadline is bounded to five seconds.

Host security discard cancels the executor without erasing uncertain firmware
ownership. Cancellation retains DMA ownership for ordinary disconnect; an
in-flight WEP ECHO is tracked as rollback work. WEP disconnect retires its
multi-slot state through peer DELETE/unmap, STOP and ECHO/RX instead of trying
to clear the RSN single-pair/current-GTK slot cache. Proven Disabled retirement
releases executor uncertainty. Key indications matching a cancelled/duplicate
WEP operation are consumed as ignored diagnostics, not RSN acknowledgements;
this supersedes the earlier statement that all duplicate WEP indications error.

Production service fixtures delay CE consumption, key receipts, ECHO and RX
retirement independently; verify group/mirror progression and no early queue
commit or port opening; retain DMA on cancellation/timeout; and reject host
cleanup as proof of firmware retirement. Eight affected tests passed ASan/UBSan
across the repair runs (service/executor, connection/disconnect, EAP service,
SAE radio, PMF receive and native security lifecycle). Two fixture include
errors were fixed; final tests and native build/link/symbol check passed.

Still missing before WEP enablement: native static/shared/dynamic admission,
RX/TX cipher integration and system controlled-port authorization. This is
local integration, not radio interoperability. No full-suite acceptance,
installation, push, commit, version bump or reboot.

### 2026-10-31 — WEP data-path slot admission (bounded local coverage)

Verified Linux v6.12 rx_desc.h: RX cipher0/1 means WEP40/104, unlike HTT
key receipts3/2. Source: https://raw.githubusercontent.com/torvalds/linux/v6.12/drivers/net/wireless/ath/ath10k/rx_desc.h .
Local htt_rx.c crypto-length helpers establish four-byte WEP IV/key ID and
four-byte ICV, with FCS stripped separately. Raw normalization now handles
that layout and preserves integrity error flags. Cipher2/3 are not admitted
as WEP40/104. Existing unsupported fragmentation remains rejected.

The native key service publishes per-cast/per-index installed lengths only
after the complete key program/fences succeed, then advances RX generation
to invalidate buffered packets from the preceding key set. WEP receive checks
that slot, RX cipher, mapped peer, BSSID, key ID/reserved bits, key-operation
hold and controlled port. No CCMP-style monotonic PN rule is applied to WEP IVs;
this does not invent cryptographic replay protection absent from WEP.

Confirmed default-TX selection is exported separately from installed key
bytes. BSD data admission and HTT packet construction reject WEP data without
a selected installed pair slot, and hold it during key programming. Secret
retirement clears both RX slot metadata and TX selection. Initial system EAP
transport remains independent from ordinary controlled traffic.

Tests cover both lengths/casts, raw normalization through the production RX
pipeline, wrong/missing slot, cipher mismatch, in-flight replacement, closed
port, unknown peer, ExtIV misuse, integrity error, truncation and unsupported
cipher; service fixtures verify snapshot publication and TX admission fixtures
verify selection/retirement. Static/shared/dynamic native join admission,
controlled-port authorization and WEP fragmentation remain unfinished; no
hardware compatibility or full WEP support is claimed.

Five affected tests passed ASan/UBSan across RX and TX edits; native build/link
and symbol check passed. Evidence/source checkpoint: outputs/NATIVE-security-compatibility-20261030/wep-rxtx-slots;
SD copy byte-verified. No full-suite acceptance, installation or publication.

### 2026-10-31 — Static WEP association producer contract

Read-only disassembly of the installed Apple80211Associate producer confirms
separate Open System (lower1) and Shared Key (lower2) requests, upper0,
WEP40 length5/cipher1 and WEP104 length13/cipher2. The association record
starts at rbp-0x3d4; initialization zeros its following0x380 bytes, and the WEP
branch writes flags0xf at record+0x48. Key index+0x4a remains zero on this
inspected producer path. This is the legacy user-mode record, not the WCL
kernel record: WCL key length/cipher/flags/key offsets remain0x44/48/4c/50.

Function-aligned evidence fixes initially reversed helper filenames: address
0x7ffc0c06ae44 is WEP40;0x7ffc0c06aeb9 is WEP104. Open System stores occur
at0x7ffc0c0695c8 and0x7ffc0c069669. No speculative fallback policy is claimed.
The stock static flags differ from dynamic EAP key callback flags1/2/5/9.

Added a borrowed static-WEP envelope decoder and a boolean diagnostic at native
join admission. It rejects inconsistent lengths/ciphers, unsupported flags,
RSN overrides, upper/extended auth, transition policy and invalid addresses.
It does not admit WEP or retain key bytes. Existing nativeJoinAuth still rejects
these requests until the coordinated authentication/key/port path is complete.
Indices0..3 are bounded by the existing ABI; only index0 was observed in this
stock producer. No live successful WEP association is claimed.

native_wire passed ASan/UBSan; native build/link and symbol validation passed.
Source remains1.0.111, installed1.0.110 unchanged. No commit, push or reboot.

### 2026-10-31 — Shared-Key authentication crypto and exchange owner

Added bounded transaction3 encoding: Shared Key body plus little-endian CRC32,
RC4 with IV||WEP40/104 key and no WPA1 discard, IV/key-id prefix. Encoding rejects
malformed challenge IE, invalid key/index, insufficient capacity and overlapping
borrowed buffers before output changes; temporary cryptographic state is wiped.
Algorithm/layout reference: Linux v6.12 net/mac80211/wep.c (read for protocol
behavior, no source copied):
https://raw.githubusercontent.com/torvalds/linux/v6.12/net/mac80211/wep.c .

Added an association/generation/identity/deadline-bound Shared-Key exchange owner.
Request submission precedes accepting challenge2; response3 submission precedes
accepting success4. Exact repeated challenges retain identical ciphertext;
a changed challenge cannot overwrite the live IV/ciphertext owner. Cancellation,
clock rollback and expiry retire secrets. Known FMS weak-IV families are rejected;
the caller must supply fresh randomness and own TX retirement. This owner is not
yet wired into the radio management worker or native admission, and does not
open the port. Firmware protection/double-encryption behavior remains to verify.

The new wep_auth test passed ASan/UBSan: both key lengths, all four indices,
1/128/255-byte challenges, independent CommonCrypto RC4 decryption, independent
CRC formulation, malformed/short/overlap rejection, wrong owner, out-of-order
success, duplicate/changed challenge, cancellation and expiry. It is included
in the consolidated runner on macOS (CommonCrypto reference). No new native
build is claimed for this header-only, not-yet-integrated addition. No hardware
WEP interoperability claim, publication, version bump, installation or reboot.

### 2026-10-31 — Shared-Key ciphertext HTT submission integration

The Shared-Key owner now constructs the protected authentication response frame
and validates its complete retained ciphertext, generation, station/peer and
clock before submission. Maximum challenge255 yields frame295, exceeding the
old management stack buffer256; the new bounded builder rejects short buffers.
An explicit SoftwareWEPAuthentication representation is admitted only during
secure WEP authentication with matching key length, closed port, no cancellation
or disconnect, and this live owner proof. Plain and software-CCMP admission do
not widen. Retries may vary sequence/retry flag but not payload or identities.

Core HTT descriptor generation uses NO_ENCRYPT (flags0x65) for the pre-encrypted
frame, consistent with inspected Linux v6.12 htt_tx.c NO_HWCRYPT mapping. The
actual submitNetworkPacket path now passes the same proof through preflight
and descriptor construction and requires its time to equal the submission
clock. Firmware DMA receives a copied ciphertext; host cancellation cannot
invalidate that owned DMA buffer. Firmware interoperability remains unverified.

Native admission and management-loop sequencing are still unfinished; no normal
join reaches this path yet. The production submission fixture verifies missing
and stale proofs rejected before TX-state changes, exact DMA/descriptor bytes,
and cancellation while completion owns the copied ciphertext. Existing fixture
prototype was updated for the optional proof parameter after a compile failure.

Three affected tests (connection, pmf_transport, wep_auth) passed ASan/UBSan;
native build/link/symbol check passed. No full-suite acceptance or installation.
Evidence: outputs/NATIVE-security-compatibility-20261030/wep-htt-transmit; SD byte-verified.

### 2026-10-31 — Native Shared-Key management service

Added explicit sharedKeyAuth state (cleared by resetDisconnected); it blocks
both open-auth frame encoding and algorithm0 receive acceptance. The native
management consumer routes selected Shared-Key replies into the bound owner,
checking exact receiver/transmitter/BSSID, subtype, fragmentation, RX status
and channel. Request1 and response3 are submitted by the radio service with
separate three-attempt retry accounting. Maximum response uses a320-byte local
buffer. Completion4 does not release Auth until HTT/CE ownership retires and
TX completion succeeds. It does not authorize ordinary data.

Native reset cancels the Shared-Key owner without erasing DMA ownership.
Production service tests inject challenge2 while request1 is still TX-owned,
maximum255-byte challenge, final4 before response3 retirement, wrong peer,
request retry exhaustion, cancellation and open-auth fallback attempts.
The existing PMF/SAE fixture now accepts the explicit optional WEP proof;
normal PMF and SAE behavior retains its prior path.

Native WEP profile admission, owner initialization and key/port sequencing
remain unfinished, so no normal macOS join reaches the new service yet.
This closes service wiring, not hardware interoperability or overall WEP.

Five affected tests passed ASan/UBSan across integration runs (native_shared_wep,
native_pmf_receive, native_sae_radio, connection, pmf_transport). Final added
scan-TX retirement guard passed native_shared_wep; final native build/link/symbol
check passed with warnings. Source/evidence checkpoint: outputs/NATIVE-security-compatibility-20261030/wep-native-management.
No full-suite acceptance, publication, installation, version change or reboot.

### 2026-10-31 — Static WEP profile, keys and controlled-port barriers

Added explicit wepSelected candidate policy: require privacy with no RSN/WPA
advertisement, exact WEP40/104 cipher, no WPA1/PMF contradiction; retain legacy
PHY negotiation. WEP association encodes Privacy but no RSN/WPA IE. This does
not infer WEP from privacy alone or admit a macOS join yet.

EAPOwner now separately marks static WEP. beginStaticWEP copies/wipes the
profile key, queues group+pair mirror then default-TX selection through the
existing WEP executor; it does not impersonate an EAP callback. Static owners
reject system EAP routing, dynamic-key callbacks and PMK replacement. Tests
confirm exactly two firmware key writes plus one TX selection, with no pair
reinstallation merely to select its TX index. Confirmed slots and the original
authentication deadline survive until authorized completion.

serviceNativeWEP consumes either explicit WEP owner. Once static key programs
finish, it enters only existing peer-authorize/ECHO phases3/4 (never RSN key
phases1/2). The authorization guard requires current nonexpired static owner,
no pending key program, matching selected TX index, confirmed pair/group slot
lengths and no teardown. Final ECHO also waits RX retirement for WEP. Only after
port completion does finishStaticWEP retire the initial authentication deadline.
Dynamic WEP has no implied authorization: its system provenance remains pending.

Native join admission/profile retention and initial owner setup are still not
wired, so this is integrated lower-path support, not advertised WEP support.
No hardware interoperability, full-suite acceptance or installation is claimed.

Five affected tests passed ASan/UBSan across profile/port integration runs;
final authorization guard test and native build/link/symbol check passed.
Evidence: outputs/NATIVE-security-compatibility-20261030/wep-static-profile-port;
SD copy byte-verified. No publication, version bump or reboot.

### 2026-10-31 — Native static WEP admission and credential ownership

nativeBeginJoin now recognizes explicit WEPOpen/WEPShared requests only behind
Ath10kNativeWEPExperimental on the validated24G90 kernel, separate from the
legacy-WPA experimental gate. That same WEP gate controls the capability bit;
it is absent/false in the installed and default configuration. Requests preserve
lower authentication1/2, exact5/13-byte cipher1/2, flags15 and index0..3. A zero
length with a WEP cipher cannot fall through into plaintext Open admission.

The admitted candidate owns static firmware keys through beginStaticWEP;
Shared Key additionally owns a freshly randomized three-byte IV and its bound
exchange generation. Random-provider failure or exhaustion of16 weak-IV retries
cancels/wipes the attempted setup. ProfileCredentials retains the exact WEP
cipher/auth/index/key under its own generation; copied request and public join
credential storage are wiped. Candidate/profile/setup failure returns through
ordinary reset, leaving no admitted credential or stale shared-auth owner.

Production nativeBeginJoin fixtures exercise both lower-auth types, both lengths
and all four indices, default-disabled rejection, retained profile snapshot,
request wiping, Shared-Key first-frame startup and RNG-failure cleanup. The
fixture random provider required a three-byte IV path (formerly asserted32).
Capability/decoder/profile tests passed; the corrected admission fixtures and
native_wire passed ASan/UBSan. No full WEP interoperability is claimed: static
roam, fragmentation and firmware behavior still need acceptance; dynamic WEP
system-session authorization remains unfinished. This is one unpublished group,
not a separate candidate, commit or installation.

Final native build/link/symbol check passed with warnings. Evidence/source checkpoint:
outputs/NATIVE-security-compatibility-20261030/wep-native-admission; SD byte-verified.
Version remains1.0.111, installed1.0.110 unchanged; no push or reboot.

### 2026-10-31 — Static WEP prepared-roam profile handoff

prepareRoamJoin now selects WEPOpen/WEPShared from the explicitly selected live
WEP mode, snapshots that exact credential profile, preserves lower auth/key
cipher/length/index, and leaves RSN empty. Candidate selection continues to
reject plaintext and WPA/RSN substitution. Existing prepared-roam generation,
retirement and final nativeBeginJoin gates remain in force; dynamic-WEP EAP
profiles cannot acquire static credentials through this path.

native_profile passed ASan/UBSan for both auth modes, both key lengths and all
four indices, changed auth mode, plaintext replacement, output preservation on
rejection and retired profile. This verifies profile preparation, not physical
inter-AP roaming (only one router exists). No publication or installation.

Native build/link/symbol validation passed; evidence and source checkpoint
wep-roam-profile saved and byte-verified on SD.

### 2026-10-31 — WEP fragment ownership and system-session audit

RXDefrag now accepts WEP40/104 raw/native unicast fragments against confirmed
pair slots. Every fragment must retain peer, receiver/transmitter, cipher,
slot, security generation and integrity; key I/O blocks admission. Raw frames
strip four-byte IV plus ICV/FCS and require descriptor/raw IV agreement.
WEP IVs are not treated as monotonic CCMP packet numbers. An exact Retry must
retain IV and payload without extending the deadline; completion still passes
normal controlled-port validation. Mixed keys/ciphers, corrupt continuation,
missing slots, malformed key flags and expired assemblies are rejected.

Affected rx_pipeline passed ASan/UBSan across both lengths, four indices and
raw/native formats, including closed-port rejection. Native compile/link/symbol
checks passed with existing warnings. This closes local WEP RX reassembly,
not hardware interoperability or a claim of cryptographic WEP replay protection.
Firmware/hardware transmission of fragmented MSDUs remains unverified.

Apple eap8021x source at 6f181a4221f6a0a8bf9559894818cb4f0f369b25 confirms
process_key authenticates/decrypts descriptor1 before EAPOLSocketSetKey. Its
inspected function and authenticated-state caller do not expose an authenticated
replay-counter receipt to the driver. EAPOLSocketReportStatus marks the system
client authenticated and requests renew independently of firmware key completion.
These observations do not prove absence of replay protection in other layers.
Do not advance a replay floor from an unauthenticated received descriptor, or
open the dynamic-WEP port on EAP Success alone. Dynamic admission remains gated
pending exact session/key provenance; no APSL source was copied into the driver.

Evidence: outputs/NATIVE-security-compatibility-20261030/wep-fragment-session-audit.
Unpublished grouped work; version/installed kext unchanged, no reboot.

### 2026-10-31 — Stock WEP versus PMK dispatch resolved

Decoded the installed BCM JoinAdapter::setKey jump table directly from its
Mach-O segment (table0xffffff8001586ad4): Apple ciphers1/2 both target
0xffffff80015865cc, mapAppleKeyToBcomKey. Successful conversion reaches
0xffffff8001586975 and chooses programKeyAsync/Sync through virtual predicate
0x130; its meaning is not inferred. Both program paths send command45 with
164-byte BCM key payload. Async submission uses kNoRxExpected plus the existing
callback; this is not proof of firmware completion or controlled-port opening.
WEP does not enter the PMK branch that enables supplicant events and its6s timer.

This narrows the dynamic-WEP implementation contract: preserve the standalone
key executor, never reuse PMK/WPA handshake startup merely because the profile
uses EAP. Native session/replay authorization still needs evidence. No binary
code or BCM wire structures copied into the QCA driver. Evidence with image
SHA256 and decoded table: stock-wep-key-dispatch under the security output.
No source activation, tests rerun, publication, installation or reboot.

### 2026-10-31 — Dynamic-WEP userspace namespaces separated

airportd labels securityType0x100 and0x200 DynamicWEP at0x100037afb–0x100037b61;
these are userspace profile values, not proof of WCL upperAuth bits. Its separate
setWEPKey XPC bridge normalizes public flags with(input>>1)&15, rejects zero,
accepts public index1..4 and sends a148-byte operation3 record. The inspected
system eapolclient producer uses descriptor index0..3 and flags1/2/5/9 instead.
Do not conflate these callers or widen native EAP key admission based on public
API values. The dynamic association producer and session completion still need
tracing. Existing default-off dynamic admission remains unchanged.
Evidence: stock-wep-userspace-boundaries in the security compatibility output;
source hash and address excerpts retained, SD copy verified. No hardware claim.

### 2026-10-31 — Current WEP inventory reconciled

Reconciled four stale current-plan fields with implementation and prior local
checkpoints: static join/authentication, key/port completion and RX fragmentation
are integrated; dynamic EAP-session admission/authorization is not. Replaced
the contract's stale current-state paragraph while retaining historical evidence.
No new support claim, hardware validation or repeated regression. The next
system trace must map userspace DynamicWEP securityType into WCL join fields;
public enum labels alone are insufficient to enable a native association.

### 2026-10-31 — WCL EAP predicate excludes legacy WEP values

IO80211BssManager::isEAPJoin at0xffffff800211d2ac reads state+0xfc and
accepts only exact1,4,128,2048,16384,32768. getAuthType at0xffffff800211e076
places that field at output+8, cross-checking upper-auth ownership. Values32/64
(LEAP/WEP8021X in the current headers) are excluded. Thus the previously traced
setKey observer's conditional EAP6s timer cannot establish dynamic-WEP
completion. This is not proof that legacy EAP is absent elsewhere in macOS.
Keep standalone WEP key/port state and continue tracing the actual session owner.
Evidence: stock-wep-eap-predicate; disassembly/hash and SD copy verified.
No source activation, repeated tests, publication, installation or reboot.

### 2026-10-31 — WEP reconnect completion isolation

Extended production WEPExecution fixtures across both key lengths, group and
TX-key programs, and five retirement stages through Complete-before-commit.
Replacing an EAP owner on the same station/BSSID changes generation/ticket;
an old commit cannot publish keys or consume the new head. Uncertain executor
cannot start replacement work before explicit firmware retirement. Cancellation
after restart likewise cannot commit the queued new key. All20 combinations
passed native_wep_execution with ASan/UBSan. This extends cancellation evidence;
no new runtime capability or dynamic-session authorization is claimed.
No full-suite rerun/build needed for test-only change. One unpublished package,
version/installed driver unchanged. Evidence: wep-reconnect-isolation.

### 2026-10-31 — WCL structural validation is not auth admission

Traced the complete checkValidationForApple80211AssociationData function
at0xffffff8002232fa0 through its return/error branches. It bounds SSID, embedded
key lengths, IE and ancillary fields, but contains no lower/upper auth whitelist.
Therefore passing this validator cannot establish dynamic-WEP admission; the
next trace remains the actual producer/security mapping and later policy.
Legacy assoc-data offsets must not be reused as translated WCL JoinRequest
positions. Evidence: stock-wep-join-validation with full function and hash.
No driver behavior changed or new support claimed; no repeated tests/reboot.

### 2026-10-31 — Security batch integration: static/system queue separation

serviceNativeEAP now retires EAP queue ownership for static WEP after checking
its authentication deadline. Static profile key programming/port authorization
remain owned by serviceNativeWEP; no preauthorization system EAP queue or PMK
attempt is started. Existing authorized data queue is preserved by the queue
helper. Pending WEP keys/pause are retained; initial expiry still cancels.

Production service fixtures cover preauthorization and existing data-link
ownership, repeated service and expiry. native_eap_service and native_wep_service
passed ASan/UBSan. The EAP fixture also needed the securityPhase field used by
the already-integrated static waiting predicate. Native compile/link/symbol
check passed with warnings. This remains part of the unpublished security batch;
no version, installation, commit or reboot. Dynamic WEP session admission is
still unfinished. Evidence: security-batch-integration under the security output.

### 2026-10-31 — Grouped security integration regression

All84 available C++ test programs passed ASan/UBSan across the full initial
run and two continuations of only unfinished tests. The initial run stopped
at a stale lifecycle fixture (missing WEP fields/clock); the first continuation
found bridge-source extraction accidentally including subsequently inserted
TKIP methods. Both fixture/extraction issues were corrected; affected tests
passed in the continuations. No production change during this regression.
The earlier44 successful programs were not rerun. This is cumulative coverage,
not a single uninterrupted successful full-suite run or final batch acceptance.
Dynamic WEP session admission, OWE and Enterprise hardware remain open.
Version/installed driver unchanged; no commit, push, installation or reboot.
Evidence: security-batch-regression with all three logs and explicit test inventory.

### 2026-10-31 — Security batch: OWE group19 wire and KDF foundation

Added bounded group19 DH-element encode/decode and atomic PMK/PMKID derivation
in Ath10kOWE.hpp. Client/AP ordering is preserved; intermediates wipe and provider
failures leave output unchanged. Decoder validates format only, never curve
membership. ECDH validation, worker/session ownership, association integration,
AKM18 handshake and protected transition selection remain unfinished.

The new owe test passed ASan/UBSan after fixing its missing initializer_list
include. Independent Python hashlib/HMAC values use C=bytes0..31,A=32..63,
z=64..95; these are KDF inputs, not an ECDH interoperability vector. Tests cover
order reversal, every provider failure, input sizes, malformed/truncated IE,
short output and overlapping encoder input. No native linkage/advertisement,
hardware evidence or installation; full84-test checkpoint predates this addition.
Reference: https://www.rfc-editor.org/rfc/rfc8110.html sections4.3–4.4.
Evidence retained in security-batch-integration/owe; same unpublished package.

### 2026-10-31 — Security batch: OWE validated exchange ownership

Added Ath10kOWEP256.hpp using the existing admitted CoreCrypto point/field
providers: recover compact peer y from x^3-3x+b, verify the root, validate the
point, and derive shared x with blinded scalar multiplication. Noncanonical
coordinates, invalid scalar/provider failures preserve caller output. Temporary
workspaces and shared secrets wipe on every exit.

The one-shot exchange binds station, BSSID, generation and deadline; completion,
cancellation and rejected completion erase private scalar state. Fresh scalar
entropy remains the future worker caller's responsibility; no modular reduction.
Tests on actual macOS libcorecrypto cover G/2G known points, PMK derivation,
output boundaries, failed providers, invalid scalar/coordinate, wrong identity,
replaced generation, expired/backwards clock, cancellation and duplicate finish.
p256_backend passed ASan/UBSan after these changes; git diff --check passed.
This helper is not yet linked into native association or the worker: OWE/AKM18
runtime admission remains disabled. Same unpublished security package; metadata,
installed kext and EFI unchanged. No full regression repeated.
Evidence: security-batch-integration/owe-exchange. Previous goal turn only
restated execution policy (no progress); this turn adds implementation/evidence.

### 2026-10-31 — Security batch: opt-in OWE handshake and key lifecycle

Supplicant now has a separate default-false AllowOWE parameter. Its group19
AKM18/CCMP/PMF profile derives SHA256 PTK and uses HMAC-SHA256 truncated to16
for EAPOL MIC, not SAE CMAC (RFC8110 section4.4). It shares validated GTK/IGTK
transactions, retransmission suppression, pairwise rekey and replay history;
SAE-only transition-disable handling remains separate. No PMK-cache admission.
The native instantiation still does not enable OWE; worker/association integration
and hardware evidence remain required before capability publication.

Independent Python hashlib/HMAC + cryptography AES-wrap fixtures cover M1–M4,
management/group rotation, replay without reinstall, pairwise rekey without new
group keys, invalid MIC/wrap/RSN/padding/IGTK and reset. Corrected the new test's
initial mistaken assumption that Reply clears the retained last-result mask:
production contract uses Result to request installs and retains last payload.
OWE, SAE and SHA256 supplicant tests passed ASan/UBSan. Default SAE fixture
regeneration is byte-identical. Native compile/link/symbol check passed with
existing warnings; no signing/installation or final full-suite claim.
Same unpublished package; version stays1.0.111, installed kext unchanged.
Evidence: security-batch-integration/owe-handshake, mirrored/verified on SD.
Reference: https://www.rfc-editor.org/rfc/rfc8110.html#section-4.4

### 2026-10-31 — Security batch: retained OWE worker execution

Added Ath10kNativeOWEJob to the native build: two retained worker submissions
prepare the public DH request and derive keys from the response. Bounded scalar
rejection sampling and nonce generation execute off the owner/radio gate.
Identity/generation/monotonic-time/deadline checks precede publication; collection
is one-shot. Discard erases scalar/exchange, PMK, PMKID, nonce and provider tables.
Added bounded kernel SHA256 digest provider for OWE PMKID generation.

Production job code tested through the existing worker with actual macOS P256
providers and CommonCrypto hash/HMAC: queued and running cancellation in both
phases, wrong generation, deadline expiry, duplicate request/peer/key collection,
normal completion and reference reclamation. p256_backend passed ASan/UBSan;
native compile/link/symbol check passed with existing warnings. Tests use a
synthetic valid peer point, not hardware interoperability. Final build is not
signed/installed; runtime controller/association wiring and key handoff remain
unfinished, and native OWE admission stays disabled. Same unpublished package.
Evidence: security-batch-integration/owe-worker, mirrored/byte-verified on SD.

### 2026-10-31 — Security batch: OWE association transport

ConnectionState holds only public request/response DH elements. The association
encoder requires the explicit AKM18/CCMP/PMF profile and a prepared group19
request; emits matching RSN and DH, with aggregate capacity accounting. Response
processing requires RSN and exactly one valid-format group19 element, rejects
missing/duplicate/wrong-group parameters, retains the first accepted response
immutably, and clears both public elements on disconnect. Point membership
and ECDH remain worker responsibilities, never the RX/radio parser's.

Production connection tests cover request encoding and missing preparation,
valid response, missing DH/RSN, duplicate DH, wrong group, truncated element,
wrong transmitter, changed retry and reset. connection passed ASan/UBSan;
native compile/link/symbol check passed with warnings. No radio admission yet:
controller scheduling/PMK handoff and native request routing are still missing.
Recovered existing evidence identifies OWE as upperAuth0/upperAuthExt1 (audit
entry around4040); do not conflate it with plaintext Open. Same local package,
no publication/version bump/install/reboot. Evidence: owe-association under
security-batch-integration, mirrored/byte-verified on SD.

### 2026-10-31 — Security batch: native OWE request through PMK handoff

Native OWE now has an explicit default-off Ath10kNativeOWEExperimental gate,
which also requires the existing admitted SAE/backend prerequisite. Strict
upperAuth0/upperAuthExt1, no-credential requests select AKM18/CCMP/PMF; no Open
fallback. Retained profile and prepared-roam encoding preserve OWE identity.
Join creates a separate PMF owner; crypto starts at Auth, not during firmware
setup. The controller waits for a public request, then open authentication and
association, then the response-derived PMK/nonce before ordinary key processing.
Generation, identity, clock, cancellation and firmware readiness are rechecked.
Reset cancels the exact retained worker item before releasing its owner, without
waiting under a radio/WCL gate. Existing PTK/GTK/IGTK port barriers remain shared.
Management TX buffer increased256->512 to accommodate OWE+HT/VHT+spectrum IEs.

Tests: actual controller service plus real job/worker/CoreCrypto exercised both
stages, association wait, successful handoff and wrong-peer/cancel/expiry.
Native request admission/profile retention tested with gate off/on; key bytes
remain absent. Updated lifecycle fixture proves cancellation precedes release
and cleanup is idempotent. connection, native_security_lifecycle, native_join,
native_wire, native_profile, p256_backend, native_pmf_receive, native_key_stage,
and native_sae_radio passed ASan/UBSan across affected runs/continuations.
Two stale fixtures needed updates (OWE owner and matching supplicant enum type);
PMF extraction excludes the separately tested OWE service. Last SAE run includes
new OWE native-admission case. Native compile/link/symbol check passed, with
existing warnings; no claim of full-suite or hardware acceptance.

Remaining OWE gates: stock capability/selection publication, secure transition
selection, actual AP interoperability and final package regression. Runtime
option remains absent/off, installed kext/EFI unchanged. Legacy Enterprise and
dynamic WEP remain part of the same unfinished package. No commit/push/version
change. Evidence: security-batch-integration/owe-controller with separate logs,
mirrored and byte-verified on SD. Previous goal turn was progress.

### 2026-10-31 — Security batch: stock OWE capability admission

Recovered Apple80211Associate AKM jump table at0x7ffc0c06a950 from the saved
local Mach-O bytes: AKM18 dispatches to0x7ffc0c069111, reads cap cache0x64 and
requires bit0 at0x7ffc0c069060. Cache base0x58 makes this capability96. A second
OWE policy branch at0x7ffc0c068c40 tests the same bit. This is code/data evidence,
not a guess from neighboring SAE/cipher bits. Local raw excerpts/hash/table
mapping retained outside repository. No private Apple code added to source.

getCARD_CAPABILITIES now exposes byte12 bit0 only with nativeOWEEnabled(), the
same default-off admission gate. All16 WEP/WPA1/SAE/OWE switch combinations and
output bounds passed native_join ASan/UBSan. No unrelated cipher capability
added. Secure transition target selection remains stock macOS's responsibility:
the driver preserves transition advertisements and honors only explicitly
selected OWE, while Enhanced-Open-only policy rejects plaintext. End-to-end OS
selection of the hidden protected partner still requires hardware observation;
this evidence does not establish that outcome. No new full build/regression,
installation, push or version change for this isolated capability edit.
Evidence: owe-stock-admission under security-batch-integration, SD verified.

### 2026-10-31 — Integrated compatibility package: Enterprise SHA256/PMF

AKM5 now follows explicit native upper-auth 2048 admission, CCMP/PMF AP
validation, association RSN, system EAP transport and one-shot MSK handoff.
The four-way uses SHA256 derivation, descriptor 3 AES-CMAC, IGTK and shared
firmware key barriers; plaintext data stays closed until key authorization.
Fixed BSD output interception to admit both AKM1 and AKM5 EAP traffic before
controlled-port completion. Personal key traffic retains its internal owner.

Independent generated AKM5 vectors cover initial/repeated messages, pair/group
rekey and malformed inputs. Production native join/MSK/PMF/reset and EAP RX/TX
fixtures passed ASan/UBSan; affected key-stage, wire/profile and callback/service
fixtures also passed. Native compile/link/symbol validation passed. Same-key
MSK replacement is a binding test, not evidence of different-MSK radio reauth.
No Enterprise roaming, FT/Suite-B or dynamic-WEP session authorization is claimed.

This remains one unpublished WEP/WPA1/TKIP/Enterprise/OWE compatibility package.
No commit, push, version increment, installation or reboot. Installed 1.0.110
is unchanged. Final full-package regression and AP acceptance remain open.
Evidence: security-batch-integration/eap-sha256; logs mirrored and byte-verified
on SD. Goal remains active; this turn changed and validated production code.

### 2026-10-31 — Security package: reauthentication and transition policy

Independent AKM5 vectors now replace the MSK with different synthetic material:
PTK changes, replay floors remain, an old-MSK M3 is ignored while established
keys remain, and a valid new-MSK M3 completes the replacement. Initial test
expected Fatal for the unauthenticated rekey; source review confirmed Ignore
is intentional to preserve the established port. This is cryptographic local
evidence, not system EAP-server/hardware reauthentication acceptance.

Corrected Enterprise Transition Disable admission: explicit AKM5/CCMP with
required PMF remains allowed; legacy AKM1/WPA1 remains excluded. Confirmed
against wpa_supplicant wpas_glue.c at 59fa4b44b84301ac01b937a6a0e687cf5dd3593a:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/59fa4b44b84301ac01b937a6a0e687cf5dd3593a/wpa_supplicant/wpas_glue.c
No upstream code copied.

Authenticated KDE extraction and PMF-owner delivery now include OWE and AKM5,
with MIC/unwrap/key barriers, restrictive profile retention, delivery retry,
prepared-roam invalidation and reset retirement. Duplicate KDEs are rejected.
Affected eap_sha256, owe_eapol, sae_eapol, native_wire, native_profile,
native_sae_radio and native_notifications passed ASan/UBSan. The notification
fixture needed its SAE setup corrected to include the real PMF-required state.
Native compile/link/symbol check passed. Full final-package regression and
hardware acceptance remain open. Source version/installed kext unchanged;
no commit, push, installation or reboot. Previous goal turn was progress;
this turn adds production policy handling and independent security evidence.

### 2026-10-31 — Dynamic-WEP association producer boundary

Recovered a previously missing producer distinction: airportd saves is8021X at
-0x23c, tests supportsSecurity:1, and selects built-in 13-byte placeholder
association material at0x10000e86f..0x10000e885. Apple80211Associate2 receives
that argument at0x10000ea97. securityType0x100/0x200 also selects WEP open-system
parameters;0x100 selects WEP40. This is not a WCL upperAuth mapping or an
EAP-authorized event. Never recognize dynamic WEP by comparing password bytes,
and never claim its initial static-key transaction establishes EAP success.
The missing system-session indicator remains a requirement; dynamic admission
stays disabled. Evidence: enterprise-session-entry, workspace and SD verified.
Previous paused turn was a user-requested stop; resumed turn obtains new producer
evidence and starts the consolidated compatibility regression.

### 2026-10-31 — Integrated package offline gate

Signed local candidate UUID A0A505AC-F750-3636-B243-63C0B5A44A94 passes strict
signature verification and offline auxiliary collection linking. The collection
contains the exact candidate UUID; all file-backed program sections match the
probe whose OSBundleRequired metadata alone was removed for this offline check.
Candidate, link log, inclusion result and section hashes are mirrored and
byte-verified under security-batch-offline on SD. Nothing loaded or installed.
Consolidated ASan/UBSan regression is running at
/tmp/ath10k-security-complete-regression.log; do not infer completion from this
checkpoint or launch another full runner. Current execution handle87825.
Dynamic-WEP session provenance, FT/Suite-B and radio acceptance remain open;
this offline gate does not establish support for them or other macOS releases.

### 2026-10-31 — Integrated compatibility package validation

All 87 C++ regressions passed ASan/UBSan across the consolidated run and two
continuations. Two fixture issues were repaired: native_join still expected
SHA256 Enterprise rejection; the WPA1 provider extraction included the newly
adjacent hash256 wrapper. No driver behavior was changed to satisfy these
failures. Successful earlier tests were retained, not rerun. Release and Debug
compile/link/symbol checks passed. Added OWEJob to Windows source list; Windows
execution remains untested. Evidence final-package-regression mirrored/verified
on SD. Current installed 1.0.110 and configuration rollback also byte-verified.

Pending code changelog for the next published build: static WEP Open/Shared
radio/keys/port lifecycle; WPA1/TKIP handshake/MIC/replay/cancellation; retained
GTK slots; Enterprise MSK and AKM5/PMF integration; OWE group19 and native
capability/association/key ownership; authenticated transition policy for
SAE/OWE/AKM5. Experimental compatibility gates remain off by default.
Dynamic-WEP session provenance, FT/Suite-B, physical Enterprise/OWE/legacy
interoperability and protected transition selection remain open. Source version
is 1.0.111 until the grouped publication succeeds and remote HEAD is verified.
