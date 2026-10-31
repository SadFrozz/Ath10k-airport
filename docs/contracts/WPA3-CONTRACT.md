# WPA3-Personal / PMF requirements

This is the target security contract. Implementation and verification states are
tracked in [docs/development/NATIVE-STATUS.md](../development/NATIVE-STATUS.md); prior research and intermediate
states are retained in [the history](../history/WPA3-CONTRACT.md).
PMF is already implemented; remaining hardware evidence must not be described
as missing implementation.

| Requirement | Required behavior / acceptance |
| --- | --- |
| Native admission | macOS credentials, requested AKM, RSNE/RSNXE and PMF policy must remain bound to the selected association; reject unsupported profiles without downgrade |
| SAE | Validate P-256 provider ABI/lifetime, independent crypto vectors, H2E/legacy selection, commit/confirm, retries and cancellation; never perform expensive crypto under networking gates |
| Four-way handshake | Bind PMK/PTK and replay state to current peer/association; authenticate messages before accepting keys or transition-disable policy; wipe secrets on retirement |
| PMF keys | Bind pairwise and IGTK epochs to the active session; install/acknowledge keys before authorizing the controlled port; reject stale completion |
| Protected management | Protect/verify unicast robust management and BIP-CMAC group management; validate PN/IPN, address, key identity and frame layout; reject replay and malformed frames |
| SA Query | Bound requests/retries/deadlines; validate protected responses; queue ownership and transport submission do not prove RF acknowledgement |
| Rekey | Handle PTK, GTK and IGTK-only updates, duplicate messages and cancellation; prevent key reinstallation/replay rollback; drain old packet owners before changing epoch |
| Recovery | Cancel crypto, replies and protected TX on leave/radio-off/retirement; old generations cannot change a new association |
| Capabilities | Advertise only implemented, admitted modes. Additional groups/ciphers, SAE-PK, FT-SAE, enterprise/external-key ownership need separate implementation and evidence |
| Hardware evidence | Ordinary SAE traffic, protected SA Query, group BIP, AP-triggered PTK/GTK/IGTK updates and prolonged stability are distinct checks |

The implemented experimental scope is Group 19/P-256, CCMP-128 and BIP-CMAC-128
on the validated Sequoia ABI. Default builds keep SAE disabled. A passing local
regression closes its tested code paths, not every security mode or RF scenario.
Use the consolidated development suite for implemented behavior; do not restart
PMF implementation or repeat closed manual tests merely because a radio test is
still pending.

## External key-owner integration requirement

Treat macOS key requests as discriminated operations (data keys, PMK/MSK,
PMKSA and password), not as interchangeable PTK/GTK buffers. Validate each
layout/length/profile and bind accepted work to the current interface, peer
and association generation. Select a single internal or external handshake
owner; an external request must not overwrite an active internal exchange.
Separate accepted submission from firmware acknowledgement and controlled-port
authorization. Recover password/PMKSA and completion semantics before enabling
those paths; do not advertise enterprise authentication from key parsing alone.

External OS-owned EAPOL requires a separately validated receive/transmit path
while ordinary data remains blocked. Do not reuse the internal four-frame,
512-byte EAPOL-Key queue as a general EAP transport. Select one packet owner
and validate its bounds, peer identity, lifetime and cancellation. Do not use
SAP-only STA_AUTHORIZE as infrastructure-client authorization; trace the
actual WCL/OS client path and its failure semantics.

For enterprise integration distinguish the EAP authentication owner from the
four-way handshake owner. The system EAP client can supply MSK while the driver
retains its existing four-way/PMF implementation. Do not require external
PTK/GTK ownership merely because EAP runs in macOS. Validate MSK handoff, EAP
versus EAPOL-Key routing and the OS completion notification as one contract.

Validate credential sizes at the driver's actual callback boundary, after
IO80211Family auth-dependent MSK translation; the userspace 64-byte MSK
length is not the native callback contract. Reuse the stock interface's
key-done notification route after the authenticated port barrier. Distinguish
initial link completion from rekey completion and avoid duplicate notifications.

## Pairwise-update completion barrier

A successful pairwise update must report the stock Sequoia supplicant event
(ID 76, 40-byte payload, status `0xe0820406`, reason `0xe0822c15`) after both
the authenticated key/port barrier and matching M4 transport completion.
Initial association, group-only updates and retransmitted M3/M4 must not create
a new pairwise-update notification. Preserve the active transition-disable
policy when composing the event. Transport completion is not a separate RF-ACK
claim.

Capture the result at serial DMA retirement, before another management packet
can reuse the slot. Shared latest-TX fields are not a completion ticket. Bind
the captured result to its reply and association lifetime; process failure for
all native EAPOL replies, including phase-5 rekey replies. Failed enqueue retains
the same notification; successful enqueue consumes it once. Leave, radio-off,
roaming retirement and stop invalidate the old owner and pending completion.

Native PTK completion delivery has a fixed 5000 ms local recovery budget from
consumption of the successful M4 completion receipt. This is driver policy, not an asserted IEEE deadline.
Transient queue failures retain the original ticket and start time; preceding
notification failures or temporarily unready PMF must not extend it. On expiry
close the controlled port and cancel the association through normal teardown,
without reporting successful completion. A retired key generation cannot expire
or notify its replacement. Successful enqueue and association reset clear the
pending timer. The radio service checks expiry independently of event admission.

## Legacy compatibility and common security acceptance

User-requested scope includes WEP-40/104, WPA1-Personal/TKIP and WPA2-Personal
with TKIP/CCMP, in addition to WPA3. These are implementation requirements, not
current support claims. Match the explicit native request to the AP security IE;
never downgrade an admitted WPA2/WPA3 profile after failure. Recover each native
credential/key format and firmware cipher layout before advertising support.

The complete compatibility path includes discovery, authentication, association,
key derivation and delivery, firmware acknowledgement, controlled-port admission,
TX/RX integrity, replay, rekey and cancellation. WEP authentication modes and key
indices, WPA vendor IE/descriptor/MIC/key-wrap rules, TKIP pairwise/group MIC-key
direction and MIC-failure countermeasures require their own evidence. A TKIP group
key supported by an RSN/CCMP association does not prove WPA1 or pairwise TKIP.

Test malformed inputs and failures at real production boundaries, ensuring no
partial key publication, replay rollback, stale completion or leaked secrets.
Legacy hardware interoperability, modern Personal security and Enterprise are
separate acceptance observations; no one-router result certifies all three.

## TKIP MIC report and countermeasure ownership

This legacy boundary belongs to the active security package; it is not
implemented merely because MIC evidence and an authenticated report encoder
exist. Keep native event publication separate from enforcement: installed
airportd events 5/6 only drive the recovered repeated-error UI path.

- Timestamp qualified RX evidence on the radio gate at detection, not when a
  delayed worker eventually handles it. Bind AP, association/key epoch, slot,
  TID and TSC. Duplicate evidence must not count as a second failure.
- A report needs its own bounded TX/completion owner. Do not reuse the ordinary
  handshake authorizePending state: its completion may authorize a port or
  publish PTK completion, neither of which a MIC report may do.
- A second distinct qualified failure inside the 60-second window requires
  countermeasures. Retain the report's signing key until submission/completion
  or bounded failure, then perform normal drained teardown. Stop ordinary data
  immediately when countermeasures begin. A stuck transport must not postpone
  closure indefinitely.
- Preserve the 60-second reconnect exclusion outside association reset, or
  teardown would erase the protection it is meant to enforce. Radio-off,
  stop and replacement ownership must retire report work without allowing a
  stale completion to act on the next link.
- Use existing asynchronous completion receipts. The reference's 10 ms sleep
  compensates for missing callbacks; it is not a timing guarantee and must not
  be copied into the kernel gate.

Reference behavior: wpa_supplicant events.c blob
815b9947ee2f17ed2b12f666c737ebe980542379, Michael MIC failure handler:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/refs/heads/android10-dev/wpa_supplicant/events.c
The reference establishes report-before-teardown and a 60-second exclusion;
the receipt ownership and stale-callback rules above are requirements of our
existing native asynchronous transport, not claims about that reference's ABI.


### Pairwise and group TKIP MIC ownership

Legacy RSN TKIP reports must name the failing key type in both EAPOL-Key and
native event delivery (stock pairwise event 5, group event 6; six-byte BSSID).
The KCK and descriptor version belong to the established pairwise profile,
including when the failure concerns a GTK. No candidate M1 may replace that
report signing key. PTK and GTK replay/evidence histories are separate, while
the two-failure exclusion window is shared across both and survives reconnect.
Bind evidence to a firmware-acknowledged key epoch, mapped peer, current local
address/BSSID and TID; never advance the RX replay floor for a rejected packet.
Full key material and epoch publication occur only after the firmware receipt;
epoch counters survive association retirement, but installed epochs are cleared.
Native legacy admission remains closed until radio mode restrictions, all MIC
paths, association policy and firmware/key-owner integration are complete.


### Legacy cipher radio-mode contract

The selected pairwise cipher, not the advertised or selected group cipher,
controls HT/VHT admission. WEP40, TKIP and WEP104 pairwise profiles must remain
20 MHz, one stream, without HT/VHT capabilities, MCS maps or aggregation flags.
CCMP pairwise with TKIP group must retain otherwise valid HT/VHT capabilities.
Apply this rule during candidate preparation, initial negotiation, association
response processing and maintenance rate overrides. Reject a stale combination
before writing an association frame or firmware configuration. This restriction
does not itself admit a legacy security profile or provide its association IE.
Reference: https://wireless.docs.kernel.org/en/latest/en/developers/documentation/mac80211.html


### Explicit selected-profile admission

Validate the requested pairwise cipher and AKM against the AP RSNE before
committing a candidate and again in the handshake owner. Never replace absent
CCMP with TKIP automatically. The association RSNE and EAPOL M2 must encode the
same selected pair/group/AKM. Legacy RSN admission has a distinct internal gate;
its presence in core fixtures is not native macOS capability publication.
Ordinary Enterprise TKIP group/pairwise profiles require that gate; existing
CCMP Enterprise and CCMP-pairwise PSK behavior remains separately admissible.
SHA256 PSK stays CCMP-only; SAE requires CCMP and its own PMF/PMKID path.
Native enablement must bind the gate, selected cipher, supplicant configuration
and stored reconnect profile to one explicit supported macOS request.


## Recovered stock join IE ownership

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


### Incoming selected RSNE

The native join path validates a nonempty selected RSNE independently of the
key/password envelope. Require one pairwise selector and one AKM matching the
explicit native authentication request, then match its group cipher against the
selected AP. Reject malformed, ambiguous multi-suite and contradictory requests
before radio admission. An empty override preserves the supported default; it
must not be treated as permission to downgrade. WPA1 vendor IE admission stays
separate until its descriptor254 handshake is integrated. These checks are
covered by host production-path fixtures; installed-system compatibility of
nonempty overrides still needs candidate runtime evidence.
