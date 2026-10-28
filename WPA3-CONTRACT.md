# WPA3-Personal / PMF integration contract

Status: incomplete, not advertised as supported. No OS root patches are needed
or introduced by this work. Correct credential transport is a prerequisite,
not working SAE or PMF.

## Verified Sequoia credential envelope

Matching local IO80211Family UUID: 0D5AC570-04D4-38B6-8577-9F21350CDD50.
WCLJoinRequest::checkValidationForApple80211Key at 0xffffff800223326a reads
key_len at offset 4 and rejects unsigned lengths >=65 at
0xffffff800223327f..3283. It bounds RSC length at offset 0x50, and the two
WoW key lengths at 0x64/0x78. fillAssocCandidatesList copies the whole
0x94-byte key structure to candidate offset 0x40 at
0xffffff8002231e9f..1eb0. Thus the credential bytes at key offset 0x10 occupy
64 bytes before the RSC-length field at key offset 0x50. The previous imported
32-byte key plus 30-byte padding and two alignment bytes hid half the slot.

The corrected apple80211_key stays 148 bytes and preserves all following
metadata offsets. Native JoinRequest retains all 64 credential bytes, flags
and index from candidate offsets 0x50, 0x4c and 0x4e. Lengths >64 and truncated
candidate arrays are rejected before output mutation. Credentials are octets,
not a NUL-terminated string. The inherited cipher enum names value 10 PWD;
this is not evidence that a live SAE request on this laptop has been captured.
These byte offsets are verified for this Sequoia image only.

## Authentication admission remains explicit

Wire decoding and supported authentication are separate. The current native
policy accepts open (lower auth 1, no upper auth/key) or exact WPA2-PSK /
PSK-SHA256 requests with a 32-byte PMK/PMKSA. A password is not a PMK. SAE,
FT-SAE, enterprise, mixed/unknown upper-auth masks and password-cipher requests
are rejected; an SAE bit never falls back to PSK. Rejection wipes the entire
temporary request. Terminal retained-key cleanup now covers the full slot.
Diagnostics publish the authentication selector/reason, never credential bytes.

No PMF capability or SAE success may be published until the required path below
is implemented and validated. Existing SHA256-PSK support is WPA2, not WPA3.

## Remaining implementation and evidence gates

| Stage | Required work | Evidence needed |
| --- | --- | --- |
| Credential transport | Correct 64-byte Sequoia envelope and no truncation/downgrade | Implemented host decoding/policy tests and native ABI assertions; live SAE credential delivery still unverified |
| SAE backend | P-256 symbol subset binds on the inspected Sequoia CoreCrypto; actual ABI/backend and scalar/point behavior still need validation (SAE-CRYPTO-BACKEND.md) | Independent cryptographic vectors and runtime ABI/lifetime proof; symbol binding alone is insufficient |
| SAE exchange | Password element derivation (including H2E), commit/confirm, peer validation, anti-clogging/group handling, retransmission/timeouts and PMK output | Independent SAE fixtures and management-frame state tests; no open-system auth substituted for SAE |
| Queue/lifetime integration | Crypto work outside radio/WCL gates, cancellation/generation checks, retained context and secret retirement across sleep/stop | Production-method race/failure tests and real sleep/stop without deadlock or stale publication |
| AKM 8 four-way | SAE-derived PMK, correct AKM-specific KDF, descriptor and MIC semantics, replay/reinstall handling | Independent AKM 8 fixtures; do not reuse AKM 6 behavior merely by changing its number |
| PMF negotiation | Correct RSN/RSNX/PMKID/cipher selection and mandatory protection for the chosen SAE path | Wire fixtures plus pure/mixed WPA3 AP negotiation; no fabricated MFPC/MFPR support |
| Management keys | Strict IGTK KDE parsing, key epochs, install/rekey, replay state and removal | Malformed/duplicate/rekey fixtures; failed updates cannot silently authorize a link |
| Protected management RX/TX | Verified pairwise protection, group BIP integrity/replay, protected SA Query/action handling and authenticated disconnect events | Actual firmware RX/TX protection metadata contract, adversarial host fixtures and isolated hardware verification |
| System exposure | Capability/RSNX/query behavior matches implemented SAE/PMF, no AKM downgrade, actionable failure states | Matching stock callers plus macOS UI/association/recovery tests |
| Compatibility | Versioned ABI adapters for other requested macOS releases | Per-version credential/message layouts and kernel/hardware evidence; Sequoia offsets are not cross-version proof |

Current receiveStationManagement rejects protected management frames and handles
open-system authentication; the current supplicant excludes required PMF and
supports AKMs 2/6 only. Those facts contradict any claim of complete WPA3 support.
The missing rows above remain part of the original active goal.

Primary implementation/testing references for subsequent work:

* [hostap SAE configuration and PMF requirements](https://github.com/vanhoefm/hostap-wpa3/blob/master/wpa_supplicant/wpa_supplicant.conf)
* [hostap SAE integration tests](https://github.com/vanhoefm/hostap-wpa3/blob/master/tests/hwsim/test_sae.py)

These references are not proof of this driver's behavior. No third-party SAE
implementation or Apple binary/assembly is copied into this document.
