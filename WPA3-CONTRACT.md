# WPA3-Personal / PMF integration contract

Status: incomplete, not advertised as supported. No OS root patches are needed
or introduced by this work. Correct credential transport is a prerequisite,
not working SAE or PMF.

## Active priority (user request, 2026-10-28)

WPA3-Personal and its dependent security path take priority over further roaming,
AWDL/AirDrop and compatibility expansion. Implement in dependency order:

1. Validate the P-256 backend ABI/lifetime and independent crypto vectors;
   keep cryptographic work outside WCL/radio gates.
2. Implement SAE password-element derivation, H2E and commit/confirm with
   anti-clogging, invalid-peer handling, retries and cancellation.
3. Implement AKM 8 four-way semantics and mandatory PMF negotiation together
   with IGTK/BIP replay protection and protected management RX/TX/SA Query.
4. Connect native credential/capability handling only to the completed paths;
   verify SAE-only and transition APs, rekey, reconnect and sleep/stop.

Do not advertise SAE or PMF while these dependent stages remain incomplete.
Roaming preparation stays local and deferred; no need to restart that work
before the security dependency path is functional.

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

P-256 operation candidate: see SAE-CRYPTO-BACKEND.md for real userland vectors and kernel compile-only checks. This is unwired and does not complete SAE, PMF or kernel ABI validation.

## Local PMF key parsing progress

A strict standalone BIP-CMAC-128 IGTK vendor-element parser is implemented
in Ath10kRSN.hpp. It accepts the exact 30-byte element (RSN selector type 9),
KeyID 4/5, a six-byte little-endian IPN and a 16-byte key. All format/length
checks precede output writes. ASan/UBSan rsn_policy tests pass all truncations,
null input, corrupted header/selector/key ID and both permitted key IDs.
The decoded key is caller-owned and must be wiped after use. It is not wired
into EAPOL processing, does not install firmware keys, and does not establish
key epochs, replay admission or management-frame integrity. Those remain open.

Format reference: hostap's wpa_igtk_kde in
https://www.w1.fi/wpa_supplicant/devel/wpa__common_8h_source.html
(two-byte KeyID, six-byte PN, cipher-dependent key). Only CMAC-128 is parsed
by this function; other group-management ciphers require separate handling.

The local key-data scanner now scans a bounded (<=512-byte) complete IE
sequence before publishing the IGTK, rejects duplicate IGTK elements (even
identical ones), malformed following elements and nonzero wrap padding, and
requires the IGTK to be present. It accepts the same 0xdd/zero wrap padding
shape already handled by the current GTK path. It stores only a pointer while
scanning; no temporary key copy is retained on a failed parse. ASan/UBSan
rsn_policy tests pass duplicate, truncated-suffix, missing-key and padding
cases with unchanged output on rejection. Caller must authenticate EAPOL and
unwrap successfully before using this scanner. No caller has been wired yet.

Local BIP verification now covers bounded, ordinary 24-byte-header group
deauthentication/disassociation frames with trailing CMAC-128 MMIE. It checks
AP addresses, KeyID, strictly increasing 48-bit IPN and constant-time truncated
CMAC comparison, publishing accepted IPN only on success. Caller must bind
the result to the still-current installed key epoch and initialize replay
state from the installed IGTK IPN. Management RX is not wired to this helper.
Action frames, fragmentation handling and firmware protection metadata remain
open; do not expose this helper as complete PMF capability.

ASan/UBSan security suite passed a fixture independently generated by Python
cryptography CMAC/AES with key bytes 00..0f, AP 02:01:02:03:04:05, reason 3,
KeyID 4 and IPN 7; protected-field mutations and replay leave the accepted-IPN
output unchanged; FC Retry/PwrMgt/MoreData changes are masked.
Reference AAD/MIC construction:
https://chromium.googlesource.com/chromiumos/third_party/hostap/+/refs/tags/hostap_2_3/wlantest/bip.c
No hardware authenticity or active WPA3 claim follows from these host tests.

BIP unsupported-header regression: independently computed valid CMAC frames
with More Fragments, nonzero fragment number and Order bit test the input
boundary independently of MIC failure. More Fragments was initially accepted;
that regression failed. Verification now rejects More Fragments, any nonzero
fragment number and Order/DS flags before authentication. Security and RSN
ASan/UBSan suites pass after the fix. Fragment reassembly remains unsupported.

Local PMFKeyEpochs now owns two software IGTK slots (4/5) and monotonic
epochs. Authenticated redelivery of identical key bytes in the same slot
retains IPN; reuse of those bytes in another active slot rejects. A new key
gets a fresh epoch. clear() wipes slots but preserves the epoch counter,
and destruction wipes the object. Snapshot/verified-IPN commit separates
cryptographic verification from replay publication; commit rejects stale
epochs, non-increasing IPN and values above 48 bits. This class is explicitly
single-owner/externally serialized, with no implied thread safety. Snapshot
key copies remain caller-owned and require zeroization.
ASan/UBSan security tests passed redelivery, replay, cross-slot reuse, key
replacement, stale completion and clear/reuse cases. Activation is not hooked
to EAPOL/firmware; real installation acknowledgement and gate/worker integration
remain prerequisites before this class can protect an actual connection.

SAE group-19 key expansion is implemented locally as deriveSAEGroup19Keys:
32-byte validated keyseed and fixed-width big-endian scalar sum modulo the
curve order feed SHA-256 KDF-512, producing 32-byte KCK, 32-byte PMK and the
first 16 bytes of the scalar sum as PMKID. A fixture generated independently
with Python hashlib/hmac matches all output bytes under the CommonCrypto
test provider; the ASan/UBSan sha256_supplicant suite passes. Input-size failure
leaves output unchanged, and temporary KDF buffers are wiped.
This helper does not validate group arithmetic or derive keyseed; callers must
implement the mode-specific salt (including H2E rejected-group handling),
PWE, shared secret, scalar validation and commit/confirm before use. It is
not invoked from native association. Reference key expansion contract:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/fb79edc9df1f20461e90e478363d207348213d35/src/common/sae.c

Group-19 SAE-confirm HMAC primitive is now implemented locally. It serializes
the 16-bit send-confirm counter in LE, followed by sender scalar/affine point
and receiver scalar/affine point (32+64 bytes each, fixed-width BE). It publishes
32-byte confirmation only after successful HMAC-SHA256 and wipes temporary
buffers. Independent Python hashlib/hmac fixture with counter 0x1234 passes
ASan/UBSan sha256_supplicant checks; reversed sender order differs, malformed
commit length rejects, and injected HMAC failure preserves output. The same
failure provider confirms KDF output is not published on initial HMAC failure.
Inputs must already be curve/scalar validated and bound to the current SAE
session. This primitive does not parse authentication frames, detect reflection
or enforce counter replay/session state. Those remain mandatory integration
requirements; no native authentication callback has been enabled.
Reference serialization/order:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/1788f701327a5a4ec84ee699b407ab56b397b96c/src/common/sae.c

Local group-19 peer-confirm verification accepts an exact 34-byte bare body,
reverses sender/receiver commit order for HMAC, uses constant-time digest
comparison, and publishes peer counter only after success. For an already
accepted session it rejects counters <=Rc and 0xffff; initial confirmation
retry policy remains the session state machine's responsibility. ASan/UBSan
sha256_supplicant tests pass valid peer confirmation, accepted-state replay,
every single-byte mutation of the body, every truncation and injected HMAC
failure without counter publication. The caller still must validate peer
identity, key generation, curve inputs and authentication transaction/status.
This helper handles no SAE-PK/extended body and does not implement a session
state machine. Reference state-dependent counter rule:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/59fa4b44b84301ac01b937a6a0e687cf5dd3593a/src/ap/ieee802_11.c

Group-19 shared-secret algebra now composes the experimental P-256 adapter:
local rand times (peer scalar times PWE plus peer element), returning only
the affine x coordinate after all operations succeed. Tests against an
independent cryptography/OpenSSL point (7*(3*G+2*G)=35*G) pass under ASan/UBSan
with actual userland CoreCrypto, with per-call failures injected throughout
the composed sequence and peer scalar 1 rejected. Temporary points and
workspace are wiped; failure leaves output unchanged. A used compile-only
kernel entry explicitly instantiates the composed function and passes the
existing kernel import/stack check. Kernel execution ABI remains unverified.
PWE derivation, mode-specific keyseed, reflection/session validation and native
authentication sequencing are still required; no real credentials are used
by these synthetic public-point tests.

SAE negative cases additionally pass under ASan/UBSan: independent point
-3*G makes peerScalar*PWE+peerElement infinity and the composed secret rejects;
peer scalars zero/one/order/above-order and zero local random reject without
output changes. Failure injected at either KDF HMAC call preserves the entire
previous KCK/PMK/PMKID output, including after a successful first block.
These are host cryptographic failure cases, not authenticated session tests.

Local SAE group-19 commit-scalar arithmetic accepts rand/mask in [2,r-1],
adds with a 33-byte carry, conditionally subtracts curve order and rejects
commit values 0/1. It does not reduce biased random samples into range:
caller must draw/retry with a cryptographic RNG and a bounded attempt count.
Nine independent Python-integer fixtures pass under ASan/UBSan, including
carry beyond 256 bits, order subtraction, invalid input and result 0/1 with
unchanged output. Temporary sum/reduction buffers are wiped. Source loops
have fixed bounds; no machine-level constant-time audit is claimed.
A used kernel compile-only entry instantiates this arithmetic. No native
SAE commit generator or mask lifetime/state machine has been enabled yet.
Reference rand/mask/commit constraints:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/3dbea20fb6570e548e831910e108b2307d6232ba/src/common/sae.c

Local group-19 commit algebra now produces scalar || affine element from
caller-provided rand/mask/PWE: scalar=(rand+mask) mod r; element=-(mask*PWE).
Point negation uses the already tested multiplier with scalar r-1. Temporary
prepared commit and masked point are wiped; output is published only after
all operations succeed. Tests with actual userland CoreCrypto plus ASan/UBSan
pass an independent -3*G fixture and per-call fault injection. Two synthetic
parties (rand/mask 7/3 and 11/5, PWE=G) form distinct commits and both derive
the same x coordinate of 77*G, independently obtained via cryptography/OpenSSL.
This is an algebraic interoperability test with known PWE, not password-based
SAE interoperability. RNG sampling/retries, PWE/H2E, live credentials, commit
frame serialization, reflection/state handling and kernel execution remain
open. A used compile-only kernel entry instantiates the complete commit helper.

Local H2E group-19 password expansion now performs HKDF-Extract with SSID
as salt over password||identifier, then two 48-byte HKDF-Expand values using
the distinct u1/P1 and u2/P2 labels, without their terminating NUL. Password
and identifier bounds are 64 and 255 bytes; SSID <=32 bytes. The 96-byte
result is published only after all five HMAC operations succeed, and seed,
password concatenation and temporary values are wiped. Independent Python
hashlib/hmac fixture passes ASan/UBSan with CommonCrypto; fault injection at
each of five HMAC calls preserves output. These outputs are not field elements
or PWE yet: reduction modulo p, SSWU and PT-to-PWE MAC binding remain open.
Matching local CoreCrypto symbol inventory exposes cczp inversion/multiply/
square-root entries, but no cch2c/SSWU-named entry was found in that inventory;
this does not prove absence of all equivalent APIs or establish callable ABI.
Reference expansion and mapping stages:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/sae.c

Local H2E 48-byte-to-field reduction now implements fixed-size bitwise long
division modulo the P-256 prime with a 33-byte remainder and one conditional
subtraction per bit. All loops have public fixed bounds; temporary remainder
and subtraction buffers are wiped. No machine-level constant-time claim is
made. Eight independent Python-integer fixtures pass ASan/UBSan: 0,1,p-1,p,
p+1,2p,2^384-1 and a mixed byte pattern. Wrong length leaves output unchanged;
output guards confirm a 32-byte publication. A used kernel compile entry
instantiates the reduction. This is not SSWU or a complete password element.

Experimental group-19 SSWU is implemented locally using Z=-10, the P-256
A/B parameters, masked denominator-zero handling and parity-based Y sign
selection. Both candidate roots are evaluated; provider Error aborts rather
than selecting another candidate. Prepared scratch and field workspace are
wiped on exit. Five independent Python-integer mapping fixtures (0,1,2,3,p-1)
match actual userland CoreCrypto under ASan/UBSan, and the mapped u=1 point
is accepted by the independent existing CoreCrypto point validator. Selected
initial/middle/final provider failures and input p reject without output
publication. A used kernel compile entry instantiates mapping and passes
import/stack checks. This is not a full H2E PWE or kernel runtime proof.
Timing/side-channel behavior is NOT approved for real password derivation:
field-root status paths and provider allocation/scheduling need further audit
before native integration. Mapping tests use synthetic public inputs only.
Reference mapping and group-19 Z:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/sae.c

Experimental group-19 H2E password-to-PT pipeline now combines HKDF values,
48-byte field reductions, both SSWU maps and point addition, publishing only
the final 64-byte PT. Password-derived buffers, intermediate field values,
points and both workspaces are cleared on exits. Actual userland CoreCrypto
ASan/UBSan passes a synthetic test-ssid/test-password/test-id fixture computed
independently with Python HMAC, modular arithmetic and affine point addition;
cryptography/OpenSSL separately validates the reference point. The result is
also accepted by the CoreCrypto point validator. Selected early/middle/late
provider failures preserve output and clear workspaces. This is PT, not PWE:
MAC-bound scalar derivation/multiplication is the next dependency. Kernel
execution and password-dependent timing behavior remain unverified, so the
pipeline stays outside native association and uses synthetic test inputs.

Experimental group-19 H2E PT-to-PWE now hashes max(MACs)||min(MACs) using
32 zero salt bytes, reduces the digest modulo (r-1) and adds 1, then multiplies
PT by that scalar. Inputs/output must be disjoint from workspace; caller
validates MAC/session identities. Secret temporaries/workspace are wiped.
ASan/UBSan tests with actual userland CoreCrypto match an independently
generated cryptography/OpenSSL scalar*G fixture, verify MAC reversal symmetry
and changed-MAC separation, and inject failures at every provider call.
Six Python integer fixtures cover scalar reduction boundaries, including zero
and 2^256-1. A full synthetic password->PT->MAC-bound PWE pipeline also matches
independent Python HMAC/affine arithmetic, with the expected point separately
validated by cryptography/OpenSSL and the result by CoreCrypto. A used kernel
compile entry instantiates scalar reduction; the full password pipeline has
only userland execution evidence. Timing/side-channel review, kernel ABI and
worker/session integration remain mandatory; WPA3 is still not enabled.
