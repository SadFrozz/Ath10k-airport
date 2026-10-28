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

Next integration gates, in order (the software primitives below are not hardware
support):

- Complete native SA Query request/response scheduling and protected management
  TX retirement, including timeout/cancel/rekey and existing robust-action producers.
- Establish QCA9377 protected RX layout, firmware PMF setup and management TX PN
  ownership before enabling the profile.
- Finish the credential-to-SAE worker path, then connect authenticated PMK/IGTK
  publication, AKM8 EAPOL and controlled-port readiness as one admission policy.
- Validate WPA3-only/H2E and transition APs, downgrade rejection, rekey, reconnect,
  forget-network, sleep and stop; only then expose the native capability.

Do not advertise SAE or PMF while these dependent stages remain incomplete.
Roaming preparation stays local and deferred; no need to restart that work
before the security dependency path is functional.

### Current exchange composition (2026-10-28, local)

`saeGroup19ExchangeCandidate` composes the validated scalar sum, reflection
rejection, local/peer point checks, shared secret and group-19 AKM 8 key
derivation. Outputs remain candidate keys until peer confirm succeeds. The
caller must bind local commit/random/PWE, identities, mode and the exact
prevalidated rejected-group payloads to one live session/generation.

`deriveSAEGroup19ExchangeKeys` derives keyseed using zero salt without rejected
groups, or H2E's retained lists in higher-MAC-first order. It bounds each LE16
list payload to 254 bytes and rejects malformed lengths, missing buffers,
invalid/equal MAC identities and rejected lists in non-H2E mode. It does not
parse or authenticate rejected-group IEs. Scalar addition now distinguishes
transmitted commits (result 0/1 invalid) from KDF context (0/1 valid).

ASan/UBSan tests with actual userland CoreCrypto cover two parties' independent
commits producing identical keys, independently calculated Python affine/HMAC
fixtures, each provider failure preserving old output and clearing workspace,
reflected/invalid points, and H2E salt ordering. A synthetic complete
password-to-PT-to-PWE-to-commit-to-keys exchange passes mutual confirmation;
one changed password fails confirmation. Used kernel compile-only entries
instantiate full H2E and exchange composition, with stack/import checks.

These are ordinary-process tests, not AP/frame interoperability or kernel
execution. Native credential delivery, retained crypto worker/cancellation,
full SAE frame/state handling, timing validation, AKM 8 EAPOL and mandatory
PMF remain incomplete; this work does not advertise or enable WPA3.
Reference derivation and reflection rules:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/sae.c

### Confirmation publication fence (local, not wired)

`Ath10kSAE.hpp` separates owner-gate state from worker-owned KCK/commit
snapshots. Owner methods perform no cryptography. Candidate keys are consumed
and wiped even on stale/failed completion; PMK/PMKID remain private until a
local confirm was generated and submitted and the peer confirm verified.
Snapshots contain no PMK. Both owner identity and monotonic generation must
match at publication; peer counters are checked again after worker execution.
Before frame submission, `localReadyToTransmit` must be checked under the
owner gate, and any additional TX queue must recheck at actual submission.

Cancel wipes retained keys/commits and prevents late local TX admission, peer
confirmation or PMK export. Generation is retained across reuse, never wrapped.
Local confirm reservations stop before 0xffff. Invalid replacement and failed
current key calculation retire the old exchange; stale failures do not cancel
the new one. Owner/job copying is forbidden and destruction wipes each object.

ASan/UBSan tests cover peer-before-local completion, failed local submission,
provider failure, late verification/completion after cancel/restart, equal-token
different-owner rejection, out-of-order concurrently snapshotted peer confirms,
replay, reservation exhaustion, output bounds and destructor cleanup. The full
synthetic password-based two-party exchange also passes this publication fence
and exports the independently calculated PMK only after both confirmations.
Kernel compile/import/stack checks instantiate the fence and both worker paths.

This is a reusable confirmation fence, not a retained kernel work queue, full
SAE state machine or proof of race-free live I/O. Native integration must retain
owner/jobs, serialize every state operation, ensure proper worker handoff/drain,
bind peer/mode/credentials to the same connection epoch, enforce deadlines,
and revoke downstream EAPOL keys on leave/sleep/stop. Pending worker snapshots
are wiped when drained/destroyed, not by concurrently writing into running jobs.

### Authentication frame codec (local, not wired)

`Ath10kSAEWire.hpp` adds owned, bounded group-19 authentication messages and
client-to-AP frame construction/AP-to-client frame admission. SAE algorithm 3,
transaction 1 commit, transaction 2 confirm, H2E status 126, anti-clogging status
76 and rejected-group status 77 are distinct. Other failure statuses are
reported as rejections, not authentication success. Confirm bodies are exactly
34 bytes. Full frame admission requires the expected unicast receiver, AP
source/BSSID and an ordinary unfragmented/unprotected authentication header;
input excludes firmware metadata and FCS. It does not validate scalar/curve,
confirm MIC, authentication phase, channel, replay or connection generation.

Commit extensions retain exact password identifier octets, rejected-group
payload and token, reject duplicates/reordering/truncation and fail explicitly
on unknown extensions/extended-key AKMs. H2E tokens use extension 93; legacy
tokens precede scalar/element with an explicit context-supplied length. The
client's AP-reply decoder expects no legacy token prefix and never guesses a
prefix from remaining bytes or switches mode based on token contents. The
retained exchange's H2E choice must match the commit marker; mismatch cannot
silently downgrade. Mode-specific challenge processing preserves opaque tokens.

The codec caps H2E identifier/group/token payloads at 254 bytes, legacy tokens
at 1024, full frames at 1536. Rejected-group payloads must be nonempty LE16
groups, even length, with no zero/current-group entry. Scalar/point/session
validation remains worker/FSM work. Decoder output and encoder output/length
are unchanged on failure; messages own their bytes rather than retaining RX
pointers. Serializer status is derived from kind/mode, not caller status data.

This exposed a password-ID boundary error in the H2E expansion helper: its
former 255-byte admission cannot fit extension length 255 plus extension ID.
The shared H2E helper now admits at most 254 identifier bytes, with a tested
254-success/255-reject boundary. Earlier historical notes of 255 are superseded.

ASan/UBSan tests cover independent layout fixtures, incomplete fixed/IE fields,
duplicate/reordered/unknown extensions, identities/header flags, token formats,
mode mismatch, exact confirms, output guards, maximal payloads and 3000 seeded
mutations. The synthetic two-party H2E test now crosses this body codec before
key/confirmation publication. A kernel compile entry instantiates full frame
encoding/decoding and passes stack/import checks. Real firmware RX/TX dispatch,
anti-clogging retry state, timeouts and the complete SAE FSM remain unimplemented.
Reference serialization/constants and client challenge interpretation:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/sae.c
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/ieee802_11_defs.h
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/wpa_supplicant/sme.c

### Client exchange coordinator (local, not wired)

`Ath10kSAEExchange.hpp` joins framing, a private candidate-key worker result and
the confirmation fence from an already prepared/validated local group-19 commit.
It is allocated/retained off the kernel stack. The native caller must bind the
same immutable random/PWE/credential context to the key job; this coordinator
does not derive the initial commit or provide IOKit ownership/queue scheduling.

| Phase | Admitted work/events | Transition/effect |
| --- | --- | --- |
| Idle/Failed | explicit begin with validated local commit and identities | new monotonic exchange generation, fixed deadline |
| Committed | current commit TX, token challenge, peer commit | revision-checked TX; opaque token retry; one key job on non-reflected matching-ID peer commit |
| Computing | one retained key job; bounded early-confirm queue | duplicate/changed commits ignored; successful current keys enter Confirming; failure retires exchange |
| Confirming | local confirm workers/TX and queued peer verification | both confirmations required for Accepted; no PMK on partial success |
| Accepted | matching-generation PMK export | no authentication restart from unsolicited frames; explicit cancellation revokes retained keys |
| any active phase | cancel, stale jobs, clock/timeout, explicit rejection | wipe/retire or discard; no replacement of a new generation by old completion |

Initial prototype policy uses a 5000ms absolute deadline, 750ms retry interval,
five commit attempts (including failed submission), five local-confirm worker
reservations, three changed tokens, four owned queued peer confirms and sixteen
peer-verification reservations per exchange. These are bounded implementation
defaults, not claimed IEEE-mandated timer values. Challenges, RX noise and
duplicates cannot extend the deadline. Same-token challenges are ignored;
new tokens invalidate old TX revisions and reuse the exact original commit.
No mode, group or open-auth fallback is performed on rejection. Commit mode
mismatch fails explicitly; malformed/wrong-peer frames cannot advance state.

Peer confirms may be held before peer commit/key completion without advancing
authentication. Once keys exist, each candidate is verified off-gate; a bad
queued confirm does not discard a later valid one. Consumed/failed local TX
results cannot be resubmitted; timer retry reserves a new confirmation counter.
Before actual submission, commit/confirm owner/generation/revision admission
must be rechecked under the serialized owner context. Temporary encoding
buffers and jobs must remain retained until the transport has consumed them.

Pure ASan/UBSan tests cover fixed deadline/retry budgets, token revision races,
reflection, duplicate job suppression, replacement/cancellation, clock checks,
mode/identifier/group failures and unchanged PMK output. Actual userland
CoreCrypto tests additionally exercise token retry, early invalid/valid confirms,
queue dedup/capacity/verification budget, failed local TX then timed retry,
successful PMK matching the independent H2E fixture, cancellation followed by
real late key computation, and valid keys completed exactly after timeout.
Stale/expired key results are wiped. A used kernel compile entry instantiates
the complete coordinator, key worker and both confirmation worker paths;
individual stack frames/import checks pass, not a live native call-stack audit.

The coordinator is not dispatched by firmware RX/TX or native macOS joins yet.
Outstanding requirements include retained kernel queue/drain/power integration,
initial random/PWE preparation, kernel crypto runtime/timing validation, native
credential/capability delivery, association PMKID/AKM8 EAPOL and mandatory PMF.
Only group 19 is modeled; no fallback to groups 20/21, SAE-PK/extended-key/FT
or accepted-session reauthentication is claimed. WPA3 remains disabled.
The client source used for state-order comparison is the SME reference linked
above; its synchronous key processing is deliberately moved into explicit jobs.

### Kernel worker lifecycle (source-integrated, not boot-verified)

`Ath10kSAEWorker` is now compiled/linked into the native kext and allocated by
NativeSecurity initialization when allocation succeeds. An unavailable SAE queue
is reported as a readiness property and does not disable existing WPA2; future
SAE admission must fail explicitly rather than downgrade. Radio-gated reset cancels without waiting;
stopNativeRequests drains the existing service producer and then shuts the crypto
queue down outside radio/WCL. Partial allocation and repeated stop are supported.
The queue is idle in the native join path: concrete session/job adapters are
described below, but native dispatch and WPA3 admission/capabilities remain disabled.

The queue owns one retained job through pending/running/unconsumed completion and
retains itself for each scheduled callback. Jobs must own immutable session data,
never borrowed NativeSecurity pointers. Final free is sealed in the work-item
base and invokes the job's idempotent discard hook even after normal consumption;
concrete jobs must wipe/release their private session material there. A result
is pulled by its owner, which must still check session/generation before use.
execute/discard/free must not enter driver gates or drain the queue. No callback
enters WCL/radio or allocates another unbounded queue of pending crypto jobs.

Cancellation preserves pending state after false thread-call cancellation: kernel
dispatch may have begun before callback entry. Running jobs are not concurrently
wiped. Queued/completed cancellation disposes outside the bookkeeping lock; a
retirement counter also makes shutdown wait for preempted disposal. Shutdown
permanently blocks admission, drains queued/running/retiring ownership and frees
the callout. Sleep/reset cancellation permits later reuse. The final callback has
no queue access after dropping its retained reference.

The installed kernel identifies xnu-11417.140.69. Its published thread_call source
confirms cancellation and allocated ONCE callout lifetime rules used by this design;
the queue uses no cancel_wait export. This source comparison is not live execution.
https://github.com/apple-oss-distributions/xnu/blob/xnu-11417.140.69/osfmk/kern/thread_call.c

Tests compile the production queue declarations/definitions with an explicitly
modeled ONCE scheduler, locks and reference counts. ASan/UBSan and ThreadSanitizer
pass allocation failure, bounded admission/result transfer, queued cancel,
dispatch-before-callback cancel, cancellation during execution, delayed disposal,
shutdown outside owner gates, callback retention after last external release and
requeue/cancel before kernel callback return. Production NativeSecurity and bridge
tests cover init failure, nonblocking reset and outside-gate drain order. Native
kext compilation/link/import checks pass. Actual IOKit scheduling, sleep/stop,
crypto backend calls and a complete retained native SAE session remain unverified.

### Retained native session and concrete jobs (compiled, host-executed)

`Ath10kSAESession` and `Ath10kSAEJob` now compile/link into the kext. A one-shot
prepared session owns the client coordinator and connection-generation identity.
The factory requires an already prepared/validated local commit/random/PWE and
an externally validated callable P-256 API. It does no expensive crypto under
the owner gate and does not establish that backend validation itself.

Key calculation, local-confirm generation and peer-confirm verification are
concrete retained jobs submitted through Ath10kSAEWorker. Each job owns its
metadata/body/workspace and a private context copy; it retains its session for
owner identity/lifetime, without borrowing NativeSecurity or IO80211 pointers.
The worker never reads mutable session state. Prepared owner secrets are erased
after successful key-job admission or cancellation; private random/PWE copies
and workspace are erased after execution and again by idempotent disposal.
Confirmation snapshots/results are disposed on final job release.

Owner consumption checks session pointer, native connection generation and
worker execution/consumption state before touching the coordinator. Keys/peer
results are single-use. Local confirm results retain their identity until actual
TX admission/completion; failed/consumed results cannot be resubmitted. PMK
export still requires both confirmations and the current connection generation.

Busy queue admission happens before coordinator snapshot/reservation. Object
initialization/allocation failure leaves work unreserved. If admission loses a
terminal race after snapshot, the session cancels instead of stranding a key
reservation or popped confirm. A transferred result remains caller-owned until
release. NativeSecurity reset cancels the session, discards/releases its pending
TX result, releases the session and only then cancels the worker; stop drains it
outside owner gates. Concrete native joins do not yet create these sessions.

Production session/job methods run in host tests with the real userland P-256
CoreCrypto adapter and a CommonCrypto HMAC substitute for kernel ccsha256/cchmac.
ASan/UBSan checks pass prepared-input copying, busy/no-memory admission without
lost reservations, terminal admission race, cross-session/generation rejection,
real key/confirm flow through the queue, provider failure and timed/failed-TX
retries, current-generation PMK fixture, cancellation while HMAC is paused, and
retained old-result cleanup. A pre-delete observer scans job/session storage for
the known PWE/PMK fixtures after disposal and finds neither. Production queue and
session race tests also pass ThreadSanitizer. Kernel build/link/import checks
pass; actual kernel P-256 execution and live IOKit scheduling remain unverified.

The owner/queue/job lifetime path now exists in kext sources. Initial credential
preparation, verified kernel backend binding, native join/firmware dispatch,
association PMKID/AKM8 EAPOL, mandatory PMF and hardware validation remain open.
No SAE/PMF capability is advertised and no native WPA3 join is enabled yet.

### AKM8 EAPOL and authenticated IGTK delivery (local, opt-in software)

`Supplicant<Crypto,AllowSHA256,AllowSAE>` adds a separate default-false SAE option.
Existing native `Supplicant<...,true>` still admits only its prior WPA2 profiles.
Software AKM8 admission requires CCMP group/pairwise, AP MFPC and BIP-CMAC-128;
unsupported capability/cipher/AKM combinations are rejected. The PMK must already
come from authenticated SAE; the caller must bind it to the same association.
This API does not derive SAE PMK from a password or bypass session verification.

The selected AKM8 profile uses descriptor version 0, SHA256 PTK expansion and
AES-CMAC MIC. Versions 2/3 are rejected for this profile. `buildSAEStationRSN`
constructs a CCMP/SAE RSNE with MFPC/MFPR, BIP-CMAC-128 and an optional exact
16-byte verified SAE PMKID. This is distinct from the retained AP RSNE checked
in M3; transition APs need not set MFPR or advertise the same AKM list as the
station. No extended-key/FT/enterprise/GCMP profile is enabled by this option.

Initial M3 requires authenticated/unwrapped GTK and IGTK. IGTK KDEs must have
the exact CMAC-128 length and KeyID 4/5; duplicates, malformed trailing data and
active identical key material moved across slots reject the entire transaction.
IGTK-only group rekey has a distinct `ManagementKeys` result; group and pairwise
changes expose PTK/GTK/IGTK change bits while preserving the existing 56-byte
data-key payload. Pairwise rekey may retain omitted GTK/IGTK; unchanged keys
are not marked for installation. Cached M3/group retries return Reply, never a
key-install result. Same-key IGTK delivery does not request reinstallation or
republish a lower IPN. The observed-key cache is not firmware installation state
or the receiver's PMF replay state: those still require acknowledged key epochs.

The key-result fields describe the last successful key result only; callers
must dispatch on Result first, and honor change bits to avoid installing an
unchanged key. No M4/group-ack result alone authorizes the controlled port. The
native adapter does not yet consume the management result/mask or activate
software IGTK epochs. Firmware IGTK installation is not presumed necessary;
the ath10k reference below explicitly handles BIP keys in software.
RSN/PMKID/RSNX association integration and protected RX/TX/SA Query remain open.

This work reproduced a shared WPA2/SAE bug: M3 copied candidate keys to the
public payload before M4 MIC construction succeeded. The old published header
changed that payload under an injected M4 encryption failure (reproducer exit
7); the fixed header preserved it (exit 0). Publication now follows successful
acknowledgement construction. This is not proof that a previously observed
hardware freeze/disconnect had that cause. A null receive buffer now rejects
before parsing as well.

Independent fixtures are generated by `tools/sae/generate-eapol-vectors.py` using
Python hashlib/hmac and cryptography AES-CMAC/RFC3394 wrap, with a synthetic SAE
PMK, not user credentials. CommonCrypto ASan/UBSan tests cover M1-M4, PMKID/no-ID,
transition/default management cipher, IGTK-only and combined rekeys, old-key
retry suppression, moved-key rejection, PTK rekey with retained group keys,
malformed/duplicate/missing IGTK, bad MIC/wrap/padding/RSN and failed M4 publication.
The retained-session test feeds its verified queued SAE PMK/PMKID into these
AKM8 messages and matches the independent PTK/IGTK fixtures. A kernel compile-only
entry receives into an arbitrary existing supplicant state with full provider
indirection, preventing begin/M1-only optimization from hiding M3/group paths.
The emitted receive frame is 1160 bytes and passes kernel import/frame checks;
this is not proof of complete kernel call-stack depth or runtime behavior.

Reference descriptor/MIC/KDF selection:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/wpa_common.c
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/src/common/defs.h

### PMF transport evidence and bounded SA Query (local, not dispatched)

The Linux v6.12 ath10k set_key path explicitly returns software handling for
AES-CMAC/BIP keys, before checking the firmware's data-key index limit. Do not
invent an INSTALL_KEY command for IGTK indices 4/5 or wait for an HTT data-key
acknowledgement that the reference does not use. Authenticated IGTK delivery
must instead activate a software PMF key epoch, with retained IPN and stale-job
checks, coordinated with the data-key transaction before port authorization.
The existing `PMFKeyEpochs`/BIP disconnect helpers remain unwired to native RX.

The reference WMI path reports protected PMF action/deauth/disassoc frames as
decrypted but retains their IV/MIC layout for mac80211's subsequent processing.
It excludes WEP authentication from that assumption. This does not establish
integrity/replay verification in our current WMI path; simply clearing Protected
and dispatching the body at offset 24 would be incorrect. Native integration
must identify the current pairwise key epoch, handle IV/MIC, verify PN/integrity,
and reject stale crypto completion before using any protected management body.
Essential management RX is carried via WMI; duplicate HTT copies must not create
a second state transition. Protected management TX is also still unimplemented.
Reference paths (mac.c: set_key/peer_assoc_h_crypto; wmi.c: mgmt_rx):
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/mac.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/wmi.c

The reviewed QCA9377 firmware WLAN.TF.2.1-00021-QCARMSWP-1 container has SHA256
8f8b002fccfe81d42238f27dd1f56d189604f180bd4772c7c8e75ae1fef16f01 and feature IE
hex c0: feature 12 (MFP_SUPPORT) is not declared. Linux guards its peer PMF flag
with that feature but advertises MFP_CAPABLE separately. Missing bit 12 alone
therefore proves neither working PMF nor the need to replace firmware. VDEV/peer
flags, PMF QoS setup and actual RX/TX layout require verification for this TLV
profile before native SAE admission can be enabled.

`Ath10kSAQuery.hpp` adds a serialized, allocation-free client coordinator and
ordinary 28-byte SA Query frame construction/admission. Incoming plaintext must
be accompanied by caller-verified integrity/replay and matching connection/PTK
epochs; Protected alone cannot admit it. Frames must have expected unicast
receiver, AP source/BSSID, action category 8, request/response code, no DS,
fragment or ordered header. OCV/OCI extensions are explicitly unsupported.
Outgoing frames are plaintext templates still requiring PTK encryption, sequence
and PN assignment; setting Protected here does not implement protection.

Unprotected unicast deauth/disassoc reasons 6/7 may trigger a bounded query only
for an authorized PMF association; they never authorize disconnect themselves.
Other unprotected robust frames and group triggers are rejected by this helper.
Native RX must still apply the full PMF drop policy. Each query has a fixed
1000-TU deadline, 201-TU retry interval and at most five attempts. Repeated
triggers do not extend it; starts are limited to one per ten seconds per binding.
Random two-byte IDs are caller supplied, distinct within the submitted set, and
only admitted after the protected TX path accepts them. An RX response may match
any submitted ID; reserved/failed TX IDs do not complete the query. Owner/serial,
connection/key epoch and actual TX-admission checks reject mutated/stale tickets;
clear/rebind invalidates pending work without resetting the monotonic serial.
Backward clocks fail the procedure and retry arithmetic cannot overflow.

ASan/UBSan tests cover wire fixtures, authentication/replay/epoch/identity guards,
protected/header/fragment rules, unchanged outputs on rejection, reason-code
triggers, TX handoff failures, old and multiple submitted IDs, duplicate IDs,
fixed deadlines/rate limiting, cancellation/rebind, cross-owner tickets and
near-UINT64_MAX timestamps. A kernel compile-only entry instantiates receive,
TX admission/submission and retry paths with arbitrary existing state. No native
query timer, protected TX, WMI RX normalization or disconnect policy is enabled
by this software coordinator; PMF/WPA3 hardware interoperability remains open.
Reference retry/timeout/response semantics:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/wpa_supplicant/sme.c

### Pairwise CCMP-128 management authentication (local, not dispatched)

`Ath10kPMFCCMP.hpp` implements AES-CCM for nonfragmented unicast robust
management with an ordinary 24-byte header, key index 0 and an 8-byte MIC.
Its 13-byte nonce is management flag 0x10 || transmitter || big-endian PN.
AAD retains management subtype/addresses, masks Retry/Power/MoreData and the
sequence number, and uses the 22-byte header AAD length. Deauth/disassoc and
robust action bodies are supported; known nonrobust action categories reject.
DS/fragment/ordered headers, group addresses, wrong local/AP/BSSID binding,
missing Protected, reserved CCMP bits, other key indices, zero/replayed PN,
wrong lengths and invalid MIC reject without publishing a plaintext result.

The receive API has two explicit layouts: wire ciphertext, and plaintext body
with the ORIGINAL encrypted CCMP tag/IV retained. Both independently authenticate
the body/tag with AES-CCM. The second layout is a software contract, not an
assertion about this QCA9377 firmware: actual WMI byte layout must be measured
before selecting it. An already-decrypted body with an absent/rewritten tag or
IV is not silently trusted. RX normalization must also reject firmware CRC,
decryption, MIC or key-cache errors before invoking this path.

`protect` constructs complete CCMP ciphertext/tag from a protected plaintext
header/body and a caller-reserved nonzero 48-bit PN. The transport must preserve
these bytes without encrypting them again. The primitive itself supplies no TX PN allocator, raw/HTT mode selection,
hardware management encryption or actual frame submission. The retained TX
coordinator below adds a host management PN allocator and leases; radio transport
selection and actual frame submission remain open. Failed encryption/submission must consume its PN. Extended key
IDs, fragmentation/reassembly, CCMP-256 and GCMP remain unsupported profiles.

A caller-owned workspace stages plaintext/ciphertext, CBC state and counters;
it is wiped after every admitted attempt, including provider failure. Publication
occurs only after the entire authenticated operation succeeds. Input, result and
workspace must be disjoint; output/workspace alias checks precede workspace use.
Bounds/layout/alias failures leave the old result intact. AES provider calls
must run outside driver gates with a retained key snapshot/workspace.

`PMFPairwiseEpoch` supplies a separate management RX replay domain. It activates
a PTK only after installation acknowledgement, and snapshots key, local/AP,
connection, monotonic epoch and current PN. Same-key delivery preserves epoch/PN;
reusing the live key for a different binding rejects. Owner-gated commit checks
the current epoch/connection and live PN again, then publishes `PMFVerifiedRX`
for SA Query. Clear/key rotation invalidates old snapshots. The caller must
commit only after successful CCMP verification with that same immutable snapshot;
this API is not a security boundary against arbitrary in-process callers.
The optional native PTK-acknowledgement hook uses this state when a PMF owner
exists; current native joins still create no such owner, and WMI dispatch is
not connected to it yet.

Independent cryptography AESCCM fixtures cover AP deauth/disassoc/SA Query,
protected vendor action, 15/16/17-byte and maximum 472-byte bodies, high/max PN
and station TX. Both explicit RX layouts match the independent plaintext;
station ciphertext matches independently generated bytes. Tests corrupt header,
IV, body, key and MIC; reject nonrobust public action, wrong direction, layout,
reserved bits, fragmentation, replay and input/alias bounds. Per-AES-call fault
injection preserves output and clears workspace. A composed receive -> current
key/PN commit -> SA Query response test succeeds; stale rotation/clear, duplicate
and out-of-order commits reject. ASan/UBSan and kernel compile/import/frame checks
pass. This is software interoperability with independent AESCCM, not AP/kernel
runtime or firmware-layout evidence.
Reference nonce/AAD/header/management replay processing:
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/net/mac80211/wpa.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/include/linux/ieee80211.h

### Sanitizer result correction and scan-metadata alignment

The development runner previously judged child exit status only, while UBSan's
recovery mode could emit a diagnostic and still exit 0. Reviewing retained logs
found misaligned `BeaconMetadata` member accesses in native notifications; the
previous successful full-suite status was therefore insufficient evidence of a
clean UBSan run. The runner now forces `halt_on_error=1` for UBSan. Before the
source fix, the focused native-notifications regression exits nonzero under
this setting. `nativeBSSMessage` now constructs aligned local metadata and copies
bytes into the possibly unaligned output buffer instead of casting that buffer.
A wire regression compares exact metadata/IE bytes at all four alignment offsets.
This is a confirmed C++ alignment defect, not proof of any previous hardware hang.

### Retained PMF owner/jobs and native data-key boundaries (source-integrated)

`Ath10kPMFSession` is an OSObject owner for one PMF association. It binds the
local/AP identities and connection generation once and cannot be reinitialized.
Owner methods require the serialized radio context. PTK acknowledgement activates
a management replay epoch; a new epoch pauses PMF admission until authorization.
Authenticated IGTK publication activates software IGTK/IPN state only after a
pairwise key exists. Authorization requires both key families. Same-key redelivery
does not create a fresh replay epoch or clear an already authorized association.

The native data-key state machine now calls the PMF pairwise hook only after its
existing HTT security acknowledgement/CE credit checks, before publishing the
installed PTK. Before constructing the firmware peer-authorization command, it checks PMF
readiness; its final controlled-port barrier checks again before setting
portAuthorized. A present but incomplete/invalid PMF owner blocks
that transition with an error. No PMF owner is created by current native joins,
and the native supplicant still does not admit SAE, so these hooks do not enable
WPA3/PMF or alter the previous no-PMF key path.

NativeSecurity owns an optional retained PMF session. Reset/leave/sleep/stop
cancels and releases it before cancelling the existing crypto queue. The existing
outside-gate shutdown drains that same queue; PMF introduces no second workloop,
lock-order edge or synchronous wait beneath a radio/WCL gate. The existing bounded
kernel AES/HMAC provider is moved unchanged into `Ath10kKernelCrypto.hpp`, shared
by native EAPOL and the new PMF job translation unit.

RX jobs retain their PMF owner and independent key/identity/frame snapshots on
the heap (bounded to 4096 bytes). WMI admission errors use the existing 0x39 mask,
frames are bounded to 512 bytes and layout selection remains explicit. CCMP jobs verify unicast robust management and protect outgoing frames. Group
jobs verify BIP-CMAC deauth/disassoc and robust actions, then remove the MMIE
from the authenticated message before dispatch.
Job execution reads no mutable owner security state and enters no driver gate.
It erases crypto key snapshots/workspace on completion, retaining only lease
metadata and authenticated output until consumption/disposal.

The owner consumes only its own executed, unconsumed result for the current
connection. It rechecks the live PTK epoch/PN or IGTK slot epoch/IPN before
publication; cancellation, key rotation and another committed packet can make
an otherwise valid crypto result stale. Failed/stale results leave the caller's
message unchanged. Group verification has a distinct message kind and never
publishes a pairwise PMFVerifiedRX stamp usable by SA Query. Final sealed work-item
free/discard wipes remaining frame/result/lease state and releases the retained
owner. Terminal native cleanup also checks retained SAE/PMF owners and pending
TX when EAPOL ready/reply/key flags have not been set yet; failed/disabled,
explicitly cancelled and disconnecting connections retire them.
A terminal submit race consumes no RX replay reservation and does not
invalidate a valid association; the frame is dropped, never passed unverified.

Production worker/PMF sources are extracted into the existing host IOKit/ONCE
model. ASan/UBSan tests cover actual independent CCMP/BIP fixtures, PTK/IGTK
rotation after crypto completion, duplicate/out-of-order results, wrong owner or
generation, WMI error flags, allocation/init failure, failed crypto, decrypted
layout, terminal queue admission race, cancellation before dispatch and during
paused AES, and key-pattern erasure before object free. ThreadSanitizer passes
the retained PMF and worker lifecycle tests. Native cleanup/key-hook tests also
exercise optional-resource failure propagation. Native kext build/link/import
checks compile the PMF owner/jobs and shared provider. The provider body matches
the prior native implementation byte-for-byte. The full 47-test development
suite passes with UBSan halt enabled; an additional focused final regression
covers early terminal cleanup before EAPOL readiness.

These are modeled IOKit lifecycle tests and compiled native hooks, not observed
kernel execution. Native SAE admission, EAPOL IGTK staging/activation, WMI
interception/layout validation, completion dispatch, protected TX/PN allocation,
SA Query timers/drop policy and hardware validation remain mandatory before any
PMF/SAE capability may be advertised. In particular, the current raw management
handler must not be used as a fallback for an unverified PMF frame.

### Group robust management and retained protected TX (source-integrated)

`verifyBIPManagement` authenticates group deauth/disassoc and robust actions with
BIP-CMAC-128. It requires an ordinary unfragmented management header, group A1,
expected AP source/BSSID, no DS/Order/Protected bits, exact final CMAC-128 MMIE,
KeyID 4/5 and strictly increasing IPN. Known nonrobust action categories reject
even with a valid CMAC. Authentication does not validate each action's semantics:
for example, the separate SA Query parser still rejects group-addressed messages.
`verifyBIPDisconnect` remains a disconnect-only wrapper for existing callers.
The shared action classification is also used by unicast CCMP admission.

Retained PMF group results commit the current IGTK epoch/IPN before publishing a
normalized header/body with the 18-byte MMIE removed. They have a distinct
GroupManagement kind and no pairwise-authentication stamp. Independent CMAC
fixtures cover group channel-switch action, disassociation, maximum/zero IPN,
valid-CMAC nonrobust categories and invalid Protected usage. Corruption/replay
checks and the normalized worker-to-owner message pass ASan/UBSan.

`PMFPairwiseEpoch` also owns the host-generated management TX counter. Each
reservation snapshots the current key epoch and spends a fresh nonzero 48-bit
PN. Same-key acknowledgement preserves the counter; a new key resets it under
a fresh monotonic epoch. The checked successor refuses maximum/out-of-range
counters without wrap or output mutation. This pool must be the sole source for
protected management TX on this PTK, including any future hardware-encrypted
management path. Coordination with autonomous firmware management traffic must
be verified before native use; an independent second management PN pool is not
permitted.

This follows the ath10k reference division: ordinary data crypto is offloaded,
while CCMP keys request GENERATE_IV_MGMT and mac80211 reserves the management IV
from its host key counter. It does not establish the correct HTT flags or actual
QCA9377 firmware behavior for our fully software-encrypted packets.
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/mac.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/net/mac80211/wpa.c

`queueProtect` admits one outstanding protected TX lease per PMF owner, reserves
its PN after bounded allocation/init, copies plaintext and the key snapshot into
an independent retained worker job, and performs CCMP outside driver gates.
Busy/no-memory before reservation consumes no PN. Crypto failure, cancellation,
or a terminal queue-submit race after reservation never returns the PN to the
pool. The outstanding lease prevents later ciphertext from overtaking an older
retained result through this API.

`copyProtected` requires a successful job for the live owner/connection/key epoch
and unchanged pending PN. `protectedReady` must be checked again under the owner
gate immediately before actual transport submission. `retireProtected` consumes
both successfully handed-off and failed-crypto/failed-handoff jobs, including
those whose ciphertext cannot be copied. `abandonProtected` invalidates the lease
without touching a running job, allowing owner cancellation plus queue cancel.
New-key acknowledgement/cancel also invalidates old leases. RX consumption cannot
consume a TX result, and caller buffers remain untouched on failed copy. The
caller must retain the job until frame copying/handoff is complete and retire or
abandon every pending TX operation.

Independent AESCCM PN1/PN2/PN3 ciphertext fixtures verify no reuse after failed
crypto and terminal submit races, no consumption before failed init, same-key
redelivery, duplicate retirement, invalidation after key rotation/abandonment and
RX/TX result separation. A paused AES worker can be abandoned/cancelled while the
association remains live; the next protected frame uses PN2. ASan/UBSan and
ThreadSanitizer pass these production owner/job tests. A compile-only kernel
entry instantiates generic BIP and TX-PN allocation/current-epoch checks; native
kext build/link/import checks pass. Native SAE admission, WMI RX interception,
protected HTT submission and hardware validation are still disabled/incomplete.
The final focused key-boundary regression extracts the phase-3 readiness guard
from before the firmware security-command builder and verifies rejection when
PMF is incomplete, while key-install phases remain able to make progress.

### Explicit hardware PMF transport and required-profile guards (source-integrated)

The pinned Linux v6.12 HTT path selects management packet type 3 with a MAC
header. For protected action/deauth/disassoc it appends an eight-byte CCMP MIC
slot before DMA; CCMP keys request host-generated management IVs, while firmware
performs encryption. It sets NO_ENCRYPT only when hardware crypto is disabled.
Thus the normal protected-management reference is not proof that a complete
software ciphertext/tag may be passed unchanged through our old 0x65 path.
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/htt_tx.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/htt.h

`ManagementTX` now distinguishes Plain, HardwareCCMP and SoftwareCCMP explicitly.
`PMFHardwareCCMP::prepare` constructs the protected 24-byte header, eight-byte
CCMP IV with caller-reserved PN, plaintext body and exactly one zeroed eight-byte
MIC slot. It publishes only after profile/bounds/alias validation. It performs
no AES operation and requires neither a password nor a key copy. Its separate
validator checks ordinary unicast robust management, expected identities, key
index 0, reserved IV bits, nonzero PN, supported body and the reserved MIC slot.

The retained PMF TX queue accepts an explicit representation; its default remains
the existing software candidate for compatibility with the host tests. Hardware
jobs immediately wipe the unused secret key from their snapshot and prepare the
frame off-gate. `copyForTransport` exports the representation together with the
bytes. The old ciphertext-only `copyProtected` refuses hardware plaintext results,
preventing accidental use by a caller that did not request a representation.
Hardware and software jobs share one epoch/PN pool and one pending lease.
Independent fixtures verify hardware PN1 -> software PN2 -> hardware PN3 without
counter reuse, plus byte-for-byte hardware IV/body/MIC-slot construction.

`submitNetworkPacket` and `buildHTTPacket` accept the explicit representation.
The driver validates it before allocations, descriptor-ID changes or DMA ownership.
Plain management uses 0x65 (MAC header + management + NO_ENCRYPT); hardware PMF
uses 0x61 with NO_ENCRYPT clear, TID 17 and a direct payload DMA address. The
prepared length already includes the MIC slot; the transport never appends a
second slot. Software ciphertext passthrough is explicitly rejected by this HTT
profile rather than silently choosing another mode. Ethernet/control-port flags
and their existing encryption policy are unchanged.

ConnectionState now has a default-false pmfRequired policy bit. No current
native join sets it. Hardware PMF submission requires that bit, a secure
association and an acknowledged pairwise key. After PTK installation, the ordinary
raw management path rejects unverified robust input and the Plain TX path rejects
robust output for that profile; pre-key rejection and nonrobust/public traffic
retain their previous admission rules. Verified PMF receive dispatch must use
a dedicated authenticated path, not fall back to this raw handler. Native PTK and
port-readiness hooks refuse missing PMF owners when the connection requires PMF;
absence of resources cannot silently select WPA2 behavior.

The portable transport regression checks exact HTT header bytes, pointer, length,
TID, NO_ENCRYPT polarity, max 512-byte payload and PN, mode separation, missing
key/profile, malformed IV/MIC-slot, output preservation and raw pre-/post-key
policy. A production submitNetworkPacket/CE host model confirms the actual DMA
payload/length and completion flow, and that rejected modes leave TX ownership
and descriptor state unchanged. Retained PMF hardware preparation invokes no AES
and passes lifecycle/race tests. Native owner-absence guards are also tested.
These checks prove host formatting/submission in a model, not firmware encryption,
wire MIC validity, PMF negotiation or autonomous firmware PN coordination. SAE
admission, protected TX scheduling and hardware interoperability remain open.
The receive bridge added below supplies authenticated WMI dispatch and RX job
scheduling; WPA3/PMF is not advertised or enabled by this work.

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


### Native PMF WMI receive bridge (source-integrated, profile still disabled)

The runtime WMI parser now offers an optional synchronous management consumer
only after complete HTC/TLV/trailer/credit validation. Consumed frames bypass
both raw station-management dispatch and its unauthenticated RSSI update. The
native consumer copies required-profile robust frames into a four-entry,
512-byte-per-entry radio-owned inbox, without crypto, allocation, WCL calls or
waiting. DMA storage is never retained. Overflow and invalid status/identity
are drops. Legacy associations keep their existing path.

Native service submits at most one retained PMF receive job to the existing
worker, and only takes a completion it submitted. A busy worker preserves the
queued frame; polling uses the existing service cadence without a new wake loop.
The owner commits the live generation/key epoch and replay counter before
trusted station-management dispatch or signal publication. Pairwise and BIP
group authentication have separate dispatch assertions; the ordinary raw entry
cannot assert either. Reset wipes the inbox and cancels retained security work.
An explicitly required PMF association with a missing owner cannot fall back
to accepting an unverified disconnect.

Tests exercise the production callback, completion service and crypto jobs:
DMA overwrite after admission, invalid MIC/status, replay, key rotation while
queued, terminal cancellation, bounded overflow, BIP disconnect without a
pairwise-layout assumption, and preservation of another worker user's result.
A parser-level regression proves malformed/truncated WMI and invalid credit
trailers never reach the consumer, while consumed frames cannot trigger the
raw disconnect/RSSI path. Software tests do not prove firmware interoperability.

Unicast receive remains blocked unless the exact firmware frame layout has
been verified and explicitly selected. No code currently enables that flag or
creates a native PMF association. Unprotected reason-6/7 disconnects are dropped
and mark an SA Query trigger; the native query initiator/responder, deadlines,
protected TX handoff and routing of existing robust action producers remain
unfinished. The primitive query state machine is not sufficient by itself.
Native credential/SAE integration, authenticated IGTK staging, firmware PMF
configuration and real WPA3-only AP validation also remain required. SAE/PMF
capabilities stay disabled until that complete path is ready.
