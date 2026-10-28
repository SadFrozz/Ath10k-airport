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

- Native SA Query, Spectrum/TPC and protected TX retirement are source-integrated
  (see below); validate timeout/cancel/rekey and protected management with firmware.
- Establish QCA9377 protected RX layout, firmware PMF setup and management TX PN
  ownership before enabling the profile.
- Finish the credential-to-SAE worker path, then connect authenticated PMK/IGTK
  publication, AKM8 EAPOL and controlled-port readiness as one admission policy.
- Validate WPA3-only/H2E and transition APs, downgrade rejection, rekey, reconnect,
  forget-network, sleep and stop; only then expose the native capability.

Do not advertise SAE or PMF while these dependent stages remain incomplete.
Roaming preparation stays local and deferred; no need to restart that work
before the security dependency path is functional.

### Current integration matrix (supersedes earlier incremental status notes)

| Path | Current source/model evidence | Still required for hardware support |
| --- | --- | --- |
| Native credentials | Sequoia 64-byte envelope decoded; explicit SAE rejection | Real SAE request binding and complete native admission |
| SAE group 19/H2E | Independent crypto fixtures, retained preparation and native Auth RX/TX source hooks | Credential/PWE admission, kernel/timing and physical radio validation |
| AKM8 / IGTK | Native export staging, deferred IGTK/key barriers and rekey fixtures | SAE-to-PMK native join wiring and physical port validation |
| PMF RX | WMI consumer, bounded inbox, retained verification and authenticated dispatch | Exact QCA9377 RX layout and firmware negotiation |
| PMF TX | Explicit hardware formatting, shared PN leases and DMA model | Firmware encryption/MIC and autonomous management PN ownership |
| SA Query | Native requests/responses, retry/deadline, cancellation and priority | AP interoperability and scan/power timing under load |
| Spectrum/TPC | Verified request to protected report, epoch binding and TX completion | Protected wire capture and physical radio power reporting |
| Firmware PMF setup | TLV PMF_QOS startup, firmware-file feature and peer flag gates | Physical firmware/wire behavior and RX format |
| Native WPA3 capability | Disabled; native joins create no PMF session | Complete and validate the rows above before enabling |

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
At that revision the native `Supplicant<...,true>` admitted only its prior WPA2 profiles; the internal crypto option is enabled in the later key-bridge section, while native request admission still rejects SAE.
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
and native request admission still rejects SAE, so these hooks do not enable
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


### Native SA Query initiation, responses and protected handoff (source-integrated)

Native service now binds the existing SAQueryExchange to the live PMF generation
and acknowledged PTK epoch. An unprotected unicast reason-6/7 disconnect starts
a bounded query instead of disconnecting. It draws a fresh two-byte kernel RNG
ID only when a retry is due, prepares a retained hardware-CCMP job outside driver
gates and checks the exchange ticket, live key epoch and fixed deadline again
at actual protected HTT handoff. Only a successful handoff admits that ID for a
response. Failed handoff burns the PN and the attempt, without admitting its ID
or immediately terminating an otherwise valid association. Retry/timeout/start
rate limits remain 201 TU / 1000 TU / ten seconds, as in the referenced SME.

Verified pairwise PMF input is parsed as SA Query before generic management
dispatch. A matching response to any submitted transaction ends the exchange.
An unsent, wrong, stale-key, unprotected or replayed response cannot do so.
Authenticated AP requests get protected responses with the identical two-byte
ID. A four-entry response queue has bounded lifetime and duplicate suppression;
no group-authenticated frame can masquerade as a pairwise SA Query response.
OCV/OCI remains unsupported and is not negotiated by this profile.

One TX job/result is tracked independently of the PMF RX job. A retained TX result
can wait for firmware ownership while incoming RX is still verified on the same
worker. Completion collection never consumes an unrelated SAE/PMF user's result.
Reset releases retained results and clears query/reply state; PTK replacement or
controlled-port closure invalidates query IDs, replies and old TX handoffs.
The exchange's original monotonic deadline is checked even while transport is
busy; timeout closes the controlled port and uses the existing native teardown
and macOS notification path. A clock regression fails the association closed.
No additional synchronous wait or timer/workloop is introduced.

A temporary pmfTXPending flag stops new BSD data admission while existing data
DMA drains. It prevents new ordinary maintenance from overtaking the protected
frame, suppresses radio power-save entry and requests normal scan cancellation.
Already active WMI maintenance/scan ownership must still complete its existing
credit/ECHO/STOP barriers. Clearing the priority flag preserves the deferred BSD
queue wake. PMF management MAC-ACK failure no longer follows the generic immediate
MLME-disconnect rule: the query coordinator determines retry/timeout. Other
management TX policy is unchanged.

Production-source host tests cover a full trigger->hardware preparation->handoff
->authenticated response, timeout after five distinct transactions/PNs, late and
unsent response rejection, replay, failed handoff followed by PN2, authenticated
AP request/response with an independent AESCCM fixture, rekey before handoff,
radio/power/credit/scan contention, finite response lifetime, bounded replies and
clock rollback. The actual Connection/CE model checks that failed PMF MAC ACK does
not cancel the connection and that priority closes data admission; the actual
scan pre-submission path verifies cancellation without inventing DMA completion.
ThreadSanitizer passes the native bridge and retained PMF/worker tests. Native
build/import and compile-only kernel checks pass. The optimized native PMF service
uses a 712-byte static stack frame on this build, under the 4096-byte compile gate.
These remain software/model and compile results, not live WPA3 interoperability.

Spectrum/TPC protection is integrated by the next section. Remaining before
native WPA3 admission: verify actual QCA9377 protected RX layout, firmware PMF setup, autonomous
management PN ownership, scan/power timing and wire encryption; complete native
credential-to-SAE integration and authenticated PMK/IGTK/AKM8 EAPOL publication.
Then test SAE-only/H2E and transition APs, rekey/reconnect, forget-network and
sleep/stop. No native join currently creates a PMF session or enables its layout
flag, and no SAE/PMF capability is advertised by this change. Installed EFI is
unchanged; hardware validation needs a separately authorized later boot.

Primary SME reference (trigger/limits/request ID echo/response matching):
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/4865f3ef1209f92405d03ced3c3986952244e0ef/wpa_supplicant/sme.c


### Protected Spectrum/TPC reports and transport retirement (source-integrated)

Verified PMF receive dispatch now binds any newly queued spectrum report to the
current connection generation and PTK epoch, with a five-second absolute deadline.
The ordinary Connected state machine defers required-profile robust reports to
the native PMF scheduler; it cannot submit them as Plain management. Legacy
no-PMF spectrum behavior is unchanged.

The scheduler uses the existing bounded report buffer and retained hardware-CCMP
job path. SA Query responses and due requests take priority; reports use that
same single pending TX lease and monotonic management PN pool. The original buffer keeps one semantic report owner; immutable worker and DMA
copies are bounded snapshots.
Queuing transfers its semantic state from pending to inFlight, preventing a new
request from replacing the frame while a job/result is retained. Unprepared
reports also hold the temporary PMF data/scan/power priority while the worker is
busy. No new workloop, wait or AES/CCMP under the owner gate is introduced.

At hardware handoff, live generation/key epoch, report ownership and the original
deadline are rechecked. A TPC report's power byte is refreshed using the actual
applied radio limit at this point: hardware will compute its MIC after handoff.
The prepared representation is never passed to a software-ciphertext route.
Successful handoff marks the existing spectrum completion path, even though DMA
received a copied protected buffer instead of the original report address. Its
actual MAC completion updates completed/dropped counters and deferred data wake;
PMF query policy does not consume that report completion.

Failed preparation/handoff, independent worker cancellation, expiry or PTK change
drop the source report once and retire the retained lease without recycling PN.
Terminal native cleanup clears unsent pending reports and prepared-but-unhanded
inFlight reports. An already submitted report remains owned by the transport;
cleanup must not fabricate its DMA completion or retire that ownership early.

Production native bridge tests cover independent incoming AESCCM TPC and
measurement requests through verification, report construction and protected
handoff, including exact IV/body/MIC-slot comparison with independently generated
fixtures. They cover an applied-power change while queued, failed handoff, key
rotation, worker cancellation, expiry and shared PN1-query/PN2-report ordering.
The production Connection/CE model verifies that required-profile reports are
never submitted raw and that the copied protected report retires through normal
spectrum completion. Native cleanup tests distinguish an unsent source from
transport-owned completion. Focused ASan/UBSan and ThreadSanitizer tests pass;
native build/import checks pass. The optimized PMF service remains a 712-byte
static stack frame on this build.

This closes source-level routing of the current host-generated spectrum/TPC
robust action producers. It does not prove autonomous firmware ADDBA/DELBA PMF,
firmware encryption/MIC correctness, management PN coordination, physical radio
power accuracy or real WPA3 association. Those hardware requirements, native SAE
credential/exchange wiring and authenticated IGTK/EAPOL staging remain open.
No SAE/PMF capability is advertised, installed EFI is unchanged and no live kext
load/unload or reboot is performed by this source work.


### Firmware PMF startup and feature provenance (source-integrated)

Firmware preparation now reads MFP_SUPPORT from bit 12 of the firmware container
feature IE. The prepared manifest, generated payload constants and selected Profile
carry that exact declaration; a missing/short IE means false. Board-only Lunnen
profiles alias the same reviewed firmware capability rather than inventing it from
a subsystem ID or SERVICE_READY service bitmap. Single-bit fixtures distinguish
bit 12 from neighboring OTP/clock features. The selected QCA9377 image still does
not declare this feature; this is not proof that software PMF is impossible.

The TLV radio startup sequence adds PDEV_SET_PARAM PMF_QOS=34, value=1, after the
existing TX/RX/domain/power steps and before scan-channel setup. It uses the same
CE3 ownership and HTC credit barrier, deadline and verified-reset release policy.
The additional sixth owner is included in DMA release admission. Scan-channel
setup consumes its final CE position, never the prior power command's position.
Tests execute the complete six-command sequence, hold the PMF QoS credit to prove
scan cannot overtake it, and test failed PCI bus-master disable for every owner.
A literal 28-byte fixture verifies the exact TLV command and rejected parameters.

Join state records the selected firmware MFP declaration and QoS transport state.
Peer association sets TLV PEER_PMF (0x08000000) only when PMF is required and the
firmware file declares MFP_SUPPORT, matching ath10k_peer_assoc_h_crypto. No guessed
VDEV_START_PMF flag is enabled for STA: the reference station path zero-initializes
that field. Required-profile peer construction rejects absent QoS transport state.
Native protected TX and controlled-port authorization also check the live runtime,
QoS command completion/CE/credit ownership, power fence and DMA quarantine. A stale
connection snapshot cannot authorize PMF after its firmware owner has stopped.

These are command-transport and source-policy checks. No readback/semantic RF
acknowledgement, actual firmware PMF encryption, AP interoperability or RX layout
is inferred from HTC credits. Native SAE admission/capabilities remain disabled.

References (Linux v6.12):
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/core.h
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/mac.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/wmi-tlv.c
https://kernel.googlesource.com/pub/scm/linux/kernel/git/torvalds/linux/+/v6.12/drivers/net/wireless/ath/ath10k/wmi-tlv.h


### Authenticated native IGTK export staging and key barriers (local source)

NativeSecurity now uses the SAE-capable opt-in supplicant internally, so its
result bridge can consume the already tested AKM8 exports. This does not change
native request admission: SAE/password requests are still rejected before begin,
SAE/PMF capabilities remain disabled, and no native join creates a PMF owner.
The verified SAE-to-PMK/native radio exchange is still required before that gate
can open. The prepared 0.0.99 stability-test candidate from commit 5d365c6 is
immutable and does not contain this subsequent local source work.

Authenticated key results now pass through nativeAcceptSecurityResult. It checks
bounded reply length, data-key index/cipher and result/change-mask consistency
before copying reply/data-key exports. IGTKChanged requires the current required
PMF profile and a live owned PMF session; initial required-PMF keys must include
IGTK. Reply/retransmit results explicitly ignore the previous successful result's
keyChanges and managementKey fields. Malformed exports do not enqueue a reply or
program data keys. The existing service caller closes the port and cancels on
rejection, rather than acknowledging an uninstalled management key.

A changed IGTK is held privately with the one-shot PMF owner and its connection
generation. That owner pointer is borrowed only under the radio gate from this
NativeSecurity's owned session; reset clears the stage before releasing the
session. Required-profile port readiness rechecks the live firmware barrier and
the exact owner/generation, then activates the software management epoch only
after the data-key state has reached phase 3 or later with a pairwise key
acknowledged. An early readiness query preserves a valid stage; a stale/cancelled
owner rejects and wipes it. Activation also wipes the stage before authorization.
No IGTK is sent to firmware key indices 4/5.

Initial and combined GTK/IGTK results retain the existing data-key HTT/credit/ECHO
transaction. GTK-only and pairwise rekey keep the existing management epochs when
there is no IGTKChanged export. An IGTK-only ManagementKeys result requires an
already authorized phase-5 pairwise association, commits its BIP epoch directly
and queues its authenticated EAPOL acknowledgement without opening a firmware GTK
transaction. It does not alter securityPhase or pretend to install a data key.
Both IGTK slots retain their independent key epochs/replay floors.

The native-key test executes the production NativeSecurity class, result bridge,
PTK/port hooks and real retained PMF owner/jobs, using actual CommonCrypto SAE
EAPOL fixtures. It composes M1/M3 exports, deferred hardware-key fences, initial
IGTK publication, IGTK-only and combined rekeys, retransmitted M3, pairwise rekey,
cancelled owners and malformed exports. Independent cryptography CMAC fixtures
verify the resulting BIP keys/replay floors across both slots; accepted frames
cannot be replayed after an EAPOL retransmission. A native SHA256-PSK composition
checks the prior no-PMF data-key path. Native request-policy tests still reject
SAE. The full 54-test development suite passes with ASan/UBSan halt-on-error;
retained-owner/native-key ThreadSanitizer checks pass;
native build/import/stack compilation passes. The result bridge and port helper
use 56 and 40 bytes of optimized static stack respectively on this build.

This is source/model integration, not firmware installation or a working native
WPA3 association. Native credential/SAE exchange and verified PMK delivery,
firmware protected RX layout/PN/wire behavior, kernel crypto backend validation
and physical rekey/reconnect/sleep testing remain open. No live kext load/unload,
EFI change or reboot is performed for this local key-bridge work.


### Retained first-commit preparation from a derived PWE

`Ath10kSAEPrepareJob` now fills the gap between a caller's derived group-19 PWE
and `Ath10kSAESession::initPrepared`. Initialization copies the exact PWE,
backend/RNG providers, station/BSSID, connection generation and initial deadline
without invoking curve operations. Only the existing retained worker executes
point validation, random/mask generation and commit calculation. This is not
password derivation or native SAE admission; the caller must first prove the
PWE belongs to those credentials/identities and validate the kernel backend.

Random and mask are independently sampled as 32-byte strings; the existing
scalar validator rejects 0, 1 and values at/above the group order. No modulo
reduction biases the sample. The transmitted sum must also exceed 1. A maximum
of 128 candidate pairs bounds a defective provider; RNG or curve backend failure
fails preparation instead of silently replacing the provider or changing mode.
This follows the rejection/commit constraints in hostap's `sae_get_rand` and
`sae_derive_commit`; the retry bound is our explicit resource policy, not a claim
that hostap has the same bound. Reference:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/3dbea20fb6570e548e831910e108b2307d6232ba/src/common/sae.c

A completed job creates a one-shot session only for the original station,
BSSID and generation, while still inside the original deadline. Completion
collection cannot restart the authentication timer. Rejected collection,
queue cancellation and final release erase retained PWE/random/commit material.
The worker does not publish a PMK, invoke IO80211 or enter driver gates.

The retained-session test runs actual userland CoreCrypto on the queue and
compares the prepared commit with the independent scalar/point fixtures. It
covers out-of-range scalars, sums 0/1, a failed RNG (first and second call), a
bounded all-zero RNG, invalid PWE, repeated execution/collection, changed
identities/generation, expired/backward clocks, and cancellation while running.
Kernel compilation and import checks pass; optimized preparation uses 232 bytes
of static stack and owner-side collection uses 56 bytes. This does not validate
kernel CoreCrypto runtime behavior, native credential transport, physical SAE
frames or a working WPA3 association. The prepared 0.0.99 boot candidate and EFI
are unchanged by these source additions.


### Historical native SAE radio integration baseline (0.0.100)

The retained preparation job is intentionally not sufficient to enable a join.
At that revision, the following open-auth assumptions required replacement.
Subsequent 0.0.101/0.0.102 integration and local password work supersede this
baseline; use the current matrix at the end of this document for open items:

| Boundary | Current implementation | Required SAE behavior |
| --- | --- | --- |
| `setWCL_ASSOCIATE` | Rejects SAE; PSK path calls supplicant immediately | Decode the actual password/PWE envelope, bind generation/MAC/BSSID/mode and queue preparation; never treat password bytes as PMK |
| `buildStationManagement` in `Ath10kConnection.hpp` | Auth builds algorithm 0, transaction 1 | SAE commit/confirm frames from the retained exchange, with its exact immutable TX reservation and actual HTT submission outcome |
| `receiveStationManagementAuthenticated` | Auth accepts only algorithm 0, transaction 2 | Route bounded algorithm-3 frames to the SAE owner before this open-auth handler; no unauthenticated shortcut to `authReply` |
| `serviceNative` | Drives EAPOL only after `sec->ready` and association | Collect preparation/key/confirm work without consuming a PMF job; validate original generation, identity and deadline after every handoff |
| Auth-to-association transition | Common connection state consumes `authReply` | Set it only after local confirm handoff and verified peer confirm, then bind exported PMK/PMKID to AKM8 supplicant and mandatory PMF profile |
| Cancellation/stop/sleep | NativeSecurity resets retained sessions and cancels the shared worker | Include preparation ownership and invalidate native join generation before late collection; preserve worker shutdown outside all gates |

Auth stage timeout, management TX capacity and shared management DMA ownership
must also be reviewed as part of that change. Neither a generic successful
firmware event nor an accepted open-auth reply proves SAE authentication. The
native SAE capability must stay disabled until these rows and firmware PMF
validation are complete.

The combined key-export/preparation source batch is development version 0.0.100.
It is not installed. Full 54-test ASan/UBSan halt-on-error validation passes; the
immutable 0.0.99 candidate is still the separately saved reboot candidate.

The combined batch also passes ThreadSanitizer for `sae_session` (including
preparation/cancellation) and `native_key_stage`. Development 0.0.100 builds,
ad-hoc signature verification passes, and an offline diagnostic AuxKC contains
this exact Mach-O UUID D2278F3E-3B30-3391-9990-46ADDCE15F20. For the offline link
only, a copy has OSBundleRequired removed to make it AuxKC-eligible; deployed
metadata is unchanged. This does not install a kernel collection, patch the OS
or validate a running driver. No new external imports were introduced.


### Identity-bound SAE-to-EAPOL publication (local follow-up)

`Ath10kSAESession::beginEAPOL` transfers verified SAE PMK/PMKID directly to an
AKM8 supplicant once. The session keeps its original station/BSSID separately
from the key worker context (which is erased after key-job submission). The
handoff checks the retained identities, nonzero connection generation, both SAE
confirmation fences and the original authentication deadline. Accepted SAE state
does not grant an unlimited delayed handoff or a fresh authentication lifetime.
No unverified password bytes enter a PMK slot. Temporary PMK/PMKID storage is
wiped on return; successful handoff prevents subsequent raw key copies or an
EAPOL reinitialization through this session. A rejected target initialization
cancels the session rather than retrying its PMK under another profile. Wrong
identity/generation or a null nonce leaves the existing target untouched.

The real retained-session test now composes queued first-commit preparation,
key computation, local-confirm submission, peer-confirm verification, this
handoff and authenticated AKM8 M1/M3 processing, checking exported PTK/IGTK.
It also covers premature publication, wrong identity/generation, retransmitted
M3 after a rejected repeated handoff, invalid RSN and delayed publication after
the original deadline. Kernel compile-only code instantiates the exact helper;
its optimized static frame is 104 bytes. Focused ASan/UBSan tests pass for
sae_session, sae_eapol and native_key_stage; the previous full 54-test result
belongs to published 5db129c and is not a new full-suite claim for this follow-up.

This is a local follow-up to 5db129c, saved separately for the next publication
batch. Native request admission still rejects SAE. The controller still needs
the real credential/PWE binding and SAE authentication radio exchange, followed
by firmware PMF validation. No kext installation or reboot is performed.

Focused ThreadSanitizer retained-session/preparation/handoff tests also pass.


### Shared completion routing by retained session (local follow-up)

The shared worker now records an immutable opaque completion-owner identity at
submission and offers `takeCompletedFor(owner)`. SAE and PMF jobs submit the
retained session as owner; a preparation job defaults to its own retained job
identity. No owner pointer is dereferenced and no callback/crypto/allocator runs
beneath the bookkeeping lock. A mismatching/null typed request leaves the
completed job, slot and reference count unchanged; the rightful owner or normal
cancellation must retire it. Unfiltered `takeCompleted()` remains available to a
sole dispatcher/test harness, but both native PMF collectors now use their exact
PMF session. This is routing, not authentication: session/generation/key-epoch
checks in each consumer remain mandatory.

The binding clears with collection, queued/completed cancellation and running
cancellation retirement. It cannot leak into the next slot use. Worker tests
cover wrong/null/default owners, unchanged references, blocked replacement while
a foreign completion is pending, cancel/reuse and simultaneous matching and
nonmatching consumers. Native PMF tests inject stale RX/TX producer flags while
a foreign job is complete: neither branch consumes/releases the foreign result,
and a subsequent genuine PMF job still verifies/dispatches normally. Actual SAE
preparation -> confirm -> EAPOL composition also collects by the retained owner.

Focused halt-on-error ASan/UBSan validation passes for sae_worker, sae_session,
pmf_session, native_pmf_receive and native_key_stage. ThreadSanitizer passes for
sae_worker, sae_session, pmf_session and native_pmf_receive. Native and kernel
compile-only builds pass with unchanged external imports; completion matching
uses 24 bytes static stack and serviceNativePMF uses 712 bytes on this build.
The earlier full-suite claim still belongs to published 5db129c, not these local
follow-ups. Hardware SAE/PMF, credential/radio admission and physical traffic
validation remain open. No source follow-up here installs a kext or reboots.


### Retained SAE management-channel coordinator (local follow-up)

`Ath10kSAERadio` now coordinates an exclusively owned prepared SAE session,
shared retained worker, validated RX inputs, commit/confirm TX reservations and
one-shot AKM8 handoff. It is compiled into the native driver sources but the
controller's request/WMI/HTT hooks are not wired to it yet. This is model/source
integration, not an on-radio SAE association or enabled native capability.

The owner polls the original exchange deadline even while the channel is busy.
It collects only its retained session's work, queues bounded key/confirm jobs,
and holds an immutable commit snapshot or completed confirm until channel
admission. Prepare, the actual channel copy/admission and complete must share
the radio gate. A failed submission consumes the exchange's bounded attempt,
not a fictitious successful send; an expired/revoked TX cannot complete. TX
bytes are borrowed only until the next owner method. Cryptography stays entirely
on the worker. A session revoked externally cannot remain silently in Progress.

New `cancelFor(session)` retires only that owner's queued/running/completed
work, without waiting or disturbing another producer. The transport retains
both queue and session; running work keeps independent snapshots. Cancel,
failure and destruction erase prepared TX bytes and release retained results.
Acceptance drains pending work before PMK handoff. The existing exchange still
owns anti-clogging/retry/confirmation policy; the adapter does not infer success
from arbitrary firmware events.

The actual userland CoreCrypto test now drives the radio coordinator through
commit admission, peer commit RX, worker key/local-confirm jobs, confirm
admission, peer confirmation and AKM8 M1/M3, checking PTK/IGTK. Additional tests
cover bad RX status, duplicate completion, TX expiration, external revocation,
foreign completed work surviving cancellation, and cancellation during actual
key HMAC. Focused ASan/UBSan and TSan pass; native and kernel compile-only builds
pass without new external imports. Optimized static frames are 56 bytes for
service and 72 for prepareTX. These focused results do not replace a full-suite
or physical hardware validation claim.

Next controller integration must bind the admitted credential/PWE generation,
route validated algorithm-3 WMI frames into this owner, bypass open-auth frame
building/retries in Auth, use actual HTT admission and DMA completion ownership,
and set authReply only after this coordinator's accepted PMK/profile handoff.
The existing 1522-byte packet limit versus 1536-byte SAE frame-buffer limit,
accepted-state confirm retransmissions, join/auth deadlines and worker shutdown
must be reviewed before enabling native SAE/PMF. No install or reboot occurs.


### Native WMI/Auth/HTT source hooks (development 0.0.101)

The controller now owns an optional Ath10kSAERadio alongside its retained SAE
session. The validated WMI management consumer routes Auth frames for a selected
AKM8/Auth attempt to it. This consumes even algorithm-0 replies, preventing the
open-auth handler from setting authReply for an SAE join. Other management and
ordinary PSK authentication retain their existing handlers. Reset/terminal
cleanup cancels and deletes the coordinator before releasing its session.

The common connection state machine calls serviceNativeSAE in Auth/AKM8 and
returns before open-auth construction/retry until authenticated handoff is ready.
The handler checks the native join/radio/profile, PMF firmware readiness and
exact SAE/PMF owner generation. It schedules retained work before considering
TX availability, then uses the existing submitNetworkPacket/HTT admission with
plain algorithm-3 commit/confirm frames. Scan, pause, credit, CE/data ownership,
radio/power and maintenance fences postpone TX without extending the exchange.
A separate lastTxSAE discriminator prevents the legacy three-attempt open-auth
TX failure logic from taking over SAE retries. Common CE/HTT DMA retirement and
its existing timeout remain unchanged.

Accepted exchange state alone cannot publish authReply: the real outstanding
HTT/CE ownership must retire, the last TX must complete successfully, and the
verified PMK/PMKID must initialize the AKM8 supplicant. The handler then permits
the common Auth-to-Assoc transition. Any handler error marks cancellation and
immediately discards native crypto under the radio gate, independently of WCL
terminal-event allocation; driver-owned packet DMA still retires normally.

The new native_sae_radio test executes the production NativeSecurity, WMI
management callback, serviceNativeSAE and extracted common Auth dispatch, with
actual retained SAE/PMF sessions and userland CoreCrypto. Only hardware packet
admission/completion is simulated. It checks algorithm-0 suppression, real
commit/confirm bytes, scan deferral, HTT-vs-CE ownership, authenticated handoff,
M1/M3 PTK output, failed profile/generation/power/TX/cancel cases and immediate
terminal cleanup. The PSK guard bypasses the new path. This is not physical
firmware validation or evidence of a successful native WPA3 association.

Native request policy/capabilities remain disabled for SAE. prepareBSSCandidate
still accepts only PSK AKMs, and the generic association builder still needs an
SAE/PMF/PMKID RSN matching the supplicant. These are explicit next integration
requirements, together with credential/PWE admission, accepted-state confirm
retransmissions and firmware PMF/RX/PN/backend checks. No kext is installed and
no reboot is performed. The immutable 0.0.99 boot candidate remains unchanged.

The combined development 0.0.101 batch passes the full 55-test ASan/UBSan suite
with halt-on-error and focused ThreadSanitizer for sae_worker, sae_session,
pmf_session, native_pmf_receive and native_sae_radio. Native/kernel compilation,
strict ad-hoc signature verification and exact offline AuxKC inclusion pass.
Mach-O UUID is 62791364-F0F4-3790-B9FB-D2AA27F8899D; no new external imports are
introduced. The offline AuxKC uses only a diagnostic copy without OSBundleRequired
for eligibility; the actual bundle metadata and OS kernel collections are not
changed. serviceNativeSAE uses 88 bytes optimized static stack. Hardware packet
completion remains simulated in the host test; this is not an on-device result.


### SAE BSS selection and association RSNE (local follow-up to 8b65f75)

prepareBSSCandidate now validates the selected AKM instead of always requiring
PSK. AKM8 requires the connection's mandatory PMF profile and a valid software
SAE/CCMP/BIP AP RSNE; a transition BSS does not change the selected AKM or fall
back to PSK. Other infrastructure/rates/channel/regulatory/power checks remain.

The supplicant exposes copyAssociationRSN, returning only public RSNE/PMKID
metadata. Its existing M2 encoder now calls the same method. The native
association builder requires a live authenticated SAE/PMF owner generation,
ready supplicant, enabled native radio/network/join, accepted auth and firmware
PMF readiness, then obtains the verified 44-byte station RSNE. The common
management TX path calls this builder in Assoc/AKM8. The generic builder refuses
open-auth for AKM8 and refuses SAE association without the exact canonical
CCMP/AKM8/mandatory-PMF/BIP station profile; it never substitutes a PSK RSNE.
No PMK/PTK is copied into connection request storage.

Association response RSNE validation now follows the selected AKM and negotiated
group cipher too. The former hard-coded supportsWPA2 check rejected SAE and
AKM6-only responses. Optional response-RSNE presence policy is unchanged; when
present it must validate for this association. The controller test composes real
retained SAE -> native authenticated handoff -> BSS candidate validation ->
association RSNE with verified PMKID -> response acceptance -> M1/M3 PTK/IGTK.
Association and M2 key-data RSNE bytes are compared directly. It also checks
transition BSS selection, PSK-only rejection for SAE, mandatory PMF, disabled
radio/network, malformed station RSNE and AKM6 response acceptance without PSK2
fallback. Public station-profile tests cover truncated/modified encodings.

Focused halt-on-error ASan/UBSan passes for connection, rsn_policy, security,
sha256_supplicant, sae_eapol and native_sae_radio; retained-session/native-radio
ThreadSanitizer checks pass. Native/kernel builds pass without new external
imports. buildNativeSAEAssociation uses 104 bytes optimized static stack.
The previous full 55-test result belongs to published 8b65f75, not this local
follow-up. No new signature/offline-collection or hardware result is claimed.

Native request admission/capabilities still reject SAE. RSNXE/H2E mode binding
remains required: WMIBSS currently retains RSNE but no RSNXE, and association/M2
must carry the mode/capabilities consistently before native SAE can be enabled.
The primary SME reference appends RSNXE separately to the association request:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/master/wpa_supplicant/sme.c
Credential/PWE admission, accepted-confirm retransmission, kernel backend timing
and actual firmware PMF/RX/PN validation remain open. This local source package
is saved for a later combined publication; no install or reboot is performed.


### RSNXE scan/cache/native beacon transport (local follow-up)

WMIBSS now retains the standard RSN Extension element (ID 244), including its
full 1..16 capability octets. A bounded shared validator checks the outer IE
length and first-octet length encoding; a separate query reports the H2E bit
without inferring native capability support. Unknown capability bits remain
unchanged. Duplicate or malformed RSNXE rejects the candidate before cache
mutation, and a later valid advertisement omitting RSNXE clears the old value.

Whole-BSS/candidate copies preserve the new field. nativeBSSMessage carries the
exact original RSNXE in the complete beacon IE message delivered to WCL. No new
field/offset is invented in Sequoia's fixed extended-BSS RSNE slot, which has
insufficient space for an appended extension. The complete beacon message's
existing 800-byte IE allowance also fits the maximum bounded RSNXE plus all
other currently serialized fields; canary tests cover the combined maximum.

Primary bit/length definitions:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/80390943513e2c324f25c9b5fc4bb7769c4fcf8f/src/common/ieee802_11_defs.h
The reference supplicant also checks authenticated M3 RSNXE against its AP
advertisement snapshot; this is a required next integration step, not implemented
by merely preserving scan data:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/0be32f16ad21da5b5f30ab56b2b49a10260c41fc/src/rsn_supp/wpa.c

Focused ASan/UBSan halt-on-error passes for connection, native_scan, rsn_policy,
native_wire and native_sae_radio. Tests cover all 16 standard lengths, unknown
bits, truncation, encoded-length mismatch, duplicates, unchanged old observations
on rejection, removal on a valid update, exact native beacon bytes and maximum
buffer bounds. Native/kernel compilation passes with no new external imports;
nativeBSSMessage uses 152 bytes optimized static stack on this build. No new
ThreadSanitizer, full-suite, signature or hardware result is claimed for these
synchronous parser/serialization changes. Published 8b65f75 remains the last
full 55-test batch.

H2E mode must still bind the retained SAE session, the station association/M2
RSNXE and the authenticated AP M3 advertisement snapshot. Password/PWE/native
admission and physical backend/firmware PMF checks remain open; SAE/H2E native
capabilities stay disabled. This is local source for the next publication batch;
no install or reboot is performed.


### Bound H2E association/EAPOL advertisement snapshots (development 0.0.102)

Native personal joins now bind the AP's copied RSNXE snapshot immediately after
supplicant initialization, before M1; failed binding erases the just-initialized
supplicant. A retained SAE session preserves its accepted H2E mode separately
from erased worker secrets. Native SAE Auth rejects H2E when the selected AP
never advertised it, and successful authenticated PMK handoff binds that mode
and the AP snapshot before readiness/authReply publication.

The supplicant's one-shot bindRSNXE API accepts only a valid bounded AP element
(or an explicitly absent snapshot), only in initial state 1. H2E requires SAE
and an advertised H2E bit. Copies are independent of the caller's storage and
cannot be replaced after binding or M1. Station H2E capability is the minimal
three-byte standard RSNXE; unsupported AP capabilities are not echoed as station
capabilities. Legacy SAE/PSK does not claim H2E. Generic software callers that
explicitly leave the new API unbound retain their prior behavior; every native
personal initialization path binds, including the absent-snapshot case.

Native association and M2 use the same RSNE/PMKID encoder plus the same station
RSNXE encoder. H2E M2 is exactly 160 Ethernet bytes, within the existing M2,
reply and output buffers; tests compare the full independent CMAC fixture and
the native reply boundary. Initial/pairwise M3 must contain exactly the captured
AP RSNXE (or omit it if absent), with duplicate/presence/content mismatches
rejected only after MIC and key-data authentication. An optional RSNXE in group
rekey must also match; group rekey does not require the AP to repeat it. Retry
M3 remains an acknowledgement without key reinstallation.

New fixtures reuse only public synthetic SAE keys and use independent Python
cryptography AES-wrap/CMAC. Cases include correct/missing/changed/duplicate
RSNXE in authenticated M3, retry, pairwise and group rekey. Native retained SAE
and association tests cover a proper H2E AP, absent H2E advertisement, matching
association/M2 bytes and authenticated PTK/IGTK staging; the no-RSNXE native
baseline now explicitly models legacy SAE. These are pre-derived synthetic-PWE
sessions, not evidence of native password admission or real hardware exchange.
The fixture generator is reproducible; no user passwords or captured packets
are read. Primary reference for AP advertisement/M3 comparison:
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/0be32f16ad21da5b5f30ab56b2b49a10260c41fc/src/rsn_supp/wpa.c

Native SAE capability and request admission remain disabled. Native password/PWE
and kernel backend validation, accepted-state confirm retransmission and actual
firmware PMF/RX/PN behavior remain required before enabling or claiming support.
No driver installation or reboot is performed; immutable 0.0.99 is retained.

The combined 0.0.102 batch passes the full 55-test ASan/UBSan suite with
halt-on-error, and ThreadSanitizer for sae_worker, sae_session, pmf_session,
native_pmf_receive and native_sae_radio. Native and legacy kernel builds pass;
the new fixture regenerates byte-for-byte. Strict ad-hoc signature and exact
offline AuxKC inclusion pass for native Mach-O UUID
D2294BE8-5187-3C3A-9041-D4E40561A96F, with unchanged external imports. The offline
link uses a diagnostic copy without OSBundleRequired only for AuxKC eligibility;
no system kernel collection is installed or patched. Static stack frames are
104 bytes for native SAE service and association construction. No hardware
WPA3/H2E success is inferred from these source/model checks.


### Retained H2E credential derivation (local follow-up to bc45c34)

Ath10kSAEPrepareJob now has an experimental initH2E path taking copied SSID,
password octets, optional nonempty password identifier, identities/generation,
point/field providers and RNG. Bounds follow the existing 64-byte credential
slot, 1..32-byte named SSID and bounded identifier; input is not interpreted as
a C string. Native macOS credential delivery/interpretation is not thereby
validated, and no native request is admitted by this change.

Initialization only validates/copies metadata; the retained worker derives PT,
then MAC-bound PWE, samples rand/mask and builds the commit. Password and PT are
erased immediately after derivation, on both success and failure, while public
SSID/identifier binding survives until collection. Queue cancellation and final
release erase unexecuted or abandoned snapshots too. HMAC/field-provider errors
fail closed without RNG/legacy fallback. Kernel ABI/timing remains an explicit
prerequisite: the field provider runs only on the worker, not an owner gate.

A credential result can be collected once through takePreparedH2E only with the
same SSID octets, identities/generation and original deadline. The old unbound
PWE collector cannot extract a password-derived session; a new deadline is not
created at collection. The request carries the password identifier that was
included in derivation. Prepared session/job ownership remains independent.

The retained-session test uses real userland CoreCrypto and an independent
known H2E PWE vector. It mutates original inputs after initialization, compares
the prepared commit/identifier, then executes peer commit/key/local-confirm/
peer-confirm work and checks authenticated PMK/PMKID agreement. Cases also cover
wrong SSID, unbound-collector bypass, expired result, field/HMAC errors, invalid
bounds/providers, queued cancellation, final release and cancellation during
actual HMAC. Memory checks verify password/PT erasure in completed jobs and
password erasure at destruction. Focused ASan/UBSan passes for sae_session,
sae_eapol and native_sae_radio; sae_session ThreadSanitizer passes. Native and
kernel compile-only builds pass without new external imports; preparation's
optimized static frame is 1464 bytes, under the enforced 4096-byte frame limit.
This is not a new full-suite, offline-link, signature or hardware claim.

This follow-up stays local for the next publication batch. Native password
request decoding/admission, legacy password PWE, kernel crypto ABI/timing and
firmware PMF/RX/PN validation remain open. Native WPA3 capabilities remain
disabled; no kext installation or reboot is performed.


### Sequoia field-provider static ABI check (local follow-up)

The locally extracted CoreCrypto image has cczp_add at
0xffffff800323de53, cczp_mul at 0xffffff800323ef1c, cczp_sub at
0xffffff800323f67e and cczp_inv at 0xffffff80031f9939. The first three
consume (field context, output, left, right) and return a 32-bit status;
inverse consumes (field context, output, input) and preserves its backend
status. Add/multiply/subtract wrappers return zero after successful dispatch
and -13 on workspace-allocation failure. This agrees with the experimental
P256FieldAPI return types for this image; no void-return correction is justified.
These wrappers allocate temporary heap workspaces, reinforcing worker-only use.

This is static evidence for one extracted Sequoia image, not a runtime test or
an ABI guarantee for other macOS versions. The existing offline crypto probe
previously checked twelve point/scalar/RNG exports only. It now also references
cczp_n, cczp_prime, cczp_mul, cczp_inv, cczp_add and cczp_sub. The rebuilt
18-import diagnostic probe links offline against the running system's boot
collection; exact fileset inclusion matches probe UUID
46600F2A-4E86-3083-A97A-C69F912A0404. The probe has no personality, calls no
crypto and refuses start/stop; it is not loaded or installed. This establishes
export availability on this system, not the parameter ABI. Context
representation, runtime behavior and timing still require validation before
native H2E credential admission. Raw Apple disassembly remains local
and is not included in the repository or SD source snapshots.


### H2E credential boundary vectors (local follow-up)

The retained preparation test now crosses the worker/collection boundary with
independent Python integer/HMAC vectors for a one-octet zero SSID/password,
32-octet binary SSID plus 64-octet binary password and 254-octet identifier,
and UTF-8 SSID/password with no identifier. The generator imports no production
code and uses cryptography to validate resulting P-256 points. It reproduces
the earlier known PT/PWE before emitting new PT/PWE/commit expectations; fixture
regeneration is byte-identical. Inputs are synthetic and do not read the native
credential store. The maximal password pattern is deliberately distinct from
the public identifier, so memory-erasure checks do not mistake public identifier
bytes for retained password data.

Tests mutate caller buffers before worker execution and compare the actual
serialized scalar/element and full identifier against independent expected
values. They verify password/PT erasure, one-time execution/collection and
failure on a changed final SSID octet after an embedded NUL, changed station/AP,
changed generation, backwards time and the exact original deadline. These are
preparation/ownership checks; they do not prove how macOS delivers a live SAE
password or approve the kernel provider's execution/timing.

The three focused ASan/UBSan suites (sae_session, sae_eapol and
native_sae_radio) pass with these vectors; sae_session ThreadSanitizer passes.
No new full-suite or hardware validation is claimed for this local follow-up.


### Retained legacy SAE password derivation (local follow-up)

Ath10kSAEPassword.hpp adds the group-19 hunting-and-pecking password-to-PWE
path. The seed is HMAC-SHA256(max(MACs)||min(MACs), password||counter), with
explicit password octet length; PRF-256 uses the group prime and the label
"SAE Hunting and Pecking". Out-of-range x candidates take the field path using
a canonical substitute and cannot be selected. The first valid x and seed
parity are retained through masked selection. At least 40 iterations run;
authentication fails if no candidate is found by 200. After finding the first
candidate, later iterations use a copied random dummy password.

Quadratic-residue testing is blinded: a random nonzero field element forms
QR=r0^2 and QNR=-QR (P-256's p is 3 mod 4). Each iteration draws fresh r and
checks the coset of y_squared*r^2*(odd(r)?QR:QNR), reversing the result according
to that parity. The final unblinded square root is calculated only for the
selected valid x, its sign follows the saved seed, and the point provider
validates the output. Random field draws use bounded rejection (128 attempts)
without modulo reduction. Random, field or HMAC failure is terminal. Temporary
password material, seeds, field values and both workspaces are wiped on every
exit, and output is published only after complete success.

The retained job gains initLegacyPassword and an exact-SSID-bound
takePreparedPassword collector for both modes. initH2E retains its behavior;
its mode-specific collector cannot relabel a legacy result. The unbound PWE
collector cannot extract either password-derived mode. Both modes preserve
the original MACs, generation and authentication deadline. Legacy derivation
has no password-identifier input and is selected explicitly; H2E failure never
causes an automatic fallback. NativeJoinAuth still rejects SAE, so this does
not enable native password admission or advertise working WPA3.

Independent Python integer/HMAC vectors cover one-octet, ordinary and 64-octet
binary passwords. Serialized commits match independently calculated PWE points,
then retained worker key/confirm exchange produces matching authenticated
PMK/PMKID with a synthetic peer. Tests cover no owner-gate crypto, copied inputs,
password erasure, mode/collector separation, RNG failure, bounded all-zero RNG,
HMAC/field failures, 200 forced out-of-range candidates and cancellation during
real HMAC. Tests assert the normal 40 iterations even when the first candidate
succeeds. These checks establish algorithm/ownership behavior in a process;
provider timing/ABI in the kernel and native credential delivery remain open.

Primary references (pinned upstream source, read locally):
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/80390943513e2c324f25c9b5fc4bb7769c4fcf8f/src/common/sae.c
(sae_derive_pwe_ecc, sae_test_pwd_seed_ecc), and
https://android.googlesource.com/platform/external/wpa_supplicant_8/+/80390943513e2c324f25c9b5fc4bb7769c4fcf8f/src/common/dragonfly.c
(dragonfly_min_pwe_loop_iter, dragonfly_is_quadratic_residue_blind).


### Current native SAE matrix after local password preparation work

This matrix supersedes the historical 0.0.100 baseline above. Source behavior
is distinct from native request admission and physical validation.

| Boundary | Current source evidence | Still required |
| --- | --- | --- |
| Password preparation | Retained H2E and legacy jobs, exact SSID/MAC/generation/deadline binding, exclusive worker, terminal errors and wiping; independent commit and authenticated PMK/PMKID tests | Decode/validate actual native password request and connect preparation ownership to native join cancellation |
| P-256 provider | Userland real-provider tests; kernel compilation; eighteen-export offline link and static Sequoia ABI evidence | Bind and validate kernel provider/context execution and timing; repeat ABI work for other supported macOS versions |
| Authentication TX/RX | Ath10kSAERadio routes algorithm 3, retained compute/confirm jobs, generation checks and actual management TX reservation; open-auth builder refuses AKM8 | Physical frames/firmware validation, plus accepted-state behavior audit for the station role |
| Authentication to association | Verified local/peer confirmations precede PMK handoff; exact AKM8 RSNE/PMKID and negotiated H2E RSNXE; no PSK fallback | Native entry path and physical association |
| EAPOL and keys | H2E RSNXE snapshot/M3 validation, PTK/GTK/IGTK staging, retained PMF ownership and replay epochs tested | Physical PMF RX layout, firmware management TX/PN ownership and complete required-PMF exchange |
| Lifecycle | Retained worker/session cancellation, original deadlines and typed completion ownership in source tests | Native credential/preparation factory integration; real leave/rejoin/sleep/wake and runtime terminal-fault recovery |
| Admission/capabilities | NativeJoinAuth rejects SAE and no native WPA3 capability is enabled | Enable only with the dependent credential, backend and PMF paths implemented and verified |

macOS 11–26 ABI coverage and AWDL/AirDrop remain separate stages. No additional
application, system-volume patch or installed kernel-collection change is used.
The retained 0.0.99 reboot candidate is unchanged; local password development
is not an installed or hardware-validated driver release.


The combined local H2E/legacy preparation changes pass the full 55-test
ASan/UBSan suite with halt-on-error; sanitizer logs are checked, not only process
exit codes. Native build and kernel compile checks pass, with unchanged external
imports relative to immutable 0.0.99. The optimized preparation frame is 1656
bytes (the enforced per-frame limit is 4096); this is not a proof of total
kernel call-depth usage or provider latency. No new signature/offline-inclusion
or hardware-success claim is made for this local, uninstalled driver build.

The retained preparation/session test also passes ThreadSanitizer with legacy
derivation/cancellation enabled. Both H2E and legacy vector generators regenerate
byte-identical fixtures. The source and validation package is backed up to the
UUID-checked SD volume and compared byte-for-byte; no installation or reboot.


The combined retained H2E/legacy password preparation and expanded crypto-export
probe batch is development version 0.0.103 (compatible version 0.0.98). Native
SAE admission/capabilities remain disabled; this release does not claim working
hardware WPA3. It is separate from the immutable 0.0.99 reboot candidate and
does not authorize installation or reboot.


The 0.0.103 publication candidate passes strict ad-hoc signature validation and
exact offline AuxKC inclusion for Mach-O UUID
5D27CA7A-B539-35EA-BC2B-26DFB5B23066. The diagnostic AuxKC copy alone removes
OSBundleRequired; the saved native bundle retains Network-Root. Native and
legacy builds and callback-audit checks pass. The full 55-test sanitizer suite
and sae_session ThreadSanitizer cover unchanged preparation/protocol source;
subsequent edits are version metadata and documentation. No installed kernel
collection, EFI files or running driver is changed by this validation.
