# Changelog

Versions below are read from the driver metadata in Git history. Dates mark the
last code change grouped under that version, not an inferred release date.
The imported history starts at 0.0.91; 0.0.90 is mentioned only in the original
README, so its exact changes cannot be reconstructed from this repository.
Versions skipped by the recorded source history are not invented here.

## 1.0.111 — 2026-10-30

- Preserve macOS packet traffic class through admission and radio TX descriptor
  creation while retaining the access restrictions announced by the AP.
- Apply native Fastlane host marking outside the radio gate, using the WCL
  termination fence; clear marking on link-down and reject unsupported ACM
  override before changing host state.

## 1.0.110 — 2026-10-30

- Accept native IPv4/IPv6 and legacy ARP/NDP address notifications into the
  stock macOS interface cache, without enabling firmware offload.
- Validate IPv6 list sizes and clear unused entries on replacement, including
  removal of the final address; normalize unused record bytes.
- Preserve partial ARP updates and local-address removal semantics; propagate
  system cache errors and retain stop/power admission for all address requests.

## 1.0.109 — 2026-10-30

- Preserve pending EAP queue/TX, replacement authentication and pairwise-key
  completion ownership before admitting or retiring a native roam operation.
- Continue servicing the old link's notifications while roaming waits for owners;
  prevent circular waiting between teardown and the pending key-update event.
- Preserve ordered roam-event retry and cancellation without duplicating accepted
  key-completion notifications.

## 1.0.108 — 2026-10-30

- Add bounded experimental same-association Enterprise reauthentication. Preserve
  queued EAP and prior TX/key ownership while waiting to replace the master key.
- Replace Enterprise PMK without resetting established keys or replay history;
  defer new key frames until handoff and reject stale or unauthenticated updates.
- Coordinate restart with an existing firmware rekey without opening its port
  early. Finish only after key-generation/M4 barriers and accepted macOS update
  notification; retain the deadline through retries and cancel expired work.
- Keep Enterprise disabled by default pending live integration and radio evidence.

## 1.0.107 — 2026-10-30

- Start the experimental Enterprise EAP output queue before controlled-port
  authorization; stop and flush its ownership on retirement even with carrier down,
  while preserving an authorized data queue.
- Reject expired EAP ingress independently of delayed service cleanup; stop EAP
  submission while the interface, runtime or power admission is disabled.
- Preserve the system client's initial empty MSK reset without cancelling the
  association or extending its deadline. Clearing an accepted key still revokes it.
- Propagate MSK callback expiry into cancellation and release orphaned EAP queue
  ownership after security/profile/association retirement. Enterprise remains
  default-disabled pending late-key isolation and interoperability evidence.

## 1.0.106 — 2026-10-30

- Bound native pairwise-key completion delivery to five seconds after consuming the successful M4
  transport completion. Cancel the affected association and close its controlled
  port if macOS never accepts the completion event; do not report false success.
- Retire notification timers across key-generation replacement, successful
  delivery and association reset, preserving retries within the original budget.

- Add default-disabled experimental ordinary WPA2-Enterprise integration: system
  EAP packet routing, bounded TX ownership, translated MSK callback and AKM1/CCMP
  four-way exchange. Keep mixed/unsupported enterprise modes rejected.
- Separate OS EAP packet size/queue accounting from the internal EAPOL-Key queue,
  and retire pending EAP owners during association cancellation and shutdown.
- Start the four-way timeout after consuming the system key, while retaining the
  bounded overall join deadline. Enterprise interoperability, reauthentication
  and roaming are not yet verified or advertised as supported.

## 1.0.105 — 2026-10-30

- Move native driver version metadata from `0.0.105` to `1.0.105`, retaining
  build number 105. This version change introduces no new radio behavior.

## 0.0.105 — 2026-10-30

### Native authentication and WPA3

- Bind password preparation to the selected AP, authentication attempt,
  association generation and original deadline. Discard prepared credentials
  after cancellation, expiry or a change of security profile.
- Integrate guarded experimental SAE with the native connection path. Require
  the supported kernel crypto backend and firmware PMF transport before admission.
- Accept text passwords for WPA2-PSK and PSK-SHA256 through asynchronous native
  preparation while preserving the separate SAE path.
- Advertise supported PMF capability, expose bounded RSNXE data and deliver
  authenticated Transition Disable policy without silently downgrading security.
- Complete protected-management RX/TX handling, key ownership and protected
  SA Query scheduling. Keep pending management work from entering idle power save
  prematurely; permit a wake transaction needed to submit protected traffic.
- Validate association-response elements and preserve AP refusal reasons.
  Honor temporary association-refusal/comeback intervals within the existing
  connection deadline instead of immediately discarding the attempt.

### Scanning and macOS integration

- Report the native interface as IEEE 802.11 rather than Ethernet.
- Support native multi-SSID scan requests, channel restrictions and active/passive
  planning; validate variable-length scan messages before DMA submission.
- Correct native BSS/security record layouts used by macOS for network discovery
  and authentication-mode selection.
- Cancel accepted scans when EAPOL/key replacement requires the channel or control
  transport; serialize scan, channel-switch and AP-maintenance ownership.
- Preserve native cancellation and completion ordering across pending joins.
- Release STOP_SCAN buffer ownership when HTC credits arrive after CE completion,
  rather than leaving a completed scan holding the shared buffer.
- Defer root power notifications to an owned worker and acknowledge them after
  hardware quiescence; fence late notifications during teardown. These code
  changes do not establish reliable platform sleep/wake.

### Roaming and key completion

- Implement host-requested reassociation with retained credential profiles,
  generation-bound prepared requests and shared native join admission.
- Retire old firmware peers, scans, packets and keys asynchronously before admitting
  the replacement association; invalidate stale work and changed security policy.
- Deliver native Start/Prep/Reassoc/new-BSS/Complete events in order, retry rejected
  enqueue operations and publish one completion per transaction.
- Preserve BSD carrier during a valid handoff and release it when handoff fails.
- Support empty roam-cache clear/disable requests; reject unsupported autonomous
  firmware roam-cache/offload requests. Physical inter-AP roaming remains unverified.
- Capture EAPOL transport completion at serial DMA retirement so another management
  packet cannot overwrite it. Handle failures for initial and phase-5 rekey replies.
- Publish the pairwise-key update event only after matching M4 completion and
  key-installation barriers; retain policy flags, retry delivery and invalidate
  retired tickets. Initial, duplicate and group-only exchanges do not emit a
  new pairwise-update event.

Sources: [native SAE admission](https://github.com/SadFrozz/Ath10k-airport/commit/c1d80b9),
[SAE/PMF integration](https://github.com/SadFrozz/Ath10k-airport/commit/9dc1eea),
[native scan/ABI/lifecycle](https://github.com/SadFrozz/Ath10k-airport/commit/35c3263),
[STOP_SCAN ownership](https://github.com/SadFrozz/Ath10k-airport/commit/4504c49),
[roaming](https://github.com/SadFrozz/Ath10k-airport/commit/a3ab0b5),
[EAPOL/PTK completion](https://github.com/SadFrozz/Ath10k-airport/commit/ef24356).

## 0.0.104 — 2026-10-29

- Add an isolated P-256 kernel diagnostic service with known-answer checks on
  an owned worker, cancellation fencing and platform guards.
- Keep this diagnostic mode separate from networking and firmware initialization;
  normal builds do not enable its private crypto imports by default.
- Report the actual module version at driver startup.

Source: [eb04bf3](https://github.com/SadFrozz/Ath10k-airport/commit/eb04bf3).

## 0.0.103 — 2026-10-29

- Derive H2E and legacy SAE password elements and commits outside the owner gate.
- Bind asynchronous preparation to exact SSID, peer identity, generation and
  deadline; erase secret material on completion or cancellation.
- Add blinded legacy SAE password derivation. Native SAE admission remained
  disabled at this intermediate implementation stage.

Source: [2bd8186](https://github.com/SadFrozz/Ath10k-airport/commit/2bd8186).

## 0.0.102 — 2026-10-28

- Select SAE/PMF candidates without falling back to PSK; construct association
  RSNE and EAPOL M2 from the same verified PMKID/security profile.
- Validate response RSNE against the selected AKM and group cipher, including
  PSK-SHA256.
- Retain bounded AP RSNXE in scan/native beacon data and bind H2E negotiation to
  that snapshot; reject authenticated handshake/rekey mismatches before installing keys.
- Keep native SAE admission disabled pending the remaining credential and backend work.

Source: [bc45c34](https://github.com/SadFrozz/Ath10k-airport/commit/bc45c34).

## 0.0.101 — 2026-10-28

- Connect retained SAE commit/confirm work to native authentication RX and the
  common authentication state machine, with generation-bound cancellation.
- Publish verified PMK/PMKID once for the admitted identity and deadline.
- Prevent open-authentication fallback and wait for real HTT/CE packet retirement
  before transferring ownership. Native SAE admission remained disabled at this stage.

Source: [8b65f75](https://github.com/SadFrozz/Ath10k-airport/commit/8b65f75).

## 0.0.100 — 2026-10-28

- Bind IGTK publication to the current PMF owner and hardware key barriers.
- Preserve BIP replay floors through retries and independent management-key updates.
- Prepare SAE group-19 commit random/mask on an owned worker with bounded rejection,
  immutable identity/generation binding and the original deadline.
- Keep native SAE admission disabled until credential, radio and firmware PMF
  integration is ready.

Source: [5db129c](https://github.com/SadFrozz/Ath10k-airport/commit/5db129c).

## 0.0.99 — 2026-10-28

- Unblock power-save-retained TX with a wake-only PS-disable/ECHO transaction that
  does not wait for firmware-owned payloads to drain or release them prematurely.
- Bound the recovery wake, preserve the watchdog deadline and defer re-entry into
  idle power save until the drain hold ends.
- Carry firmware MFP capability into payload/peer profiles and initialize the
  PMF_QOS transport owner before scan channels.
- Require live firmware PMF transport evidence before native protected TX or port
  authorization; native SAE/PMF admission was still disabled at this checkpoint.

Source: [5d365c6](https://github.com/SadFrozz/Ath10k-airport/commit/5d365c6).

## 0.0.98 — 2026-10-28

### DMA and native interface

- Correct CE ring DMA segment mapping, alignment/contiguity validation and
  failure handling during allocation and hardware setup.
- Add the experimental Sequoia native Wi-Fi adapter and Lunnen QCA9377 profile;
  expose networks through the macOS Wi-Fi interface instead of requiring the
  legacy companion application.
- Separate WCL, radio and BSD workloop responsibilities; fix BSD preparation,
  native registration ownership and provider lifetime through cleanup.
- Answer required WCL channel/session/low-latency queries before association.
- Apply station MAC changes through bounded firmware vdev recreation.
- Report coherent HT/VHT capabilities, configured channel width and current
  link metrics; reject stale link-up/current-AP queries after retirement.

### Scan and association

- Shorten native passive scans, enable client DFS within regulatory policy and
  preserve requested channel subsets and pre-submit cancellation.
- Publish discovered networks before the complete scan sweep finishes.
- Preserve associated-BSS queries during background scans and correct visible
  SSID handling so broadcast networks are not reported as hidden.
- Fix idle leave/late-abort paths that could cancel the next association or wait
  for key-install replies during teardown.
- Serialize scan admission with channel switching/AP maintenance, reject stale
  events and separate cancellation deadlines from AP DMA-drain deadlines.
- Preserve AP disconnect reasons and correct the Sequoia deauthentication ABI.
- Preserve the full native credential slot and requested authentication policy.

### Queue, power and teardown correctness

- Enforce WCL-first notification ordering to remove reverse-gate deadlock paths;
  retain event order and retry delivery after enqueue failure.
- Guard native startup, report terminal radio errors to macOS and avoid blocking
  bridge gates during user-client termination.
- Drain deferred probing before workers/radio teardown and serialize firmware
  initialization with sleep/shutdown quiescence.
- Block new work during suspend, retire security state and preserve pending
  suspend intent through restart readiness.
- Retain borrowed BSD interface/callback ownership until framework cleanup;
  retire radio before leaf stop and avoid duplicate child cleanup.
- Fence late power callbacks, wait for actual power completion before releasing
  resources, and perform wake retirement/rematching outside power callbacks.
- Preserve deferred TX wakeups across EAPOL/queue holds and start retained-payload
  teardown timeouts at disconnect entry. Platform sleep remains unverified.

### Security foundations

- Add WPA2 PSK-SHA256 KDF/AES-CMAC/descriptor-3 handling and preserve requested AKM
  in association frames; reject unsupported security/PMF requirements explicitly.
- Retire expired pairwise-rekey replies before advancing native service state.
- Add P-256, SAE H2E/commit-confirm, authentication-frame parsing and bounded
  retained crypto/session work with cancellation and secret cleanup.
- Add opt-in SAE four-way handling, authenticated IGTK delivery, protected
  management CCMP/BIP replay handling and bounded SA Query foundations.
- Connect protected-management receive/transmit jobs and spectrum-management
  scheduling to explicit hardware ownership. These intermediate foundations did
  not yet enable complete native WPA3 admission.

Sources: [DMA mapping](https://github.com/SadFrozz/Ath10k-airport/commit/066af06),
[native adapter](https://github.com/SadFrozz/Ath10k-airport/commit/e16038f),
[native interface and scan](https://github.com/SadFrozz/Ath10k-airport/commit/c1956b5),
[connection/security](https://github.com/SadFrozz/Ath10k-airport/commit/850636f),
[WCL lock ordering](https://github.com/SadFrozz/Ath10k-airport/commit/cbaa582),
[teardown](https://github.com/SadFrozz/Ath10k-airport/commit/e105f82),
[early scan results](https://github.com/SadFrozz/Ath10k-airport/commit/5a5d69c),
[scan arbitration](https://github.com/SadFrozz/Ath10k-airport/commit/1a5a0c3),
[PMF transport](https://github.com/SadFrozz/Ath10k-airport/commit/79b261f).

## 0.0.94 — 2026-10-26

- Add experimental QCA9377 initialization/profile handling and exact board-data
  selection with validation of the fallback path.
- Support WPA2 TKIP group keys with CCMP pairwise traffic, including group-cipher
  selection and receive/security handling. Pairwise TKIP remains unsupported.
- Add adapter recovery after sleep to the then-current legacy path. This historical
  change does not establish working sleep on the present native configuration.

Sources: [QCA9377 and group TKIP](https://github.com/SadFrozz/Ath10k-airport/commit/5ce1a8e),
[legacy wake recovery](https://github.com/SadFrozz/Ath10k-airport/commit/6e391a8).

## 0.0.91 — 2026-10-08

Initial imported code snapshot, rather than a recoverable delta from 0.0.90:

- QCA6174 client operation with 2.4/5 GHz scanning, open/WPA2-CCMP association,
  HT/VHT negotiation, TX/RX aggregation, WMM/EDCA and regulatory handling.
- QCA9377 code/firmware profile present but not yet validated in that snapshot.
- Legacy Ethernet-presented network interface controlled by a companion app;
  this predates the native macOS Wi-Fi adapter described above.

Source: [initial snapshot](https://github.com/SadFrozz/Ath10k-airport/commit/3dcee46).
