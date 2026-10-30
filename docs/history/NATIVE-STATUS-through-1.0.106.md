# Implementation and verification map

Updated 2026-10-30. This is the current feature map. Contracts define requirements;
chronological entries in the audit/history are not current status overrides.

| Feature | Implementation | Local verification | Hardware evidence / remaining scope |
| --- | --- | --- | --- |
| Native interface, scan, association, traffic | Implemented on Sequoia adapter | Consolidated suite | Native networks and traffic observed; prolonged stability remains open |
| SAE | Implemented, opt-in experimental | Crypto and production admission paths | SAE IPv4/IPv6 traffic observed on 15.6.1/24G90; both password modes not fully certified |
| PMF | Implemented: key epochs, protected TX/RX, BIP, SA Query | PMF/key/cancellation regressions | One protected SA Query round trip verified; group BIP and AP-triggered rekey hardware evidence pending |
| PTK/GTK/IGTK updates | Implemented internal-supplicant paths | Key-stage, replay, cancellation and firmware barrier fixtures | AP-triggered updates not yet captured; do not label as unimplemented |
| Native EAPOL completion ownership | Durable retirement receipt and all-reply failure handling implemented locally | Consolidated 64-test suite passed | Installed/loaded 39B543D3 (1.0.105); bounded ordinary traffic observed, not a rekey test |
| macOS notification after pairwise rekey | Implemented locally after matching M4/key-generation barrier | Production completion, lifecycle and notification regressions passed | Installed/loaded 39B543D3 (1.0.105); AP-triggered hardware update remains unverified |
| Native host-requested roaming | Integrated | Request through teardown/common join/notifications covered | Ordinary SAE regression passed; physical inter-AP handoff unavailable with one router |
| Autonomous roam-cache/offload | Not implemented | Parser does not establish firmware scheduling | Nonempty/enable requests rejected; clear/disable supported |
| Ordinary WPA2-Enterprise | Local opt-in EAP/MSK and AKM1 integration; default disabled | Focused fixtures and native build; integrated completion checks remain | No enterprise infrastructure test |
| Enterprise reauthentication/roaming, FT/SAE-PK | Not implemented | Separate contracts remain | Not advertised |
| Sleep/wake | Driver lifecycle implemented, possibly working | Local lifecycle regressions | Platform sleep deferred by user; do not claim fixed |
| macOS 11–14, 15.0–15.1, 26 | Adapter work remains | Sequoia coverage is insufficient | See docs/compatibility/COMPATIBILITY.md |
| AWDL/AirDrop | Not implemented | Separate feature stage | No interoperability claim |

## Previous 0.0.105 installed checkpoint

- Version `0.0.105`, UUID `D2D48A34-9F25-327E-A916-7C7D4C297822`,
  source publication `ef243563cbe39db05df9c1c07f16c2ff4944436e`.
- Boot `6984797B-73E1-4EC7-B965-39E6A1CA08AF`; loaded UUID rechecked locally.
- `NATIVE-ptk-postboot-20261030/result.json`: 30/30 en1-bound router replies,
  mean 33.293 ms, maximum 384.290 ms. Disconnect count stayed zero; TX errors
  rose from 6 to 7. Security/replay drops stayed zero and key generation stayed 1.
- This bounded observation does not prove prolonged stability or AP-triggered rekey.

## Current installed 1.0.105 checkpoint

Reorganization branch `repository-structure` merged through PR #3 as `302a8c8`.
Functional work resumes in `native-sequoia-development` from that main.
The completed reorganization contains layout, pinned dependencies, firmware grouping, documentation, CI and
user-requested version metadata changes, without new radio behavior.

Before the version change, all three files of the signed reorganized kext matched
the installed candidate byte-for-byte (executable SHA-256
`694d1cd8d75b2eda229f8654a446445012cb2861f78789b85fea82ac8975af3d`).
This equivalence does not describe the new versioned binary.

- Installed experimental candidate: `1.0.105`, UUID
  `39B543D3-B8B1-3147-98AB-EE4A99315DFD`, source `0f2db5ce24546a1d7717a5749fc00ecbaf292f1f`.
- Native configuration matches the installed profile except version fields;
  SAE remains explicitly enabled for this laptop candidate.
- Signature, structure and exact-UUID offline auxiliary inclusion passed.
  The auxiliary copy alone removes OSBundleRequired; its program sections match
  the normal OpenCore candidate. No system kernel collection was modified.
- Release, Debug and consolidated sanitized logic CI passed at the source commit.
- Current EFI kext/config rollback and candidate were copied and verified on SD.
- Installed after explicit approval; exact loaded UUID verified on boot
  `73C778EA-96FB-42A9-80B6-73566E2524CA`. Native connection is `connected-sae`,
  security phase 5, PMF port ready. Thirty en1-bound router probes all succeeded
  (mean 4.388 ms, maximum 10.021 ms). Disconnects stayed 0; TX errors stayed 12;
  replay/security drops stayed 0. Evidence: `postboot/result.json` in the candidate
  directory. This bounded check does not prove prolonged stability or AP rekey.

Evidence: workspace/SD `NATIVE-repository-restructure-20261030`, particularly
`hardware-candidate-1.0.105/READY.json`, `inclusion.json` and rollback files.
Historical changelog and hardware checkpoint are reconciled in the same
documentation batch.

## Previous functional checkpoint

- Published source: remote commit `a3ab0b5a08ba3d085e75b45ee936891f53941ae2`,
  tree `373e552399ed81016ba04b6af8e73848ebfdff60`.
- Installed/loaded UUID: `AF185664-F6A2-3EE4-B3D6-723E5CB4C1BD`.
- Boot: `87DD2905-4A4F-4305-B72B-40B525B9A789`.
- Candidate acceptance: 63 C++ tests plus runner checks, signature and exact UUID
  inclusion in offline dependency collection passed before installation.
- Postboot: connected-sae, PMF port ready, 30/30 en1-bound router replies,
  3.932 ms mean; no disconnect/watchdog increment during bounded observation.
- This map refresh is local and is not a new published driver build.

## Evidence locations

Workspace `outputs/` and SD contain:

- `NATIVE-ptk-completion-candidate-20261030`: installed candidate and validation.
- `NATIVE-ptk-postboot-20261030`: bounded traffic/counter evidence.
- `NATIVE-roam-integrated-candidate-20261030`: full tests, build, validation,
  rollback and `INSTALLED.json`.
- `NATIVE-roam-postboot-20261030`: before/after state and counter comparison.
- `WPA3-PMF-protected-roundtrip-VERIFIED-20261029-171424`: earlier protected
  SA Query verification on UUID `A3E38378-BAE6-346C-8E1D-88A192367DE1`.

Do not transfer an earlier image's hardware observation to a later image as if
it were retested. Callback inventory covers 190 inline overrides (35 forwarded,
155 rejected); those counts do not mean 190 complete feature implementations.

## Pairwise-completion implementation evidence

The D2D48A34 candidate passed the consolidated 64-test suite, signature,
structural and exact-UUID offline checks before installation. Installation and
bounded postboot observations are now recorded above. Its AP-triggered pairwise
update notification and group-rekey interoperability remain separately unverified.

## Local macOS notification reliability fix (not installed)

PTK completion delivery now has a fixed 5000 ms budget from consumption of the successful M4
completion receipt. Persistent WCL queue admission failure cancels the affected
association and closes its controlled port, without a fabricated completion.
Stale generations retire without cancelling a replacement; successful delivery
and reset clear the timer. Four affected production-path regressions passed
with ASan/UBSan, including deadline boundaries, clock reversal, generation
replacement, transient enqueue failure, PMF readiness and lifecycle cleanup.
All 64 consolidated regressions passed. Version 1.0.106 UUID C92C0F32-AA19-318E-B57C-15D9C5E1684A built; signature, structure and exact-UUID offline dependency inclusion passed. Current EFI rollback verified on SD. Hardware validation remains pending; installed version is still 1.0.105.

## Current local EAP integration (default disabled)

This is separate from implemented WPA3-Personal SAE/PMF. The installed image
remains 1.0.105; the following source changes are local and unpublished.

| Boundary | Current evidence | Remaining work |
| --- | --- | --- |
| Profile admission | Explicit property and examined-kernel gate; ordinary AKM1/CCMP only; production join fixture | Confirm actual enterprise join envelope from macOS |
| Packet routing | Extracted RX/TX and batch preflight fixtures cover current-peer EAP, 1024-byte packets, full key queue, copy/allocation failure and retry ownership | Confirm IO80211 delivery before authorized link and system client startup |
| MSK ownership | Real header ABI; zero-BSSID 32-byte translated key; duplicate/conflict/clear handling; generation/MAC-bound owner | OS callback has no generation token: late cross-association callback serialization remains unresolved |
| Four-way binding | One-shot PMK, fresh nonce, AKM1 vectors, initialization failure and cleanup | Enterprise reauthentication and host roaming remain unimplemented |
| Completion | Combined production admission/callback/binding/M1–M4/export/receipt fixture; wrong receipt ID and failed M4 do not authorize | Firmware ACKs emulated; actual port publication and enterprise radio interoperability unverified |
| Cancellation | EAP-only owner retired on cancel/disable/failure/disconnect drain; bounded MSK/queue wait | Extracted wait/deadline boundaries additionally passed ASan/UBSan; overall join deadline fixture passed in full suite |
| Local build | UUID 316E8378-1379-35B5-BCC9-BB4B99D59C0E compiled; ad-hoc signature and exact-UUID offline auxiliary inclusion passed | Not installed; no runtime claim |
| Regression | All 68 C++ tests and supporting runner checks passed with explicit ASan/UBSan; extraction-boundary fix included | Portable fixtures do not prove hardware interoperability |

Correction: recent local focused invocations used plain `--cxx clang++`, so
prior EAP checkpoint wording claiming ASan/UBSan for those runs was incorrect.
The completed full invocation explicitly included
`-fsanitize=address,undefined -fno-omit-frame-pointer`. Its exit status was 0; `FULL-REGRESSION.json` and `full-sanitized.log` preserve
the result. Passing earlier ordinary fixtures alone was not sanitizer evidence.

Offline validation uses a separate copy without OSBundleRequired. The original
OpenCore candidate remains intact; no system kernel collection was changed.
Evidence: workspace/SD `NATIVE-eap-integration-20261030`, with
`offline-validation/inclusion.json`, signed candidate and local test logs.

Installed eapolclient UUID FAC5670D recognizes upper-auth 4 as Enterprise.
That consumer-side observation does not establish the producer's current
getAUTH_TYPE response, startup orchestration or radio interoperability.

User requested ending the current batch for hardware testing. Candidate 1.0.106
316E8378 is frozen with Enterprise off; existing WPA3 option matches installed
1.0.105. Fresh EFI/config rollback is verified on SD. Installation/reboot still
requires explicit approval; remaining Enterprise contracts stay open.

## Paused after 1.0.106 hardware checkpoint — 2026-10-30

User requested pausing work. Installed/loaded UUID is
316E8378-1379-35B5-BCC9-BB4B99D59C0E; boot
00B8BFE0-3C67-4D3A-8A64-78C908CB4C79. SAE phase 5 and PMF ready.
Native en1 probe: 30/30 replies, mean 119.750 ms, maximum 946.372 ms.
TX errors rose 0→15 during that window; later counters classify all 15 as
NoAck, with discard and watchdog counts 0. Disconnect, security and replay
drops stayed 0. This is connectivity evidence, not a clean stability pass.
No new driver changes follow published 826c310; future work must investigate
latency/NoAck before claiming prolonged stability.

Separately, user requested restoring NVMe APST. Removed only the 8-byte zero
ps-max-latency-us override from EFI config, validated and backed up on SD in
OpenCore-restore-nvme-apst-20261030-083129. Reboot explicitly deferred; runtime
has not applied this config change. Random reboot cause remains unproven.
No reboot or sleep is scheduled. Do not resume development until requested.

Final user-requested review of the Wi-Fi kext 1.0.106 completed before pause.
Reviewed production changes for PTK notification lifetime, EAP packet ownership,
callback admission, credential cleanup and personal-mode separation. Four affected
production-path tests passed again with explicit ASan/UBSan. No additional confirmed
defect requiring a code change was found in that review; this is not a claim that
latency/NoAck or all broader requirements are resolved. Evidence:
NATIVE-eap-integration-20261030/FINAL-WIFI-REVIEW.json. No new image installed.

Final installed-driver runtime check requested by user: exact 1.0.106 UUID verified; 45/45 router replies bound to en1, mean 6.411 ms, max 43.066 ms. Disconnect/watchdog/security/replay remain 0; TX NoAck stayed 15→15. SAE/PMF remained ready. Short runtime check passed; earlier latency spikes remain historical unresolved evidence. No settings changed. Work paused after this runtime check. Evidence: installed-final-check/result.json on workspace and SD.
