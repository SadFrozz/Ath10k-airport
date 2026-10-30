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
| Enterprise/external key owner, FT/SAE-PK | Not implemented | Contract work remains | Not advertised |
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

The active branch is `repository-structure`, based on main after PR #2 merged.
It contains layout, pinned dependencies, firmware grouping, documentation, CI and
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
it were retested. Callback inventory covers 190 inline overrides (34 forwarded,
156 rejected); those counts do not mean 190 complete feature implementations.

## Pairwise-completion implementation evidence

The D2D48A34 candidate passed the consolidated 64-test suite, signature,
structural and exact-UUID offline checks before installation. Installation and
bounded postboot observations are now recorded above. Its AP-triggered pairwise
update notification and group-rekey interoperability remain separately unverified.
