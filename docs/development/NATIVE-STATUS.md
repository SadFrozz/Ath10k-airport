# Implementation and verification map

Updated 2026-10-30. This is the current feature map. Contracts define requirements;
chronological entries in the audit/history are not current status overrides.

| Feature | Implementation | Local verification | Hardware evidence / remaining scope |
| --- | --- | --- | --- |
| Native interface, scan, association, traffic | Implemented on Sequoia adapter | Consolidated suite | Native networks and traffic observed; prolonged stability remains open |
| SAE | Implemented, opt-in experimental | Crypto and production admission paths | SAE IPv4/IPv6 traffic observed on 15.6.1/24G90; both password modes not fully certified |
| PMF | Implemented: key epochs, protected TX/RX, BIP, SA Query | PMF/key/cancellation regressions | One protected SA Query round trip verified; group BIP and AP-triggered rekey hardware evidence pending |
| PTK/GTK/IGTK updates | Implemented internal-supplicant paths | Key-stage, replay, cancellation and firmware barrier fixtures | AP-triggered updates not yet captured; do not label as unimplemented |
| Native EAPOL completion ownership | Durable retirement receipt and all-reply failure handling implemented locally | Consolidated 64-test suite passed | Candidate built/signed and included in offline collection; not installed |
| macOS notification after pairwise rekey | Implemented locally after matching M4/key-generation barrier | Production completion, lifecycle and notification regressions passed | Not installed; AP-triggered hardware update remains unverified |
| Native host-requested roaming | Integrated | Request through teardown/common join/notifications covered | Ordinary SAE regression passed; physical inter-AP handoff unavailable with one router |
| Autonomous roam-cache/offload | Not implemented | Parser does not establish firmware scheduling | Nonempty/enable requests rejected; clear/disable supported |
| Enterprise/external key owner, FT/SAE-PK | Not implemented | Contract work remains | Not advertised |
| Sleep/wake | Driver lifecycle implemented, possibly working | Local lifecycle regressions | Platform sleep deferred by user; do not claim fixed |
| macOS 11–14, 15.0–15.1, 26 | Adapter work remains | Sequoia coverage is insufficient | See docs/compatibility/COMPATIBILITY.md |
| AWDL/AirDrop | Not implemented | Separate feature stage | No interoperability claim |

## Repository organization checkpoint

The active branch is `repository-structure`, based on main after PR #2 merged.
Only layout, dependencies, documentation and necessary build/test paths change.
Firmware inputs are grouped by chipset/revision; generated files are under
`build/generated/firmware`. Original firmware and board-calibration bytes match.

The consolidated 64-test suite and native build pass after the firmware move.
The signed executable SHA-256 is
`694d1cd8d75b2eda229f8654a446445012cb2861f78789b85fea82ac8975af3d`,
identical to the installed candidate with UUID
`D2D48A34-9F25-327E-A916-7C7D4C297822`. This is binary-equivalence evidence,
not a fresh installation, reboot or broader stability certification.
PR #3 remains subject to final remote packaging checks and merge review.
Evidence: workspace/SD `NATIVE-repository-restructure-20261030`.

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

- `NATIVE-roam-integrated-candidate-20261030`: full tests, build, validation,
  rollback and `INSTALLED.json`.
- `NATIVE-roam-postboot-20261030`: before/after state and counter comparison.
- `WPA3-PMF-protected-roundtrip-VERIFIED-20261029-171424`: earlier protected
  SA Query verification on UUID `A3E38378-BAE6-346C-8E1D-88A192367DE1`.

Do not transfer an earlier image's hardware observation to a later image as if
it were retested. Callback inventory covers 190 inline overrides (34 forwarded,
156 rejected); those counts do not mean 190 complete feature implementations.

## Local pairwise-completion candidate

UUID `D2D48A34-9F25-327E-A916-7C7D4C297822`: consolidated 64-test suite,
ad-hoc signature, structural validation and matching-UUID inclusion in an
isolated auxiliary collection passed. The auxiliary validation copy removes
OSBundleRequired; the OpenCore candidate retains Network-Root. No live loading,
EFI update or reboot was performed. This does not replace the installed
checkpoint above or establish AP-triggered rekey interoperability.
