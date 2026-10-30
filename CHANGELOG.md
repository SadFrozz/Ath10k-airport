# Changelog

## Unreleased — repository organization

- Organize original firmware by chipset/revision, document provenance, and move generated payload files to build/generated/firmware; firmware bytes and profile selection are unchanged.

- Separate radio/security/macOS sources, test groups, packaging and developer documentation.
- Replace copied MacKernelSDK and Airport headers with pinned submodules and four reviewed ABI overrides; generated headers are hash-verified.
- Update Make, Xcode, Windows tooling, diagnostics and CI paths; rewrite README for users and contributors.
- Driver declarations and executable statements are unchanged across all 90 relocated source files; on-machine acceptance is required before merging this branch.

## Unreleased — EAPOL completion and native PTK-update notification

- Preserve EAPOL transport results at serial DMA retirement independently of
  later management transmissions. Check failures for initial and rekey replies.
- Added production-fragment regression for wrong IDs, overwritten serial status,
  initial authorization, phase-5 failures and retired connection state.
- Publish the stock pairwise-update event only after the matching M4 and key
  generation barrier. Preserve policy flags; retry failed enqueue, invalidate
  retired ownership, and exclude initial and group-only key updates.
- All 64 tests passed; signed candidate D2D48A34-9F25-327E-A916-7C7D4C297822
  passed structural validation and exact-UUID auxiliary inclusion. Not installed
  or published; AP-triggered hardware rekey remains unverified.

## Unreleased — documentation reconciliation, 2026-10-30

- Separate normative native/security contracts from historical investigations.
- Add a current implementation/evidence map and repository agent instructions.
- Correct stale diagnostics that described implemented SAE/PMF as absent.
- Record installed roaming package and bounded postboot SAE traffic evidence.
- Recover the stock external-key dispatch split; record remaining ownership and completion requirements.
- No driver behavior change in this documentation batch.

## 2026-10-30 — integrated native roaming package

Published as `a3ab0b5a08ba3d085e75b45ee936891f53941ae2`.

- Integrate host-requested reassociation, retained credential profiles, generation
  fencing, asynchronous firmware retirement and stock macOS event ordering.
- Preserve BSD carrier during valid handoff and release it on failure.
- Strengthen scan/TX/RX/peer retirement barriers and late policy cancellation.
- Support mandatory empty roam-cache clear/disable; reject unsupported offload.
- Acceptance: 63 C++ tests and associated checks, signed/dependency-verified kext,
  verified SD rollback. Loaded candidate and ordinary SAE traffic confirmed.
  Physical inter-AP handoff remains unverified.

## Earlier development

Historical SAE/PMF implementation and radio checkpoints, lifecycle fixes and
other experiments are preserved in [docs/development/NATIVE-CONNECTION-AUDIT.md](docs/development/NATIVE-CONNECTION-AUDIT.md)
and [contract research](docs/history/NATIVE-CONTRACT.md). This changelog does not
invent release boundaries or claim every historical experiment was installed.
