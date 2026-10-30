# CI and releases

Exactly three workflows are maintained:

| Workflow | Triggers | Work |
| --- | --- | --- |
| Logic tests | Pull request, manual, reusable call | One consolidated suite with ASan/UBSan, callback audit, independent P-256 vectors |
| Kext builds | Pull request, manual, reusable call | Release and Debug matrix; native build, signature/structure/import checks, packages and checksums |
| Publish Release | Push of a v* tag only | Reuse the first two workflows for the tag; publish both packages only after both succeed |

Ordinary branch pushes, including main, never trigger workflows. Superseded
PR/manual runs are cancelled; tagged release runs are not cancelled. No workflow
publishes on a branch push or manual dispatch. Manual build dispatch produces
`NIGHTLY` Release and Debug archives (UTC date and source SHA) as Actions artifacts;
it does not create a GitHub Release. Manual logic-test dispatch runs tests only. A release tag must match both
source version declarations (an optional prerelease suffix is allowed).

Release uses `OPT=-O2 DIAGNOSTICS=0`. Debug uses `OPT="-O1 -g" DIAGNOSTICS=1`.
Both use the normal native controller (`DIAGNOSTIC_STAGE=0`), and default SAE
policy is unchanged. Debug is a full driver with symbols and diagnostics, not
the old controller stage-3 or P-256 stage-4 probe. Archives include their
configuration, source commit, licenses and SHA-256 checksum.

Special diagnostic controllers and offline kernel symbol probes remain local
Make targets; they are no longer rebuilt for every PR. The macOS runner is
retained for the platform-specific security regressions. The consolidated suite
runs once with sanitizers rather than again without them. Leak detection alone
is disabled for host IOKit lifetime models; invalid access and UB still fail.

A tag starts a fresh verified build of that exact source, rather than publishing
an arbitrary branch artifact. Publication uses the same run's two build artifacts.

## Manual revision selection

In Actions, choose **Logic tests** or **Kext builds / NIGHTLY**, then **Run workflow**.
Select the branch using GitHub's branch selector. Optionally enter the full
40-character `source_commit` SHA; empty means the selected branch HEAD.
The chosen commit must be reachable from that branch's selected revision.
Both build configurations use that exact commit and its pinned submodules.
Package names and BUILD-INFO use the checked-out SHA, not the branch HEAD.
Workflow instructions come from the selected branch; the source can be an older
commit with the compatible reorganized layout. Old layouts may fail validation.

Manual dispatch becomes available in GitHub's Actions UI once these workflows
are present on the default branch; this reorganization PR has not yet merged.

## Version numbering

The native series uses `major.minor.build`: `1.0.105` retains build number 105
from `0.0.105`. The third component is a build number, not a patch-release
classification. Both plist version fields and kmod_info.c must agree. A normal
release tag is `v1.0.105`; existing NIGHTLY/PR suffixes label artifacts only.
Changelog headings put version before date and describe driver code changes;
repository/CI/documentation work belongs in PR descriptions and the journal.
The 1.0 series name does not remove the documented experimental limitations.
