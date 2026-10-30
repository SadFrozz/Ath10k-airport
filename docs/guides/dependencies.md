# Dependencies

Initialize dependencies with `git submodule update --init --recursive`. Builds
must use the pinned revisions, not download a moving branch head.

| Submodule | Pinned revision | Purpose |
| --- | --- | --- |
| `vendor/MacKernelSDK` | `05094e5e88cec7caedbfb35e8449ed0db94bf95b` | Kernel headers and link libraries; matches every file of the previous tracked SDK snapshot |
| `vendor/itlwm-upstream` | `738d4c61b5a64433b27c1ab09dba94916ab77d8d` | Native Airport ABI source from laobamac/itlwm |

`python3 scripts/build/prepare-native-headers.py` selects 48 files from the itlwm
submodule and four reviewed overrides in `src/macos/abi/overrides/itlwm`, then
writes verified headers to `build/generated/itlwm`. It checks the pinned commit
and every output hash against `scripts/build/native-headers.json`. Make and the
consolidated tests run this automatically. Submodule working trees are not patched.

The overrides retain the existing WCL records, apple80211 declarations and
Sequoia Skywalk registration layout corrections. This reorganization does not
introduce new ABI behavior. Changes to an override require review and an explicit
manifest update; a changed dependency must never be silently accepted.

Firmware containers and regulatory inputs remain versioned data with their
existing provenance and licenses. Moving a selected binary to an unrelated
repository revision is not an equivalent submodule conversion.
