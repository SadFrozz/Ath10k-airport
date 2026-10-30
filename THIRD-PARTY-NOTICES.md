# Third-party notices

Ath10k-airport retains the GPLv3 text inherited from jonasw8/Ath10kMac.
This does not apply GPL terms to all third-party components. No additional
license exception or relicensing permission is asserted by this notice.

| Component | Source / exact revision | Notice location |
| --- | --- | --- |
| Ath10kMac original project | https://github.com/jonasw8/Ath10kMac | LICENSE |
| MacKernelSDK | acidanthera/MacKernelSDK, 05094e5e88cec7caedbfb35e8449ed0db94bf95b | vendor/MacKernelSDK/LICENSE.txt and individual headers |
| Selected Airport/WCL headers | laobamac/itlwm, 738d4c61b5a64433b27c1ab09dba94916ab77d8d | vendor/itlwm-upstream/LICENSE; individual file notices take precedence |
| Apple Airport declarations | Selected apple80211_var.h and apple80211_ioctl.h name APSL 1.1 | packaging/licenses/APSL-1.1.txt |
| Qualcomm board/WLAN/OTP binaries | firmware/QCA6174/hw3.2 and firmware/QCA9377/hw1.0 | firmware/LICENSE.QualcommAtheros_ath10k and each chipset's notice |
| Wireless regulatory database | regulatory/ | regulatory/LICENSE and regulatory/SOURCE.md |

The selected header manifest is `scripts/build/native-headers.json`.
Four modified copies live under `src/macos/abi/overrides/itlwm`: WCL.hpp,
Airport/apple80211_var.h, Airport/macOS15/IOSkywalkEthernetInterface.h and
Airport/macOS15/IOSkywalkNetworkInterface.h. These retain upstream notices;
their local changes cover native ABI records and Skywalk registration layouts.
The upstream submodule is unmodified. Git history and the manifest identify
local versions; this notice does not supersede file-level obligations.

Firmware containers and exact selected payloads remain under their original
terms. Firmware executes on the Qualcomm device and is not licensed as GPL by
this project. Chipset-specific PROVENANCE.json files record the available
provenance and explicitly identify missing historical revisions.

The APSL 1.1 license text is reproduced from the SPDX license-list-data
APSL-1.1 entry (https://github.com/spdx/license-list-data/blob/main/text/APSL-1.1.txt).

See docs/guides/license-audit.md for unresolved compatibility questions.
Notice inclusion is not a legal determination that every combination is cleared.
