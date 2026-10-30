# Licensing review — 2026-10-30

This is an evidence-based engineering review, not a legal clearance or a change
of license. The root LICENSE remains unchanged. A single GPL label does not
relicense third-party SDKs, headers or firmware.

## Findings

| Component | Observed terms | Consequence / unresolved question |
| --- | --- | --- |
| Project and original jonasw8/Ath10kMac | Root LICENSE contains GPL version 3, inherited from the original repository | Retained upstream code cannot simply be relicensed to MIT/BSD by this fork. Establish rightsholder permissions before changing terms. |
| Pinned laobamac/itlwm | Root LICENSE contains GPL version 2; selected headers often have only copyright notices | The selected files need individual provenance/permission review. No specific upgrade grant was established for the selected WCL/Skywalk files. The example 'or later' notice in the GPL template alone is not an application of that notice to every file. Do not assume GPLv2-only conclusively either. |
| Airport ABI headers | `apple80211_var.h` and `apple80211_ioctl.h` explicitly name APSL 1.1; the former has local modifications | Retain the file-specific notices and establish applicable license/version and modification obligations. They are not made GPL by the itlwm root LICENSE. |
| MacKernelSDK | Root APSL 2.0; individual headers have their own notices; OSObject.h also contains an OS-license-use restriction | Audit actually used declarations, inline code and linked libkmod/libkmodc++ objects separately. Presence of an SDK alone does not prove a derivative-work conflict, nor does calling it an SDK establish a system-library exception. |
| Qualcomm firmware/calibration | Qualcomm binary redistribution terms, chipset-only use, no modification, required notices | Firmware is not GPL. Current generator extracts board/WLAN/OTP bytes and embeds them as arrays, without patching the selected bytes. Independent device firmware and the host driver require separate licensing analysis; embedding does not itself prove either GPL compatibility or a violation. |
| Regulatory database | ISC-style permission notice | Preserve attribution and permission text; this is not the identified copyleft conflict. |

Original upstream license: [jonasw8/Ath10kMac LICENSE](https://github.com/jonasw8/Ath10kMac/blob/main/LICENSE).
Dependency evidence is pinned in `.gitmodules`, Git gitlinks and
`scripts/build/native-headers.json`. Firmware terms are in
`firmware/LICENSE.QualcommAtheros_ath10k` and the chipset notices.

The GPLv2/GPLv3 distinction matters: GPLv2-only and GPLv3 cannot generally be
combined into one covered work, whereas a valid GPLv2-or-later grant permits
choosing GPLv3. Relicensing or adding exceptions requires the relevant
rightsholders' authority. System-library exceptions have conditions and cannot
be assumed for copied or statically included material.
[GNU FAQ](https://www.gnu.org/licenses/gpl-faq.en.html#v2v3Compatibility),
[system-library exception](https://www.gnu.org/licenses/gpl-faq.en.html#SystemLibraryException).

FSF lists APSL 2.0 as GPL-incompatible. Apple distinguishes file-level covered
code from a larger work and retains obligations for the covered portions.
Whether particular ABI declarations/inline definitions constitute incorporated
copyrightable code needs file-specific analysis; the inventory alone does not
prove that distributing this kext violates a license.
[FSF license list](https://www.gnu.org/licenses/license-list.html#apsl2),
[Apple APSL terms](https://opensource.apple.com/apsl/).

## Decision and remaining work

GPLv3 is retained at the user's direction; MIT/BSD relicensing is not pursued.
The GPLv3 upstream license is not replaced or amended, and no unilateral
exception is asserted for third-party code.

- Resolve the exact grants covering selected itlwm declarations and local
  derivative headers; obtain rightsholder permission if required.
- Establish the SDK/system-library boundary for the actual linked objects and
  any incorporated header implementation, not the SDK name alone.
- Retain the Qualcomm notices and document the independent device-firmware
  boundary. No GPL grant is asserted over those binaries.
- Keep source provenance, local override provenance and required notices in
  the distributed package. APSL 1.1 text was missing from the previous package;
  it is now included without silently upgrading the affected files' license.

These packaging corrections address demonstrated notice gaps. They do not
prove compatibility of every combined component or grant additional rights.
The unresolved header/SDK questions require a file-level rightsholder/licensing
review before a claim of complete distribution clearance.
