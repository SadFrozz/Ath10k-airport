# Native macOS compatibility roadmap

Target: macOS 11 Big Sur, 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia,
and 26 Tahoe on x86_64, using OpenCore injection and each OS's own networking
components. These are support targets, not a claim of tested compatibility.

| macOS | Status | Required work |
| --- | --- | --- |
| 11–12 | Planned | Separate legacy IO80211 adapter and hardware validation |
| 13–14 | Planned | Verify each networking ABI and build an appropriate adapter |
| 15.2+ | Experimental | Native scan and WPA2 IPv4/IPv6 observed on 15.6.1; opt-in SAE IPv4/IPv6 traffic and one protected SA Query round trip observed on exact build 24G90; stability, group BIP/rekey and sleep/wake pending |
| 15.0–15.1 | Planned | Separate ABI validation; current adapter rejects these kernels |
| 26 | Planned | Distinct Tahoe adapter, kernel guards and hardware validation |

Keep PCI/firmware/DMA/WMI/HTT, regulatory policy and security logic in a shared
radio core. Confine private OS declarations, vtables, wire layouts and events to
versioned adapters. Select mutually exclusive builds with OpenCore MinKernel and
MaxKernel; each build also validates the kernel ABI before opening PCI. Multiple
kexts may eventually ship in one package; this does not promise one universal
binary or automatic compatibility with an untested macOS update.

First complete Sequoia stability, key-update and sleep/wake validation. Initial
WPA2 association and IPv4/IPv6 traffic passed on 15.6.1 with 5a5d69c. Next implement Tahoe,
then work backward through the older systems. Gate support on cold boot,
scan/association, DHCP/data transfer, disconnect, sleep/wake and update tests on
each target. WPA3/SAE/PMF validation and AWDL remain separate incomplete stages. Never
claim certification based only on host tests or successful compilation.

Do not install OCLP root patches, replace system networking families, remove
version guards or spoof dependency versions to claim compatibility.

## WPA3 requirement

WPA3-Personal is an explicit support target. PSK-SHA256 is not WPA3. The opt-in
experimental image 9A07D3C3-B210-31A1-A28D-73795400E9D1 auto-associated with
AKM8 on 24G90 and passed short interface-bound ICMP/HTTPS checks. This does not
certify PMF interoperability or other kernel builds. Complete hardware coverage
for SAE, required PMF/BIP, IGTK/IPN replay
protection, protected deauthentication/disassociation and SA Query together.
Test SAE-only and transition networks, anti-clogging/retransmission paths,
wrong-password and downgrade resistance with independent fixtures and hardware.
Default builds still reject SAE/required PMF. The explicit experimental option
announces SAE and MFP together only on its guarded kernel and admits requests
only with the implemented crypto/worker/PMF barriers. Do not broaden this to a
release support claim until validation is complete, or silently convert an
explicitly requested WPA3 connection to WPA2. See WPA3-CONTRACT.md for evidence
and remaining profile-persistence, protected-management and lifecycle work.

## AWDL and AirDrop requirement

AWDL and AirDrop are explicit planned features, not provided by the current
infrastructure adapter. After stable AP association/data and security, implement
AWDL peer discovery/action frames, synchronization and channel scheduling,
AP/AWDL coexistence, a versioned native virtual interface and IPv6 data path.
Validate regulatory limits and sleep/wake behavior. AirDrop then requires working
Bluetooth discovery plus AWDL, bidirectional transfer, peer interoperability and
continued AP traffic. Do not infer AirDrop support from a working Wi-Fi menu.

Latest Sequoia hardware checkpoint (2026-10-29): normal-mode image
0E9AA8BE-EF2E-393A-A9DA-58AEA243E6E5 connected with SAE after the AP requested
a 1000-TU association comeback. Twenty interface-bound ICMP requests and
IPv4/IPv6 HTTPS succeeded without a disconnect increment in a one-minute check.
This confirms that retry on this AP, not long-duration stability, group PMF,
rekey, sleep/wake or another OS ABI. No extra application is required.
