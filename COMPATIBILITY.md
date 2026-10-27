# Native macOS compatibility roadmap

Target: macOS 11 Big Sur, 12 Monterey, 13 Ventura, 14 Sonoma, 15 Sequoia,
and 26 Tahoe on x86_64, using OpenCore injection and each OS's own networking
components. These are support targets, not a claim of tested compatibility.

| macOS | Status | Required work |
| --- | --- | --- |
| 11–12 | Planned | Separate legacy IO80211 adapter and hardware validation |
| 13–14 | Planned | Verify each networking ABI and build an appropriate adapter |
| 15.2+ | Experimental | Native interface and system scan verified; association in progress |
| 15.0–15.1 | Planned | Separate ABI validation; current adapter rejects these kernels |
| 26 | Planned | Distinct Tahoe adapter, kernel guards and hardware validation |

Keep PCI/firmware/DMA/WMI/HTT, regulatory policy and security logic in a shared
radio core. Confine private OS declarations, vtables, wire layouts and events to
versioned adapters. Select mutually exclusive builds with OpenCore MinKernel and
MaxKernel; each build also validates the kernel ABI before opening PCI. Multiple
kexts may eventually ship in one package; this does not promise one universal
binary or automatic compatibility with an untested macOS update.

First complete Sequoia association, WPA2 keys and traffic. Next implement Tahoe,
then work backward through the older systems. Gate support on cold boot,
scan/association, DHCP/data transfer, disconnect, sleep/wake and update tests on
each target. WPA3/SAE/PMF and AWDL remain separate unimplemented features. Never
claim certification based only on host tests or successful compilation.

Do not install OCLP root patches, replace system networking families, remove
version guards or spoof dependency versions to claim compatibility.

## WPA3 requirement

WPA3-Personal is an explicit support target, not implemented by the current
PSK-SHA256 work. Implement and test SAE, required PMF/BIP, IGTK/IPN replay
protection, protected deauthentication/disassociation and SA Query together.
Test SAE-only and transition networks, anti-clogging/retransmission paths,
wrong-password and downgrade resistance with independent fixtures and hardware.
Until complete, reject SAE/required PMF explicitly; do not advertise WPA3 support
or silently convert an explicitly requested WPA3 connection to WPA2.

## AWDL and AirDrop requirement

AWDL and AirDrop are explicit planned features, not provided by the current
infrastructure adapter. After stable AP association/data and security, implement
AWDL peer discovery/action frames, synchronization and channel scheduling,
AP/AWDL coexistence, a versioned native virtual interface and IPv6 data path.
Validate regulatory limits and sleep/wake behavior. AirDrop then requires working
Bluetooth discovery plus AWDL, bidirectional transfer, peer interoperability and
continued AP traffic. Do not infer AirDrop support from a working Wi-Fi menu.
