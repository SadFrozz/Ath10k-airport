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
