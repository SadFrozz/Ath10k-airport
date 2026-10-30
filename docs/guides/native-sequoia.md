# Native Sequoia adapter

The default build is the full native kext (`make NATIVE=1 DIAGNOSTIC_STAGE=0 kext`),
using stock macOS Wi-Fi control interfaces. No companion app is shipped.
A threaded radio/BSD workloop and distinct WCL workqueue have separate ownership
and synchronization; see [the current contract](../contracts/NATIVE-CONTRACT.md).

The early stage-3 workloop correction from main is preserved along with subsequent
PM, termination, queue and connection fixes. The optional `DIAGNOSTIC_STAGE=3`
controller-only build exits before opening PCI, loading firmware or starting DMA.
It must not be confused with the full driver or installed as a functional release.

Native scanning and WPA2 traffic have been observed. On macOS 15.6.1 build 24G90,
the opt-in experimental SAE build also auto-associated with AKM8 and mandatory
PMF; interface-bound ICMP and HTTPS traffic passed. This short hardware run does
not establish long-term stability. One protected unicast SA Query round trip
was subsequently observed with the explicit startup diagnostic; group BIP,
AP-driven rekey and sleep/wake still need hardware validation. AWDL/AirDrop
and other macOS ABI adapters remain incomplete. See [connection audit](../development/NATIVE-CONNECTION-AUDIT.md),
[compatibility](../compatibility/COMPATIBILITY.md) and [WPA3](../contracts/WPA3-CONTRACT.md).
