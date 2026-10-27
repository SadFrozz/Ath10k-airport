# Native connection audit (2026-10-28)

Hardware-confirmed: firmware starts, macOS creates en1 and shows scanned networks.
Association/data traffic are not yet confirmed. WCLJoinManager was observed aborting
on unsupported WCL_LOW_LATENCY_INFO before dispatching the association callback.

This revision answers that query with the actual zero session mask, applies scan
away-time settings, keeps a bounded 30-second candidate cache, and adds PSK-SHA256
(AKM 6, descriptor 3) without changing a requested AKM to PSK/SHA1. Required PMF,
SAE and enterprise authentication remain explicitly unsupported. MAC changes still
require future firmware-vdev reconfiguration; the driver refuses to claim an address
it is not transmitting with. Optional offloads are not falsely marked implemented.

Host tests cover native wire layouts, association RSN, cache freshness, regulatory
bounds, SHA1 legacy behavior and independent SHA256 four-way/rekey fixtures. SHA256
fixtures use hashlib plus cryptography; regenerating them requires
`tests/requirements-fixtures.txt`. The committed fixtures use only public test keys.
The macOS SHA256 test uses CommonCrypto, while the kernel uses corecrypto. Hardware
validation, DHCP and live traffic are still necessary.

KDF reference: https://w1.fi/hostapd/devel/sha256_8c_source.html
AES-CMAC reference: https://www.rfc-editor.org/rfc/rfc4493
Current adapter and private ABI: pinned upstream in vendor/itlwm/SOURCE.json.

WPA3-Personal (SAE plus mandatory PMF/BIP) is a required next development target.
PSK-SHA256 support must not be described as WPA3.

AWDL and AirDrop are explicit planned features; they require a separate AWDL
interface/data path and Bluetooth integration, not only AP connectivity.
