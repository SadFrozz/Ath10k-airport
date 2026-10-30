# Implementation and verification map

Updated 2026-10-30 after user resumed development. Requirements are in
[Native contract](../contracts/NATIVE-CONTRACT.md), [WPA3 contract](../contracts/WPA3-CONTRACT.md)
and [EAP contract](../contracts/NATIVE-EAP-CONTRACT.md). Historical checkpoints are
preserved in [the previous map](../history/NATIVE-STATUS-through-1.0.106.md);
its dated candidate/install statements are historical, not current state.

## Installed checkpoint

Ath10kMac **1.0.110**, UUID **E39009FE-C6F8-385B-8B0C-B6DC48AED01A**,
functional source **add6acf41627edc4d7158a31db7bec597c752d08**. Boot verified on
CF493E4E-E6A4-406D-85DA-C5DDA4C4D505. Interface en1 has IPv4 and three IPv6
addresses; native SAE/PMF remains ready. 45/45 gateway probes returned, but TX NoAck
rose 0→12, mean RTT 99.094 ms and max 1012.305 ms. Disconnect/watchdog/replay/security
counters stayed zero. This is bounded connectivity evidence, not stability acceptance
or proof of individual address callback invocation. Latency/NoAck correlation is
under investigation; do not infer that the host-address change caused it.
Evidence: outputs/NATIVE-installed-1.0.110-runtime-20261030 (workspace and SD).
69 sanitized tests and offline candidate checks passed before installation.
Follow-up correlation interval: 120/120 replies, mean RTT 9.444 ms, one sample
above the descriptive 100 ms cutoff (595.887 ms, 0.83%); NoAck remained 12→12.
No scan generation/event change around that spike. This interval fits the user's
<=1% rare-spike allowance; no targeted latency fix justified by this sample.
Earlier startup interval remains recorded; prolonged stability is not certified.

## Current implementation

| Area | Implementation / evidence | Open requirements |
| --- | --- | --- |
| Native interface, scan, association, traffic | Implemented; hardware observed on 15.6.1/24G90 | Prolonged stability, earlier latency/NoAck |
| WPA3-Personal SAE | Implemented experimental gate; native traffic observed | Both password modes not fully certified |
| PMF | Implemented; protected SA Query round trip observed in earlier image | Group BIP and AP-driven rekey radio evidence |
| PTK/GTK/IGTK and completion | Implemented firmware barriers, receipt ownership and bounded macOS notification | AP-triggered updates on hardware |
| Host-requested roaming | Integrated and covered by production-path fixtures | Physical inter-AP test unavailable with one router |
| Autonomous roam cache/offload | Enable/nonempty requests rejected | Implementation remains |
| Ordinary WPA2-Enterprise | Default-disabled AKM1/CCMP, EAP transport/MSK/four-way integrated in 1.0.106 | System startup/pre-link delivery, late MSK serialization and radio evidence |
| Enterprise reauthentication/roaming | Same-association replacement published in 45335d8; sanitized regression and native/offline build passed; Enterprise roaming unimplemented | OS provenance, roam session handoff and radio evidence |
| Sleep/wake | Lifecycle implemented; possibly working | Platform sleep deferred by user |
| macOS 11–14, 15.0–15.1, 26 | Separate adapters unfinished | ABI recovery, implementation and per-OS verification |
| AWDL/AirDrop | Not implemented | Separate protocol/interface/channel integration stage |

## Published and local checkpoints

Uncontrolled EAP port lifecycle was published as
862ed1f0bba3df83732eb68860ad95edcd72ce69. Its 68-test sanitized regression and
exact-UUID offline linking are saved under NATIVE-eap-port-lifecycle-20261030.
Only after publication was source version advanced to 1.0.107. Version 1.0.107 metadata was included in 45335d8. After that publication was
verified, source metadata advanced to 1.0.108; that next metadata/changelog edit
remains local.

Published batch 45335d8 adds same-association Enterprise reauthentication: bounded
restart, retained queue and old transport ownership, deferred PMK replacement
without wiping established key/replay history, early key-frame admission, and
completion after firmware/M4/macOS notification barriers. Restart during an existing
pair/group key installation preserves that operation's port policy. Affected
sanitized fixtures passed; final full 68-test regression passed with ASan/UBSan, native build and offline inclusion passed.
Evidence: outputs/NATIVE-eap-reauth-contract-20261030. No new image installed.

Enterprise remains off. Static installed user-mode startup ordering is recovered;
actual Enterprise delivery and other startup modes remain unverified. A tokenless
MSK callback cannot prove EAP session provenance. Wrong PMK cannot pass the tested
M3 authentication boundary, but stale requests can still affect availability.

## Evidence and work policy

Use the consolidated suite once after final batch changes. Do not repeat accepted
manual scan/boot/Personal traffic checks without a changed affected path or new
failure. Keep intermediate edits local and publish a reviewed batch. Pending
OpenCore/APST changes and platform sleep are outside this driver batch; do not
infer their runtime state from the historical pre-reboot checkpoint.

The installed user-mode client starts before radio association, as recovered from
exact-UUID airportd/CoreWLAN. Initial empty MSK reset preserves the current empty
owner and original deadline. Expiry in a key callback explicitly cancels; service
retires orphaned EAP queue ownership without stopping authorized data. See the
EAP contract and audit for precise evidence and unresolved boundaries.

## Published roam ownership batch

Published admission/teardown guards retain pending PTK notification, EAP TX/queue and
replacement-authentication owners. Dispatcher waits allow the old link's key
completion to progress instead of returning before its producer. Added fixtures
cover residual EAP owners and notification retry ordering. The full 68-test regression passed with ASan/UBSan; native compilation, strict
isolated signature and exact-UUID offline inclusion passed. Candidate UUID
CB30D84D-5AAB-3595-AFD4-F259BD9CB5AA, source version 1.0.108. Published as a88bbed after exact remote-tree verification.
Only after that publication, local metadata advanced to 1.0.109. The metadata-only 1.0.109 candidate was subsequently rebuilt, validated, installed
and boot-verified; its metadata update is not yet published. Enterprise
roam admission is still unsupported until the OS session handoff is implemented.

## Published address-notification group

Four host notifications now reach the stock interface cache: IPV4_PARAMS,
IPV6_PARAMS, legacy OFFLOAD_ARP and OFFLOAD_NDP. These are synchronous gated
copies, not firmware-offload activation. Invalid counts fail before mutation;
unused bytes are zeroed; empty IPv6 lists clear the cached list. Legacy ARP
preserves the old local IPv4 when its replacement word is zero and always updates
gateway/MAC. Explicit replacement with zero clears the gateway as stock does.
No separate retained pointer or asynchronous address owner is introduced, and
radio roam does not clear OS-owned L3 state. Existing stop/power/MAC admission
applies to all four requests. The added getter bridge preserves upstream headers.

Focused production dispatch and request admission checks passed; final expanded
69-test regression passed with ASan/UBSan. The current native build, strict
isolated signature and exact-UUID offline inclusion passed, including the getter
bridge (UUID F1A75ABE-5C9E-3570-9DF7-0C62A3422E9C). DHCP sleep hint, conditional traffic
engineering and radio ARP/NS offload remain unfinished; no capability advertised.
Published as add6acf41627edc4d7158a31db7bec597c752d08 after exact remote-tree
verification. Only then metadata advanced locally to 1.0.110; metadata is not yet
published. Installed image is now boot-verified 1.0.110.

Hardware candidate 1.0.110 is ready, UUID E39009FE-C6F8-385B-8B0C-B6DC48AED01A.
The metadata-only rebuild passed strict signature and exact-UUID offline inclusion;
current EFI 1.0.109/config and new candidate copies were hash-verified on SD.
Installation/reboot explicitly authorized and executed; loaded UUID verified.
Evidence: outputs/NATIVE-1.0.110-hardware-candidate-20261030/READY.json.

## Local traffic-policy package (unpublished)

Host mbuf traffic class now survives admission and HTT descriptor generation; AP ACM downgrade remains enforced. Native host Fastlane marking is applied synchronously within WCL after releasing radio, protected by the existing termination fence; link-down clears it. Enabled ACM override remains unsupported. All 71 tests passed with ASan/UBSan. Native build, strict isolated signature and exact-UUID offline inclusion passed (9A28E4F5-FD99-3724-9599-3B470EFC47AE). Hardware verification remains pending. This code is not in the installed 1.0.110 UUID listed above. Congestion-monitor and battery-policy integration remain open.
