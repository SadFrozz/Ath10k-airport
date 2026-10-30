# Implementation and verification map

Updated 2026-10-30 after user resumed development. Requirements are in
[Native contract](../contracts/NATIVE-CONTRACT.md), [WPA3 contract](../contracts/WPA3-CONTRACT.md)
and [EAP contract](../contracts/NATIVE-EAP-CONTRACT.md). Historical checkpoints are
preserved in [the previous map](../history/NATIVE-STATUS-through-1.0.106.md);
its dated candidate/install statements are historical, not current state.

## Installed checkpoint

Ath10kMac **1.0.106**, UUID **316E8378-1379-35B5-BCC9-BB4B99D59C0E**,
source **826c310abf1c1e1888679a07bd9a22442e5b5e7b**. Enterprise remains disabled.
The loaded UUID was verified on boot 37571895-159B-4AF9-A20D-B1F2F1554098.
The latest requested installed-image check returned 45/45 en1-bound router replies,
mean 4.175 ms, maximum 38.304 ms. Disconnect/watchdog/security/replay counts stayed
zero; TX NoAck stayed 2→2. SAE/PMF remained ready. Evidence:
`outputs/NATIVE-installed-runtime-20261030-154050/result.json`, workspace and SD.
Earlier 1.0.106 observation had maximum 946.372 ms and 15 NoAck; later short
successful checks do not resolve that observation or prove prolonged stability.

The published source checkpoint passed 68 C++ tests and runner checks with explicit
ASan/UBSan, native build, signature and offline exact-UUID dependency inclusion.
Those results describe 826c310, not untested subsequent changes.

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

## Pending roam ownership batch

Local admission/teardown guards retain pending PTK notification, EAP TX/queue and
replacement-authentication owners. Dispatcher waits allow the old link's key
completion to progress instead of returning before its producer. Added fixtures
cover residual EAP owners and notification retry ordering. The full 68-test regression passed with ASan/UBSan; native compilation, strict
isolated signature and exact-UUID offline inclusion passed. Candidate UUID
CB30D84D-5AAB-3595-AFD4-F259BD9CB5AA, source version 1.0.108. These changes
are unpublished and not installed. Enterprise
roam admission is still unsupported until the OS session handoff is implemented.
