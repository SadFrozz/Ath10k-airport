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
| Enterprise reauthentication/roaming | Different MSK rejected; no supported reauthentication/handoff | Separate owner/OS contracts and implementation |
| Sleep/wake | Lifecycle implemented; possibly working | Platform sleep deferred by user |
| macOS 11–14, 15.0–15.1, 26 | Separate adapters unfinished | ABI recovery, implementation and per-OS verification |
| AWDL/AirDrop | Not implemented | Separate protocol/interface/channel integration stage |

## Active local batch

Uncontrolled EAP port lifecycle: start the output queue while ordinary data stays
blocked; close the EAP-only queue even when BSD carrier was already down; reject
expired/retired receive and transmit traffic before asynchronous cleanup.
The shared runtime timer requests native service each successful tick; timer
interval is at most 100 ms during runtime power idle. WCL contention can delay
processing, so ingress checks independently enforce the owner deadline.

The current source includes queue lifetime, initial empty-key reset and explicit
callback-driven timeout cleanup. Affected fixtures passed ASan/UBSan. The final
consolidated 68-test regression passed with ASan/UBSan. Native build and symbol validation passed at
1.0.106, UUID 9CB4F564-2283-3261-A46A-3A27CBC19C87. An isolated validation copy
passed strict ad-hoc signature verification and offline dependency linking; its
exact UUID was verified in the generated collection. The source bundle remains
unsigned and uninstalled. The earlier premature 1.0.107 image is superseded.

Enterprise remains off. The zero-BSSID key callback carries no transaction token;
internal generations do not establish isolation from old OS callbacks. Installed
user-mode startup ordering is recovered; real Enterprise delivery and other
startup modes remain unverified. No publication or build-number advancement yet.

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
