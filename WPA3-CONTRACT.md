# WPA3-Personal / PMF requirements

This is the target security contract. Implementation and verification states are
tracked in [NATIVE-STATUS.md](NATIVE-STATUS.md); prior research and intermediate
states are retained in [the history](docs/history/WPA3-CONTRACT.md).
PMF is already implemented; remaining hardware evidence must not be described
as missing implementation.

| Requirement | Required behavior / acceptance |
| --- | --- |
| Native admission | macOS credentials, requested AKM, RSNE/RSNXE and PMF policy must remain bound to the selected association; reject unsupported profiles without downgrade |
| SAE | Validate P-256 provider ABI/lifetime, independent crypto vectors, H2E/legacy selection, commit/confirm, retries and cancellation; never perform expensive crypto under networking gates |
| Four-way handshake | Bind PMK/PTK and replay state to current peer/association; authenticate messages before accepting keys or transition-disable policy; wipe secrets on retirement |
| PMF keys | Bind pairwise and IGTK epochs to the active session; install/acknowledge keys before authorizing the controlled port; reject stale completion |
| Protected management | Protect/verify unicast robust management and BIP-CMAC group management; validate PN/IPN, address, key identity and frame layout; reject replay and malformed frames |
| SA Query | Bound requests/retries/deadlines; validate protected responses; queue ownership and transport submission do not prove RF acknowledgement |
| Rekey | Handle PTK, GTK and IGTK-only updates, duplicate messages and cancellation; prevent key reinstallation/replay rollback; drain old packet owners before changing epoch |
| Recovery | Cancel crypto, replies and protected TX on leave/radio-off/retirement; old generations cannot change a new association |
| Capabilities | Advertise only implemented, admitted modes. Additional groups/ciphers, SAE-PK, FT-SAE, enterprise/external-key ownership need separate implementation and evidence |
| Hardware evidence | Ordinary SAE traffic, protected SA Query, group BIP, AP-triggered PTK/GTK/IGTK updates and prolonged stability are distinct checks |

The implemented experimental scope is Group 19/P-256, CCMP-128 and BIP-CMAC-128
on the validated Sequoia ABI. Default builds keep SAE disabled. A passing local
regression closes its tested code paths, not every security mode or RF scenario.
Use the consolidated development suite for implemented behavior; do not restart
PMF implementation or repeat closed manual tests merely because a radio test is
still pending.

## External key-owner integration requirement

Treat macOS key requests as discriminated operations (data keys, PMK/MSK,
PMKSA and password), not as interchangeable PTK/GTK buffers. Validate each
layout/length/profile and bind accepted work to the current interface, peer
and association generation. Select a single internal or external handshake
owner; an external request must not overwrite an active internal exchange.
Separate accepted submission from firmware acknowledgement and controlled-port
authorization. Recover password/PMKSA and completion semantics before enabling
those paths; do not advertise enterprise authentication from key parsing alone.

External OS-owned EAPOL requires a separately validated receive/transmit path
while ordinary data remains blocked. Do not reuse the internal four-frame,
512-byte EAPOL-Key queue as a general EAP transport. Select one packet owner
and validate its bounds, peer identity, lifetime and cancellation. Do not use
SAP-only STA_AUTHORIZE as infrastructure-client authorization; trace the
actual WCL/OS client path and its failure semantics.

For enterprise integration distinguish the EAP authentication owner from the
four-way handshake owner. The system EAP client can supply MSK while the driver
retains its existing four-way/PMF implementation. Do not require external
PTK/GTK ownership merely because EAP runs in macOS. Validate MSK handoff, EAP
versus EAPOL-Key routing and the OS completion notification as one contract.

Validate credential sizes at the driver's actual callback boundary, after
IO80211Family auth-dependent MSK translation; the userspace 64-byte MSK
length is not the native callback contract. Reuse the stock interface's
key-done notification route after the authenticated port barrier. Distinguish
initial link completion from rekey completion and avoid duplicate notifications.

## Pairwise-update completion barrier

A successful pairwise update must report the stock Sequoia supplicant event
(ID 76, 40-byte payload, status `0xe0820406`, reason `0xe0822c15`) after both
the authenticated key/port barrier and matching M4 transport completion.
Initial association, group-only updates and retransmitted M3/M4 must not create
a new pairwise-update notification. Preserve the active transition-disable
policy when composing the event. Transport completion is not a separate RF-ACK
claim.

Capture the result at serial DMA retirement, before another management packet
can reuse the slot. Shared latest-TX fields are not a completion ticket. Bind
the captured result to its reply and association lifetime; process failure for
all native EAPOL replies, including phase-5 rekey replies. Failed enqueue retains
the same notification; successful enqueue consumes it once. Leave, radio-off,
roaming retirement and stop invalidate the old owner and pending completion.
