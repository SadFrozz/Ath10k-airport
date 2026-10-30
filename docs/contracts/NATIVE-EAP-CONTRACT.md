# Native macOS EAP integration contract

Status: local experimental integration, disabled by default and not hardware verified. This is separate from implemented
WPA3-Personal SAE/PMF and from the local PTK-notification timeout correction.

## One implementation and validation group

| Boundary | Required behavior | Current source evidence |
| --- | --- | --- |
| Native join | Admit only explicitly supported enterprise auth, with no password/PSK reinterpretation or mixed-AKM downgrade | Opt-in ordinary WPA2-Enterprise AKM1; mixed, FT, SHA256 enterprise and supplied key material rejected |
| Association RSN | Select the requested enterprise suite consistently in AP validation, association and M2 | AKM1/CCMP supported consistently; PMF-required enterprise remains unsupported |
| EAP owner | System eapolclient owns EAP, driver owns the four-way handshake and PMF | Existing source/disassembly audit establishes MSK handoff architecture |
| Uncontrolled port RX | Route EAP to macOS before controlled-port authorization; preserve peer, bounds and one packet owner | Current-owner EAP routes to the system; internal-key queue remains separate, including preflight |
| Uncontrolled port TX | Admit only valid current-peer EAP while ordinary traffic remains blocked; bound ownership and drain | Bounded current-owner EAP bypass before normal controlled-port admission |
| EAPOL-Key RX | Retain internal handling and separate it from general EAP transport | Existing internal supplicant is operational for personal profiles |
| MSK callback | Validate the actual kernel-translated request, profile, station, peer and generation; wipe rejected/retired copies | MSK-only callback accepts translated 32-byte current-owner key; personal profiles and preauthentication rejected |
| Key derivation | Support only validated enterprise AKM derivation/MIC/RSN rules; do not relabel PSK vectors as enterprise proof | Ordinary AKM1 four-way integrated with one-shot PMK consumption; unsupported enterprise variants rejected |
| Ordering | Publish association/BSS events needed by the OS EAP client before controlled-port completion; no premature ordinary traffic | Existing notifications publish association before port authorization and gate final success on authorization |
| Completion | Preserve stock initial key-done path and separate rekey event; avoid duplicate property-change messages | Recovered Up=2 path reaches handleKeyDone; pairwise update uses ID76/reason0xe0822c15 |
| Cancellation | Forget, leave, radio-off, roam, timeout and stop retire packet/key work and reject late MSK callbacks | Existing personal lifecycle must remain intact |
| Evidence | Test admission through EAP routing, MSK acceptance, internal handshake, firmware barriers and cancellation together | Enterprise radio interoperability needs separate EAP infrastructure |

## ABI constraints

Included ABI headers name upper-auth bits 2 and 11 as WPA2 and SHA256-8021X,
respectively, and bits 14/15 as WPA3 enterprise/FT enterprise. These names alone
do not establish interoperability or authorize enabling the profiles.
The recovered local IO80211Family path clamps MSK/PMK callback key material to
32 bytes for ordinary auth or 48 bytes for auth 0x4000/0x8000; auth 0x80 selects
a different source portion. Do not accept all these variants through one
32-byte PMK branch. FT, Suite-B/192-bit, preauthentication and PMKSA cache
operations need their own validated contracts, not success placeholders.

## Acceptance

Implement the complete admitted EAP profile before advertising it. Tests must
exercise real production dispatch/routing and ownership, including malformed
lengths, EAP versus EAPOL-Key discrimination, stale peer/generation, duplicate
MSK, clear-key operations, queue pressure, timeout, reset and completion retry.
The full development test entry point remains the single regression gate for
previously implemented behavior. Hardware evidence for SAE does not establish
enterprise support; one available personal router cannot prove it.

## Local experimental admission

`Ath10kNativeEAPExperimental=true` is an explicit property gate, absent by
default. It additionally checks the examined 24G90 kernel. Ordinary upper-auth
bit 2, lower-auth 1 and an empty cipher-0/key envelope are the currently admitted
subset; acceptance of that envelope is locally tested, not an observed enterprise
request from the installed OS. No password is retained by the driver.

EAP owner waits at most 30 seconds from admission for MSK. The normal 15-second
four-way timer starts on successful PMK consumption; the existing overall native
join deadline still bounds the complete join. No extension or perpetual retry is
introduced. Enterprise host roaming and reauthentication remain to be integrated;
a second different MSK currently returns Busy, rather than replacing live keys.

Production admission, native key callback, PMK binding, M1–M4 exports and M4
completion have a combined sanitized fixture. Firmware key acknowledgements are
emulated, and it checks authorization intent rather than actual radio port opening.
Failure completion and clear-key cancel without authorizing.

Still required: actual IO80211 pre-link delivery/startup evidence, timeout scheduling,
and enterprise reauthentication/roaming. The 68-test sanitized suite and offline
dependencies passed. Local validation is not
enterprise interoperability or supported macOS 11–26 coverage.

The zero-BSSID MSK callback carries no association transaction token. Checking
current internal generation prevents reuse of our retired owner but cannot prove
that a delayed OS callback originated in the current association. Cross-association
serialization must be established before claiming stale-OS-key isolation.
