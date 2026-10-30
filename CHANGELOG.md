# Changelog

## 1.0.105 — 2026-10-30

- Preserve EAPOL transport completion at serial DMA retirement so subsequent
  management transmissions cannot overwrite the result; handle failures during
  both initial authentication and rekey replies.
- Publish the native pairwise-key update event only after matching M4 completion
  and the key-installation barrier. Preserve security policy, retry rejected
  notifications, and invalidate retired association state.
- Exclude initial authentication, duplicate replies and group-only updates from
  pairwise-key update notifications.
- Implement host-requested reassociation with retained credentials, generation
  checks, asynchronous firmware retirement and native macOS event ordering.
- Preserve BSD carrier during a valid handoff and release it on failure.
- Strengthen scan, TX/RX, peer and key retirement before reconnecting, including
  cancellation after a security-policy change.
- Support empty roam-cache clear/disable requests; reject unsupported autonomous
  offload requests.
