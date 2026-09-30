# Prototype validation — 30 September 2026

Environment: Windows, Node.js v24.19.0. No third-party runtime packages.

## Automated checks

`node --test test/*.test.js`: **8 passed, 0 failed**.

- Instrumented file reads, rejected and accepted synthetic logins, denied vault access, and ordered activity correlation.
- Separate ordinary and intrusion demo sessions with explicit provenance labels.
- Reading the actual filesystem asset rather than returning a canned preview.
- Evidence edit, rehash, deletion, reordering, checkpoint alteration, substituted signing key, and missing trusted-key rejection.
- Ledger restart, corruption detection, and incomplete-store failure.
- Offline verifier success/failure exit codes.
- Deterministic placement replay and held-out sample denominators.
- HTTP integration: working routes, JSON evidence download, invalid inputs, CSRF, host, and origin checks.

## Browser walkthrough

Verified the interface in the Codex in-app browser with keyboard activation:

1. Intrusion demo: 4 recorded operations, 3 decoy alerts, 1 complete chain.
2. Manual flow: opened the synthetic credential file, submitted its lab-only token, read the synthetic vault document.
3. Ordinary demo: 3 file reads with no alerts.
4. Resulting combined ledger: **10 events, 6 alerts, 2 complete chains**.
5. Seed-42 placement comparison generated three result cards. Training-selected placement was backup + vault: **104/120** intrusion routes detected and **26/120** ordinary routes alerted in this synthetic held-out set. These are simulation results, not real-world detection claims.
6. Live verification passed. Modified and truncated in-memory evidence copies were rejected.
7. Exported the 10-event sample and successfully verified it using the offline verifier and saved public-key fingerprint.

Browser mouse automation did not reliably activate controls in this session; keyboard activation was used for the walkthrough. No application JavaScript warnings or errors were reported by the browser log at the inspected point.

## Limitations

No system-wide file monitoring, production deployment, hardware-backed trust anchor, large-scale performance benchmark, cross-browser certification, or power-failure recovery was tested. See README.md for the evidence threat model and experiment assumptions.
