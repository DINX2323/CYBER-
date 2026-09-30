# CanaryGraph — working local prototype

A cybersecurity research lab combining instrumented synthetic files, a decoy credential service, ordered activity reconstruction, reproducible placement experiments, and signed incident evidence. This is a functioning lab prototype, not an endpoint protection product or a claim of unprecedented invention.

## Start on this computer

Double-click **START.cmd**. It starts a hidden local server and opens **http://127.0.0.1:4317** in your default browser. Double-click **STOP.cmd** to stop that server. Logs are in `server.log` and `server-error.log`. Evidence remains in `data/` after shutdown. The launcher uses installed Node.js or the bundled runtime already on this computer; it does not install anything. The launcher's PowerShell execution-policy option is scoped to that invocation and does not change your saved policy.

Alternatively, from this directory, run `node server.js` and visit the same URL. Press Ctrl+C to stop. Requires Node.js 20+; no third-party packages, paid APIs, or internet connection are required. Set `PORT` or `CANARYGRAPH_DATA` when running `server.js` directly to use a different local port or data directory. The Windows launcher uses the default port and directory.

## Five-minute demonstration

1. On **Incident overview**, click **Run intrusion demo**. This really reads synthetic files and invokes the same instrumented service operations as the manual lab. Four events appear, with three decoy alerts and one ordered bait/login/vault chain. Events are explicitly labelled `scripted-intrusion`.
2. Open **Interactive lab** and click **Run ordinary activity**. Three ordinary reads appear in a separate `scripted-benign` session with no decoy alerts.
3. Return to the lab. Read **Service-credentials.txt** and paste its `CG-DECOY-ONLY-7F3A` token into the local service. Click **Try decoy login**, then **Read vault document**. These events are marked `manual`. The token has no use outside this local lab.
4. Open **Placement experiment** and click **Run comparison**. Change the seed to explore repeatable synthetic results. This never changes your actual lab documents.
5. Open **Evidence integrity**, click **Verify live ledger**, then **Run tamper checks**. The original passes; an edited copy and a truncated copy fail. Your stored ledger is not altered. Export evidence with the download button.

The graph connects observed event order within a lab-issued session. It does not infer process lineage, causality, or attacker identity. File reads outside this application's instrumented actions are not observed. Browser refresh creates a new manual session; earlier events remain available. Manual sessions expire after 24 hours or a server restart.

## Evidence design and verification

Each event has a sequence number, timestamp, preceding record hash, and SHA-256 hash of its canonical JSON content. An Ed25519 signature authenticates the checkpoint's count, head hash, and creation time. The live ledger is checked against its checkpoint before each append and export. Exports contain events, a public key, and a signed checkpoint, but never the private signing key.

Save the **Trust anchor** fingerprint separately from the export, using a channel or location you trust. Then run:

```text
node verify.js canarygraph-evidence.json YOUR_SEPARATELY_SAVED_FINGERPRINT
```

Exit status is 0 for valid evidence, 1 for invalid evidence, and 2 for missing command arguments. The fingerprint is SHA-256 of the base64-encoded SPKI DER public key, as implemented in `lib.js`.

This detects edits, reordering, added/deleted events, or substituted public keys relative to a trusted signed checkpoint. It does **not** establish that original events were true. An older complete signed export is still cryptographically valid; preserve the latest count/head or a separate latest checkpoint to detect rollback. The key is stored locally under `data/keys/`, so this prototype cannot withstand a local administrator or another process with access to the signing key. POSIX private-file mode is requested; on Windows protection follows the parent directory's ACLs. This is not hardware-backed signing or forensic-grade storage.

Append and checkpoint replacement are separate filesystem operations. A crash or power loss between them can leave a mismatch. The application fails closed instead of silently repairing or re-signing unverified records. Preserve the store for inspection and use a new `CANARYGRAPH_DATA` directory if you need a fresh lab. Do not delete the ledger to recover a running research experiment.

## Experiment methodology

Six candidate locations, a two-decoy budget, 120 training routes and 240 held-out routes. Each split is balanced between intrusion and ordinary activity. All 15 placements are evaluated on training data; the selected pair maximizes detection rate minus false-positive rate, with deterministic tie-breaking. Evaluation compares that frozen pair, one seeded random pair, and a fixed finance/backup pair on identical held-out routes. Training and held-out generators have different seeds but use the same route templates/distribution.

Detection rate uses all intrusion routes as denominator. False-positive rate uses ordinary routes. Mean steps to detection excludes missed intrusions. The placement experiment's simplified “touching a location triggers a decoy” model is separate from the live lab's event-severity rules. Results are generated, not hard-coded, and are not a real-world efficacy claim. Add multiple seed trials, confidence intervals, additional workloads and distribution shifts before drawing research conclusions.

## Tests

```text
node --test test/*.test.js
```

Tests cover actual file reads, isolated sessions, valid/invalid credential use, ordered correlation, replay determinism, evidence edits/deletions/key substitution, restart and corruption handling, offline verifier exit codes, HTTP flows, and loopback host/origin/CSRF checks. Test stores use temporary directories and do not modify the demonstration ledger.

## Boundaries

- Server binds only to `127.0.0.1`; no network-wide scanning, exploitation, malware, or real credential collection.
- Strict host/origin validation, a per-start CSRF token, body-size limit, no CORS access, and a restrictive content policy protect the local web interface. This is not authentication against other local programs. Do not expose it through a proxy or public tunnel.
- Instrumented resources are allow-listed. All built-in files are synthetic. Submitted service tokens are not stored in events. If you edit the files yourself, their contents become visible in the local preview.
- Evidence is append-only by application convention, not by filesystem permissions. The full ledger is read for each action; this deliberately small prototype is intended for hundreds or a few thousand events, not production-scale traffic.
- No automatic monitoring of personal folders, email, browsers, or other programs. No telemetry or external fonts/scripts.

## Project structure

`lib.js` implements the lab, ledger, verifier and experiment. `server.js` exposes loopback routes and serves `public/`. `verify.js` is the offline verifier. `test/` contains automated tests. `data/` is created on first start and contains synthetic assets, event records, checkpoint, and a private signing key. **Never publish `data/` or the private key**; they are excluded by `.gitignore`.

For a portfolio release, publish source and an exported evidence sample only after reviewing it, plus experiment methodology and a demonstration video. Describe it as a prototype that evaluates decoy placement and evidence integrity, not as malware detection or proof of real-world intrusion prevention.
