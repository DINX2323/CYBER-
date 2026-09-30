# Reproducible sample outputs

`sample-evidence.json` contains the 10 synthetic demo events recorded during the prototype walkthrough. It contains a public signing key but no private key. `sample-key-fingerprint.txt` is the matching fingerprint for demonstration. A fingerprint distributed beside an export is convenient for a sample, but is not an independent trust channel; for your own evidence, save and trust the fingerprint separately before verifying an export.

`placement-seed-42.json` contains the generated placement comparison, denominators, objective, and simulation limitations. Reproduce it in the app with seed 42.

The app creates its own signing key for a fresh `data/` directory. These sample outputs therefore need not match a fresh installation's fingerprint.
