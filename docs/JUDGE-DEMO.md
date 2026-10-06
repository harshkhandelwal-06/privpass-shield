# Judge demo

1. Open Password Shield and paste `aaaasfiefifosdnofsdfn`.
2. Show that long length is not enough: repeated structure and weak guessability lower the resilience assessment.
3. Click the common-password demo and show the HIBP range privacy receipt.
4. Generate a secure passphrase with WebCrypto.
5. Open SecretGuard and upload `data/demo-repo/sample.env` or the demo ZIP.
6. Show CRITICAL secret findings with confidence and line numbers.
7. Move one finding through DETECTED -> TRIAGED -> CONTAINED -> ROTATED -> VERIFIED.
8. Open Exposure Graph to show the repository owner/domain correlated with the password posture.
9. Open Command Center and export the evidence report.
10. Finish on the Privacy Proof view: exact data that leaves the browser and exact data that never leaves it.


## SecretGuard developer workflow

For the CI/pre-commit portion of the demo, use the same detection engine outside the website:

```text
INSTALL-SECRETGUARD-HOOK.bat
  → stages a fake AWS key
  → git commit
  → commit is blocked

python tools/secret_scan.py . --fail-on high --min-confidence 0.80
  → repository gate

.github/workflows/secretguard.yml
  → push / pull_request
  → SARIF + JSON
  → GitHub Code Scanning
  → HIGH/CRITICAL gate
```

`RUN-SECRETGUARD-DEMO.bat` runs the bundled synthetic repository and treats the expected blocking exit as a successful demo.
