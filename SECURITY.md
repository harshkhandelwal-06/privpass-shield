# Security Notes

- Raw user passwords are not persisted by PrivPass Shield.
- The HIBP flow uses only a five-character SHA-1 range prefix for breach lookup and compares the returned suffix locally.
- Password strength scores are heuristic guessability estimates, not proofs of entropy.
- Generated secrets use Web Crypto and rejection sampling for unbiased character selection.
- Repository scans do not execute uploaded code.
- Raw repository secrets are not stored; only redacted previews and keyed fingerprints are retained.
- Demo credentials and demo endpoints are intended for local development and judging only.
- Production deployments must provide a stable secret, PostgreSQL, Redis, HTTPS and a proper email/reset delivery path.
- A custom client-derived verifier flow is not a replacement for audited WebAuthn/OPAQUE deployments.


## Vault privacy boundary

Vault records are encrypted client-side with AES-GCM-256. The server stores an opaque ciphertext string, version and timestamps. The browser derives the vault key from the master password with PBKDF2-HMAC-SHA-256 (600,000 iterations in this demo build).

No admin API can decrypt or enumerate vault contents. The admin console may display the number of encrypted vault records attached to an account.
