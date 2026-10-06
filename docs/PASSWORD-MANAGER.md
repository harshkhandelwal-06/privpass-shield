# PrivPass Shield 5.6 — Zero-Knowledge Password Manager

## Threat model
The vault is designed so the PrivPass application server, database administrator and normal admin console cannot recover saved vault passwords from stored records.

## Client-side protection
Each vault record is encrypted in the browser with AES-GCM-256. The encryption key is derived from the user's master password with PBKDF2-HMAC-SHA-256 (600,000 iterations in this demo build). The server receives only opaque ciphertext blobs.

Titles, usernames, passwords, notes, tags, favorites and rotation dates are inside the encrypted payload. The server stores only an item id, ciphertext, version and timestamps.

## Unlock protocol
The vault unlock flow uses a separate short-lived server challenge. The browser derives the same account verifier material locally, creates an HMAC proof, and sends only that proof to the server. The master password itself is never sent to the vault endpoints.

## Wrong-password behavior
A vault check marker is stored as ciphertext. During unlock, the browser decrypts the marker locally. A wrong master password fails the integrity check without revealing any vault content.

## Forgot-password reset
A zero-knowledge vault cannot be re-encrypted after a password reset if the old master password is unavailable. PrivPass therefore clears the old encrypted vault during the forgot-password reset flow instead of introducing a server-side recovery key that could defeat the privacy model. Users should use the encrypted backup export for recovery planning.

## Operational features
- Local strength analysis for every saved password.
- Optional HIBP breach check for a saved password; only the first 5 SHA-1 characters leave the browser.
- Duplicate-password detection across saved entries is computed locally.
- Optional 30-day rotation reminders; this is a reminder, not a forced policy.
- Auto-lock after five minutes of inactivity.
- Encrypted vault backup export.
- Admins can manage user accounts but do not receive vault plaintext or decrypted vault metadata.

## Practical workflow

The vault is intended to behave like a useful personal password manager, not a static encrypted table:

1. Sign in and unlock once.
2. Search by site, username or tag.
3. Reveal/copy a password only in the browser.
4. See a live strength/resilience bar for each saved password.
5. Detect reuse across stored entries locally.
6. Check a saved password against HIBP with only a five-character SHA-1 prefix leaving the browser.
7. Rotate an entry with a locally generated CSPRNG secret.
8. Track optional 30-day rotation reminders.
9. Export/import ciphertext-only encrypted backups.
10. Auto-lock clears decrypted vault data from browser memory after five minutes of inactivity.

The monthly reminder is intentionally optional. It is a convenience feature, not a claim that routine password changes are required by NIST; current guidance does not recommend arbitrary periodic password changes without evidence of compromise.
