# Password Shield model notes

PrivPass Shield reports a **conservative resilience/guessability estimate**, not exact entropy, for human-chosen passwords. The model intentionally gives independent weight to predictable identity, dictionary, numeric, date, repetition, keyboard and sequence evidence.

## Why length alone is not enough

- `divymathur` → very low: identity tokens + short length.
- `divy1934` → very low: identity + year.
- `3492847592039485720` → very low: numeric-only structure.
- `aaaasfiefifosdnofsdfn` → very low: repeated runs/substrings.
- `asfajfbjadbfiwebfiwefiewb` → low: repeated substrings/trigrams despite length.
- `river lantern copper orbit` → strong passphrase profile, but not exact entropy unless generated.
- `idsfiwefi38y238@dbf1412314@fhiw&dfihwif*jcowjf^^^iqhfiwhef7&` → strong mixed-class human-chosen secret; still not treated as cryptographic proof.
- Web-Crypto generated secrets receive a separate construction-entropy metric because their generation process is known.

## Account gate

The UI score is advisory. Signup/reset enforcement remains: password-only baseline 15+ characters plus successful HIBP verification; compromised passwords are rejected regardless of the UI score.
