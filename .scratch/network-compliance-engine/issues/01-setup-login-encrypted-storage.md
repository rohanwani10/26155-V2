# 01: First-run setup, login, and encrypted local storage

**What to build:** A first-run setup flow where the admin creates a master password and is shown a one-time recovery key, plus a login flow gating the rest of the app. All app data (uploaded files, database records) is encrypted at rest with a key only derivable from the master password or the recovery key.

**Blocked by:** None (can start immediately)

**Status:** ready-for-agent

- [ ] On first run (no admin account exists yet), the app presents a setup screen requiring a master password.
- [ ] On successful setup, a one-time recovery key is generated and displayed exactly once; it is never stored in recoverable plaintext form.
- [ ] After setup, the app requires login (master password OR recovery key) before any other route is reachable.
- [ ] A data-encryption key is generated at setup and is only recoverable by unwrapping it with the password or the recovery key — never stored unencrypted.
- [ ] Data written to disk (uploaded files, database records containing device data) is encrypted using the unlocked data key.
- [ ] Wrong password/recovery key is rejected with a clear error and does not unlock anything.
- [ ] Losing both the password and the recovery key means the data is unrecoverable — this is a deliberate, documented tradeoff, not a bug.
- [ ] The app binds to localhost only.
