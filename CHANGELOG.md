# Changelog

## 0.2.2
- Keep cryptographic device trust alive while Android is locked.
- Track `user_present` independently from device trust.
- Remove `owner-mode.json` while the paired phone is locked, without dropping `session.json`.
- Reject signed owner-proof authorization immediately while the phone is locked.
- Accept `POLL LOCKED` / `POLL UNLOCKED` heartbeat states.


## 0.2.1

- Use a headless Android bootstrap for normal trusted-host reconnects; pairing remains visible.
- Re-kick the phone runtime after trust loss while ADB remains attached, covering OEM process eviction/task removal.
- Target the stable `dev.zorin.trustruntime` phone package.

## 0.2.0
- ZTRUST/2 protocol and bounded ZOWNER/1 phone-signed owner proofs.
- Deny-by-default local policy engine and authenticated local control API.
- `authorize`, `credential`, `gate`, `policy` and `identity` commands.
- Ephemeral `owner-mode.json` for hidden/private workstation features.
- Windows CNG/TPM identity backend with explicit migration for existing users.
- Idempotent Windows lifecycle scripts and Task Scheduler result decoding.

## 0.1.3
- Idempotent pairing/install lifecycle fixes.
