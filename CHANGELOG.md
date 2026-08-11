# Changelog

## 0.8.0

- Added deny-by-default policy migration for phone-approved `ZSSH/1` OpenSSH certificate issuance.
- Added explicit phone-approved policy scopes for Zorin Node installation and SSH CA enrollment.
- Added SSH certificate policy documentation; direct legacy `credential.ssh` remains denied.

## 0.7.0
- Suite version alignment for Zorin Trust 0.7.
- Preserves the ZTRUST/2 owner-presence and explicit-approval policy surface used by Zorin Ops 0.2.
- No signer migration and no phone re-pair are required when upgrading from the owner-managed signer line.

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

## 0.3.0
- Bootstrap `dev.zorin.trustruntime.TrustService` directly for known-host reconnects; normal owner USB reconnects no longer wake `NativeActivity`.
- Trigger the stock red Trust Visual pulse only after a successful mutual `ZTRUST/2` session is established.
- Skip automatic pulse when more than one ADB device is present and no explicit `--serial` is configured.
- Windows lifecycle/status scripts now identify the daemon by its trust listener port instead of relying on an executable/process name.
