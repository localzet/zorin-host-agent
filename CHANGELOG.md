## 0.3.3

- Persist an absolute ADB executable path for Scheduled Task startup.
- Add daemon-health diagnostics and `doctor`.
- Report ADB device/reverse/bootstrap failures instead of silently ignoring them.
- Pair with Runtime 5.0.3, whose TrustService is isolated from the UI process.

## 0.3.2

- Persist the absolute adb executable path instead of relying on Scheduled Task PATH.
- Add daemon-health.json with ADB device/reverse/service bootstrap health.
- Add `doctor` diagnostics for ADB reverse and Android TrustService presence.
- Decode Task Scheduler 0x00041306 in Windows status output.

## 0.3.1
- Headless reconnect remains service-only; the Activity is never started outside explicit pairing.
- Increase failed headless bootstrap retry interval to 30s to prevent process-crash thrash.
- Runtime 5.0.1 fixes the ART `VerifyError` that caused the v0.3 bootstrap loop.

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

## 0.3.0
- Bootstrap `dev.zorin.trustruntime.TrustService` directly for known-host reconnects; normal owner USB reconnects no longer wake `NativeActivity`.
- Trigger the stock red Trust Visual pulse only after a successful mutual `ZTRUST/2` session is established.
- Skip automatic pulse when more than one ADB device is present and no explicit `--serial` is configured.
- Windows lifecycle/status scripts now identify the daemon by its trust listener port instead of relying on an executable/process name.
