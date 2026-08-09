# Changelog

## 0.1.1

- Add `--serial` / `-serial` daemon option used by the Windows owner-pairing launcher.
- Limit ADB reverse/wake handling to the selected device during one-time pairing.
- Fix Windows quick-start pairing failing with `flag provided but not defined: -serial`.

## 0.1.0

- Persistent EC P-256 host identity.
- ZTRUST/1 mutual nonce/signature authentication.
- Explicit `--pair-once` enrollment and optional ADB serial filter.
- ADB USB watcher, reverse tunnel and Android NativeActivity wake-up.
- Live trusted-session state with disconnect revocation.
- Optional local `--on-trust` / `--on-untrust` hooks.
- Windows/Linux amd64 and arm64 builds with no runtime dependencies besides ADB for stock-phone transport.

## 0.1.2
- Fix Windows autostart registration by using the ScheduledTasks PowerShell API rather than `schtasks.exe /TR` quote construction.
- Verify the registered task before reporting success.
- Show autostart state/action in `status.ps1`.
