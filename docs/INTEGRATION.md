# Integrating laptop features

The host agent writes `%LOCALAPPDATA%\ZorinTrust\session.json` while at least one mutually authenticated owner phone session is alive and removes it when the last session disappears.

For immediate actions, use local administrator-configured hooks:

```powershell
zorin-host-agent.exe daemon `
  --on-trust "powershell -ExecutionPolicy Bypass -File C:\Zorin\on-trust.ps1" `
  --on-untrust "powershell -ExecutionPolicy Bypass -File C:\Zorin\on-untrust.ps1"
```

The phone never supplies hook command text. This separation is intentional: the USB protocol proves identity/presence; local host policy decides what that presence unlocks.

Do not make the mere existence of a USB device or ADB serial your authorization signal. Gate sensitive features on the authenticated session produced by the agent.


`session.json` persists while the paired device remains cryptographically connected, including while its screen is locked. Inspect `user_present` when displaying state. Do not use `session.json` alone for sensitive authorization. `owner-mode.json` is the convenience presence file and is removed whenever all trusted phones are locked. For security-sensitive actions prefer the local `authorize`/`gate` API, which obtains a signed proof from an unlocked phone.
