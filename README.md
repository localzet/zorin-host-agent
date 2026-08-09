# Zorin Host Agent

Desktop-side owner-presence agent for **Zorin Trust Runtime**.

The agent has a persistent P-256 host identity, watches authorized ADB devices, installs an `adb reverse` tunnel, wakes the Android NativeActivity, and performs mutual challenge/response with the phone. The phone identity private key stays in Android Keystore and is never exported.

## Security model

- Pairing is explicit on both sides: start the host with `--pair-once`, then tap **APPROVE HOST** on the phone.
- After pairing, each USB session is authenticated using fresh 256-bit nonces and ECDSA signatures in both directions.
- An authenticated TCP connection is kept alive. Disconnecting USB tears the connection down and removes the trusted-session state.
- Optional local hooks run only on the owner workstation and only after mutual authentication.
- No server/SSH credential is sent to the host by this milestone.

> v0.1 stores the host identity as a mode-0600 EC private key in the OS config directory. A Windows CNG/TPM backend is on the roadmap; do not treat v0.1 host-key storage as equivalent to TPM-backed identity.

## Quick start

```powershell
.\zorin-host-agent-windows-amd64.exe daemon --pair-once
```

Keep it running, connect the authorized Android device via USB, and approve the displayed host fingerprint once on the phone.

After pairing, normal startup is simply:

```powershell
.\zorin-host-agent-windows-amd64.exe daemon
```

Optional owner-session hooks:

```powershell
.\zorin-host-agent-windows-amd64.exe daemon `
  --on-trust "powershell -File C:\\Zorin\\unlock.ps1" `
  --on-untrust "powershell -File C:\\Zorin\\lock.ps1"
```

`status` prints paired phone fingerprints and the active session file.
