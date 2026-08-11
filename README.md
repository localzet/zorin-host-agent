# Zorin Host Agent

Mutual-authentication workstation runtime for Zorin Trust. The Host Agent owns the local `ZTRUST/2` device session, `ZOWNER/1` proof requests, host identity, policy evaluation and the authenticated localhost control API.

## 0.10 — transport-independent trust

`ZTRUST/2` no longer assumes that the authenticated TCP stream arrived through ADB. The normal workstation mode still uses `adb reverse`, while the new `portable` mode exposes the same protocol on a private LAN with a memory-only host identity.

Portable mode deliberately leaves no persistent workstation identity behind:

```text
zorin-host-agent portable --proof-out owner-proof.json
```

The temporary HTTP bootstrap page is reachable only through a random tokenized path and emits an expiring `zorintrust://connect` deep link carrying the same 128-bit invitation for the Android Runtime. The phone must still verify and approve the ephemeral host fingerprint. A portable host is not added to the phone's persistent trusted-host registry.

When `--proof-out` is supplied, the agent requests one additional explicit approval and writes a short-lived `ZOWNER/1` proof for `portable.session / host:<fingerprint>`. The proof is a capability, not a new private key; its current default lifetime is 60 seconds.

See [`docs/PORTABLE.md`](docs/PORTABLE.md) and [`docs/PROTOCOL.md`](docs/PROTOCOL.md).

## OS integration

Policy controls approval strength. A caller may ask for a stricter explicit approval, but it cannot weaken an action that the matched rule marks as `require_explicit`.

Current OS-integration scopes include:

- `os.pam.authenticate` — explicit phone approval for PAM authentication;
- `os.sudo.authorize` — explicit phone approval for sudo;
- `os.windows.sensitive` — explicit approval for native Windows Trust Center sensitive actions.

Existing ZSSH/1, Authority, Ops and owner-presence flows remain compatible.
