# Zorin Host Agent

Desktop owner-presence, policy and credential-broker agent for **Zorin Trust Runtime**.

## v0.2 architecture

- Mutual `ZTRUST/2` P-256 challenge/response with the phone.
- Paired phone private key remains in Android Keystore.
- Windows host identity supports CNG/TPM (`Microsoft Platform Crypto Provider`). Fresh Windows installs prefer TPM; existing v0.1 PEM identities are preserved until an explicit migration so upgrades do not silently break pairing.
- Local deny-by-default `Principal/Action/Resource`-style policy in `policy.json`.
- Authenticated local control endpoint on `127.0.0.1:47473`; its random token is stored in the per-user state directory.
- `authorize` asks the connected/unlocked phone for a bounded, short-lived `ZOWNER/1` proof. The phone never signs arbitrary caller-supplied bytes.
- `gate` runs a **locally chosen** command only after policy + live phone proof succeeds.
- `owner-mode.json` exists only while an authenticated owner session is alive, so local applications can expose hidden/private features without trusting mere USB presence.

## Useful commands

```powershell
zorin-host-agent.exe status
zorin-host-agent.exe policy
zorin-host-agent.exe authorize --action owner.console --resource local:demo
zorin-host-agent.exe gate --action owner.console --resource local:owner-console -- powershell.exe
zorin-host-agent.exe identity status
zorin-host-agent.exe identity migrate-tpm
```

`credential.ssh` is deliberately denied by the default policy in this milestone. v0.2 establishes the signed credential primitive; the separate `zorin-access-broker` repository verifies those proofs and is where SSH certificate issuance will live.

## Security boundaries

The phone is not a generic signing oracle and the desktop listener is not a remote shell. High-level operations are fixed, domain-separated and policy checked. A local administrator can still subvert a user-mode agent; system-level Windows hardening is a later layer, not something v0.2 claims to solve.


### Device trust vs owner presence
From v0.2.2, device trust survives screen lock. `session.json` therefore means *paired device is cryptographically present*, not necessarily *user is actively present*. Sensitive integrations should use `authorize` / `gate`; these require `user_present=true` and a fresh phone-signed owner proof.

### v0.3 service + visual lifecycle

Known paired-host reconnects now start the phone's foreground `TrustService` directly through ADB shell instead of launching the UI Activity. After mutual authentication succeeds, the agent requests one predefined red owner-trust pulse. Pairing remains the only normal flow that intentionally opens the TRUST UI.
