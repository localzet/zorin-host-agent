# Zorin Host Agent

Mutual-authentication workstation runtime for Zorin Trust. The Host Agent owns the local `ZTRUST/2` device session, `ZOWNER/1` proof requests, host identity, policy evaluation and the authenticated localhost control API.

## 0.9

Policy v7 moves approval strength into the policy itself. A caller may ask for a stricter explicit approval, but it can no longer weaken an action that the matched rule marks as `require_explicit`.

New OS-integration scopes:

- `os.pam.authenticate` → explicit phone approval for PAM authentication;
- `os.sudo.authorize` → explicit phone approval for sudo;
- `os.windows.sensitive` → explicit approval for native Windows Trust Center sensitive actions.

The control `status` response now also includes structured trust state, host fingerprint, phone fingerprint and identity provider for native local UIs.

Existing ZSSH/1, Authority, Ops and owner-presence flows remain compatible.
