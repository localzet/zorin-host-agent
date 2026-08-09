# Security

Do not publish the generated host identity from `%LOCALAPPDATA%/ZorinTrust` (Windows) or the platform user config directory.

The agent intentionally exposes only the fixed ZTRUST handshake/heartbeat protocol on `127.0.0.1:47472`; it is not a remote shell. `--on-trust` and `--on-untrust` are local administrator-configured hooks and are never supplied by the phone.

Report vulnerabilities privately before opening a public issue when practical.
