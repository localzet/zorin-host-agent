# Short-lived SSH certificates

Zorin Trust 0.8 adds `authority.ssh.issue / sshcert:*` to the default deny-by-default host policy.

A certificate request binds the ephemeral OpenSSH public key, principal, target, purpose, TTL and request id into one `ZSSH/1` resource scope. Zorin Authority asks the trusted phone for an explicit `ZOWNER/1` proof for that exact scope before the local SSH CA signs the key.

The default and maximum certificate lifetime in 0.8 is five minutes. Zorin Ops generates a fresh Ed25519 client keypair for each activation window and removes it after expiry; it does not import an existing user SSH private key into its state.

Servers must explicitly trust the Authority CA via OpenSSH `TrustedUserCAKeys`. `zorin-node ssh-ca install` is the reference Linux enrollment path and validates `sshd` configuration before reloading the service.
