# Policy

`policy.json` is deny-by-default. Rules match `action` and `resource` globs and can require a live trusted phone session.

Default examples:

- `owner.session / *` — allow with trust.
- `owner.console / local:*` — allow with trust.
- `credential.owner-proof / *` — explicit phone approval.
- `portable.session / host:*` — explicit short-lived owner proof for an ephemeral portable host.
- `authority.ssh.issue / sshcert:*` — allow only with a trusted phone; each issuance is still explicit and transaction-bound.
- `credential.ssh / server:*` — legacy direct credential capability remains denied by default.

A matching allow rule controls proof TTL, capped by the phone at 120 seconds.
