# Policy

`policy.json` is deny-by-default. Rules match `action` and `resource` globs and can require a live trusted phone session.

Default examples:

- `owner.session / *` — allow with trust.
- `owner.console / local:*` — allow with trust.
- `credential.owner-proof / *` — allow with trust.
- `credential.ssh / server:*` — deny until explicitly enabled by the owner.

A matching allow rule controls proof TTL, capped by the phone at 120 seconds.
