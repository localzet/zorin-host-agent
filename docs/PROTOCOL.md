# ZTRUST/2

Stock-phone transport is TCP `127.0.0.1:47472` reached through `adb reverse`.

## Authentication

Host sends its name, PKIX P-256 public key, fresh 256-bit nonce and identity-provider label. Phone returns its public key, nonce and ECDSA/SHA-256 proof over a domain-separated transcript. Host pins/validates the phone and returns its own proof.

## Post-auth polling

The phone sends `POLL`. Normally the host returns `PONG`. If a local policy-approved operation needs owner evidence, the host may instead return one bounded frame:

```text
PROOF_REQUEST
ACTION_HEX <UTF-8 hex>
RESOURCE_HEX <UTF-8 hex>
NONCE <256-bit random hex>
ISSUED <unix-seconds>
EXPIRES <unix-seconds; max 120s>
END
```

The unlocked phone only signs the canonical domain-separated message:

```text
ZTRUST/2|OWNER_PROOF|host-fp|phone-fp|action-hex|resource-hex|nonce|issued|expires
```

and replies with `PROOF_RESULT OK` + DER ECDSA signature. There is no raw-sign, shell, arbitrary-file or arbitrary-Binder operation.

## Local control

The daemon separately binds `127.0.0.1:47473`. Requests are JSON and require a random control token from the per-user state directory. This API is for local applications/CLI integration and does not accept remote network connections.
