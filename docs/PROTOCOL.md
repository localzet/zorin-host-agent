# ZTRUST/1 host side

Transport in the stock-phone milestone is TCP on `127.0.0.1:47472` reached from Android using `adb reverse`.

The host sends:

```text
ZTRUST/1
HOST_NAME <display-name>
HOST_PUB <PKIX DER hex>
HOST_NONCE <32 random bytes hex>
END
```

The phone responds with its PKIX public key, nonce and an ECDSA/SHA-256 signature over a domain-separated transcript. The host verifies the signature and pinned phone key, then returns its own ECDSA signature.

After authentication, only `PING`, `BYE` and fixed protocol responses are accepted. This listener is not a shell/RPC endpoint.
