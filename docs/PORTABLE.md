# Portable owner session

Portable mode is the first non-ADB transport for Zorin Trust. It is intentionally a transport and capability primitive, not a separate weaker authentication protocol.

## Security model

The portable computer generates a fresh P-256 host identity in memory and listens for normal `ZTRUST/2` on a private or link-local IPv4 network. Its default trust port is `47482`, deliberately separate from the normal workstation listener on `47472`. The Android Runtime receives only an expiring endpoint invitation through `zorintrust://connect`; it still authenticates the host key through the normal transcript and shows the pair-verification code before approval.

The phone keeps an approved `portable/ephemeral` host only in the `:trust` process memory. Ending the session, forgetting the portable host, or losing that process removes the temporary pin. The portable computer removes its temporary state directory when the process exits.

The printed bootstrap URL contains a random 128-bit invitation token. The portable listener requires that token on the first authenticated connection, so an unrelated device that merely scans the LAN cannot claim the one-shot pairing window. The invitation is bounded by the same expiry as the deep link and exists only in process memory.

The token is admission control, not the trust anchor. Still compare the displayed host fingerprint and pair-verification code: the normal ZTRUST/2 key authentication remains the anti-MITM check.

## Start

Windows bundles include a one-shot launcher. The underlying command is:

```text
zorin-host-agent portable --proof-out owner-proof.json
```

The agent prints private-LAN bootstrap URLs. Open one from the phone, tap **OPEN ZORIN TRUST**, compare the pairing code, and approve the temporary workstation.

If `--proof-out` is present, a second explicit approval creates a `ZOWNER/1` proof for:

```text
portable.session / host:<ephemeral-host-fingerprint>
```

The default policy gives that proof a 60-second lifetime. The proof is intended for a local portable consumer; replay protection and transaction binding remain the consumer's responsibility.

## Current limitations

- Direct transport is IPv4 private/link-local LAN only in 0.10.
- Windows Firewall may require a one-time inbound-network prompt for the portable executable.
- Native USB/WinUSB/HID transport is not implemented yet.
- Android cannot reliably surface an arbitrary background approval UI without additional notification work, so keep Zorin Trust open during the initial portable flow.
- The portable proof is not yet consumed by Zorin Node for remote SSH access; that is the next integration step.
