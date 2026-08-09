# Security

Report vulnerabilities privately before opening public issues.

Design constraints: no arbitrary remote command execution; no raw phone signing; proofs are domain-separated, action/resource-bound and short-lived; default policy denies unknown actions; pairing requires phone approval; ephemeral owner state is deleted when trust is lost.

The local user account and administrators remain part of the workstation trust boundary. v0.2 does not claim to resist a fully compromised Windows kernel/admin account.
