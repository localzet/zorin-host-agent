# Windows host identity

Fresh v0.2 installations attempt a persistent P-256 key in the Windows CNG **Microsoft Platform Crypto Provider**, which is the Windows TPM key-storage provider. If unavailable, the agent falls back to the Microsoft Software KSP, then legacy PEM.

Existing v0.1 users retain the current PEM key to avoid an unexpected identity change. Run `identity migrate-tpm` to create/select the TPM identity; then pair the new host fingerprint once on the phone.
