# Runtime owner signing

Windows owner bundles keep the Android Runtime signing identity outside the repository:

- `%LOCALAPPDATA%\ZorinTrust\signing\runtime-owner.p12`
- `%LOCALAPPDATA%\ZorinTrust\signing\runtime-owner.pass`

The PKCS#12 key and the keystore intentionally use the same randomly generated password.
When invoking Android SDK Build-Tools `apksigner`, the password file is supplied only as
`--ks-pass file:...`. `--key-pass` is omitted so `apksigner` reuses the keystore password.
Do **not** pass the same one-line password file to both options: password files are consumed
line-by-line and the second password request would hit EOF.

If either the `.p12` or `.pass` file survives while the other is missing, the tooling refuses
to silently generate a replacement because that would break Android update-signature continuity.
