# Changelog

## Unreleased

- Added the PKCS#11 provider (feature `pkcs11`): `Pkcs11Signer` and
  `Pkcs11KeyAgreement` for P-384 keys that stay in a token, each with a worker
  thread that owns its session. Tested against SoftHSM.
- Copied IronPrivacyGuard's TPM 2.0 layer here as `ironkeys-tpm2` (IPG commit
  `1ffc55e`), with its imports re-rooted.
- Added the software provider (feature `software`): IronCrypto's
  `SoftwareSigner`, loaded under a custody policy. Needs IronCrypto 0.2.21.
- Copied IronPrivacyGuard's native FFI crates here as `ironkeys-pkcs11` and
  `ironkeys-cng` (IPG commit `1e12250`), unchanged apart from names.
- Scaffolded IronKeys: workspace, licence, CI, dependency policy, the initial
  types and the design notes in `docs/`. Not published.
