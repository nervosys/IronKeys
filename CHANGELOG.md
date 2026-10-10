# Changelog

## Unreleased

- Added the software provider (feature `software`): IronCrypto's
  `SoftwareSigner`, loaded under a custody policy. Needs IronCrypto 0.2.21.
- Copied IronPrivacyGuard's native FFI crates here as `ironkeys-pkcs11` and
  `ironkeys-cng` (IPG commit `1e12250`), unchanged apart from names.
- Scaffolded IronKeys: workspace, licence, CI, dependency policy, the initial
  types and the design notes in `docs/`. Not published.
