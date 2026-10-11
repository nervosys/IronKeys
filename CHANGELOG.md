# Changelog

## Unreleased

- IronKeys is dual-licensed: AGPL-3.0-or-later, with a commercial licence
  available from NERVOSYS. Added `LICENSE-COMMERCIAL.md`, `CLA.md` and
  `CONTRIBUTING.md`.
- Added the Windows CNG provider (feature `cng`, Windows only): `CngSigner`,
  `CngKeyAgreement`, `create` and `delete` for P-384 keys persisted in the
  TPM by the Microsoft Platform Crypto Provider. The usage authorization is
  checked when a key is opened. Tested against one Windows TPM.
- Added the AWS KMS provider (feature `kms`): `KmsSigner` and
  `KmsKeyAgreement` for P-384 keys that stay in KMS. A signature KMS returns
  is checked against the bound public key before it is passed on. Tested
  against a mock KMS on loopback, not against AWS.
- Copied IronPrivacyGuard's KMS client here as `ironkeys-kms` (IPG commit
  `0e6344d`): credential chain, SigV4, IronSocketLayer TLS and the bundled
  roots. Its JSON is read by `ic-json`, its environment variables are
  `IRONKEYS_KMS_ENDPOINT` and `IRONKEYS_KMS_FIPS`, and a client can be given
  an endpoint and credentials directly.
- Device failures in `sign` and `agree` now say whether a retry is safe:
  `ProviderUnavailable` or `ProviderRefused`, from IronCrypto 0.2.24, which is
  now the minimum.
- Added the TPM 2.0 provider (feature `tpm2`): `Tpm2Signer`,
  `Tpm2KeyAgreement` and `create` for P-384 keys wrapped by a TPM's storage
  root. Tested against swtpm.
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
