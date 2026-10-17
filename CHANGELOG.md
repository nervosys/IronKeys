# Changelog

## Unreleased

Version 0.2.0 of every crate, not yet released: IronCrypto 0.3 changes the
types these crates expose, so the change is breaking for callers even though
IronKeys' own interface is the same.

- Moves to IronCrypto 0.3.1. From 0.3.0 hashes and MACs refuse once the
  module is in its error state; IronKeys passes that refusal on as an error
  where it used to compute a digest regardless. 0.3.1 clears vector
  registers and dead stack after code that handles secrets.
- `ironkeys-kms` moves to IronSocketLayer 0.7.0, which is on IronCrypto 0.3.
- `CngSigner::open` proves the usage authorization by signing a fixed
  48-byte value instead of hashing a fixed message first.

- The KMS provider has been run against AWS KMS: signing and key agreement
  with two `ECC_NIST_P384` keys in us-east-1 over TLS 1.3, checked by
  IronCrypto, on 2026-10-12. Once, by hand; CI still uses the mock.
- Added `docs/controls.json`: IronKeys' statements against NIST SP 800-53
  (SC-12, SC-13) and CMMC 2.0 (SC.L2-3.13.10, SC.L2-3.13.11) in the stack's
  `ironsecurity-controls/1` form, for IronEvidence. Key management is partial
  and FIPS-validated cryptography unmet. Each is IronKeys' claim about
  itself, not an assessment.

## 0.1.2

Changes `ironkeys` and `ironkeys-kms`; the other crates stay at 0.1.0.

- `ironkeys-kms` moves to IronSocketLayer 0.5.0, which validates server
  certificates with IronPKI 0.2.0. Nothing in this crate's interface or
  handshake settings changes, and no caller-named certificate policy is set:
  any policy is acceptable, as before.

## 0.1.1

Changes `ironkeys` and `ironkeys-kms`; the other crates stay at 0.1.0.

- `ironkeys-kms`: `Client::with_fips` sets FIPS mode for one client whatever
  `IRONKEYS_KMS_FIPS` says, and `Client::with_role_session_name` sets the web
  identity session name. Each mode has its own TLS configuration.
- `ironkeys-kms`: `Client::mldsa65_public_key` and `Client::sign_mldsa65_mu`,
  for `ML_DSA_65` keys signing a FIPS 204 external mu. The `ironkeys`
  interface does not offer ML-DSA through KMS yet.
- `scripts/import-tls-roots.py`, the importer for the bundled TLS roots, moved
  here from IronPrivacyGuard.

## 0.1.0

The first published release.

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
