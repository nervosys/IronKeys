# IronKeys

Key custody for the IronSecurity stack: one interface over private keys held in
software, a PKCS#11 HSM, a TPM 2.0, Windows CNG or AWS KMS.

**Status: early.** The interface, provider descriptions, custody policy and
software provider exist and are tested. The PKCS#11 provider signs and agrees
with keys in a token (tested against SoftHSM), and the TPM 2.0 provider with
keys wrapped by a TPM (tested against swtpm). The AWS KMS provider signs and
agrees with keys in KMS (tested against a mock KMS on loopback, not against
AWS). The Windows CNG provider signs and agrees with keys persisted in the
machine's TPM (tested against one Windows TPM). Nothing is published, and
IronPrivacyGuard still uses its own copies of the code moved here.

## What is here

| Item | Purpose |
| --- | --- |
| `Signer` (re-exported from IronCrypto's `ic_core::sig`) | Sign with a key wherever it lives |
| `KeyAgreement` | ECDH with a key wherever it lives; returns the raw shared secret |
| `Provider`, `ProviderKind` | Describe a configured backend: custody class, exportability, declared validation |
| `Validation` | What an operator declares about a module's FIPS 140 validation |
| `CustodyPolicy` | Which providers a host accepts: any, non-exportable, hardware, or declared-validated |
| `software` (feature `software`) | In-memory keys: IronCrypto's `SoftwareSigner`, loaded under a custody policy |
| `pkcs11` (feature `pkcs11`) | `Pkcs11Signer` and `Pkcs11KeyAgreement`: P-384 keys that stay in an HSM or token |
| `tpm2` (feature `tpm2`) | `Tpm2Signer`, `Tpm2KeyAgreement` and `create`: P-384 keys wrapped by a TPM's storage root, kept by the caller as blobs |
| `kms` (feature `kms`) | `KmsSigner` and `KmsKeyAgreement`: P-384 keys that stay in AWS KMS, named by exact key ARN |
| `cng` (feature `cng`, Windows) | `CngSigner`, `CngKeyAgreement`, `create` and `delete`: P-384 keys persisted in the TPM by the Microsoft Platform Crypto Provider |

The `ironkeys` crate is `no_std` without its default `std` feature, forbids
unsafe code, and depends only on IronCrypto (`ic-core`, and `ic-sig` for the
software provider). The `kms` feature adds IronSocketLayer for TLS; no AWS
SDK or third-party crate is used.

| Crate | Purpose |
| --- | --- |
| `ironkeys` | The interface, descriptions, policy and software provider |
| `crates/ironkeys-pkcs11` | Native PKCS#11 boundary: a vendor module loaded from an absolute path |
| `crates/ironkeys-cng` | Windows CNG and TPM Base Services (Windows only) |
| `crates/ironkeys-tpm2` | TPM 2.0 in safe Rust: marshalling, structures, software MakeCredential and, with `device`, HMAC sessions and commands over Windows TBS, a Linux device or swtpm |
| `crates/ironkeys-kms` | AWS KMS client in safe Rust: the credential chain, SigV4, and the key operations over IronSocketLayer's TLS 1.3 with a bundled root store |

Unsafe code is confined to the two FFI crates. They are IronPrivacyGuard's
`ipg-pkcs11` and `ipg-cng` at commit `1e12250`, unchanged apart from names.
Their device tests are ignored or skipped unless a token or TPM is configured.

`ironkeys-tpm2` is IronPrivacyGuard's `src/tpm2` at commit `1ffc55e` with its
imports re-rooted and its items made public. Its unit tests pass here, and the
TPM provider's swtpm test drives its command layer: storage root, key
creation, loading, salted HMAC sessions, signing and ECDH. Its attestation
commands are exercised only by IronPrivacyGuard's own tests.

`ironkeys-kms` is IronPrivacyGuard's `src/kms.rs` at commit `0e6344d` with its
types re-rooted, its JSON read by IronCrypto's `ic-json`, and its environment
variables renamed (`IRONKEYS_KMS_ENDPOINT`, `IRONKEYS_KMS_FIPS`). A client can
also be given its endpoint and credentials directly. The bundled roots in
`crates/ironkeys-kms/data` are IPG's, byte for byte.

## What it does not do

- The CNG provider has been run against one machine's TPM, by hand: CI has
  no TPM, so its device test runs only when `IRONKEYS_TEST_CNG=1` is set. It
  covers the Platform Crypto Provider only, not software CNG providers or
  smart cards.
- The KMS provider has been run against a mock KMS over plain HTTP on
  loopback. It has not been run against AWS, and its TLS path is exercised
  here only as far as building the configuration; IronPrivacyGuard's tests
  cover the same transport code against a TLS server. A test against real
  keys runs when `IRONKEYS_TEST_KMS_SIGNING_ARN` and
  `IRONKEYS_TEST_KMS_AGREEMENT_ARN` are set.
- The KMS provider does not cache credentials or reuse connections: every
  operation resolves credentials and opens a connection.
- Every provider but the software one supports P-384 only. The PKCS#11 and
  TPM providers have been run against SoftHSM and swtpm, not against a hardware HSM or a hardware TPM, and
  the TPM provider's Windows storage root has not been run at all.
- The TPM and CNG providers take the key's auth value as given; deriving it
  from a PIN is the caller's job.
- It validates nothing. `Validation` records an operator's declaration; the
  crate cannot check a certificate number against a module, and a provider
  kind never implies validation.
- IronCrypto is not CMVP validated. A validation is planned, with no date.

## Plan

See [docs/DESIGN.md](docs/DESIGN.md) for the extraction plan from
IronPrivacyGuard and the open questions.

## Checks

```text
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
cargo test --locked --workspace --all-features
cargo test --locked --workspace --no-default-features
python scripts/check-first-party-only.py --all-features
bash scripts/test-softhsm.sh        # PKCS#11 provider against SoftHSM (Linux)
bash scripts/test-swtpm.sh          # TPM 2.0 provider against swtpm (Linux)
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). The other IronSecurity projects also
offer a commercial licence; whether IronKeys does is the maintainer's decision
and is not stated here.
