# IronKeys

Key custody for the IronSecurity stack: one interface over private keys held in
software, a PKCS#11 HSM, a TPM 2.0, Windows CNG or AWS KMS.

**Status: early.** The interface, provider descriptions, custody policy and
software provider exist and are tested. The PKCS#11 provider signs and agrees
with keys in a token (tested against SoftHSM), and the TPM 2.0 provider with
keys wrapped by a TPM (tested against swtpm). The Windows CNG and AWS KMS
providers have not been written. Nothing is published, and IronPrivacyGuard
still uses its own copies of the code moved here.

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

The `ironkeys` crate is `no_std` without its default `std` feature, forbids
unsafe code, and depends only on IronCrypto (`ic-core`, and `ic-sig` for the
software provider).

| Crate | Purpose |
| --- | --- |
| `ironkeys` | The interface, descriptions, policy and software provider |
| `crates/ironkeys-pkcs11` | Native PKCS#11 boundary: a vendor module loaded from an absolute path |
| `crates/ironkeys-cng` | Windows CNG and TPM Base Services (Windows only) |
| `crates/ironkeys-tpm2` | TPM 2.0 in safe Rust: marshalling, structures, software MakeCredential and, with `device`, HMAC sessions and commands over Windows TBS, a Linux device or swtpm |

Unsafe code is confined to the two FFI crates. They are IronPrivacyGuard's
`ipg-pkcs11` and `ipg-cng` at commit `1e12250`, unchanged apart from names.
Their device tests are ignored or skipped unless a token or TPM is configured.

`ironkeys-tpm2` is IronPrivacyGuard's `src/tpm2` at commit `1ffc55e` with its
imports re-rooted and its items made public. Its unit tests pass here, and the
TPM provider's swtpm test drives its command layer: storage root, key
creation, loading, salted HMAC sessions, signing and ECDH. Its attestation
commands are exercised only by IronPrivacyGuard's own tests.

## What it does not do

- It has no `Signer` or `KeyAgreement` implementation for Windows CNG or AWS
  KMS yet.
- The PKCS#11 and TPM providers support P-384 only. They have been run
  against SoftHSM and swtpm, not against a hardware HSM or a hardware TPM, and
  the TPM provider's Windows storage root has not been run at all.
- The TPM provider takes the key's auth value as given; deriving it from a PIN
  is the caller's job.
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
