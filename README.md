# IronKeys

Key custody for the IronSecurity stack: one interface over private keys held in
software, a PKCS#11 HSM, a TPM 2.0, Windows CNG or AWS KMS.

**Status: early.** The interface, provider descriptions, custody policy and
software provider exist and are tested. The two native FFI crates and the TPM
2.0 layer have been copied from IronPrivacyGuard; the device and service
backends that implement `Signer` and `KeyAgreement` over them have not. Nothing
is published, and IronPrivacyGuard still uses its own copies.

## What is here

| Item | Purpose |
| --- | --- |
| `Signer` (re-exported from IronCrypto's `ic_core::sig`) | Sign with a key wherever it lives |
| `KeyAgreement` | ECDH with a key wherever it lives; returns the raw shared secret |
| `Provider`, `ProviderKind` | Describe a configured backend: custody class, exportability, declared validation |
| `Validation` | What an operator declares about a module's FIPS 140 validation |
| `CustodyPolicy` | Which providers a host accepts: any, non-exportable, hardware, or declared-validated |
| `software` (feature `software`) | In-memory keys: IronCrypto's `SoftwareSigner`, loaded under a custody policy |

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
imports re-rooted and its items made public. Its three unit tests pass here.
The device paths are exercised only by IronPrivacyGuard's own TPM and swtpm
tests, which have not been run against this copy.

## What it does not do

- It has no `Signer` or `KeyAgreement` implementation for a device or service
  yet; the FFI crates are the layer those will be built on.
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
```

## Licence

AGPL-3.0-or-later; see [LICENSE](LICENSE). The other IronSecurity projects also
offer a commercial licence; whether IronKeys does is the maintainer's decision
and is not stated here.
