# IronKeys

Key custody for the IronSecurity stack: one interface over private keys held in
software, a PKCS#11 HSM, a TPM 2.0, Windows CNG or AWS KMS.

**Status: scaffold.** The interface, provider descriptions and custody policy
exist and are tested. The backends have not been moved here yet; they still
live in IronPrivacyGuard. The crate is not published.

## What is here

| Item | Purpose |
| --- | --- |
| `Signer` (re-exported from IronCrypto's `ic_core::sig`) | Sign with a key wherever it lives |
| `KeyAgreement` | ECDH with a key wherever it lives; returns the raw shared secret |
| `Provider`, `ProviderKind` | Describe a configured backend: custody class, exportability, declared validation |
| `Validation` | What an operator declares about a module's FIPS 140 validation |
| `CustodyPolicy` | Which providers a host accepts: any, non-exportable, hardware, or declared-validated |

The crate is `no_std` without its default `std` feature, forbids unsafe code,
and depends only on IronCrypto's `ic-core`.

## What it does not do

- It performs no cryptography and talks to no device yet.
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
