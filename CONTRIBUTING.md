# Contributing to IronKeys

## Before anything else

- **Licensing.** Contributions are accepted under the
  [Contributor License Agreement](CLA.md), so they can be distributed under
  both the AGPL v3 and the commercial licence
  ([LICENSE-COMMERCIAL.md](LICENSE-COMMERCIAL.md)). Opening a pull request
  indicates agreement; your commit name and email serve as the signature.
- **Security issues** are reported privately: see [SECURITY.md](SECURITY.md).
- **Cryptography belongs in IronCrypto.** A hash, a signature algorithm or a
  key encoding goes to
  [nervosys/IronCrypto](https://github.com/nervosys/IronCrypto), not here.
  IronKeys reaches keys; it does not implement primitives.

## Rules

- Only the IronSecurity stack is depended on: IronCrypto everywhere, and
  IronSocketLayer for the KMS client. `scripts/check-first-party-only.py`
  fails on anything else.
- `unsafe` code lives only in `crates/ironkeys-pkcs11` and
  `crates/ironkeys-cng`. Every other crate forbids it.
- Nothing panics on input or on a device's answer. Return an error.
- A device failure says whether a retry is safe: `ProviderUnavailable` only
  when one may succeed, `ProviderRefused` for a refusal and for anything
  unclassified. Retrying a refusal is how a token or TPM gets locked.
- A provider checks the provider description and the custody policy before it
  touches a device or the network.
- `Validation` records what an operator declares. Nothing here may present a
  declaration as a finding.
- `ironkeys-pkcs11`, `ironkeys-cng`, `ironkeys-tpm2` and `ironkeys-kms` are
  copies of code in IronPrivacyGuard. Until IronPrivacyGuard depends on these
  crates, a fix to one copy is made in both.
- A provider is tested against a device or a stand-in for one, and the
  documentation says which: SoftHSM, swtpm, a mock KMS, one Windows TPM.
- Break the thing and confirm the test fails. A test that passes on broken
  code verified nothing.

## Before you open a pull request

```console
$ cargo fmt --all -- --check
$ cargo clippy --locked --workspace --all-targets --all-features -- -D warnings
$ cargo test --locked --workspace --all-features
$ cargo test --locked -p ironkeys --no-default-features
$ python scripts/check-first-party-only.py --all-features
$ bash scripts/test-softhsm.sh        # if you changed the PKCS#11 provider (Linux)
$ bash scripts/test-swtpm.sh          # if you changed the TPM provider (Linux)
```

Never claim FIPS 140-3 validation or an independent review, in code,
documentation or commit messages. Neither exists.
