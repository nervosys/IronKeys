# ironkeys-kms

An AWS KMS client in safe Rust for [IronKeys](https://crates.io/crates/ironkeys):
the AWS credential chain, SigV4, and `GetPublicKey`, `Sign` and
`DeriveSharedSecret` over IronSocketLayer's TLS 1.3 with a bundled root
store. No AWS SDK and no third-party TLS library.

Use it through `ironkeys` with the `kms` feature, which adds the custody
policy and the `Signer` and `KeyAgreement` implementations. P-384 only.
Tested against a mock KMS on loopback; it has not been run against AWS.

Nothing here is FIPS 140 validated. AWS's HSMs are; this client and
IronCrypto are not.

AGPL-3.0-or-later, with a commercial licence available from NERVOSYS
(licensing@nervosys.ai). The trust-anchor data in `data/` is under
CDLA-Permissive-2.0 (`data/tls-roots.LICENSE`).
