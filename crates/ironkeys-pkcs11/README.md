# ironkeys-pkcs11

The native PKCS#11 boundary for [IronKeys](https://crates.io/crates/ironkeys):
a vendor module loaded from an absolute path, with sessions, key lookup,
ECDSA signing and ECDH derivation.

This crate contains `unsafe` code, confined to the FFI calls. Use it through
`ironkeys` with the `pkcs11` feature, which adds the custody policy and the
`Signer` and `KeyAgreement` implementations. P-384 only. Tested against
SoftHSM, not against a hardware HSM.

AGPL-3.0-or-later, with a commercial licence available from NERVOSYS
(licensing@nervosys.ai). The vendor module has its own licence.
