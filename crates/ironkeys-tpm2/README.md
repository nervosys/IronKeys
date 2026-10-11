# ironkeys-tpm2

A TPM 2.0 layer in safe Rust for [IronKeys](https://crates.io/crates/ironkeys):
marshalling, structures and software MakeCredential, and, with the `device`
feature, salted HMAC sessions and commands over Windows TBS, a Linux TPM
device or an swtpm socket.

Use it through `ironkeys` with the `tpm2` feature, which adds the custody
policy and the `Signer` and `KeyAgreement` implementations. P-384 only.
Tested against swtpm, not against a hardware TPM on Linux.

AGPL-3.0-or-later, with a commercial licence available from NERVOSYS
(licensing@nervosys.ai).
