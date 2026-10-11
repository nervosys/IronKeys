# ironkeys-cng

The native Windows boundary for [IronKeys](https://crates.io/crates/ironkeys):
CNG's Microsoft Platform Crypto Provider for TPM-backed persisted keys, and
TPM Base Services for raw TPM 2.0 commands. Windows only; it is empty on
other systems.

This crate contains `unsafe` code, confined to the FFI calls. Use it through
`ironkeys` with the `cng` or `tpm2` feature. P-384 only. Tested against one
Windows TPM.

AGPL-3.0-or-later, with a commercial licence available from NERVOSYS
(licensing@nervosys.ai).
