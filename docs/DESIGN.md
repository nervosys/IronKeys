# IronKeys design notes

IronKeys is the IronSecurity stack's key-custody layer. It exists so that
IronPrivacyGuard, IronSocketLayer and IronPKI use private keys in devices and
services through one interface and one set of backends.

## Scope

In scope:

- The interface callers are written against: `Signer` (from IronCrypto) and
  `KeyAgreement`.
- The backends: PKCS#11, TPM 2.0, Windows CNG and AWS KMS.
- Provider descriptions: custody class, exportability and the operator's
  declared validation, for policy and for IronEvidence.
- Custody policy: which providers a host accepts.

Out of scope:

- Cryptographic primitives. They stay in IronCrypto.
- Identity formats, envelopes and protocols. They stay in the projects that
  define them.
- Certificates. They belong to IronPKI.
- Any claim of validation. IronKeys records declarations.

## Where the code is today

Everything below is in IronPrivacyGuard (master `a6b69b7`):

| Code | Lines | Notes |
| --- | --- | --- |
| `crates/ipg-pkcs11` | about 770 plus tests | FFI over a vendor module loaded from an absolute path; depends on `ic-core` only |
| `crates/ipg-cng` | about 1,100 | Windows CNG and TPM Base Services FFI; no runtime dependencies |
| `src/tpm2/` | about 1,730 | Native TPM 2.0 command layer: marshalling, HMAC sessions with parameter encryption, transports (Windows TBS, Linux device, swtpm TCP) |
| `src/pkcs11.rs`, `src/tpm_native.rs`, `src/cng.rs` | 643, 596, 180 | Identity implementations over those layers |
| `src/kms.rs` | about 1,400 | AWS KMS JSON API, SigV4 and the credential chain; TLS through IronSocketLayer once IPG's `isl-tls` branch merges |
| `src/provider.rs` | about 1,000 | Key-reference files, custody policy and the possession check at bind |
| `src/attest.rs` | 566 | TPM attestation verification (not a custody interface) |

Unsafe code is confined to the two FFI crates. Everything is P-384 only today.

## Extraction plan

1. **Interface (done).** `Signer`, `KeyAgreement`, `Provider`, `Validation`,
   `CustodyPolicy`, and the software provider over IronCrypto's
   `SoftwareSigner`.
2. **FFI crates (copied).** `ipg-pkcs11` and `ipg-cng` are here as
   `ironkeys-pkcs11` and `ironkeys-cng`, from IPG commit `1e12250`, unchanged
   apart from names. IPG still builds its own copies: it pins exact versions
   from crates.io, so it can depend on these only once they are published.
   Until then a fix to either copy must be made in both.
3. **TPM command layer (copied).** `src/tpm2/` is here as `ironkeys-tpm2`,
   from IPG commit `1ffc55e`. It needed an error type, a random source and
   two P-384 helpers of its own in place of IPG's; nothing else changed. It
   keeps IPG's error codes as strings so that IPG's adapter maps them one to
   one. IPG's TPM and swtpm tests have not been run against this copy.
4. **Backends.** Implement `Signer` and `KeyAgreement` for each backend here.
   IPG keeps thin adapters from these to its `IdentityKey` trait.
5. **AWS KMS.** Move after IPG's KMS client runs on IronSocketLayer, since it
   needs TLS and a root store.
6. **IPG adoption.** IPG's `CustodyPolicy` and custody reporting map onto the
   types here.

Each step should leave IPG's full test matrix passing.

## What stays in IronPrivacyGuard

- `PublicKey`, fingerprints and the key-reference file formats
  (`ipg-pkcs11-key-v1`, `ipg-tpm-key-v1`, `ipg-kms-key-v1`, CNG).
- `Sealed` and in-device envelope decryption, which follow IPG's envelope
  layout.
- The hybrid key-agreement convention (`ss_ML-KEM || ss_X25519`).
- The PIN-to-authorization framing strings, unless a second consumer needs
  the same keys.
- Host policy other than custody: delegation, path confinement, the FIPS
  algorithm policy.

## Open questions

- **Algorithms.** The backends implement P-384 only. IronSocketLayer's server
  keys may need P-256, RSA or Ed25519. Which are required first?
- **Errors.** The backends return IPG's error type with IPG error codes.
  IronKeys uses IronCrypto's `Error`; a backend-specific error with a provider
  status code may be needed for PKCS#11 `CKR_*` and TPM response codes.
- **Encodings.** `Signer` uses DER `SubjectPublicKeyInfo` keys and DER ECDSA
  signatures. IPG uses raw `r || s`. The adapters convert.
- **Blocking.** KMS operations are network calls made inside `sign` and
  `agree`. Callers that cannot block need their own executor.
- **Attestation.** TPM key attestation verification is not custody. It could
  live here, in IronPKI, or stay in IPG.
- **Licence.** AGPL-3.0-or-later matches IPG and IronSocketLayer. Whether a
  commercial licence is offered is the maintainer's decision.
- **Validated-module data.** `Validation` holds an operator's declaration.
  Whether IronKeys should also ship a list of known CMVP certificates, and who
  maintains it, is undecided.
