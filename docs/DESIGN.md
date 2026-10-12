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

## Where the code was

Before the extraction, everything below was in IronPrivacyGuard (master
`a6b69b7`). The FFI crates, `src/tpm2/` and the KMS client have since moved
here, and IPG depends on them:

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
   apart from names. IPG removed its copies and depends on these from
   0.1.0.
3. **TPM command layer (copied).** `src/tpm2/` is here as `ironkeys-tpm2`,
   from IPG commit `1ffc55e`. It needed an error type, a random source and
   two P-384 helpers of its own in place of IPG's; nothing else changed. It
   keeps IPG's error codes as strings so that IPG's adapter maps them one to
   one. IPG removed its copy and depends on this crate from 0.1.0; its
   swtpm suite, including attestation, passes against it.
4. **Backends.** Implement `Signer` and `KeyAgreement` for each backend here.
   IPG keeps thin adapters from these to its `IdentityKey` trait.
   - **PKCS#11 (done).** `pkcs11::Pkcs11Signer` and `Pkcs11KeyAgreement`. A
     PKCS#11 session belongs to one thread and a `Signer` must be shareable,
     so each key owns a worker thread that holds its session. Keys must be
     P-384, sensitive and non-extractable. Tested against SoftHSM by
     `scripts/test-softhsm.sh`. Not carried over from IPG: in-token envelope
     decryption (`open_in_device`), which follows IPG's envelope layout.
   - **TPM 2.0 (done).** `tpm2::Tpm2Signer`, `Tpm2KeyAgreement` and
     `tpm2::create`. Keys are TPM-wrapped blobs the caller stores; nothing
     persists in the TPM. A blob must be created in the TPM, fixed to it and
     its parent, and of the right role. Each key owns a worker thread with its
     TPM connection, and its auth value is checked when it is opened. Tested
     against swtpm by `scripts/test-swtpm.sh`, under the owner storage root;
     the Windows storage root is untested. Not carried over from IPG: PIN
     stretching and the key-file format.
   - **AWS KMS (done).** `kms::KmsSigner` and `KmsKeyAgreement`, over the
     client in `ironkeys-kms`. Keys are named by exact ARN and must be
     `ECC_NIST_P384` of the right usage. They are `Custody::Service`, so the
     `Hardware` policy refuses them. A returned signature is verified against
     the bound key before it is passed on. Tested against a mock KMS on
     loopback, and run once against AWS KMS in us-east-1 at 0.1.2. Not carried over from IPG: ML-DSA signing
     and the key-file format.
   - **Windows CNG (done).** `cng::CngSigner`, `CngKeyAgreement`,
     `cng::create` and `cng::delete`, over the Microsoft Platform Crypto
     Provider. Keys are persisted by name in the provider's storage for the
     current user. A key must report the algorithm of its role (`ECDSA` or
     `ECDH`) and a P-384 public key. NCrypt handles are usable from any
     thread, so there is no worker. Opening a key performs one TPM operation
     to check the usage authorization: a signature over a fixed string, or an
     agreement with the curve's base point. Tested against one Windows TPM
     with `IRONKEYS_TEST_CNG=1`; CI cannot run it. Not carried over from IPG:
     the PIN-to-authorization derivation, the vendor check against a key
     file, and attestation.
5. **AWS KMS client (copied).** `src/kms.rs` is here as `ironkeys-kms`, from
   IPG commit `0e6344d`, with the bundled TLS roots. It differs from IPG's in
   three ways: JSON is read by `ic-json`, the environment variables are
   `IRONKEYS_KMS_ENDPOINT` and `IRONKEYS_KMS_FIPS`, and `Client` takes an
   explicit endpoint and credentials so that a caller, or a test, need not
   set process environment. From 0.1.1 a client also takes its FIPS mode
   and web identity session name, and offers ML-DSA-65 public keys and
   external-mu signing. IPG removed its client and its copy of the roots and
   depends on this crate from 0.1.1; root-store updates are made here.
6. **IPG adoption (partly done).** IPG takes the FFI crates, the TPM layer
   and the KMS client from here. Not done: IPG's key backends still implement
   its own `IdentityKey` directly instead of adapting the providers here, and
   its `CustodyPolicy` and custody reporting are still its own.

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
- **Errors.** Opening a key returns a provider error (`pkcs11::OpenError`
  carries the PKCS#11 return value and function). `Signer::sign` and
  `KeyAgreement::agree` return IronCrypto's `Error`. From IronCrypto 0.2.24
  the providers report `ProviderUnavailable` when the device could not be
  reached or could not answer (a retry may succeed), `ProviderRefused` when it
  answered no or the failure cannot be classified (never retried, since
  retrying a refusal is how a token or TPM gets locked), and `Unsupported`
  for a missing mechanism. The device's own status code is not carried.
- **Encodings.** `Signer` uses DER `SubjectPublicKeyInfo` keys and DER ECDSA
  signatures. IPG uses raw `r || s`. The adapters convert.
- **Blocking.** KMS operations are network calls made inside `sign` and
  `agree`, each on a new connection with a 30-second timeout, and each
  resolving credentials again. Callers that cannot block need their own
  executor. Caching credentials until they expire is not done.
- **Secrets in parsed JSON.** `ic-json` values are not wiped when dropped, so
  a parsed credential response or `DeriveSharedSecret` response leaves its
  strings in freed memory. The raw response buffers are wiped. A wiping
  parser, or extracting the fields without building a tree, would close this.
- **Attestation.** TPM key attestation verification is not custody. It could
  live here, in IronPKI, or stay in IPG.
- **Validated-module data.** `Validation` holds an operator's declaration.
  Whether IronKeys should also ship a list of known CMVP certificates, and who
  maintains it, is undecided.
