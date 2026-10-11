//! The Windows CNG provider: P-384 keys persisted in the machine's TPM by the
//! Microsoft Platform Crypto Provider.
//!
//! A key is a name in the provider's key storage for the current user.
//! [`create`] makes one, [`CngSigner`] implements [`Signer`] over a signing
//! key, [`CngKeyAgreement`] implements [`KeyAgreement`] over an agreement
//! key, and [`delete`] removes one. The provider does not export these keys.
//!
//! Each key is protected by a usage authorization the caller supplies. It is
//! checked when a key is opened, by one operation in the TPM, so a wrong
//! value is reported then and counts toward the TPM's dictionary-attack
//! lockout.
//!
//! # Scope
//!
//! P-384 only, as in IronPrivacyGuard's backend this is taken from. The usage
//! authorization is the caller's to derive: this module does not stretch a
//! PIN. Windows only.

use crate::p384;
use crate::{
    AgreementAlgorithm, Custody, CustodyPolicy, Error, ErrorKind, KeyAgreement, Provider,
    ProviderKind, Result, SignatureAlgorithm, Signer,
};
use ic_core::traits::{Digest, KeyAgreement as _, RandomSource};
use ironkeys_cng::{Algorithm, Key, Provider as Storage, status};

/// A failed CNG call and its `HRESULT`.
pub use ironkeys_cng::Error as CngError;

/// What a key is for. A provider key signs or agrees, never both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// ECDSA P-384 signing.
    Sign,
    /// ECDH P-384 key agreement.
    Agree,
}

impl Role {
    fn algorithm(self) -> Algorithm {
        match self {
            Self::Sign => Algorithm::EcdsaP384,
            Self::Agree => Algorithm::EcdhP384,
        }
    }

    /// What the provider reports as the algorithm of a key in this role.
    /// The curve is not part of it: the public key's field size gives that.
    fn name(self) -> &'static str {
        match self {
            Self::Sign => "ECDSA",
            Self::Agree => "ECDH",
        }
    }
}

/// A failure creating, opening or deleting a provider key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum OpenError {
    /// The provider description or the host's custody policy does not accept
    /// a key from this provider. Nothing was opened.
    Policy,
    /// The Platform Crypto Provider could not be opened: no usable TPM.
    Unavailable(CngError),
    /// A CNG call failed. The `HRESULT` says why: a missing key, a wrong
    /// usage authorization, a TPM in lockout.
    Cng(CngError),
    /// The key exists but is not a P-384 key of the role asked for.
    WrongKey,
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy => f.write_str("the custody policy does not accept this key provider"),
            Self::Unavailable(e) => {
                write!(
                    f,
                    "the Microsoft Platform Crypto Provider is unavailable: {e}"
                )
            }
            Self::Cng(e) => write!(f, "{e}"),
            Self::WrongKey => f.write_str("the key is not a P-384 key of the requested role"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<CngError> for OpenError {
    fn from(error: CngError) -> Self {
        Self::Cng(error)
    }
}

/// `NTE_PERM`: the provider refused the usage authorization.
const NTE_PERM: i32 = 0x8009_0010_u32 as i32;

/// Statuses after which the same request may succeed: the TPM asked for a
/// retry, yielded or is self-testing, or TPM Base Services had an I/O error,
/// was not running, was starting, or was out of contexts or resources.
const TRANSIENT: [u32; 9] = [
    0x8028_0800, // TPM_E_RETRY
    0x8028_0908, // TPM 2.0 RC_YIELDED
    0x8028_090a, // TPM 2.0 RC_TESTING
    0x8028_0922, // TPM 2.0 RC_RETRY
    0x8028_4006, // TBS_E_IOERROR
    0x8028_4008, // TBS_E_SERVICE_NOT_RUNNING
    0x8028_4009, // TBS_E_TOO_MANY_TBS_CONTEXTS
    0x8028_400a, // TBS_E_TOO_MANY_RESOURCES
    0x8028_400b, // TBS_E_SERVICE_START_PENDING
];

/// A provider failure as the shared interface expresses it: `Unsupported`
/// for a missing mechanism, `ProviderUnavailable` for a status in
/// [`TRANSIENT`], and `ProviderRefused` otherwise (a wrong authorization, a
/// lockout, a deleted key, anything unclassified). Refusals are not
/// retryable: retrying one is how a TPM gets locked out.
fn device_error(error: CngError) -> Error {
    if error.status == status::NOT_SUPPORTED {
        Error::new(
            ErrorKind::Unsupported,
            "the Platform Crypto Provider does not offer the mechanism",
        )
    } else if TRANSIENT.contains(&(error.status as u32)) {
        Error::new(
            ErrorKind::ProviderUnavailable,
            "the TPM could not be reached or could not answer",
        )
    } else {
        Error::new(
            ErrorKind::ProviderRefused,
            "the Platform Crypto Provider refused the operation",
        )
    }
}

/// Whether `error` means the usage authorization was wrong or the TPM is
/// refusing authorizations.
pub fn is_authorization_failure(error: &CngError) -> bool {
    matches!(
        error.status,
        NTE_PERM
            | status::TPM_AUTHFAIL
            | status::TPM_20_AUTH_FAIL
            | status::TPM_20_BAD_AUTH
            | status::TPM_20_LOCKOUT
            | status::TPM_DEFEND_LOCK_RUNNING
    )
}

fn storage() -> std::result::Result<Storage, OpenError> {
    Storage::open().map_err(OpenError::Unavailable)
}

/// The provider's `Algorithm Name` property: UTF-16, NUL-terminated.
fn algorithm_name(key: &Key) -> std::result::Result<String, OpenError> {
    let raw = key.property("Algorithm Name")?;
    let (units, _) = raw.as_chunks::<2>();
    Ok(units
        .iter()
        .map(|unit| u16::from_le_bytes(*unit))
        .take_while(|unit| *unit != 0)
        .map(|unit| char::from_u32(unit.into()).unwrap_or('?'))
        .collect())
}

/// Create a persisted P-384 key named `name` for `role`, protected by
/// `usage_auth`, and return its public key as DER `SubjectPublicKeyInfo`.
///
/// The key stays in the provider's storage until [`delete`] removes it. A
/// name already in use is refused by the provider.
pub fn create(
    name: &str,
    role: Role,
    usage_auth: &[u8],
) -> std::result::Result<[u8; 120], OpenError> {
    let storage = storage()?;
    let key = storage.create(name, role.algorithm(), usage_auth)?;
    spki(&key)
}

/// Delete the persisted key named `name`, which requires its usage
/// authorization.
pub fn delete(name: &str, usage_auth: &[u8]) -> std::result::Result<(), OpenError> {
    Ok(storage()?.delete(name, usage_auth)?)
}

fn spki(key: &Key) -> std::result::Result<[u8; 120], OpenError> {
    let point: [u8; 97] = key
        .public_point()?
        .try_into()
        .map_err(|_| OpenError::WrongKey)?;
    if !p384::on_curve(&point) {
        return Err(OpenError::WrongKey);
    }
    Ok(p384::spki(&point))
}

/// Check the description and policy, then open the key and check its role.
fn open(
    name: &str,
    usage_auth: &[u8],
    role: Role,
    provider: &Provider,
    policy: CustodyPolicy,
) -> std::result::Result<(Storage, Key, [u8; 120]), OpenError> {
    if provider.kind != ProviderKind::WindowsCng || provider.exportable || !policy.permits(provider)
    {
        return Err(OpenError::Policy);
    }
    let storage = storage()?;
    let key = storage.open_key(name, usage_auth)?;
    if algorithm_name(&key)? != role.name() {
        return Err(OpenError::WrongKey);
    }
    let spki = spki(&key)?;
    Ok((storage, key, spki))
}

/// A P-384 signing key held by the Platform Crypto Provider.
pub struct CngSigner {
    key: Key,
    spki: [u8; 120],
    // Declared last so the key is freed before the provider handle.
    _storage: Storage,
}

impl CngSigner {
    /// Open the signing key named `name` and check `usage_auth` by signing
    /// once with it.
    ///
    /// `provider` describes the TPM (including any validation its operator
    /// declares) and must be accepted by `policy`.
    pub fn open(
        name: &str,
        usage_auth: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, OpenError> {
        let (storage, key, spki) = open(name, usage_auth, Role::Sign, provider, policy)?;
        key.sign_digest(ic_hash::Sha384::digest(b"IronKeys CNG authorization check").as_ref())?;
        Ok(Self {
            key,
            spki,
            _storage: storage,
        })
    }
}

impl Signer for CngSigner {
    fn algorithms(&self) -> &[SignatureAlgorithm] {
        &[SignatureAlgorithm::EcdsaP384Sha384]
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn custody(&self) -> Custody {
        Custody::Hardware
    }

    fn sign(
        &self,
        algorithm: SignatureAlgorithm,
        message: &[u8],
        _rng: &mut dyn RandomSource,
        out: &mut [u8],
    ) -> Result<usize> {
        if algorithm != SignatureAlgorithm::EcdsaP384Sha384 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "this CNG key signs only ECDSA P-384 with SHA-384",
            ));
        }
        if out.len() < algorithm.max_signature_len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "signature buffer is too short",
            ));
        }
        // NCryptSignHash over the SHA-384 digest is ECDSA-SHA384 over the message.
        let digest = ic_hash::Sha384::digest(message);
        let raw = self
            .key
            .sign_digest(digest.as_ref())
            .map_err(device_error)?;
        if raw.len() != 96 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the Platform Crypto Provider returned a signature of the wrong length",
            ));
        }
        ic_pkix::ecdsa_signature::to_der(&raw, out)
    }
}

/// A P-384 key-agreement key held by the Platform Crypto Provider.
pub struct CngKeyAgreement {
    key: Key,
    spki: [u8; 120],
    // Declared last so the key is freed before the provider handle.
    storage: Storage,
}

impl CngKeyAgreement {
    /// Open the agreement key named `name` and check `usage_auth` by
    /// agreeing once with a fixed public point. See [`CngSigner::open`].
    pub fn open(
        name: &str,
        usage_auth: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, OpenError> {
        let (storage, key, spki) = open(name, usage_auth, Role::Agree, provider, policy)?;
        // The curve's base point: a valid peer whose secret nobody needs.
        let mut one = [0u8; 48];
        one[47] = 1;
        let mut base = [0u8; 97];
        ic_ec::EcdhP384::public_key(&one, &mut base).map_err(|_| OpenError::WrongKey)?;
        let peer = storage.import_public(Algorithm::EcdhP384, &base)?;
        // The result is dropped, which wipes it.
        key.agree_raw(&peer)?;
        Ok(Self { key, spki, storage })
    }
}

impl KeyAgreement for CngKeyAgreement {
    fn algorithm(&self) -> AgreementAlgorithm {
        AgreementAlgorithm::EcdhP384
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn custody(&self) -> Custody {
        Custody::Hardware
    }

    fn agree(&self, peer_public: &[u8], out: &mut [u8]) -> Result<usize> {
        if out.len() < 48 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "shared-secret buffer is too short",
            ));
        }
        let peer = p384::point(peer_public)?;
        let imported = self
            .storage
            .import_public(Algorithm::EcdhP384, &peer)
            .map_err(device_error)?;
        let mut shared =
            ic_core::Zeroizing::new(self.key.agree_raw(&imported).map_err(device_error)?.take());
        if shared.len() != 48 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the Platform Crypto Provider returned a shared secret of the wrong length",
            ));
        }
        out[..48].copy_from_slice(&shared);
        ic_core::Zeroize::zeroize(shared.get_mut());
        Ok(48)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Validation;

    const TPM: Provider = Provider::new(ProviderKind::WindowsCng);

    #[test]
    fn provider_failures_say_whether_a_retry_is_safe() {
        let kind = |status: u32| {
            device_error(CngError {
                call: "NCryptSignHash",
                status: status as i32,
            })
            .kind()
        };
        assert_eq!(kind(status::NOT_SUPPORTED as u32), ErrorKind::Unsupported);
        for status in TRANSIENT {
            assert_eq!(kind(status), ErrorKind::ProviderUnavailable);
            assert!(kind(status).retryable());
        }
        // A wrong authorization, a lockout, a missing key and anything
        // unclassified must not be retried.
        for status in [
            NTE_PERM,
            status::TPM_20_AUTH_FAIL,
            status::TPM_20_BAD_AUTH,
            status::TPM_20_LOCKOUT,
            status::TPM_DEFEND_LOCK_RUNNING,
            status::BAD_KEYSET,
            -1,
        ] {
            assert_eq!(kind(status as u32), ErrorKind::ProviderRefused);
            assert!(!kind(status as u32).retryable());
            assert_eq!(
                is_authorization_failure(&CngError { call: "x", status }),
                !matches!(status, status::BAD_KEYSET | -1)
            );
        }
    }

    #[test]
    fn a_policy_or_provider_mismatch_is_refused_before_the_provider_opens() {
        for (provider, policy) in [
            (Provider::new(ProviderKind::Software), CustodyPolicy::Any),
            (Provider::new(ProviderKind::Tpm2), CustodyPolicy::Any),
            (TPM, CustodyPolicy::DeclaredValidated),
        ] {
            assert!(matches!(
                CngSigner::open("ironkeys-absent", b"auth", &provider, policy),
                Err(OpenError::Policy)
            ));
            assert!(matches!(
                CngKeyAgreement::open("ironkeys-absent", b"auth", &provider, policy),
                Err(OpenError::Policy)
            ));
        }
    }

    /// Against this machine's TPM: set IRONKEYS_TEST_CNG=1. Creates three
    /// persisted keys and deletes them.
    #[test]
    fn a_tpm_key_signs_and_agrees_without_leaving_the_tpm() {
        if std::env::var("IRONKEYS_TEST_CNG").as_deref() != Ok("1") {
            return;
        }
        let auth = [0x5a_u8; 32];
        let unique = std::process::id();
        let name = |role: &str| format!("ironkeys-test-{unique}-{role}");
        let (signing, agreement) = (name("sig"), name("enc"));
        let result = std::panic::catch_unwind(|| {
            let created = create(&signing, Role::Sign, &auth).unwrap();
            create(&agreement, Role::Agree, &auth).unwrap();
            // The name is taken now.
            assert!(matches!(
                create(&signing, Role::Sign, &auth),
                Err(OpenError::Cng(_))
            ));

            let declared = TPM.with_validation(Validation::fips140(3, 1, 1).unwrap());
            let signer: std::sync::Arc<dyn Signer> = std::sync::Arc::new(
                CngSigner::open(&signing, &auth, &declared, CustodyPolicy::DeclaredValidated)
                    .unwrap(),
            );
            assert_eq!(signer.custody(), Custody::Hardware);
            assert_eq!(signer.public_key(), created);
            let mut rng = ic_drbg::Rng::from_os().unwrap();
            let mut signature = [0u8; 104];
            let n = signer
                .sign(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    b"held in the TPM",
                    &mut rng,
                    &mut signature,
                )
                .unwrap();
            ic_sig::verify_spki(
                SignatureAlgorithm::EcdsaP384Sha384,
                signer.public_key(),
                b"held in the TPM",
                &signature[..n],
            )
            .unwrap();
            assert!(
                ic_sig::verify_spki(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    signer.public_key(),
                    b"another message",
                    &signature[..n],
                )
                .is_err()
            );
            // Shared between threads, as a `Signer` must be.
            let shared = signer.clone();
            std::thread::spawn(move || {
                let mut rng = ic_drbg::Rng::from_os().unwrap();
                let mut signature = [0u8; 104];
                shared
                    .sign(
                        SignatureAlgorithm::EcdsaP384Sha384,
                        b"from another thread",
                        &mut rng,
                        &mut signature,
                    )
                    .unwrap();
            })
            .join()
            .unwrap();

            // Agreement: both sides reach the same secret.
            let key =
                CngKeyAgreement::open(&agreement, &auth, &TPM, CustodyPolicy::Hardware).unwrap();
            let mut peer = [0x21_u8; 48];
            peer[0] = 0;
            let mut peer_public = [0u8; 97];
            ic_ec::EcdhP384::public_key(&peer, &mut peer_public).unwrap();
            let (mut ours, mut theirs) = ([0u8; 48], [0u8; 48]);
            assert_eq!(key.agree(&peer_public, &mut ours).unwrap(), 48);
            ic_ec::EcdhP384::agree(&peer, &key.public_key()[23..], &mut theirs).unwrap();
            assert_eq!(ours, theirs);
            let mut off = peer_public;
            off[96] ^= 1;
            assert_eq!(
                key.agree(&off, &mut ours).unwrap_err().kind(),
                ErrorKind::InvalidParameter
            );

            // A key opens only in its own role, and a missing key not at all.
            assert!(matches!(
                CngSigner::open(&agreement, &auth, &TPM, CustodyPolicy::Any),
                Err(OpenError::WrongKey)
            ));
            assert!(matches!(
                CngKeyAgreement::open(&signing, &auth, &TPM, CustodyPolicy::Any),
                Err(OpenError::WrongKey)
            ));
            assert!(matches!(
                CngSigner::open(&name("absent"), &auth, &TPM, CustodyPolicy::Any),
                Err(OpenError::Cng(_))
            ));
            // One wrong authorization, reported when the key is opened. It
            // counts toward the TPM's lockout, so there is only one.
            match CngSigner::open(&signing, &[0u8; 32], &TPM, CustodyPolicy::Any) {
                Err(OpenError::Cng(error)) => {
                    assert!(is_authorization_failure(&error), "{error}")
                }
                other => panic!("a wrong authorization opened the key: {:?}", other.err()),
            }
        });
        let deleted = [delete(&signing, &auth), delete(&agreement, &auth)];
        result.unwrap();
        assert_eq!(deleted, [Ok(()), Ok(())]);
        assert!(matches!(
            CngSigner::open(&signing, &auth, &TPM, CustodyPolicy::Any),
            Err(OpenError::Cng(_))
        ));
    }
}
