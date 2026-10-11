//! The PKCS#11 provider: P-384 keys held in an HSM or token.
//!
//! [`Pkcs11Signer`] implements [`Signer`] and [`Pkcs11KeyAgreement`]
//! implements [`KeyAgreement`] over a private key that never leaves the
//! token. Both refuse a key the token would release: the private key object
//! must be sensitive and non-extractable.
//!
//! # Threads
//!
//! A PKCS#11 session belongs to one thread, and a [`Signer`] must be usable
//! from many. Each key therefore owns a worker thread that holds the session;
//! `sign` and `agree` send it a request and wait for the answer. The worker
//! ends, and the session closes, when the key is dropped.
//!
//! # Scope
//!
//! P-384 only (ECDSA with SHA-384, and ECDH), which is what IronPrivacyGuard's
//! backend this is taken from supports. The token module is trusted native
//! code, loaded from the absolute path the host gives.

use crate::{
    AgreementAlgorithm, Custody, CustodyPolicy, Error, ErrorKind, KeyAgreement, Provider,
    ProviderKind, Result, SignatureAlgorithm, Signer,
};
use ic_core::traits::{Digest, RandomSource};
use ironkeys_pkcs11::{
    Attribute, AttributeType, Error as CkError, KeyType, ObjectClass, ObjectHandle, Pkcs11, Session,
};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};

/// DER OBJECT IDENTIFIER 1.3.132.0.34 (secp384r1), the CKA_EC_PARAMS value.
const P384_PARAMS: [u8; 7] = [0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

/// Why a token key could not be opened.
#[derive(Debug)]
#[non_exhaustive]
pub enum OpenError {
    /// The host's custody policy does not accept this provider.
    Policy,
    /// The module could not be loaded, or its worker could not start.
    Module(String),
    /// No present token, or no key object, matches.
    NotFound(&'static str),
    /// More than one token or key object matches; none is chosen.
    Ambiguous(&'static str),
    /// The key exists but must not be used: wrong curve, wrong usage, or a
    /// private key the token would release.
    Refused(&'static str),
    /// The token refused or failed a call: the PKCS#11 return value and the
    /// function that returned it.
    Device(u64, &'static str),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Policy => f.write_str("the custody policy does not accept this provider"),
            Self::Module(detail) => write!(f, "PKCS#11 module unavailable: {detail}"),
            Self::NotFound(what) | Self::Ambiguous(what) | Self::Refused(what) => f.write_str(what),
            Self::Device(rv, function) => write!(f, "{function} returned 0x{rv:x}"),
        }
    }
}

impl std::error::Error for OpenError {}

impl From<CkError> for OpenError {
    fn from(error: CkError) -> Self {
        match error {
            CkError::Pkcs11(rv, function) => Self::Device(rv, function),
            CkError::Invalid(detail) => Self::Module(detail.into()),
        }
    }
}

/// Where a key is: the module to load, the token by serial number, and the
/// key objects by `CKA_ID`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyLocation {
    /// The absolute path of the vendor's PKCS#11 module.
    pub module: PathBuf,
    /// The token's serial number, as the token reports it.
    pub token_serial: String,
    /// The `CKA_ID` shared by the private and public key objects.
    pub key_id: Vec<u8>,
}

impl KeyLocation {
    /// A location from its parts.
    pub fn new(module: impl AsRef<Path>, token_serial: &str, key_id: &[u8]) -> Self {
        Self {
            module: module.as_ref().to_path_buf(),
            token_serial: token_serial.to_owned(),
            key_id: key_id.to_vec(),
        }
    }
}

enum Job {
    /// Sign a SHA-384 digest; the answer is raw `r || s`.
    Sign([u8; 48]),
    /// ECDH with an uncompressed peer point; the answer is the shared secret.
    Agree([u8; 97]),
}

type Answer = std::result::Result<Vec<u8>, CkError>;

/// The thread that owns a key's session.
struct Worker {
    jobs: Mutex<Sender<(Job, Sender<Answer>)>>,
}

impl Worker {
    fn call(&self, job: Job) -> Result<Vec<u8>> {
        let gone = || Error::new(ErrorKind::Internal, "pkcs11 worker is not running");
        let (reply, answer) = channel();
        self.jobs
            .lock()
            .map_err(|_| gone())?
            .send((job, reply))
            .map_err(|_| gone())?;
        answer.recv().map_err(|_| gone())?.map_err(device_error)
    }
}

/// A token failure as the shared interface can express it. Return values that
/// say the mechanism is unavailable are `Unsupported`; everything else the
/// token refuses is `InvalidParameter`.
fn device_error(error: CkError) -> Error {
    match error {
        CkError::Pkcs11(0x70 | 0x71 | 0x130 | 0x140 | 0x62, _) => Error::new(
            ErrorKind::Unsupported,
            "the pkcs11 token does not offer the mechanism",
        ),
        _ => Error::new(
            ErrorKind::InvalidParameter,
            "the pkcs11 token refused or failed the operation",
        ),
    }
}

/// Token text is blank-padded; some modules also pad with NUL.
fn token_text(field: &str) -> &str {
    field.trim_end_matches([' ', '\0'])
}

fn find_one(
    session: &Session,
    class: std::ffi::c_ulong,
    id: &[u8],
) -> std::result::Result<ObjectHandle, OpenError> {
    let found = session.find_objects(&[
        Attribute::Class(class),
        Attribute::KeyType(KeyType::EC),
        Attribute::Id(id.to_vec()),
    ])?;
    match found.as_slice() {
        [handle] => Ok(*handle),
        [] => Err(OpenError::NotFound(
            "no EC key object with this CKA_ID on the token",
        )),
        _ => Err(OpenError::Ambiguous(
            "several key objects share this CKA_ID",
        )),
    }
}

/// The public key's uncompressed point. `CKA_EC_POINT` is a DER OCTET STRING
/// per the specification; some modules return the bare point.
fn public_point(session: &Session, id: &[u8]) -> std::result::Result<[u8; 97], OpenError> {
    let handle = find_one(session, ObjectClass::PUBLIC_KEY, id)?;
    let (mut params, mut point) = (None, None);
    for attribute in
        session.get_attributes(handle, &[AttributeType::EcParams, AttributeType::EcPoint])?
    {
        match attribute {
            Attribute::EcParams(value) => params = Some(value),
            Attribute::EcPoint(value) => point = Some(value),
            _ => {}
        }
    }
    if params.as_deref() != Some(&P384_PARAMS[..]) {
        return Err(OpenError::Refused(
            "the public key object is not a named P-384 key",
        ));
    }
    let raw = point.ok_or(OpenError::Refused("the token did not report CKA_EC_POINT"))?;
    let point: &[u8] = match raw.as_slice() {
        [0x04, 0x61, point @ ..] if raw.len() == 99 => point,
        other => other,
    };
    let point: [u8; 97] = point
        .try_into()
        .map_err(|_| OpenError::Refused("the public key is not an uncompressed P-384 point"))?;
    if !crate::p384::on_curve(&point) {
        return Err(OpenError::Refused("the public key is not a point on P-384"));
    }
    Ok(point)
}

/// The private key, required to be P-384, usable for `usage`, sensitive and
/// non-extractable. A missing attribute counts as unsafe.
fn private_key(
    session: &Session,
    id: &[u8],
    usage: AttributeType,
) -> std::result::Result<ObjectHandle, OpenError> {
    let handle = find_one(session, ObjectClass::PRIVATE_KEY, id)?;
    let (mut params, mut usable, mut sensitive, mut extractable) = (None, false, false, true);
    for attribute in session.get_attributes(
        handle,
        &[
            AttributeType::EcParams,
            usage,
            AttributeType::Sensitive,
            AttributeType::Extractable,
        ],
    )? {
        match attribute {
            Attribute::EcParams(value) => params = Some(value),
            Attribute::Sign(value) | Attribute::Derive(value) => usable = value,
            Attribute::Sensitive(value) => sensitive = value,
            Attribute::Extractable(value) => extractable = value,
            _ => {}
        }
    }
    if params.as_deref() != Some(&P384_PARAMS[..]) {
        return Err(OpenError::Refused(
            "the private key object is not a named P-384 key",
        ));
    }
    if !usable {
        return Err(OpenError::Refused(
            "the private key does not permit this operation",
        ));
    }
    if !sensitive || extractable {
        return Err(OpenError::Refused(
            "the private key is not sensitive and non-extractable",
        ));
    }
    Ok(handle)
}

/// Open the session and find the key, on the worker's own thread.
fn prepare(
    location: &KeyLocation,
    pin: &[u8],
    usage: AttributeType,
) -> std::result::Result<(Session, ObjectHandle, [u8; 97]), OpenError> {
    let context = Pkcs11::new(&location.module).map_err(|e| OpenError::Module(e.to_string()))?;
    let mut slots = Vec::new();
    for slot in context.get_slots_with_token()? {
        if token_text(&context.get_token_info(slot)?.serial) == location.token_serial {
            slots.push(slot);
        }
    }
    let slot = match slots.as_slice() {
        [slot] => *slot,
        [] => {
            return Err(OpenError::NotFound(
                "no present token reports this serial number",
            ));
        }
        _ => {
            return Err(OpenError::Ambiguous(
                "several tokens report this serial number",
            ));
        }
    };
    let session = context.open_session(slot, false)?;
    // Login state belongs to the application, so another session may already
    // have logged in (CKR_USER_ALREADY_LOGGED_IN).
    match session.login(pin) {
        Ok(()) | Err(CkError::Pkcs11(0x100, _)) => {}
        Err(error) => return Err(error.into()),
    }
    let point = public_point(&session, &location.key_id)?;
    let handle = private_key(&session, &location.key_id, usage)?;
    Ok((session, handle, point))
}

fn agree_on_token(session: &Session, key: ObjectHandle, peer: &[u8]) -> Answer {
    // A short-lived session object: extractable only so the caller's KDF can
    // run on the shared secret.
    let template = [
        Attribute::Class(ObjectClass::SECRET_KEY),
        Attribute::KeyType(KeyType::GENERIC_SECRET),
        Attribute::ValueLen(48),
        Attribute::Token(false),
        Attribute::Sensitive(false),
        Attribute::Extractable(true),
    ];
    let handle = session.derive_key(key, peer, None, &template)?;
    let value = session.get_attributes(handle, &[AttributeType::Value]);
    let destroyed = session.destroy_object(handle);
    let mut shared = None;
    for attribute in value? {
        if let Attribute::Value(bytes) = attribute {
            shared = Some(bytes);
        }
    }
    destroyed?;
    shared.ok_or(CkError::Invalid(
        "the token did not release a shared secret",
    ))
}

/// Start a worker for the key at `location` and return it with the key's
/// public point.
fn start(
    location: &KeyLocation,
    pin: &[u8],
    usage: AttributeType,
    provider: &Provider,
    policy: CustodyPolicy,
) -> std::result::Result<(Worker, [u8; 97]), OpenError> {
    if provider.kind != ProviderKind::Pkcs11 || provider.exportable || !policy.permits(provider) {
        return Err(OpenError::Policy);
    }
    let (jobs, inbox) = channel::<(Job, Sender<Answer>)>();
    let (ready, opened) = channel();
    let (location, mut pin) = (location.clone(), pin.to_vec());
    std::thread::Builder::new()
        .name("ironkeys-pkcs11".into())
        .spawn(move || {
            let prepared = prepare(&location, &pin, usage);
            ic_core::Zeroize::zeroize(pin.as_mut_slice());
            let (session, key) = match prepared {
                Ok((session, key, point)) => {
                    if ready.send(Ok(point)).is_err() {
                        return;
                    }
                    (session, key)
                }
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            for (job, reply) in inbox {
                let answer = match job {
                    Job::Sign(digest) => session.sign(key, &digest),
                    Job::Agree(peer) => agree_on_token(&session, key, &peer),
                };
                let _ = reply.send(answer);
            }
        })
        .map_err(|e| OpenError::Module(e.to_string()))?;
    let point = opened
        .recv()
        .map_err(|_| OpenError::Module("the pkcs11 worker stopped".into()))??;
    Ok((
        Worker {
            jobs: Mutex::new(jobs),
        },
        point,
    ))
}

/// A P-384 signing key held in a PKCS#11 token.
pub struct Pkcs11Signer {
    worker: Worker,
    spki: [u8; 120],
}

impl Pkcs11Signer {
    /// Log in to the token and bind to the signing key at `location`.
    ///
    /// `provider` describes the token (including any validation its operator
    /// declares) and must be accepted by `policy`. The PIN is wiped from this
    /// module's copy once the token has been logged in to.
    pub fn open(
        location: &KeyLocation,
        pin: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, OpenError> {
        let (worker, point) = start(location, pin, AttributeType::Sign, provider, policy)?;
        Ok(Self {
            worker,
            spki: crate::p384::spki(&point),
        })
    }
}

impl Signer for Pkcs11Signer {
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
                "this pkcs11 key signs only ECDSA P-384 with SHA-384",
            ));
        }
        if out.len() < algorithm.max_signature_len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "signature buffer is too short",
            ));
        }
        // Raw CKM_ECDSA over the SHA-384 digest is ECDSA-SHA384 over the message.
        let mut digest = [0u8; 48];
        digest.copy_from_slice(ic_hash::Sha384::digest(message).as_ref());
        let raw = self.worker.call(Job::Sign(digest))?;
        if raw.len() != 96 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the pkcs11 token returned a signature of the wrong length",
            ));
        }
        ic_pkix::ecdsa_signature::to_der(&raw, out)
    }
}

/// A P-384 key-agreement key held in a PKCS#11 token.
pub struct Pkcs11KeyAgreement {
    worker: Worker,
    spki: [u8; 120],
}

impl Pkcs11KeyAgreement {
    /// Log in to the token and bind to the key-agreement key at `location`;
    /// see [`Pkcs11Signer::open`].
    pub fn open(
        location: &KeyLocation,
        pin: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, OpenError> {
        let (worker, point) = start(location, pin, AttributeType::Derive, provider, policy)?;
        Ok(Self {
            worker,
            spki: crate::p384::spki(&point),
        })
    }
}

impl KeyAgreement for Pkcs11KeyAgreement {
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
        let peer = crate::p384::point(peer_public)?;
        let mut shared = ic_core::Zeroizing::new(self.worker.call(Job::Agree(peer))?);
        if shared.len() != 48 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the pkcs11 token returned a shared secret of the wrong length",
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
    use ic_core::traits::KeyAgreement as _;

    #[test]
    fn a_policy_or_provider_mismatch_is_refused_before_the_module_loads() {
        let location = KeyLocation::new("/nonexistent/module.so", "serial", b"id");
        let token = Provider::new(ProviderKind::Pkcs11);
        // The module path does not exist, so reaching it would be a Module error.
        for (provider, policy) in [
            (Provider::new(ProviderKind::Software), CustodyPolicy::Any),
            (Provider::new(ProviderKind::Tpm2), CustodyPolicy::Any),
            (token, CustodyPolicy::DeclaredValidated),
        ] {
            assert!(matches!(
                Pkcs11Signer::open(&location, b"1234", &provider, policy),
                Err(OpenError::Policy)
            ));
        }
        assert!(matches!(
            Pkcs11Signer::open(&location, b"1234", &token, CustodyPolicy::Hardware),
            Err(OpenError::Module(_))
        ));
    }

    /// Against a real token: set IRONKEYS_TEST_PKCS11_MODULE, _SERIAL and _PIN
    /// (SoftHSM is enough). Generates a session key pair for each role.
    #[test]
    fn a_token_key_signs_and_agrees_without_leaving_the_token() {
        let Ok(module) = std::env::var("IRONKEYS_TEST_PKCS11_MODULE") else {
            return;
        };
        let serial = std::env::var("IRONKEYS_TEST_PKCS11_SERIAL").unwrap();
        let pin = std::env::var("IRONKEYS_TEST_PKCS11_PIN").unwrap();
        // Keys for the test, made through the same module.
        let context = Pkcs11::new(&module).unwrap();
        let slot = context
            .get_slots_with_token()
            .unwrap()
            .into_iter()
            .find(|s| token_text(&context.get_token_info(*s).unwrap().serial) == serial)
            .unwrap();
        let session = context.open_session(slot, true).unwrap();
        match session.login(pin.as_bytes()) {
            Ok(()) | Err(CkError::Pkcs11(0x100, _)) => {}
            Err(error) => panic!("{error}"),
        }
        let unique = std::process::id().to_be_bytes();
        let id = |role: u8| [&b"ironkeys-test-"[..], &unique, &[role]].concat();
        let generate = |role: u8, sign: bool, extractable: bool| {
            session
                .generate_key_pair(
                    &[
                        Attribute::EcParams(P384_PARAMS.to_vec()),
                        Attribute::Id(id(role)),
                        Attribute::Token(false),
                        Attribute::Verify(sign),
                    ],
                    &[
                        Attribute::Id(id(role)),
                        Attribute::Token(false),
                        Attribute::Private(true),
                        Attribute::Sensitive(!extractable),
                        Attribute::Extractable(extractable),
                        Attribute::Sign(sign),
                        Attribute::Derive(!sign),
                    ],
                )
                .unwrap()
        };
        generate(1, true, false);
        generate(2, false, false);
        generate(3, true, true);

        let token = Provider::new(ProviderKind::Pkcs11)
            .with_validation(Validation::fips140(3, 1, 1).unwrap());
        let at = |role: u8| KeyLocation::new(&module, &serial, &id(role));
        let open = |role: u8| {
            Pkcs11Signer::open(&at(role), pin.as_bytes(), &token, CustodyPolicy::Hardware)
        };

        // Signing: verified by IronCrypto against the key the token reports.
        let signer = std::sync::Arc::new(open(1).unwrap());
        assert_eq!(signer.custody(), Custody::Hardware);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut signature = [0u8; 104];
        let n = signer
            .sign(
                SignatureAlgorithm::EcdsaP384Sha384,
                b"held in the token",
                &mut rng,
                &mut signature,
            )
            .unwrap();
        ic_sig::verify_spki(
            SignatureAlgorithm::EcdsaP384Sha384,
            signer.public_key(),
            b"held in the token",
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
        // Refused without touching the token: another algorithm, a short buffer.
        assert!(
            signer
                .sign(SignatureAlgorithm::Ed25519, b"m", &mut rng, &mut signature)
                .is_err()
        );
        assert_eq!(
            signer
                .sign(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    b"m",
                    &mut rng,
                    &mut [0u8; 64]
                )
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidLength
        );
        // One key serves several threads.
        let threads: Vec<_> = (0..4u8)
            .map(|i| {
                let signer = signer.clone();
                std::thread::spawn(move || {
                    let mut rng = ic_drbg::Rng::from_os().unwrap();
                    let mut signature = [0u8; 104];
                    let n = signer
                        .sign(
                            SignatureAlgorithm::EcdsaP384Sha384,
                            &[i],
                            &mut rng,
                            &mut signature,
                        )
                        .unwrap();
                    ic_sig::verify_spki(
                        SignatureAlgorithm::EcdsaP384Sha384,
                        signer.public_key(),
                        &[i],
                        &signature[..n],
                    )
                    .unwrap();
                })
            })
            .collect();
        for thread in threads {
            thread.join().unwrap();
        }

        // Key agreement: the token's secret equals the software peer's.
        let agreement =
            Pkcs11KeyAgreement::open(&at(2), pin.as_bytes(), &token, CustodyPolicy::Hardware)
                .unwrap();
        let mut peer_scalar = [0u8; 48];
        peer_scalar[47] = 9;
        let mut peer_point = [0u8; 97];
        ic_ec::EcdhP384::public_key(&peer_scalar, &mut peer_point).unwrap();
        let mut from_token = [0u8; 48];
        assert_eq!(agreement.agree(&peer_point, &mut from_token).unwrap(), 48);
        let mut from_peer = [0u8; 48];
        let token_point = &agreement.public_key()[23..];
        ic_ec::EcdhP384::agree(&peer_scalar, token_point, &mut from_peer).unwrap();
        assert_eq!(from_token, from_peer);
        let mut off_curve = peer_point;
        off_curve[96] ^= 1;
        assert!(agreement.agree(&off_curve, &mut from_token).is_err());

        // Refusals: the wrong role, an extractable key, an unknown key.
        assert!(matches!(
            Pkcs11KeyAgreement::open(&at(1), pin.as_bytes(), &token, CustodyPolicy::Hardware),
            Err(OpenError::Refused(_))
        ));
        assert!(matches!(open(2), Err(OpenError::Refused(_))));
        assert!(matches!(open(3), Err(OpenError::Refused(_))));
        assert!(matches!(open(9), Err(OpenError::NotFound(_))));
        assert!(matches!(
            Pkcs11Signer::open(
                &KeyLocation::new(&module, "no-such-serial", &id(1)),
                pin.as_bytes(),
                &token,
                CustodyPolicy::Hardware
            ),
            Err(OpenError::NotFound(_))
        ));
    }
}
