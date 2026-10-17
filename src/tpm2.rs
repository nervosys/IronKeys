//! The TPM 2.0 provider: P-384 keys wrapped by a TPM's storage root.
//!
//! A key is a pair of TPM-wrapped blobs ([`KeyBlob`]) that only the TPM that
//! made them can load. Nothing is stored in the TPM: [`create`] returns the
//! blobs and the caller keeps them. [`Tpm2Signer`] implements [`Signer`] and
//! [`Tpm2KeyAgreement`] implements [`KeyAgreement`] over a loaded key.
//!
//! Keys are created in the TPM, fixed to it and to their parent, and
//! authorized with an auth value. A blob without those attributes, or of the
//! wrong role, is refused when it is opened. Key operations run in an HMAC
//! session salted with the storage root, so the auth value is never sent in
//! the clear.
//!
//! # Threads
//!
//! A TPM connection is one command stream. Each open key owns a worker thread
//! that holds its connection, loaded handle and session; `sign` and `agree`
//! send it a request. The handles are flushed when the key is dropped.
//!
//! # Scope
//!
//! P-384 only, as in IronPrivacyGuard's backend this is taken from. The auth
//! value is the caller's to derive: this module does not stretch a PIN.

use crate::p384;
use crate::{
    AgreementAlgorithm, Custody, CustodyPolicy, Error, ErrorKind, KeyAgreement, Provider,
    ProviderKind, Result, SignatureAlgorithm, Signer,
};
use ic_core::traits::{Digest, RandomSource};
use ironkeys_tpm2::structures::{
    self, ALG_ECDSA, ALG_SHA384, DECRYPT, FIXED_PARENT, FIXED_TPM, Public, SENSITIVE_DATA_ORIGIN,
    SIGN, USER_WITH_AUTH,
};
use ironkeys_tpm2::tpm::{HmacSession, RH_OWNER, Tpm};
use ironkeys_tpm2::transport;
use std::sync::Mutex;
use std::sync::mpsc::{Sender, channel};

/// A failure opening or creating a TPM key, with the layer's stable code
/// (such as `pin_locked` or `provider_unavailable`) and a description.
pub use ironkeys_tpm2::Error as Tpm2Error;

/// The Windows storage root key, which Windows provisions and keeps persistent.
const WINDOWS_SRK: u32 = 0x8100_0001;

/// The storage root a key is wrapped by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum StorageRoot {
    /// A restricted P-384 storage key derived in the owner hierarchy each
    /// time it is needed. Requires an empty owner authorization.
    Owner,
    /// The persistent storage root Windows provisions at 0x81000001.
    Windows,
}

/// What a key is for. A TPM key signs or agrees, never both.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// ECDSA P-384 with SHA-384.
    Sign,
    /// ECDH P-384.
    Agree,
}

/// A TPM-wrapped key: usable only by the TPM, and under the storage root,
/// that created it. Neither part is secret from the TPM's owner in the way a
/// software key is: the private part is encrypted to the TPM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyBlob {
    /// The marshalled `TPMT_PUBLIC`.
    pub public: Vec<u8>,
    /// The marshalled, TPM-encrypted `TPM2B_PRIVATE` contents.
    pub private: Vec<u8>,
}

/// A storage root: handle, name and public area. Transient roots are flushed.
struct Root {
    handle: u32,
    name: Vec<u8>,
    public: Public,
    transient: bool,
}

fn root(tpm: &mut Tpm, kind: StorageRoot) -> std::result::Result<Root, Tpm2Error> {
    match kind {
        StorageRoot::Owner => {
            let (handle, public) =
                tpm.create_primary(RH_OWNER, &structures::owner_srk_template().marshal()?)?;
            Ok(Root {
                handle,
                name: public.name()?,
                public,
                transient: true,
            })
        }
        StorageRoot::Windows => {
            let public = tpm.read_public(WINDOWS_SRK).map_err(|_| {
                Tpm2Error::new(
                    "provider_unavailable",
                    "The Windows storage root key (0x81000001) is not available",
                )
            })?;
            Ok(Root {
                handle: WINDOWS_SRK,
                name: public.name()?,
                public,
                transient: false,
            })
        }
    }
}

fn refused(what: &'static str) -> Tpm2Error {
    Tpm2Error::new("policy_mismatch", what)
}

/// Require a key the TPM made and will not release: created inside it, fixed
/// to it and to its parent, authorized by its auth value, P-384, and of
/// exactly `role`.
fn check_public(public: &Public, role: Role) -> std::result::Result<[u8; 97], Tpm2Error> {
    let required = FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH;
    if public.attributes & required != required {
        return Err(refused(
            "the TPM key is not fixed to this TPM, or was not created inside it",
        ));
    }
    let (wanted, other) = match role {
        Role::Sign => (SIGN, DECRYPT),
        Role::Agree => (DECRYPT, SIGN),
    };
    if public.attributes & wanted == 0 || public.attributes & other != 0 {
        return Err(refused("the TPM key is not for this operation"));
    }
    if role == Role::Sign && public.scheme != (ALG_ECDSA, ALG_SHA384) {
        return Err(refused("the TPM key does not sign ECDSA with SHA-384"));
    }
    let point: [u8; 97] = public
        .p384_point()?
        .try_into()
        .map_err(|_| refused("the TPM key is not a P-384 key"))?;
    Ok(point)
}

/// Create a key of `role` under `storage_root`, authorized by `auth`, and
/// return its wrapped blob. The key exists only in the blob.
///
/// `connection` names the TPM as [`ironkeys_tpm2::transport::open`] takes it:
/// `device:/dev/tpmrm0`, `tbs` on Windows, or `swtpm:port=2321` for a software
/// TPM on loopback.
pub fn create(
    connection: &str,
    storage_root: StorageRoot,
    role: Role,
    auth: &[u8],
) -> std::result::Result<KeyBlob, Tpm2Error> {
    let mut tpm = Tpm::new(transport::open(connection)?);
    let parent = root(&mut tpm, storage_root)?;
    let created = (|| {
        let mut session = tpm.hmac_session(parent.handle, &parent.public)?;
        let template = structures::identity_key_template(role == Role::Sign).marshal();
        let made = template.and_then(|template| {
            tpm.create((parent.handle, &parent.name), &mut session, auth, &template)
        });
        tpm.flush(session.handle());
        made
    })();
    if parent.transient {
        tpm.flush(parent.handle);
    }
    let (private, public) = created?;
    check_public(&public, role)?;
    Ok(KeyBlob {
        public: public.raw,
        private,
    })
}

enum Job {
    /// Sign a SHA-384 digest; the answer is raw `r || s`.
    Sign([u8; 48]),
    /// ECDH with an uncompressed peer point; the answer is the shared secret.
    Agree([u8; 97]),
}

type Answer = std::result::Result<Vec<u8>, Tpm2Error>;

/// The thread that owns a key's TPM connection.
struct Worker {
    jobs: Mutex<Sender<(Job, Sender<Answer>)>>,
}

impl Worker {
    fn call(&self, job: Job) -> Result<Vec<u8>> {
        let gone = || {
            Error::new(
                ErrorKind::ProviderRefused,
                "the TPM worker is not running; open the key again",
            )
        };
        let (reply, answer) = channel();
        self.jobs
            .lock()
            .map_err(|_| gone())?
            .send((job, reply))
            .map_err(|_| gone())?;
        answer
            .recv()
            .map_err(|_| gone())?
            .map_err(|e| device_error(&e))
    }
}

/// A TPM failure as the shared interface expresses it: `Unsupported` for a
/// missing mechanism, `ProviderUnavailable` when the TPM could not be reached
/// or the layer marks the failure retryable, and `ProviderRefused` otherwise
/// (a wrong auth value, a lockout, a policy). Refusals are not retryable:
/// retrying one is how a TPM gets locked out.
fn device_error(error: &Tpm2Error) -> Error {
    if error.code == "mechanism_unsupported" {
        Error::new(
            ErrorKind::Unsupported,
            "the TPM does not offer the mechanism",
        )
    } else if error.retryable || matches!(error.code, "provider_unavailable" | "io_error") {
        Error::new(
            ErrorKind::ProviderUnavailable,
            "the TPM could not be reached or could not answer",
        )
    } else {
        Error::new(ErrorKind::ProviderRefused, "the TPM refused the operation")
    }
}

/// A key loaded in the worker's TPM connection.
struct Loaded {
    tpm: Tpm,
    root: Root,
    key: (u32, Vec<u8>),
    session: Option<HmacSession>,
    auth: ic_core::Zeroizing<Vec<u8>>,
}

impl Loaded {
    fn open(
        connection: &str,
        storage_root: StorageRoot,
        blob: &KeyBlob,
        role: Role,
        auth: Vec<u8>,
    ) -> std::result::Result<(Self, [u8; 97]), Tpm2Error> {
        let auth = ic_core::Zeroizing::new(auth);
        let public = Public::parse(&blob.public)?;
        let point = check_public(&public, role)?;
        let mut tpm = Tpm::new(transport::open(connection)?);
        let root = root(&mut tpm, storage_root)?;
        let handle = match tpm.load((root.handle, &root.name), &blob.private, &public) {
            Ok(handle) => handle,
            Err(error) => {
                if root.transient {
                    tpm.flush(root.handle);
                }
                return Err(error);
            }
        };
        let name = public.name()?;
        Ok((
            Self {
                tpm,
                root,
                key: (handle, name),
                session: None,
                auth,
            },
            point,
        ))
    }

    /// Run a key operation in the session, started on first use and salted
    /// with the storage root.
    fn run(&mut self, job: Job) -> Answer {
        if self.session.is_none() {
            self.session = Some(self.tpm.hmac_session(self.root.handle, &self.root.public)?);
        }
        let session = self.session.as_mut().expect("started above");
        let key = (self.key.0, self.key.1.as_slice());
        match job {
            Job::Sign(digest) => self.tpm.sign_p384(key, session, &self.auth, &digest),
            Job::Agree(peer) => self
                .tpm
                .ecdh_z_gen(key, session, &self.auth, &peer)
                .map(|shared| shared.to_vec()),
        }
    }
}

impl Drop for Loaded {
    fn drop(&mut self) {
        if let Some(session) = self.session.take() {
            self.tpm.flush(session.handle());
        }
        self.tpm.flush(self.key.0);
        if self.root.transient {
            self.tpm.flush(self.root.handle);
        }
    }
}

/// Load `blob` on a worker thread and prove `auth` with one operation, so a
/// wrong auth value is reported when the key is opened, not at first use.
fn start(
    connection: &str,
    storage_root: StorageRoot,
    blob: &KeyBlob,
    role: Role,
    auth: &[u8],
    provider: &Provider,
    policy: CustodyPolicy,
) -> std::result::Result<(Worker, [u8; 97]), Tpm2Error> {
    if provider.kind != ProviderKind::Tpm2 || provider.exportable || !policy.permits(provider) {
        return Err(refused("the custody policy does not accept this provider"));
    }
    let (jobs, inbox) = channel::<(Job, Sender<Answer>)>();
    let (ready, opened) = channel();
    let (connection, blob, auth) = (connection.to_owned(), blob.clone(), auth.to_vec());
    let stopped = || Tpm2Error::new("provider_error", "the TPM worker stopped");
    std::thread::Builder::new()
        .name("ironkeys-tpm2".into())
        .spawn(move || {
            let mut loaded = match Loaded::open(&connection, storage_root, &blob, role, auth) {
                Ok((loaded, point)) => {
                    if ready.send(Ok(point)).is_err() {
                        return;
                    }
                    loaded
                }
                Err(error) => {
                    let _ = ready.send(Err(error));
                    return;
                }
            };
            for (job, reply) in inbox {
                let _ = reply.send(loaded.run(job));
            }
        })
        .map_err(|e| Tpm2Error::new("provider_error", e.to_string()))?;
    let point = opened.recv().map_err(|_| stopped())??;
    let worker = Worker {
        jobs: Mutex::new(jobs),
    };
    // One operation with the auth value: a wrong one is refused here.
    let proof = match role {
        Role::Sign => Job::Sign([0x5a; 48]),
        Role::Agree => Job::Agree(point),
    };
    let (reply, answer) = channel();
    worker
        .jobs
        .lock()
        .map_err(|_| stopped())?
        .send((proof, reply))
        .map_err(|_| stopped())?;
    answer.recv().map_err(|_| stopped())??;
    Ok((worker, point))
}

/// A P-384 signing key wrapped by a TPM.
pub struct Tpm2Signer {
    worker: Worker,
    spki: [u8; 120],
}

impl Tpm2Signer {
    /// Load a signing key and check its auth value.
    ///
    /// `provider` describes the TPM (including any validation its operator
    /// declares) and must be accepted by `policy`. A wrong `auth` is refused
    /// here; repeated wrong values can lock the TPM out.
    pub fn open(
        connection: &str,
        storage_root: StorageRoot,
        blob: &KeyBlob,
        auth: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, Tpm2Error> {
        let (worker, point) = start(
            connection,
            storage_root,
            blob,
            Role::Sign,
            auth,
            provider,
            policy,
        )?;
        Ok(Self {
            worker,
            spki: p384::spki(&point),
        })
    }
}

impl Signer for Tpm2Signer {
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
                "this TPM key signs only ECDSA P-384 with SHA-384",
            ));
        }
        if out.len() < algorithm.max_signature_len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "signature buffer is too short",
            ));
        }
        let mut digest = [0u8; 48];
        digest.copy_from_slice(ic_hash::Sha384::digest(message)?.as_ref());
        let raw = self.worker.call(Job::Sign(digest))?;
        if raw.len() != 96 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the TPM returned a signature of the wrong length",
            ));
        }
        ic_pkix::ecdsa_signature::to_der(&raw, out)
    }
}

/// A P-384 key-agreement key wrapped by a TPM.
pub struct Tpm2KeyAgreement {
    worker: Worker,
    spki: [u8; 120],
}

impl Tpm2KeyAgreement {
    /// Load a key-agreement key and check its auth value; see
    /// [`Tpm2Signer::open`].
    pub fn open(
        connection: &str,
        storage_root: StorageRoot,
        blob: &KeyBlob,
        auth: &[u8],
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, Tpm2Error> {
        let (worker, point) = start(
            connection,
            storage_root,
            blob,
            Role::Agree,
            auth,
            provider,
            policy,
        )?;
        Ok(Self {
            worker,
            spki: p384::spki(&point),
        })
    }
}

impl KeyAgreement for Tpm2KeyAgreement {
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
        let mut shared = ic_core::Zeroizing::new(self.worker.call(Job::Agree(peer))?);
        if shared.len() != 48 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "the TPM returned a shared secret of the wrong length",
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

    const AUTH: &[u8] = b"public test auth value, 32 bytes";

    #[test]
    fn tpm_failures_say_whether_a_retry_is_safe() {
        let kind = |code| device_error(&Tpm2Error::new(code, "x")).kind();
        assert_eq!(kind("mechanism_unsupported"), ErrorKind::Unsupported);
        for code in ["provider_unavailable", "io_error"] {
            assert_eq!(kind(code), ErrorKind::ProviderUnavailable);
            assert!(kind(code).retryable());
        }
        // A wrong auth value or a lockout must not be retried.
        for code in ["authentication_failed", "pin_locked", "provider_error"] {
            assert_eq!(kind(code), ErrorKind::ProviderRefused);
            assert!(!kind(code).retryable());
        }
        let mut transient = Tpm2Error::new("provider_error", "x");
        transient.retryable = true;
        assert_eq!(
            device_error(&transient).kind(),
            ErrorKind::ProviderUnavailable
        );
    }

    #[test]
    fn a_policy_or_provider_mismatch_is_refused_before_the_tpm_is_reached() {
        let blob = KeyBlob {
            public: Vec::new(),
            private: Vec::new(),
        };
        // No TPM listens on this port, so reaching it would be another error.
        let open = |provider: &Provider, policy| {
            Tpm2Signer::open(
                "swtpm:port=1",
                StorageRoot::Owner,
                &blob,
                AUTH,
                provider,
                policy,
            )
            .err()
            .unwrap()
            .code
        };
        assert_eq!(
            open(&Provider::new(ProviderKind::Pkcs11), CustodyPolicy::Any),
            "policy_mismatch"
        );
        assert_eq!(
            open(
                &Provider::new(ProviderKind::Tpm2),
                CustodyPolicy::DeclaredValidated
            ),
            "policy_mismatch"
        );
    }

    /// Against a TPM: set IRONKEYS_TEST_TPM to a connection such as
    /// `swtpm:port=2321` (see scripts/test-swtpm.sh).
    #[test]
    fn a_tpm_key_signs_and_agrees_and_is_bound_to_its_auth_and_role() {
        let Ok(connection) = std::env::var("IRONKEYS_TEST_TPM") else {
            return;
        };
        let tpm = Provider::new(ProviderKind::Tpm2)
            .with_validation(Validation::fips140(2, 2, 1).unwrap());
        let policy = CustodyPolicy::Hardware;
        let signing = create(&connection, StorageRoot::Owner, Role::Sign, AUTH).unwrap();
        let agreeing = create(&connection, StorageRoot::Owner, Role::Agree, AUTH).unwrap();

        let signer = std::sync::Arc::new(
            Tpm2Signer::open(
                &connection,
                StorageRoot::Owner,
                &signing,
                AUTH,
                &tpm,
                policy,
            )
            .unwrap(),
        );
        assert_eq!(signer.custody(), Custody::Hardware);
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut signature = [0u8; 104];
        let n = signer
            .sign(
                SignatureAlgorithm::EcdsaP384Sha384,
                b"wrapped by the TPM",
                &mut rng,
                &mut signature,
            )
            .unwrap();
        ic_sig::verify_spki(
            SignatureAlgorithm::EcdsaP384Sha384,
            signer.public_key(),
            b"wrapped by the TPM",
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
        assert!(
            signer
                .sign(SignatureAlgorithm::Ed25519, b"m", &mut rng, &mut signature)
                .is_err()
        );
        // One key serves several threads through its worker.
        let threads: Vec<_> = (0..3u8)
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
        drop(signer);

        // Key agreement: the TPM's secret equals the software peer's.
        let agreement = Tpm2KeyAgreement::open(
            &connection,
            StorageRoot::Owner,
            &agreeing,
            AUTH,
            &tpm,
            policy,
        )
        .unwrap();
        let mut peer_scalar = [0u8; 48];
        peer_scalar[47] = 9;
        let mut peer_point = [0u8; 97];
        ic_ec::EcdhP384::public_key(&peer_scalar, &mut peer_point).unwrap();
        let mut from_tpm = [0u8; 48];
        assert_eq!(agreement.agree(&peer_point, &mut from_tpm).unwrap(), 48);
        let mut from_peer = [0u8; 48];
        ic_ec::EcdhP384::agree(&peer_scalar, &agreement.public_key()[23..], &mut from_peer)
            .unwrap();
        assert_eq!(from_tpm, from_peer);
        let mut off_curve = peer_point;
        off_curve[96] ^= 1;
        assert!(agreement.agree(&off_curve, &mut from_tpm).is_err());
        drop(agreement);

        // Refusals: the wrong role, a wrong auth value, a tampered blob.
        let open = |blob: &KeyBlob, auth: &[u8]| {
            Tpm2Signer::open(&connection, StorageRoot::Owner, blob, auth, &tpm, policy)
                .err()
                .map(|e| e.code)
        };
        assert_eq!(open(&agreeing, AUTH), Some("policy_mismatch"));
        assert!(open(&signing, b"a wrong auth value of some length").is_some());
        let mut tampered = signing.clone();
        let last = tampered.private.len() - 1;
        tampered.private[last] ^= 1;
        assert!(open(&tampered, AUTH).is_some());
        // The right auth still works afterwards.
        assert_eq!(open(&signing, AUTH), None);
    }
}
