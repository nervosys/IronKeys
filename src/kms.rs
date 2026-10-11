//! The AWS KMS provider: P-384 keys that stay in AWS Key Management Service.
//!
//! A key is named by its exact ARN. [`KmsSigner`] implements [`Signer`] over
//! a `SIGN_VERIFY` key and [`KmsKeyAgreement`] implements [`KeyAgreement`]
//! over a `KEY_AGREEMENT` key. Opening either fetches the public key and
//! checks its spec and usage; each operation after that is one SigV4-signed
//! request over TLS 1.3. Only the SHA-384 digest of a message is sent to be
//! signed, never the message.
//!
//! Keys are bound, not created: a KMS key is a billable account resource,
//! made by infrastructure tooling.
//!
//! # Custody
//!
//! These keys are [`Custody::Service`]: they cannot be exported, but they are
//! held by a remote service rather than local hardware, so
//! [`CustodyPolicy::Hardware`] refuses them. `DeriveSharedSecret` returns the
//! raw shared secret to this process, as any ECDH does.
//!
//! # Scope
//!
//! P-384 only, as in IronPrivacyGuard's backend this is taken from.
//! Credentials and endpoints are found as [`ironkeys_kms`] documents, or set
//! on a [`Client`] passed to `open_with`.

use crate::p384;
use crate::{
    AgreementAlgorithm, Custody, CustodyPolicy, Error, ErrorKind, KeyAgreement, Provider,
    ProviderKind, Result, SignatureAlgorithm, Signer,
};
use ic_core::traits::{Digest, RandomSource};

/// The client the provider's requests go through. Build one to set an
/// endpoint or credentials explicitly.
pub use ironkeys_kms::Client;
/// A failure opening a KMS key, with the client's stable code (such as
/// `authentication_failed` or `policy_mismatch`) and a redacted description.
pub use ironkeys_kms::Error as KmsError;

/// A KMS failure as the shared interface expresses it: `Unsupported` when
/// the key does not offer the operation, `ProviderUnavailable` when KMS or
/// the credential sources could not be reached or KMS asked for a retry
/// (throttling, a 5xx), and `ProviderRefused` otherwise (access denied, a
/// disabled key, a server the TLS client would not trust).
fn service_error(error: &KmsError) -> Error {
    if error.code == "mechanism_unsupported" {
        Error::new(
            ErrorKind::Unsupported,
            "the KMS key does not offer the operation",
        )
    } else if error.retryable || matches!(error.code, "provider_unavailable" | "io_error") {
        Error::new(
            ErrorKind::ProviderUnavailable,
            "AWS KMS could not be reached or could not answer",
        )
    } else {
        Error::new(ErrorKind::ProviderRefused, "AWS KMS refused the operation")
    }
}

/// Check the provider description and policy, then fetch and check the key.
fn bind(
    client: &Client,
    arn: &str,
    usage: &str,
    provider: &Provider,
    policy: CustodyPolicy,
) -> std::result::Result<[u8; 120], KmsError> {
    if provider.kind != ProviderKind::AwsKms || provider.exportable || !policy.permits(provider) {
        return Err(KmsError::new(
            "policy_mismatch",
            "The host's custody policy does not accept this key provider",
        ));
    }
    // The client is for one region; a key elsewhere would be signed for the
    // wrong endpoint.
    ironkeys_kms::parse_arn(arn)?;
    let point: [u8; 97] = client
        .p384_public_point(arn, usage)?
        .try_into()
        .map_err(|_| KmsError::new("provider_error", "Unexpected KMS public key encoding"))?;
    Ok(p384::spki(&point))
}

/// A P-384 signing key held in AWS KMS.
pub struct KmsSigner {
    client: Client,
    arn: String,
    spki: [u8; 120],
}

impl KmsSigner {
    /// Bind to the `SIGN_VERIFY` key at `arn`, with credentials and endpoint
    /// taken from the environment.
    ///
    /// `provider` describes the service (including any validation its
    /// operator declares) and must be accepted by `policy`.
    pub fn open(
        arn: &str,
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, KmsError> {
        Self::open_with(Client::for_key(arn)?, arn, provider, policy)
    }

    /// As [`KmsSigner::open`], through a client the caller configured.
    pub fn open_with(
        client: Client,
        arn: &str,
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, KmsError> {
        let spki = bind(&client, arn, "SIGN_VERIFY", provider, policy)?;
        Ok(Self {
            client,
            arn: arn.into(),
            spki,
        })
    }
}

impl Signer for KmsSigner {
    fn algorithms(&self) -> &[SignatureAlgorithm] {
        &[SignatureAlgorithm::EcdsaP384Sha384]
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn custody(&self) -> Custody {
        Custody::Service
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
                "this KMS key signs only ECDSA P-384 with SHA-384",
            ));
        }
        if out.len() < algorithm.max_signature_len() {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "signature buffer is too short",
            ));
        }
        // ECDSA_SHA_384 over the SHA-384 digest is ECDSA-SHA384 over the message.
        let mut digest = [0u8; 48];
        digest.copy_from_slice(ic_hash::Sha384::digest(message).as_ref());
        let raw = self
            .client
            .sign_p384_digest(&self.arn, &digest)
            .map_err(|e| service_error(&e))?;
        // KMS is remote: accept only a signature that verifies under the key
        // this was opened with.
        let point = &self.spki[self.spki.len() - 97..];
        ic_ec::EcdsaP384Sha384::verify_prehash(point, &digest, &raw).map_err(|_| {
            Error::new(
                ErrorKind::ProviderRefused,
                "AWS KMS returned a signature that does not verify under the bound key",
            )
        })?;
        ic_pkix::ecdsa_signature::to_der(&raw, out)
    }
}

/// A P-384 key-agreement key held in AWS KMS.
pub struct KmsKeyAgreement {
    client: Client,
    arn: String,
    spki: [u8; 120],
}

impl KmsKeyAgreement {
    /// Bind to the `KEY_AGREEMENT` key at `arn`, with credentials and
    /// endpoint taken from the environment. See [`KmsSigner::open`].
    pub fn open(
        arn: &str,
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, KmsError> {
        Self::open_with(Client::for_key(arn)?, arn, provider, policy)
    }

    /// As [`KmsKeyAgreement::open`], through a client the caller configured.
    pub fn open_with(
        client: Client,
        arn: &str,
        provider: &Provider,
        policy: CustodyPolicy,
    ) -> std::result::Result<Self, KmsError> {
        let spki = bind(&client, arn, "KEY_AGREEMENT", provider, policy)?;
        Ok(Self {
            client,
            arn: arn.into(),
            spki,
        })
    }
}

impl KeyAgreement for KmsKeyAgreement {
    fn algorithm(&self) -> AgreementAlgorithm {
        AgreementAlgorithm::EcdhP384
    }

    fn public_key(&self) -> &[u8] {
        &self.spki
    }

    fn custody(&self) -> Custody {
        Custody::Service
    }

    fn agree(&self, peer_public: &[u8], out: &mut [u8]) -> Result<usize> {
        if out.len() < 48 {
            return Err(Error::new(
                ErrorKind::InvalidLength,
                "shared-secret buffer is too short",
            ));
        }
        let peer = p384::point(peer_public)?;
        let shared = self
            .client
            .derive_shared_secret(&self.arn, &peer)
            .map_err(|e| service_error(&e))?;
        // The client has checked the length; `shared` is wiped when dropped.
        out[..48].copy_from_slice(&shared);
        Ok(48)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Validation;
    use ic_core::codec::{b64, unb64};
    use ic_core::traits::{KeyAgreement as _, SignatureScheme as _};
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::{Arc, Mutex};

    const SIGNING: &str =
        "arn:aws:kms:us-east-1:111122223333:key/11111111-1111-1111-1111-111111111111";
    const AGREEMENT: &str =
        "arn:aws:kms:us-east-1:111122223333:key/22222222-2222-2222-2222-222222222222";
    const P256: &str =
        "arn:aws:kms:us-east-1:111122223333:key/33333333-3333-3333-3333-333333333333";
    const DENIED: &str =
        "arn:aws:kms:us-east-1:111122223333:key/44444444-4444-4444-4444-444444444444";
    const MLDSA: &str =
        "arn:aws:kms:us-east-1:111122223333:key/55555555-5555-5555-5555-555555555555";
    const MESSAGE: &[u8] = b"held in KMS";

    fn scalar(last: u8) -> [u8; 48] {
        let mut scalar = [0x5a; 48];
        scalar[0] = 0;
        scalar[47] = last;
        scalar
    }

    fn public(scalar: &[u8; 48]) -> [u8; 97] {
        let mut point = [0u8; 97];
        ic_ec::EcdhP384::public_key(scalar, &mut point).unwrap();
        point
    }

    /// What the mock was asked, for the test to inspect.
    #[derive(Default)]
    struct Seen {
        requests: Vec<(String, String, String)>,
        /// When set, the next `Sign` fails with this error type and status.
        fail_sign: Option<(u16, &'static str)>,
        /// When set, `Sign` answers with a signature by another key.
        forge: bool,
    }

    fn member(body: &ic_json::Json, name: &str) -> String {
        body.get(name)
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string()
    }

    /// Answer one KMS action as AWS would, with software keys.
    fn answer(seen: &Mutex<Seen>, action: &str, body: &ic_json::Json) -> (u16, String) {
        let error = |status, kind: &str| {
            (
                status,
                format!(
                    r#"{{"__type":"{kind}","message":"refused for arn:aws:kms:us-east-1:111122223333:key/x"}}"#
                ),
            )
        };
        let key = member(body, "KeyId");
        if key == DENIED {
            return error(400, "AccessDeniedException");
        }
        let json = |pairs: &[(&str, String)]| {
            let fields: Vec<String> = pairs
                .iter()
                .map(|(k, v)| format!(r#""{k}":"{v}""#))
                .collect();
            (200, format!("{{{}}}", fields.join(",")))
        };
        match action {
            "TrentService.GetPublicKey" if key == MLDSA => {
                // id-ml-dsa-65 SubjectPublicKeyInfo around a 1952-byte key.
                let mut spki = vec![
                    0x30, 0x82, 0x07, 0xb2, 0x30, 0x0b, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65,
                    0x03, 0x04, 0x03, 0x12, 0x03, 0x82, 0x07, 0xa1, 0x00,
                ];
                spki.extend_from_slice(&[0x6b; 1952]);
                json(&[
                    ("KeySpec", "ML_DSA_65".into()),
                    ("KeyUsage", "SIGN_VERIFY".into()),
                    ("PublicKey", b64(&spki)),
                ])
            }
            "TrentService.Sign" if key == MLDSA => {
                assert_eq!(member(body, "MessageType"), "EXTERNAL_MU");
                assert_eq!(member(body, "SigningAlgorithm"), "ML_DSA_SHAKE_256");
                assert_eq!(unb64(&member(body, "Message")).unwrap(), [0x3c; 64]);
                // The mock does not hold an ML-DSA key: the client's handling
                // of the call is under test, not the signature.
                json(&[("Signature", b64(&[0x7e; 3309]))])
            }
            "TrentService.GetPublicKey" => {
                let (spec, usage, scalar) = match key.as_str() {
                    SIGNING => ("ECC_NIST_P384", "SIGN_VERIFY", scalar(1)),
                    AGREEMENT => ("ECC_NIST_P384", "KEY_AGREEMENT", scalar(2)),
                    P256 => ("ECC_NIST_P256", "SIGN_VERIFY", scalar(1)),
                    _ => return error(400, "NotFoundException"),
                };
                json(&[
                    ("KeySpec", spec.into()),
                    ("KeyUsage", usage.into()),
                    ("PublicKey", b64(&p384::spki(&public(&scalar)))),
                ])
            }
            "TrentService.Sign" => {
                let mut seen = seen.lock().unwrap();
                if let Some((status, kind)) = seen.fail_sign.take() {
                    return error(status, kind);
                }
                assert_eq!(member(body, "MessageType"), "DIGEST");
                assert_eq!(member(body, "SigningAlgorithm"), "ECDSA_SHA_384");
                // Only the digest arrives. IronCrypto signs messages, so the
                // mock signs the one message whose digest it expects.
                assert_eq!(
                    unb64(&member(body, "Message")).unwrap(),
                    ic_hash::Sha384::digest(MESSAGE).as_ref()
                );
                let mut raw = [0u8; 96];
                let key = if seen.forge { scalar(9) } else { scalar(1) };
                ic_ec::EcdsaP384Sha384::sign(&key, MESSAGE, &mut raw).unwrap();
                let mut der = [0u8; 104];
                let n = ic_pkix::ecdsa_signature::to_der(&raw, &mut der).unwrap();
                json(&[("Signature", b64(&der[..n]))])
            }
            "TrentService.DeriveSharedSecret" => {
                assert_eq!(member(body, "KeyAgreementAlgorithm"), "ECDH");
                let spki = unb64(&member(body, "PublicKey")).unwrap();
                let mut shared = [0u8; 48];
                ic_ec::EcdhP384::agree(&scalar(2), &spki[spki.len() - 97..], &mut shared).unwrap();
                json(&[("SharedSecret", b64(&shared))])
            }
            _ => error(400, "UnknownOperationException"),
        }
    }

    /// A KMS endpoint on loopback, serving until the test process exits.
    fn mock() -> (String, Arc<Mutex<Seen>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://127.0.0.1:{}", listener.local_addr().unwrap().port());
        let seen = Arc::new(Mutex::new(Seen::default()));
        let shared = seen.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let mut stream = stream.unwrap();
                let mut request = Vec::new();
                let mut chunk = [0u8; 4096];
                let (head, body) = loop {
                    let n = stream.read(&mut chunk).unwrap();
                    assert!(n > 0, "request ended early");
                    request.extend_from_slice(&chunk[..n]);
                    let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") else {
                        continue;
                    };
                    let head = String::from_utf8(request[..end].to_vec()).unwrap();
                    let length: usize = head
                        .lines()
                        .find_map(|l| l.strip_prefix("content-length: "))
                        .unwrap()
                        .parse()
                        .unwrap();
                    if request.len() >= end + 4 + length {
                        break (head, request[end + 4..end + 4 + length].to_vec());
                    }
                };
                let header = |name: &str| {
                    head.lines()
                        .find_map(|l| l.strip_prefix(name))
                        .unwrap_or("")
                        .to_string()
                };
                let action = header("x-amz-target: ");
                shared.lock().unwrap().requests.push((
                    action.clone(),
                    header("authorization: "),
                    header("x-amz-security-token: "),
                ));
                let body = ic_json::parse(std::str::from_utf8(&body).unwrap()).unwrap();
                let (status, text) = answer(&shared, &action, &body);
                write!(
                    stream,
                    "HTTP/1.1 {status} X\r\ncontent-type: application/x-amz-json-1.1\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{text}",
                    text.len()
                )
                .unwrap();
            }
        });
        (url, seen)
    }

    fn client(url: &str, arn: &str) -> Client {
        Client::for_key(arn)
            .unwrap()
            .with_endpoint(url)
            .unwrap()
            .with_credentials("AKIDEXAMPLE", "secret", Some("session-token"))
    }

    const SERVICE: Provider = Provider::new(ProviderKind::AwsKms);

    #[test]
    fn kms_failures_say_whether_a_retry_is_safe() {
        let kind = |code| service_error(&KmsError::new(code, "x")).kind();
        assert_eq!(kind("mechanism_unsupported"), ErrorKind::Unsupported);
        for code in ["provider_unavailable", "io_error"] {
            assert_eq!(kind(code), ErrorKind::ProviderUnavailable);
            assert!(kind(code).retryable());
        }
        // Access denied, a disabled key or an untrusted server must not be
        // retried.
        for code in [
            "authentication_failed",
            "policy_mismatch",
            "key_not_trusted",
            "provider_error",
        ] {
            assert_eq!(kind(code), ErrorKind::ProviderRefused);
            assert!(!kind(code).retryable());
        }
        let mut throttled = KmsError::new("provider_error", "x");
        throttled.retryable = true;
        assert_eq!(
            service_error(&throttled).kind(),
            ErrorKind::ProviderUnavailable
        );
    }

    #[test]
    fn a_policy_or_provider_mismatch_is_refused_before_kms_is_reached() {
        // Nothing listens here, so reaching it would be a network error.
        let unreachable = || {
            Client::for_key(SIGNING)
                .unwrap()
                .with_endpoint("http://127.0.0.1:1")
                .unwrap()
                .with_credentials("AKIDEXAMPLE", "secret", None)
        };
        let code = |provider: Provider, policy| {
            KmsSigner::open_with(unreachable(), SIGNING, &provider, policy)
                .err()
                .unwrap()
                .code
        };
        for (provider, policy) in [
            (Provider::new(ProviderKind::Software), CustodyPolicy::Any),
            (Provider::new(ProviderKind::Pkcs11), CustodyPolicy::Any),
            // A service key is not local hardware.
            (SERVICE, CustodyPolicy::Hardware),
            (SERVICE, CustodyPolicy::DeclaredValidated),
        ] {
            assert_eq!(code(provider, policy), "policy_mismatch");
        }
        let reached = KmsSigner::open_with(
            unreachable(),
            SIGNING,
            &SERVICE,
            CustodyPolicy::NonExportable,
        )
        .err()
        .unwrap();
        assert_eq!(reached.code, "provider_error");
        assert!(reached.retryable);
        // Aliases can be repointed, so only exact key ARNs are bound.
        assert_eq!(
            KmsSigner::open("alias/signing", &SERVICE, CustodyPolicy::Any)
                .err()
                .unwrap()
                .code,
            "invalid_request"
        );
    }

    #[test]
    fn a_kms_key_signs_and_agrees_without_leaving_the_service() {
        let (url, seen) = mock();
        let declared = SERVICE.with_validation(Validation::fips140(3, 3, 1).unwrap());

        // Signing: verified by IronCrypto against the key KMS reports.
        let signer: Arc<dyn Signer> = Arc::new(
            KmsSigner::open_with(
                client(&url, SIGNING),
                SIGNING,
                &declared,
                CustodyPolicy::DeclaredValidated,
            )
            .unwrap(),
        );
        assert_eq!(signer.custody(), Custody::Service);
        assert_eq!(signer.public_key(), p384::spki(&public(&scalar(1))));
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut signature = [0u8; 104];
        let n = signer
            .sign(
                SignatureAlgorithm::EcdsaP384Sha384,
                MESSAGE,
                &mut rng,
                &mut signature,
            )
            .unwrap();
        ic_sig::verify_spki(
            SignatureAlgorithm::EcdsaP384Sha384,
            signer.public_key(),
            MESSAGE,
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
        // Requests carry the configured credentials, SigV4-signed.
        {
            let seen = seen.lock().unwrap();
            let (action, authorization, token) = seen.requests.last().unwrap();
            assert_eq!(action, "TrentService.Sign");
            assert!(authorization.starts_with("AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/"));
            assert!(authorization.contains("/us-east-1/kms/aws4_request"));
            assert_eq!(token, "session-token");
        }
        // Refusals of the interface's own, before any request.
        let before = seen.lock().unwrap().requests.len();
        assert_eq!(
            signer
                .sign(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    MESSAGE,
                    &mut rng,
                    &mut [0u8; 8]
                )
                .unwrap_err()
                .kind(),
            ErrorKind::InvalidLength
        );
        assert_eq!(seen.lock().unwrap().requests.len(), before);

        // Throttling may be retried; a denial may not.
        for (status, kind, expected) in [
            (400, "ThrottlingException", ErrorKind::ProviderUnavailable),
            (500, "KMSInternalException", ErrorKind::ProviderUnavailable),
            (400, "AccessDeniedException", ErrorKind::ProviderRefused),
            (400, "KMSInvalidStateException", ErrorKind::ProviderRefused),
            (400, "InvalidKeyUsageException", ErrorKind::Unsupported),
        ] {
            seen.lock().unwrap().fail_sign = Some((status, kind));
            let error = signer
                .sign(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    MESSAGE,
                    &mut rng,
                    &mut signature,
                )
                .unwrap_err();
            assert_eq!(error.kind(), expected, "{kind}");
        }
        // A signature by some other key is not passed on.
        seen.lock().unwrap().forge = true;
        assert_eq!(
            signer
                .sign(
                    SignatureAlgorithm::EcdsaP384Sha384,
                    MESSAGE,
                    &mut rng,
                    &mut signature
                )
                .unwrap_err()
                .kind(),
            ErrorKind::ProviderRefused
        );
        seen.lock().unwrap().forge = false;

        // Agreement: both sides reach the same secret.
        let agreement = KmsKeyAgreement::open_with(
            client(&url, AGREEMENT),
            AGREEMENT,
            &SERVICE,
            CustodyPolicy::NonExportable,
        )
        .unwrap();
        assert_eq!(agreement.custody(), Custody::Service);
        let peer = scalar(7);
        let mut ours = [0u8; 48];
        assert_eq!(agreement.agree(&public(&peer), &mut ours).unwrap(), 48);
        let mut theirs = [0u8; 48];
        let point = &agreement.public_key()[23..];
        ic_ec::EcdhP384::agree(&peer, point, &mut theirs).unwrap();
        assert_eq!(ours, theirs);
        // A peer key off the curve never reaches KMS.
        let before = seen.lock().unwrap().requests.len();
        let mut off = public(&peer);
        off[96] ^= 1;
        assert_eq!(
            agreement.agree(&off, &mut ours).unwrap_err().kind(),
            ErrorKind::InvalidParameter
        );
        assert_eq!(seen.lock().unwrap().requests.len(), before);

        // A key is bound only in the role and curve it was made for.
        let open = |arn: &str| {
            KmsSigner::open_with(client(&url, arn), arn, &SERVICE, CustodyPolicy::Any)
                .err()
                .unwrap()
        };
        assert_eq!(open(AGREEMENT).code, "policy_mismatch");
        assert_eq!(open(P256).code, "mechanism_unsupported");
        let denied = open(DENIED);
        assert_eq!(denied.code, "authentication_failed");
        // AWS text is redacted: the ARN in the mock's message is not echoed.
        assert!(
            !denied.message.contains("111122223333"),
            "{}",
            denied.message
        );
    }

    #[test]
    fn the_client_fetches_and_signs_with_an_ml_dsa_key() {
        let (url, seen) = mock();
        let client = client(&url, MLDSA).with_fips(false);
        assert_eq!(client.mldsa65_public_key(MLDSA).unwrap(), [0x6b; 1952]);
        assert_eq!(
            client.sign_mldsa65_mu(MLDSA, &[0x3c; 64]).unwrap(),
            [0x7e; 3309]
        );
        assert_eq!(
            seen.lock().unwrap().requests.last().unwrap().0,
            "TrentService.Sign"
        );
        // An ML-DSA key is not a P-384 key, and a P-384 key is not an ML-DSA one.
        assert_eq!(
            client
                .p384_public_point(MLDSA, "SIGN_VERIFY")
                .unwrap_err()
                .code,
            "mechanism_unsupported"
        );
        assert_eq!(
            client.mldsa65_public_key(SIGNING).unwrap_err().code,
            "mechanism_unsupported"
        );
    }

    /// Against AWS itself, over TLS: set IRONKEYS_TEST_KMS_SIGNING_ARN and
    /// IRONKEYS_TEST_KMS_AGREEMENT_ARN to ECC_NIST_P384 keys the host's
    /// credentials may use. Each run makes billable KMS requests.
    #[test]
    fn real_kms_keys_sign_and_agree() {
        let (Ok(signing), Ok(agreement)) = (
            std::env::var("IRONKEYS_TEST_KMS_SIGNING_ARN"),
            std::env::var("IRONKEYS_TEST_KMS_AGREEMENT_ARN"),
        ) else {
            return;
        };
        let signer = KmsSigner::open(&signing, &SERVICE, CustodyPolicy::NonExportable).unwrap();
        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut signature = [0u8; 104];
        let n = signer
            .sign(
                SignatureAlgorithm::EcdsaP384Sha384,
                MESSAGE,
                &mut rng,
                &mut signature,
            )
            .unwrap();
        ic_sig::verify_spki(
            SignatureAlgorithm::EcdsaP384Sha384,
            signer.public_key(),
            MESSAGE,
            &signature[..n],
        )
        .unwrap();
        let key =
            KmsKeyAgreement::open(&agreement, &SERVICE, CustodyPolicy::NonExportable).unwrap();
        let peer = scalar(7);
        let (mut ours, mut theirs) = ([0u8; 48], [0u8; 48]);
        key.agree(&public(&peer), &mut ours).unwrap();
        ic_ec::EcdhP384::agree(&peer, &key.public_key()[23..], &mut theirs).unwrap();
        assert_eq!(ours, theirs);
    }
}
