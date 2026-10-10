//! A TPM 2.0 layer in safe Rust: marshalling, public areas and names,
//! attestation structures, KDFa, RSA-OAEP, AES-CFB, software MakeCredential and,
//! with the `device` feature, a command layer with salted HMAC sessions over the
//! Windows TBS, a Linux TPM device or a swtpm socket.
//!
//! Moved from IronPrivacyGuard's `src/tpm2` (commit `1ffc55e`) with its imports
//! re-rooted and nothing else changed. The key templates are still the ones
//! IronPrivacyGuard uses: P-384 identity keys and an RSA-2048 attestation key.
//!
//! Verifier-only builds (without `device`) use only part of this layer.
#![cfg_attr(not(feature = "device"), allow(dead_code))]
pub mod crypto;
pub mod marshal;
pub mod structures;
#[cfg(feature = "device")]
pub mod tpm;
#[cfg(feature = "device")]
pub mod transport;

use ic_core::Zeroizing;
use ic_core::traits::KeyAgreement as _;

/// An error with a stable code, as IronPrivacyGuard reports them.
#[derive(Debug)]
pub struct Error {
    /// The stable code, such as `invalid_format` or `pin_locked`.
    pub code: &'static str,
    /// A description for a person.
    pub message: String,
    /// Whether repeating the operation unchanged may succeed.
    pub retryable: bool,
}

/// The result of an operation in this crate.
pub type Result<T> = std::result::Result<T, Error>;

impl Error {
    /// A non-retryable error.
    pub fn new(code: &'static str, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
        }
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Self::new(
            if e.kind() == std::io::ErrorKind::AlreadyExists {
                "already_exists"
            } else {
                "io_error"
            },
            e.to_string(),
        )
    }
}

impl From<ic_core::Error> for Error {
    fn from(_: ic_core::Error) -> Self {
        Self::new(
            "authentication_failed",
            "Cryptographic operation rejected its input",
        )
    }
}

/// Fresh random bytes from the operating system, wiped when dropped.
pub(crate) fn random<const N: usize>() -> Result<Zeroizing<[u8; N]>> {
    let unavailable = |_| {
        Error::new(
            "entropy_unavailable",
            "Operating system randomness unavailable",
        )
    };
    let mut out = Zeroizing::new([0; N]);
    // Fresh OS seeding per request avoids inherited generator state after fork.
    ic_drbg::Rng::from_os()
        .map_err(unavailable)?
        .fill(out.get_mut())
        .map_err(unavailable)?;
    Ok(out)
}

/// Require an uncompressed P-384 point on the curve.
pub(crate) fn p384_point(encoded: &[u8]) -> Result<()> {
    if encoded.len() != 97
        || encoded[0] != 0x04
        || ic_ec::p384::AffinePoint::from_sec1(encoded).is_none()
    {
        return Err(Error::new(
            "invalid_format",
            "Expected an uncompressed P-384 point on the curve",
        ));
    }
    Ok(())
}

/// A fresh P-384 key pair: the scalar and its uncompressed public point.
pub(crate) fn p384_ephemeral() -> Result<(Zeroizing<Vec<u8>>, Vec<u8>)> {
    for _ in 0..16 {
        let secret = random::<48>()?;
        let mut public = vec![0; 97];
        if ic_ec::EcdhP384::public_key(secret.get(), &mut public).is_ok() {
            return Ok((Zeroizing::new(secret.to_vec()), public));
        }
    }
    Err(Error::new(
        "entropy_unavailable",
        "Could not draw a valid ephemeral scalar",
    ))
}
