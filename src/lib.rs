//! Key custody for the IronSecurity stack.
//!
//! A private key may live in process memory, in a hardware device (an HSM, a
//! TPM, a smart card) or in a remote key service. Code that signs or agrees on
//! a secret should not need to know which. This crate is the interface those
//! callers are written against, the description of each provider, and the
//! policy a host uses to refuse providers it does not accept.
//!
//! Signing uses IronCrypto's [`Signer`] unchanged. This crate adds
//! [`KeyAgreement`] for ECDH keys, [`Provider`] to describe a backend, and
//! [`CustodyPolicy`].
//!
//! # Status
//!
//! The interface, the provider descriptions, the policy and the software
//! provider (the `software` feature) are here. The device and service
//! backends (PKCS#11, TPM 2.0, AWS KMS, Windows CNG) are being moved from
//! IronPrivacyGuard; see `docs/DESIGN.md`.
//!
//! Nothing here performs cryptography, and nothing here is validated.
//! [`Validation`] records what an operator declares about a module; this crate
//! cannot check it.
#![cfg_attr(not(feature = "std"), no_std)]

pub use ic_core::sig::{Custody, SignatureAlgorithm, Signer};
pub use ic_core::{Error, ErrorKind, Result};

#[cfg(feature = "software")]
pub mod software;

/// A key-agreement algorithm.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum AgreementAlgorithm {
    /// ECDH over P-256.
    EcdhP256,
    /// ECDH over P-384.
    EcdhP384,
    /// ECDH over P-521.
    EcdhP521,
    /// X25519.
    X25519,
}

impl AgreementAlgorithm {
    /// Every algorithm, for callers that enumerate them.
    pub const ALL: &'static [Self] =
        &[Self::EcdhP256, Self::EcdhP384, Self::EcdhP521, Self::X25519];

    /// The IronCrypto ontology identifier of the algorithm.
    pub const fn id(self) -> &'static str {
        match self {
            Self::EcdhP256 => "ecdh-p256",
            Self::EcdhP384 => "ecdh-p384",
            Self::EcdhP521 => "ecdh-p521",
            Self::X25519 => "x25519",
        }
    }

    /// The algorithm with this identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|a| a.id() == id)
    }

    /// Length of the raw shared secret in bytes.
    pub const fn shared_secret_len(self) -> usize {
        match self {
            Self::EcdhP256 | Self::X25519 => 32,
            Self::EcdhP384 => 48,
            Self::EcdhP521 => 66,
        }
    }
}

/// A private key that agrees on a shared secret, wherever it lives.
///
/// The counterpart of [`Signer`] for key agreement. The shared secret is the
/// raw output of the primitive: callers derive keys from it with a KDF and
/// never use it directly.
pub trait KeyAgreement: Send + Sync {
    /// The algorithm this key agrees with.
    fn algorithm(&self) -> AgreementAlgorithm;

    /// The public key, as a DER `SubjectPublicKeyInfo`.
    fn public_key(&self) -> &[u8];

    /// Where the private key lives.
    fn custody(&self) -> Custody;

    /// Agree with `peer_public`, the peer's key in the algorithm's wire form
    /// (an uncompressed SEC1 point, or 32 bytes for X25519), writing the raw
    /// shared secret to the front of `out` and returning its length.
    ///
    /// The peer key must be validated before use: a point not on the curve,
    /// or a low-order X25519 key, is refused with `InvalidParameter`. `out`
    /// shorter than [`AgreementAlgorithm::shared_secret_len`] is refused with
    /// `InvalidLength`, with nothing written. The caller wipes `out`.
    fn agree(&self, peer_public: &[u8], out: &mut [u8]) -> Result<usize>;
}

/// The kind of place a provider keeps keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProviderKind {
    /// Keys in this process's memory.
    Software,
    /// A PKCS#11 token or HSM, through a vendor module.
    Pkcs11,
    /// A TPM 2.0.
    Tpm2,
    /// Windows CNG, including the Platform Crypto Provider.
    WindowsCng,
    /// AWS Key Management Service.
    AwsKms,
}

impl ProviderKind {
    /// Every kind, for callers that enumerate them.
    pub const ALL: &'static [Self] = &[
        Self::Software,
        Self::Pkcs11,
        Self::Tpm2,
        Self::WindowsCng,
        Self::AwsKms,
    ];

    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Software => "software",
            Self::Pkcs11 => "pkcs11",
            Self::Tpm2 => "tpm2",
            Self::WindowsCng => "windows-cng",
            Self::AwsKms => "aws-kms",
        }
    }

    /// The kind with this identifier.
    pub fn from_id(id: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|k| k.id() == id)
    }

    /// Where keys of this kind live.
    pub const fn custody(self) -> Custody {
        match self {
            Self::Software => Custody::Software,
            Self::Pkcs11 | Self::Tpm2 | Self::WindowsCng => Custody::Hardware,
            Self::AwsKms => Custody::Service,
        }
    }
}

/// What an operator declares about a module's FIPS 140 validation.
///
/// This is a declaration carried for policy and evidence, not a finding.
/// Nothing in this crate can check a certificate number against a device, and
/// a provider kind alone never implies validation: the same PKCS#11 interface
/// fronts validated HSMs and software tokens alike.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Validation {
    /// Not validated, or nothing is known.
    None,
    /// The operator declares a FIPS 140 validation for this module.
    Fips140 {
        /// The standard's revision: 2 for FIPS 140-2, 3 for FIPS 140-3.
        revision: u8,
        /// The overall security level, 1 to 4.
        level: u8,
        /// The CMVP certificate number.
        certificate: u32,
    },
}

impl Validation {
    /// A declared FIPS 140 validation, refusing values that cannot be one.
    pub fn fips140(revision: u8, level: u8, certificate: u32) -> Result<Self> {
        if !matches!(revision, 2 | 3) || !(1..=4).contains(&level) || certificate == 0 {
            return Err(Error::new(
                ErrorKind::InvalidParameter,
                "FIPS 140 revision is 2 or 3, level 1..4, certificate nonzero",
            ));
        }
        Ok(Self::Fips140 {
            revision,
            level,
            certificate,
        })
    }

    /// Whether a validation is declared.
    pub const fn is_declared(self) -> bool {
        matches!(self, Self::Fips140 { .. })
    }
}

/// A description of one configured provider: where its keys live, whether
/// they can leave it, and what its operator declares about validation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Provider {
    /// The kind of provider.
    pub kind: ProviderKind,
    /// Whether private keys can be exported from it in usable form.
    pub exportable: bool,
    /// The operator's declared validation of the module.
    pub validation: Validation,
}

impl Provider {
    /// A provider of `kind` with that kind's usual properties and no declared
    /// validation: software keys are exportable, device and service keys are
    /// not.
    pub const fn new(kind: ProviderKind) -> Self {
        Self {
            kind,
            exportable: matches!(kind, ProviderKind::Software),
            validation: Validation::None,
        }
    }

    /// The same provider with a declared validation.
    pub const fn with_validation(mut self, validation: Validation) -> Self {
        self.validation = validation;
        self
    }

    /// Where this provider's keys live.
    pub const fn custody(&self) -> Custody {
        self.kind.custody()
    }
}

/// Which providers a host accepts for private-key operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
#[non_exhaustive]
pub enum CustodyPolicy {
    /// Any provider.
    #[default]
    Any,
    /// Only providers whose keys cannot be exported.
    NonExportable,
    /// Only local hardware: no software keys and no remote service.
    Hardware,
    /// Only providers whose operator declares a FIPS 140 validation and whose
    /// keys cannot be exported.
    DeclaredValidated,
}

impl CustodyPolicy {
    /// Stable identifier used in every serialized form.
    pub const fn id(self) -> &'static str {
        match self {
            Self::Any => "any",
            Self::NonExportable => "non-exportable",
            Self::Hardware => "hardware",
            Self::DeclaredValidated => "declared-validated",
        }
    }

    /// Whether this policy accepts `provider`.
    pub fn permits(self, provider: &Provider) -> bool {
        match self {
            Self::Any => true,
            Self::NonExportable => !provider.exportable,
            Self::Hardware => !provider.exportable && provider.custody() == Custody::Hardware,
            Self::DeclaredValidated => !provider.exportable && provider.validation.is_declared(),
        }
    }

    /// Accept `provider` or refuse it with `InvalidParameter`.
    pub fn require(self, provider: &Provider) -> Result<()> {
        if self.permits(provider) {
            Ok(())
        } else {
            Err(Error::new(
                ErrorKind::InvalidParameter,
                "the host's custody policy does not accept this key provider",
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_unique_and_round_trip() {
        for kind in ProviderKind::ALL {
            assert_eq!(ProviderKind::from_id(kind.id()), Some(*kind));
        }
        for algorithm in AgreementAlgorithm::ALL {
            assert_eq!(
                AgreementAlgorithm::from_id(algorithm.id()),
                Some(*algorithm)
            );
        }
        assert_eq!(ProviderKind::from_id("unknown"), None);
        assert_eq!(AgreementAlgorithm::EcdhP384.shared_secret_len(), 48);
    }

    #[test]
    fn providers_describe_custody_and_exportability() {
        let software = Provider::new(ProviderKind::Software);
        assert!(software.exportable);
        assert_eq!(software.custody(), Custody::Software);
        for kind in [
            ProviderKind::Pkcs11,
            ProviderKind::Tpm2,
            ProviderKind::WindowsCng,
        ] {
            let provider = Provider::new(kind);
            assert!(!provider.exportable);
            assert_eq!(provider.custody(), Custody::Hardware);
            assert_eq!(provider.validation, Validation::None);
        }
        assert_eq!(
            Provider::new(ProviderKind::AwsKms).custody(),
            Custody::Service
        );
    }

    #[test]
    fn a_provider_kind_never_implies_validation() {
        // Validation is only ever what an operator declares.
        for kind in ProviderKind::ALL {
            assert!(!Provider::new(*kind).validation.is_declared());
        }
        assert!(Validation::fips140(3, 3, 4567).unwrap().is_declared());
        for (revision, level, certificate) in
            [(1, 3, 1), (4, 3, 1), (3, 0, 1), (3, 5, 1), (3, 3, 0)]
        {
            assert!(Validation::fips140(revision, level, certificate).is_err());
        }
    }

    #[test]
    fn custody_policies_refuse_what_they_exclude() {
        let software = Provider::new(ProviderKind::Software);
        let token = Provider::new(ProviderKind::Pkcs11);
        let service = Provider::new(ProviderKind::AwsKms);
        let validated = token.with_validation(Validation::fips140(3, 3, 4567).unwrap());

        assert!(CustodyPolicy::Any.permits(&software));
        assert!(!CustodyPolicy::NonExportable.permits(&software));
        assert!(CustodyPolicy::NonExportable.permits(&token));
        assert!(CustodyPolicy::NonExportable.permits(&service));
        assert!(CustodyPolicy::Hardware.permits(&token));
        assert!(!CustodyPolicy::Hardware.permits(&service));
        assert!(!CustodyPolicy::DeclaredValidated.permits(&token));
        assert!(CustodyPolicy::DeclaredValidated.permits(&validated));
        // A software provider cannot become acceptable by declaring validation.
        let declared_software = software.with_validation(Validation::fips140(3, 1, 1).unwrap());
        assert!(!CustodyPolicy::DeclaredValidated.permits(&declared_software));
        assert!(CustodyPolicy::Hardware.require(&service).is_err());
        assert!(CustodyPolicy::Hardware.require(&token).is_ok());
        assert_eq!(CustodyPolicy::default(), CustodyPolicy::Any);
    }
}
