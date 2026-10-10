//! The software provider: private keys held in this process's memory.
//!
//! Signing is IronCrypto's [`SoftwareSigner`], unchanged. This module adds
//! only what custody needs: the provider's description, and loading a key
//! under a host's [`CustodyPolicy`], so a host that excludes software keys
//! refuses one before it is parsed.

pub use ic_sig::SoftwareSigner;

use crate::{CustodyPolicy, Provider, ProviderKind, Result};

/// The description of in-memory keys: software custody, exportable, and no
/// declared validation.
pub const PROVIDER: Provider = Provider::new(ProviderKind::Software);

/// Read a DER PKCS#8 private key as a signer, if `policy` accepts software
/// keys.
///
/// A policy that excludes them refuses with `InvalidParameter` and the key is
/// not parsed. Otherwise the errors are [`SoftwareSigner::from_pkcs8`]'s. The
/// caller wipes `der`; the signer wipes its own copy when dropped.
pub fn from_pkcs8(der: &[u8], policy: CustodyPolicy) -> Result<SoftwareSigner> {
    policy.require(&PROVIDER)?;
    SoftwareSigner::from_pkcs8(der)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Custody, ErrorKind, SignatureAlgorithm, Signer};
    use ic_pkix::{KeyAlgorithm, PrivateKeyInfo};

    /// A P-384 key from a fixed, valid scalar, as PKCS#8.
    fn p384_pkcs8() -> ([u8; 256], usize) {
        let mut der = [0u8; 256];
        let n = PrivateKeyInfo::Ec {
            algorithm: KeyAlgorithm::EcP384,
            private_key: &[0x2a; 48],
            public_key: None,
        }
        .to_der(&mut der)
        .unwrap();
        (der, n)
    }

    #[test]
    fn a_software_key_signs_and_reports_software_custody() {
        let (der, n) = p384_pkcs8();
        let key = from_pkcs8(&der[..n], CustodyPolicy::Any).unwrap();
        assert_eq!(key.custody(), Custody::Software);
        assert_eq!(key.custody(), PROVIDER.custody());
        assert_eq!(key.algorithms(), [SignatureAlgorithm::EcdsaP384Sha384]);

        let mut rng = ic_drbg::Rng::from_os().unwrap();
        let mut signature = [0u8; 160];
        let len = key
            .sign(
                SignatureAlgorithm::EcdsaP384Sha384,
                b"custody",
                &mut rng,
                &mut signature,
            )
            .unwrap();
        ic_sig::verify_spki(
            SignatureAlgorithm::EcdsaP384Sha384,
            key.public_key(),
            b"custody",
            &signature[..len],
        )
        .unwrap();
        assert!(
            ic_sig::verify_spki(
                SignatureAlgorithm::EcdsaP384Sha384,
                key.public_key(),
                b"tampered",
                &signature[..len],
            )
            .is_err()
        );
        // An algorithm the key does not list is refused, not attempted.
        assert!(
            key.sign(
                SignatureAlgorithm::Ed25519,
                b"custody",
                &mut rng,
                &mut signature
            )
            .is_err()
        );
    }

    #[test]
    fn policies_that_exclude_software_keys_refuse_before_parsing() {
        let (der, n) = p384_pkcs8();
        for policy in [
            CustodyPolicy::NonExportable,
            CustodyPolicy::Hardware,
            CustodyPolicy::DeclaredValidated,
        ] {
            // Even bytes that are not a key are refused for the policy first.
            for input in [&der[..n], &b"not a key"[..]] {
                let error = from_pkcs8(input, policy).err().unwrap();
                assert_eq!(error.kind(), ErrorKind::InvalidParameter);
            }
        }
        assert!(from_pkcs8(b"not a key", CustodyPolicy::Any).is_err());
    }
}
