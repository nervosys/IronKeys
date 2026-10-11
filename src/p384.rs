//! P-384 encodings shared by the device providers.

use crate::{Error, ErrorKind, Result};

/// The DER `SubjectPublicKeyInfo` header of a P-384 key: the algorithm
/// identifier (id-ecPublicKey, secp384r1) and the BIT STRING header that the
/// 97-byte uncompressed point follows.
const SPKI_HEADER: [u8; 23] = [
    0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x05, 0x2b,
    0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00,
];

/// The DER `SubjectPublicKeyInfo` of an uncompressed P-384 point.
pub(crate) fn spki(point: &[u8; 97]) -> [u8; 120] {
    let mut out = [0u8; 120];
    out[..23].copy_from_slice(&SPKI_HEADER);
    out[23..].copy_from_slice(point);
    out
}

/// Whether `point` is an uncompressed point on the curve.
pub(crate) fn on_curve(point: &[u8; 97]) -> bool {
    point[0] == 0x04 && ic_ec::p384::AffinePoint::from_sec1(point).is_some()
}

/// A peer's key as an uncompressed point on the curve, or `InvalidParameter`.
pub(crate) fn point(peer: &[u8]) -> Result<[u8; 97]> {
    let point: [u8; 97] = peer.try_into().map_err(|_| {
        Error::new(
            ErrorKind::InvalidParameter,
            "peer key is not an uncompressed P-384 point",
        )
    })?;
    if !on_curve(&point) {
        return Err(Error::new(
            ErrorKind::InvalidParameter,
            "peer key is not a point on P-384",
        ));
    }
    Ok(point)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::KeyAgreement as _;

    #[test]
    fn the_spki_header_wraps_a_p384_point() {
        let mut scalar = [0u8; 48];
        scalar[47] = 7;
        let mut public = [0u8; 97];
        ic_ec::EcdhP384::public_key(&scalar, &mut public).unwrap();
        // IronCrypto reads it back as the same key.
        match ic_pkix::PublicKeyInfo::from_der(&spki(&public)).unwrap() {
            ic_pkix::PublicKeyInfo::Ec {
                algorithm,
                point: p,
            } => {
                assert_eq!(algorithm, ic_pkix::KeyAlgorithm::EcP384);
                assert_eq!(p, &public[..]);
            }
            _ => panic!("not an EC key"),
        }
        assert_eq!(point(&public).unwrap(), public);
        let mut off = public;
        off[96] ^= 1;
        assert!(point(&off).is_err());
        assert!(point(&public[..96]).is_err());
    }
}
