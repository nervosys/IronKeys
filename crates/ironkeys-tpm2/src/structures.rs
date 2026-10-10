//! TPM 2.0 public areas, attestation structures, signatures and the templates IPG
//! uses. Parsing is strict: unknown algorithms and trailing bytes are refused.
use super::marshal::{Reader, Writer};
use crate::{Error, Result};
use ic_core::traits::Digest;
use ic_hash::{Sha256, Sha384};

pub const ALG_RSA: u16 = 0x0001;
pub const ALG_SHA256: u16 = 0x000b;
pub const ALG_SHA384: u16 = 0x000c;
pub const ALG_NULL: u16 = 0x0010;
pub const ALG_RSASSA: u16 = 0x0014;
pub const ALG_ECDSA: u16 = 0x0018;
pub const ALG_ECC: u16 = 0x0023;
pub const ALG_AES: u16 = 0x0006;
pub const ALG_CFB: u16 = 0x0043;
pub const CURVE_P384: u16 = 0x0004;

pub const FIXED_TPM: u32 = 1 << 1;
pub const FIXED_PARENT: u32 = 1 << 4;
pub const SENSITIVE_DATA_ORIGIN: u32 = 1 << 5;
pub const USER_WITH_AUTH: u32 = 1 << 6;
pub const ADMIN_WITH_POLICY: u32 = 1 << 7;
pub const NO_DA: u32 = 1 << 10;
pub const RESTRICTED: u32 = 1 << 16;
pub const DECRYPT: u32 = 1 << 17;
pub const SIGN: u32 = 1 << 18;

/// `TPM_GENERATED_VALUE`: every structure a TPM signs with a restricted key starts
/// with it, and a restricted key refuses to sign external data that does.
pub const GENERATED: u32 = 0xff54_4347;
pub const ST_ATTEST_CERTIFY: u16 = 0x8017;

fn malformed(message: &str) -> Error {
    Error::new("invalid_format", format!("TPM structure: {message}"))
}

/// The digest of a name algorithm.
pub fn hash(algorithm: u16, data: &[u8]) -> Result<Vec<u8>> {
    match algorithm {
        ALG_SHA256 => Ok(Sha256::digest(data).as_ref().to_vec()),
        ALG_SHA384 => Ok(Sha384::digest(data).as_ref().to_vec()),
        _ => Err(malformed("unsupported hash algorithm")),
    }
}
pub fn digest_len(algorithm: u16) -> Result<usize> {
    match algorithm {
        ALG_SHA256 => Ok(32),
        ALG_SHA384 => Ok(48),
        _ => Err(malformed("unsupported hash algorithm")),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Symmetric {
    pub algorithm: u16,
    pub bits: u16,
    pub mode: u16,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Key {
    Rsa {
        bits: u16,
        exponent: u32,
        modulus: Vec<u8>,
    },
    Ecc {
        curve: u16,
        kdf: u16,
        x: Vec<u8>,
        y: Vec<u8>,
    },
}

/// A parsed `TPMT_PUBLIC`, keeping its exact bytes for the name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Public {
    pub raw: Vec<u8>,
    pub name_algorithm: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub symmetric: Option<Symmetric>,
    /// Signing or decryption scheme and its hash, or `ALG_NULL`.
    pub scheme: (u16, u16),
    pub key: Key,
}
impl Public {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        let kind = r.u16()?;
        let name_algorithm = r.u16()?;
        digest_len(name_algorithm)?;
        let attributes = r.u32()?;
        let auth_policy = r.tpm2b()?.to_vec();
        let symmetric = match r.u16()? {
            ALG_NULL => None,
            algorithm => Some(Symmetric {
                algorithm,
                bits: r.u16()?,
                mode: r.u16()?,
            }),
        };
        let scheme = match r.u16()? {
            ALG_NULL => (ALG_NULL, ALG_NULL),
            algorithm @ (ALG_RSASSA | ALG_ECDSA) => (algorithm, r.u16()?),
            _ => return Err(malformed("unsupported scheme")),
        };
        let key = match kind {
            ALG_RSA => {
                let bits = r.u16()?;
                let exponent = r.u32()?;
                Key::Rsa {
                    bits,
                    exponent,
                    modulus: r.tpm2b()?.to_vec(),
                }
            }
            ALG_ECC => {
                let curve = r.u16()?;
                let kdf = match r.u16()? {
                    ALG_NULL => ALG_NULL,
                    _ => return Err(malformed("unsupported ECC KDF")),
                };
                Key::Ecc {
                    curve,
                    kdf,
                    x: r.tpm2b()?.to_vec(),
                    y: r.tpm2b()?.to_vec(),
                }
            }
            _ => return Err(malformed("unsupported key type")),
        };
        r.end()?;
        Ok(Self {
            raw: raw.to_vec(),
            name_algorithm,
            attributes,
            auth_policy,
            symmetric,
            scheme,
            key,
        })
    }
    /// `nameAlg || H(TPMT_PUBLIC)`.
    pub fn name(&self) -> Result<Vec<u8>> {
        let mut name = self.name_algorithm.to_be_bytes().to_vec();
        name.extend(hash(self.name_algorithm, &self.raw)?);
        Ok(name)
    }
    pub fn sized(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        w.tpm2b(&self.raw)?;
        Ok(w.finish())
    }
    /// An uncompressed P-384 point, for ECC P-384 keys.
    pub fn p384_point(&self) -> Result<Vec<u8>> {
        let Key::Ecc { curve, x, y, .. } = &self.key else {
            return Err(malformed("not an ECC key"));
        };
        if *curve != CURVE_P384 || x.len() > 48 || y.len() > 48 {
            return Err(malformed("not a P-384 key"));
        }
        let mut point = vec![0x04];
        for coordinate in [x, y] {
            point.extend(std::iter::repeat_n(0, 48 - coordinate.len()));
            point.extend_from_slice(coordinate);
        }
        crate::p384_point(&point)?;
        Ok(point)
    }
}

/// Build a `TPMT_PUBLIC` template.
pub struct Template {
    pub kind: u16,
    pub name_algorithm: u16,
    pub attributes: u32,
    pub auth_policy: Vec<u8>,
    pub symmetric: Option<Symmetric>,
    pub scheme: (u16, u16),
    pub key: Key,
}
impl Template {
    pub fn marshal(&self) -> Result<Vec<u8>> {
        let mut w = Writer::default();
        w.u16(self.kind)
            .u16(self.name_algorithm)
            .u32(self.attributes);
        w.tpm2b(&self.auth_policy)?;
        match self.symmetric {
            None => {
                w.u16(ALG_NULL);
            }
            Some(s) => {
                w.u16(s.algorithm).u16(s.bits).u16(s.mode);
            }
        }
        w.u16(self.scheme.0);
        if self.scheme.0 != ALG_NULL {
            w.u16(self.scheme.1);
        }
        match &self.key {
            Key::Rsa {
                bits,
                exponent,
                modulus,
            } => {
                w.u16(*bits).u32(*exponent);
                w.tpm2b(modulus)?;
            }
            Key::Ecc { curve, kdf, x, y } => {
                w.u16(*curve).u16(*kdf);
                w.tpm2b(x)?;
                w.tpm2b(y)?;
            }
        }
        Ok(w.finish())
    }
}

/// IPG's Linux storage root: a restricted P-384 decryption key under the owner
/// hierarchy (identical to the previous ESAPI backend's template).
pub fn owner_srk_template() -> Template {
    Template {
        kind: ALG_ECC,
        name_algorithm: ALG_SHA384,
        attributes: FIXED_TPM
            | FIXED_PARENT
            | SENSITIVE_DATA_ORIGIN
            | USER_WITH_AUTH
            | NO_DA
            | RESTRICTED
            | DECRYPT,
        auth_policy: Vec::new(),
        symmetric: Some(Symmetric {
            algorithm: ALG_AES,
            bits: 256,
            mode: ALG_CFB,
        }),
        scheme: (ALG_NULL, ALG_NULL),
        key: Key::Ecc {
            curve: CURVE_P384,
            kdf: ALG_NULL,
            x: Vec::new(),
            y: Vec::new(),
        },
    }
}

/// An IPG identity key: P-384 ECDSA (SHA-384) for signing or ECDH for decryption.
pub fn identity_key_template(signing: bool) -> Template {
    let role = if signing { SIGN } else { DECRYPT };
    Template {
        kind: ALG_ECC,
        name_algorithm: ALG_SHA384,
        attributes: FIXED_TPM | FIXED_PARENT | SENSITIVE_DATA_ORIGIN | USER_WITH_AUTH | role,
        auth_policy: Vec::new(),
        symmetric: None,
        scheme: if signing {
            (ALG_ECDSA, ALG_SHA384)
        } else {
            (ALG_NULL, ALG_NULL)
        },
        key: Key::Ecc {
            curve: CURVE_P384,
            kdf: ALG_NULL,
            x: Vec::new(),
            y: Vec::new(),
        },
    }
}

/// TCG EK Credential Profile default template L-1: RSA-2048, SHA-256, AES-128-CFB,
/// authorized only through PolicySecret(TPM_RH_ENDORSEMENT).
pub const EK_POLICY_A_SHA256: [u8; 32] = [
    0x83, 0x71, 0x97, 0x67, 0x44, 0x84, 0xb3, 0xf8, 0x1a, 0x90, 0xcc, 0x8d, 0x46, 0xa5, 0xd7, 0x24,
    0xfd, 0x52, 0xd7, 0x6e, 0x06, 0x52, 0x0b, 0x64, 0xf2, 0xa1, 0xda, 0x1b, 0x33, 0x14, 0x69, 0xaa,
];
pub fn ek_rsa_template() -> Template {
    Template {
        kind: ALG_RSA,
        name_algorithm: ALG_SHA256,
        attributes: FIXED_TPM
            | FIXED_PARENT
            | SENSITIVE_DATA_ORIGIN
            | ADMIN_WITH_POLICY
            | RESTRICTED
            | DECRYPT,
        auth_policy: EK_POLICY_A_SHA256.to_vec(),
        symmetric: Some(Symmetric {
            algorithm: ALG_AES,
            bits: 128,
            mode: ALG_CFB,
        }),
        scheme: (ALG_NULL, ALG_NULL),
        key: Key::Rsa {
            bits: 2048,
            exponent: 0,
            modulus: vec![0; 256],
        },
    }
}

/// IPG's attestation key: a restricted RSA-2048 RSASSA-SHA256 signing key created as
/// a primary in the endorsement hierarchy, so the same template always yields the
/// same key and nothing is persisted.
pub fn ak_template() -> Template {
    Template {
        kind: ALG_RSA,
        name_algorithm: ALG_SHA256,
        attributes: FIXED_TPM
            | FIXED_PARENT
            | SENSITIVE_DATA_ORIGIN
            | USER_WITH_AUTH
            | RESTRICTED
            | SIGN,
        auth_policy: Vec::new(),
        symmetric: None,
        scheme: (ALG_RSASSA, ALG_SHA256),
        key: Key::Rsa {
            bits: 2048,
            exponent: 0,
            modulus: Vec::new(),
        },
    }
}

/// The TCG storage root key template (RSA-2048), as Windows provisions at 0x81000001.
#[cfg(test)]
pub fn windows_srk_template() -> Template {
    Template {
        kind: ALG_RSA,
        name_algorithm: ALG_SHA256,
        attributes: FIXED_TPM
            | FIXED_PARENT
            | SENSITIVE_DATA_ORIGIN
            | USER_WITH_AUTH
            | NO_DA
            | RESTRICTED
            | DECRYPT,
        auth_policy: Vec::new(),
        symmetric: Some(Symmetric {
            algorithm: ALG_AES,
            bits: 128,
            mode: ALG_CFB,
        }),
        scheme: (ALG_NULL, ALG_NULL),
        key: Key::Rsa {
            bits: 2048,
            exponent: 0,
            modulus: vec![0; 256],
        },
    }
}

/// A parsed `TPMS_ATTEST` of type `TPM_ST_ATTEST_CERTIFY`.
#[derive(Clone, Debug)]
pub struct Certification {
    pub extra_data: Vec<u8>,
    pub firmware_version: u64,
    pub name: Vec<u8>,
}
impl Certification {
    pub fn parse(raw: &[u8]) -> Result<Self> {
        let mut r = Reader::new(raw);
        if r.u32()? != GENERATED {
            return Err(malformed("attestation was not generated by a TPM"));
        }
        if r.u16()? != ST_ATTEST_CERTIFY {
            return Err(malformed("attestation is not a key certification"));
        }
        r.tpm2b()?; // qualifiedSigner
        let extra_data = r.tpm2b()?.to_vec();
        r.take(8 + 4 + 4 + 1)?; // clockInfo: clock, resetCount, restartCount, safe
        let firmware_version = r.u64()?;
        let name = r.tpm2b()?.to_vec();
        r.tpm2b()?; // qualifiedName
        r.end()?;
        Ok(Self {
            extra_data,
            firmware_version,
            name,
        })
    }
}

/// A `TPMT_SIGNATURE` made with RSASSA and SHA-256.
pub fn rsassa_sha256(raw: &[u8]) -> Result<Vec<u8>> {
    let mut r = Reader::new(raw);
    if r.u16()? != ALG_RSASSA || r.u16()? != ALG_SHA256 {
        return Err(malformed("signature is not RSASSA with SHA-256"));
    }
    let signature = r.tpm2b()?.to_vec();
    r.end()?;
    Ok(signature)
}
