//! Bundled public trust-anchor data; no runtime root-store crate or fetching.
//! Source provenance and update procedure live in data/README.md.
use crate::json::{self, At as _};
use crate::{Error, Result};
use ic_json::Json;

/// DER sequence contents, preserving the previous root store's encoding.
/// These are trust-anchor inputs, not unverified peer certificates.
pub(crate) struct Anchor {
    pub subject: Vec<u8>,
    pub spki: Vec<u8>,
    pub name_constraints: Option<Vec<u8>>,
}

/// Wrap sequence contents as a complete DER SEQUENCE.
fn sequence(contents: &[u8]) -> Vec<u8> {
    let length = contents.len().to_be_bytes();
    let length = &length[length
        .iter()
        .position(|b| *b != 0)
        .unwrap_or(length.len() - 1)..];
    let mut out = vec![0x30];
    if contents.len() < 0x80 {
        out.push(contents.len() as u8);
    } else {
        out.push(0x80 | length.len() as u8);
        out.extend_from_slice(length);
    }
    out.extend_from_slice(contents);
    out
}

/// The bundled roots as an IronSocketLayer trust store. Every root must be
/// accepted as a key-form anchor, with its subject, key and name constraints.
pub(crate) fn root_store() -> Result<ironsocketlayer::x509::RootStore> {
    let invalid = || Error::new("provider_error", "Bundled TLS trust-anchor data is invalid");
    let roots = load()?;
    let mut store = ironsocketlayer::x509::RootStore::new();
    for root in &roots {
        // The data holds sequence contents; anchors are complete DER elements.
        store
            .add_anchor(
                &sequence(&root.subject),
                &sequence(&root.spki),
                root.name_constraints.as_deref().map(sequence).as_deref(),
            )
            .map_err(|_| invalid())?;
    }
    if store.len() != roots.len() {
        return Err(invalid());
    }
    Ok(store)
}

/// The members of a JSON object, which must be exactly `names`.
fn members<'a, const N: usize>(value: &'a Json, names: [&str; N]) -> Option<[&'a Json; N]> {
    let Json::Object(map) = value else {
        return None;
    };
    if map.keys().any(|key| !names.contains(&key.as_str())) {
        return None;
    }
    Some(names.map(|name| value.at(name)))
}

pub(crate) fn load() -> Result<Vec<Anchor>> {
    let invalid = || Error::new("provider_error", "Bundled TLS trust-anchor data is invalid");
    let bundle = json::parse(include_bytes!("../data/tls-roots.json")).map_err(|_| invalid())?;
    let [format, version, url, sha256, license, roots] = members(
        &bundle,
        [
            "format",
            "source_version",
            "source_url",
            "source_sha256",
            "license",
            "roots",
        ],
    )
    .ok_or_else(invalid)?;
    let roots = roots.as_array().ok_or_else(invalid)?;
    // The format name is the data's, unchanged from IronPrivacyGuard, so the
    // importer and its check apply to both copies.
    if format.as_str() != Some("ipg-tls-roots-v1")
        || version.as_str() != Some("1.0.9")
        || url.as_str()
            != Some("https://static.crates.io/crates/webpki-roots/webpki-roots-1.0.9.crate")
        || sha256.as_str()
            != Some("7dcd9d09a39985f5344844e66b0c530a33843579125f23e21e9f0f220850f22a")
        || license.as_str() != Some("CDLA-Permissive-2.0")
        || roots.is_empty()
        || roots.len() > 256
    {
        return Err(invalid());
    }
    let decode = |value: &Json| -> Result<Vec<u8>> {
        let text = value.as_str().ok_or_else(invalid)?;
        if text.is_empty() || text.len() > 131_072 {
            return Err(invalid());
        }
        ic_core::codec::unhex(text).map_err(|_| invalid())
    };
    roots
        .iter()
        .map(|root| {
            let [subject, spki, constraints] =
                members(root, ["subject", "spki", "name_constraints"]).ok_or_else(invalid)?;
            Ok(Anchor {
                subject: decode(subject)?,
                spki: decode(spki)?,
                name_constraints: match constraints {
                    Json::Null => None,
                    present => Some(decode(present)?),
                },
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ic_core::traits::Digest;

    #[test]
    fn root_set_matches_the_independently_exported_previous_store() {
        let roots = load().unwrap();
        assert_eq!(roots.len(), 121);
        assert_eq!(
            roots
                .iter()
                .filter(|r| r.name_constraints.is_some())
                .count(),
            1
        );
        let mut canonical = Vec::new();
        for root in roots {
            for value in [
                &root.subject[..],
                &root.spki,
                root.name_constraints.as_deref().unwrap_or(&[]),
            ] {
                canonical.extend_from_slice(&(value.len() as u32).to_be_bytes());
                canonical.extend_from_slice(value);
            }
        }
        // Obtained from the compiled webpki-roots 1.0.9 store before removal,
        // independently of scripts/import-tls-roots.py's source-data extraction.
        assert_eq!(
            crate::hex(ic_hash::Sha256::digest(&canonical).unwrap()),
            "a8de3f65ac091245cdd1a2a5a25e34621948c82867decfb34fd8dd1fb049cd8b"
        );
    }

    #[test]
    fn every_bundled_root_loads_into_the_tls_trust_store() {
        assert_eq!(root_store().unwrap().len(), 121);
        assert_eq!(sequence(&[]), [0x30, 0]);
        assert_eq!(sequence(&[7; 0x80])[..3], [0x30, 0x81, 0x80]);
        assert_eq!(sequence(&[7; 0x100])[..4], [0x30, 0x82, 1, 0]);
    }
}
