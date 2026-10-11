# TLS trust-anchor data

`tls-roots.json` is IronPrivacyGuard's `data/tls-roots.json` at commit
`0e6344d`, byte for byte: public Mozilla trust-anchor data imported from the
`webpki-roots` 1.0.9 release, 121 roots, one with a name constraint. It is
distributed under the accompanying `tls-roots.LICENSE` (CDLA-Permissive-2.0).

The subject, SPKI and optional name-constraint fields contain hex-encoded DER
**sequence contents**. They are not full DER certificates. The loader wraps
each as a DER SEQUENCE and adds it to IronSocketLayer's trust store as a
key-form anchor, keeping its subject, key and name constraint.

The loader checks the data's provenance fields, and a unit test checks a
digest over every root against a value exported independently from the
compiled `webpki-roots` 1.0.9 store.

## Updating

The importer is IronPrivacyGuard's `scripts/import-tls-roots.py`, which
verifies the archive's pinned SHA-256 digest before reading it. A root update
requires deliberate review of the new release, archive pin, additions,
removals, constraints and licence. Make it in IronPrivacyGuard, then copy the
data and licence here and update the loader's provenance checks and the digest
test in `src/tls_roots.rs`. Until IronPrivacyGuard depends on this crate, the
two copies must be kept the same by hand.

This static set does not follow OS root-store changes, enterprise roots or
platform revocation policy, and it does not refresh itself.
