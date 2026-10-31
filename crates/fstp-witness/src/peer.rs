//! Who sent a message, from the client certificate of its connection
//! (ADR-010 "Witnesses", ADR-009 "Cell CA").
//!
//! The witness pins each cell CA, registered at provisioning. Its TLS
//! server trusts the union of the registered CAs, so `fstp-tls` has
//! verified the client chain to one of them before this module runs. That
//! verifier does not tell the witness which CA it was. So this module
//! binds the sender to the CA that signed the leaf, and never to a name
//! the leaf asserts about itself:
//!
//! - the issuing CA is the one pinned CA whose subject Name equals the
//!   leaf's issuer Name and whose public key verifies the leaf's
//!   signature over its `tbsCertificate` (RFC 5280 sections 4.1.1.3 and
//!   4.1.2.4). Every cell CA key is ECDSA P-256 (design section 1.3). Two
//!   pinned CAs that both verify name neither (fail closed);
//! - the leaf's authorityKeyIdentifier must then equal that CA's
//!   subjectKeyIdentifier. This is a consistency check only. A leaf that
//!   names another CA's key identifier sends nothing;
//! - the chain is the leaf's subject OU: `cell-witness` writes the App
//!   chain and `vault-witness` the Vault chain ([`OU_CELL_WITNESS`],
//!   [`OU_VAULT_WITNESS`]). Any other OU sends nothing.
//!
//! [`read_cert`] is the in-house DER reader for those fields. It walks the
//! structure of RFC 5280 section 4.1 and reads nothing else. It is fuzzed
//! (`cert_names_decode`) and never panics. The signature check is
//! `fstp_crypto::sig::ecdsa_p256_sha256_verify` (ADR-001).

use crate::chain_witness::Sender;
use fstp_audit::CellId;

/// The subject OU of a `cell-witness` client certificate: the App chain's
/// writer.
pub const OU_CELL_WITNESS: &str = "cell-witness";

/// The subject OU of a `vault-witness` client certificate: the Vault
/// chain's writer.
pub const OU_VAULT_WITNESS: &str = "vault-witness";

/// The longest certificate the reader takes.
pub const MAX_CERT_LEN: usize = 16 * 1024;

/// What the witness reads from a certificate.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CertNames {
    /// The keyIdentifier of the authorityKeyIdentifier extension.
    pub authority_key_id: Option<Vec<u8>>,
    /// The subjectKeyIdentifier extension.
    pub subject_key_id: Option<Vec<u8>>,
    /// The first organizationalUnitName of the subject, as its bytes.
    pub subject_ou: Option<Vec<u8>>,
}

/// The parts of a certificate the sender check reads, borrowed from its
/// DER.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CertParts<'a> {
    /// The `tbsCertificate`, tag and length included: the signed bytes.
    pub tbs: &'a [u8],
    /// The outer signatureAlgorithm's OID, content octets.
    pub signature_algorithm: &'a [u8],
    /// The signatureValue BIT STRING's bits. A value with unused bits does
    /// not read.
    pub signature: &'a [u8],
    /// The issuer Name, tag and length included.
    pub issuer: &'a [u8],
    /// The subject Name, tag and length included.
    pub subject: &'a [u8],
    /// The SubjectPublicKeyInfo, tag and length included.
    pub spki: &'a [u8],
    /// The key identifiers and the first subject OU.
    pub names: CertNames,
}

/// Why a certificate did not read. It names the structure only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerError {
    /// The input is longer than [`MAX_CERT_LEN`].
    TooLong,
    /// The DER structure is not that of a certificate.
    Malformed(&'static str),
}

/// One DER tag-length-value read from a slice.
struct Tlv<'a> {
    tag: u8,
    value: &'a [u8],
    /// The whole TLV: tag, length and value.
    raw: &'a [u8],
}

/// Reads one TLV from the front of `input` and returns it with the rest.
/// The length is definite, in at most four length octets, and minimal.
fn tlv(input: &[u8]) -> Result<(Tlv<'_>, &[u8]), PeerError> {
    let bad = PeerError::Malformed("tlv");
    let (&tag, rest) = input.split_first().ok_or(bad)?;
    // High tag numbers do not occur in a certificate.
    if tag & 0x1f == 0x1f {
        return Err(bad);
    }
    let (&first, mut rest) = rest.split_first().ok_or(bad)?;
    let len = if first < 0x80 {
        usize::from(first)
    } else {
        let count = usize::from(first & 0x7f);
        if count == 0 || count > 4 {
            return Err(bad);
        }
        let (octets, after) = rest.split_at_checked(count).ok_or(bad)?;
        rest = after;
        if octets.first() == Some(&0) {
            return Err(bad);
        }
        let mut n = 0usize;
        for o in octets {
            n = n
                .checked_mul(256)
                .ok_or(bad)?
                .checked_add(usize::from(*o))
                .ok_or(bad)?;
        }
        if n < 0x80 {
            return Err(bad);
        }
        n
    };
    let (value, after) = rest.split_at_checked(len).ok_or(bad)?;
    let used = input.len().checked_sub(after.len()).ok_or(bad)?;
    let raw = input.get(..used).ok_or(bad)?;
    Ok((Tlv { tag, value, raw }, after))
}

/// Reads one TLV of tag `tag` from the front of `input`.
fn expect<'a>(
    input: &'a [u8],
    tag: u8,
    what: &'static str,
) -> Result<(Tlv<'a>, &'a [u8]), PeerError> {
    let (t, rest) = tlv(input)?;
    if t.tag != tag {
        return Err(PeerError::Malformed(what));
    }
    Ok((t, rest))
}

const SEQUENCE: u8 = 0x30;
const SET: u8 = 0x31;
const OID: u8 = 0x06;
const OCTET_STRING: u8 = 0x04;
const BIT_STRING: u8 = 0x03;
const BOOLEAN: u8 = 0x01;
const INTEGER: u8 = 0x02;
const EXPLICIT_0: u8 = 0xa0;
const EXPLICIT_3: u8 = 0xa3;
const IMPLICIT_0: u8 = 0x80;
/// `id-at-organizationalUnitName` (2.5.4.11), content octets.
const OID_OU: &[u8] = &[0x55, 0x04, 0x0b];
/// `id-ce-subjectKeyIdentifier` (2.5.29.14), content octets.
const OID_SKI: &[u8] = &[0x55, 0x1d, 0x0e];
/// `id-ce-authorityKeyIdentifier` (2.5.29.35), content octets.
const OID_AKI: &[u8] = &[0x55, 0x1d, 0x23];
/// `ecdsa-with-SHA256` (1.2.840.10045.4.3.2), content octets.
const OID_ECDSA_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];

/// The first OU of a `Name` (RFC 5280 section 4.1.2.4).
fn first_ou(name: &[u8]) -> Result<Option<Vec<u8>>, PeerError> {
    let mut rdns = name;
    while !rdns.is_empty() {
        let (set, rest) = expect(rdns, SET, "relative distinguished name")?;
        rdns = rest;
        let mut atvs = set.value;
        while !atvs.is_empty() {
            let (atv, rest) = expect(atvs, SEQUENCE, "attribute")?;
            atvs = rest;
            let (oid, value) = expect(atv.value, OID, "attribute type")?;
            let (v, after) = tlv(value)?;
            if !after.is_empty() {
                return Err(PeerError::Malformed("attribute value"));
            }
            if oid.value == OID_OU {
                return Ok(Some(v.value.to_vec()));
            }
        }
    }
    Ok(None)
}

/// Reads the extensions list `exts` into `names`.
fn read_extensions(exts: &[u8], names: &mut CertNames) -> Result<(), PeerError> {
    let mut list = exts;
    while !list.is_empty() {
        let (ext, rest) = expect(list, SEQUENCE, "extension")?;
        list = rest;
        let (oid, mut body) = expect(ext.value, OID, "extension id")?;
        if body.first() == Some(&BOOLEAN) {
            let (_, b) = tlv(body)?;
            body = b;
        }
        let (value, end) = expect(body, OCTET_STRING, "extension value")?;
        if !end.is_empty() {
            return Err(PeerError::Malformed("extension"));
        }
        if oid.value == OID_SKI {
            let (id, end) = expect(value.value, OCTET_STRING, "subject key identifier")?;
            if !end.is_empty() {
                return Err(PeerError::Malformed("subject key identifier"));
            }
            names.subject_key_id = Some(id.value.to_vec());
        } else if oid.value == OID_AKI {
            let (seq, end) = expect(value.value, SEQUENCE, "authority key identifier")?;
            if !end.is_empty() {
                return Err(PeerError::Malformed("authority key identifier"));
            }
            if seq.value.first() == Some(&IMPLICIT_0) {
                let (id, _) = tlv(seq.value)?;
                names.authority_key_id = Some(id.value.to_vec());
            }
        }
    }
    Ok(())
}

/// Reads the parts of the DER certificate `der` that the sender check
/// needs. Fuzzed (`cert_names_decode`).
///
/// # Errors
///
/// [`PeerError`] for input that is not a certificate's structure, or is
/// longer than [`MAX_CERT_LEN`].
pub fn read_cert(der: &[u8]) -> Result<CertParts<'_>, PeerError> {
    if der.len() > MAX_CERT_LEN {
        return Err(PeerError::TooLong);
    }
    let (cert, after) = expect(der, SEQUENCE, "certificate")?;
    if !after.is_empty() {
        return Err(PeerError::Malformed("trailing bytes"));
    }
    let (tbs, r) = expect(cert.value, SEQUENCE, "tbsCertificate")?;
    let (alg, r) = expect(r, SEQUENCE, "signature algorithm")?;
    let (alg_oid, _) = expect(alg.value, OID, "signature algorithm id")?;
    let (sig, r) = expect(r, BIT_STRING, "signature value")?;
    if !r.is_empty() {
        return Err(PeerError::Malformed("certificate"));
    }
    let signature = match sig.value.split_first() {
        Some((0, bits)) => bits,
        _ => return Err(PeerError::Malformed("signature value")),
    };
    let mut rest = tbs.value;
    // version [0] EXPLICIT, optional.
    if rest.first() == Some(&EXPLICIT_0) {
        let (_, r) = tlv(rest)?;
        rest = r;
    }
    let (_, r) = expect(rest, INTEGER, "serial")?;
    let (_, r) = expect(r, SEQUENCE, "signature algorithm")?;
    let (issuer, r) = expect(r, SEQUENCE, "issuer")?;
    let (_, r) = expect(r, SEQUENCE, "validity")?;
    let (subject, r) = expect(r, SEQUENCE, "subject")?;
    let (spki, mut r) = expect(r, SEQUENCE, "subject public key info")?;
    let mut names = CertNames {
        subject_ou: first_ou(subject.value)?,
        ..CertNames::default()
    };
    // issuerUniqueID [1], subjectUniqueID [2], then extensions [3].
    while !r.is_empty() {
        let (t, after) = tlv(r)?;
        r = after;
        if t.tag != EXPLICIT_3 {
            continue;
        }
        let (exts, trailing) = expect(t.value, SEQUENCE, "extensions")?;
        if !trailing.is_empty() {
            return Err(PeerError::Malformed("extensions"));
        }
        read_extensions(exts.value, &mut names)?;
    }
    Ok(CertParts {
        tbs: tbs.raw,
        signature_algorithm: alg_oid.value,
        signature,
        issuer: issuer.raw,
        subject: subject.raw,
        spki: spki.raw,
        names,
    })
}

/// Reads the authorityKeyIdentifier, the subjectKeyIdentifier and the
/// first subject OU of the DER certificate `der` ([`read_cert`]).
///
/// # Errors
///
/// [`PeerError`] for input that is not a certificate's structure, or is
/// longer than [`MAX_CERT_LEN`].
pub fn read_cert_names(der: &[u8]) -> Result<CertNames, PeerError> {
    read_cert(der).map(|c| c.names)
}

/// A registered cell CA: its cell, its subject Name, its public key and
/// its subjectKeyIdentifier.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PinnedCa {
    /// The cell whose CA it is.
    pub cell: CellId,
    /// Its subjectKeyIdentifier.
    pub key_id: Vec<u8>,
    /// Its subject Name, DER.
    pub subject: Vec<u8>,
    /// Its SubjectPublicKeyInfo, DER.
    pub spki: Vec<u8>,
}

impl PinnedCa {
    /// The pin of `cell`'s CA certificate `ca_der`.
    ///
    /// # Errors
    ///
    /// [`PeerError`] for a certificate that does not read, or carries no
    /// subjectKeyIdentifier.
    pub fn from_ca_der(cell: CellId, ca_der: &[u8]) -> Result<PinnedCa, PeerError> {
        let ca = read_cert(ca_der)?;
        let key_id = ca
            .names
            .subject_key_id
            .ok_or(PeerError::Malformed("subject key identifier"))?;
        Ok(PinnedCa {
            cell,
            key_id,
            subject: ca.subject.to_vec(),
            spki: ca.spki.to_vec(),
        })
    }

    /// Whether this CA signed `leaf`: the leaf's issuer is its subject and
    /// its key verifies the leaf's signature.
    fn signed(&self, leaf: &CertParts<'_>) -> bool {
        leaf.signature_algorithm == OID_ECDSA_SHA256
            && leaf.issuer == self.subject.as_slice()
            && fstp_crypto::sig::ecdsa_p256_sha256_verify(&self.spki, leaf.tbs, leaf.signature)
                .is_ok()
    }
}

/// The sender of a connection whose client certificate is `leaf_der`, among
/// the pinned cell CAs `pins` (module documentation). `None` when no
/// pinned CA, or more than one, signed it, when its authorityKeyIdentifier
/// is not its signer's, or when its OU names no chain writer.
pub fn sender_of(leaf_der: &[u8], pins: &[PinnedCa]) -> Option<Sender> {
    let leaf = read_cert(leaf_der).ok()?;
    let mut issuers = pins.iter().filter(|p| p.signed(&leaf));
    let issuer = issuers.next()?;
    // Two pins that verify the leaf name neither (fail closed).
    if issuers.next().is_some() {
        return None;
    }
    // A consistency check only: the signer decides the cell.
    if leaf.names.authority_key_id.as_deref() != Some(issuer.key_id.as_slice()) {
        return None;
    }
    match leaf.names.subject_ou.as_deref() {
        Some(ou) if ou == OU_CELL_WITNESS.as_bytes() => {
            Some(Sender::CellWitness { cell: issuer.cell })
        }
        Some(ou) if ou == OU_VAULT_WITNESS.as_bytes() => {
            Some(Sender::VaultWitness { cell: issuer.cell })
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_pki::cert::{
        CertKind, CertSpec, DistinguishedName, KeyIdentifier, SignatureAlgorithm, Validity,
        assemble, key_identifier, tbs,
    };

    /// TH-26, ADR-010: the reader refuses a truncated length, a long form
    /// that is not minimal and trailing bytes, and never panics on them.
    #[test]
    fn adr010_cert_reader_refuses_malformed_lengths() {
        assert!(read_cert_names(&[]).is_err());
        assert!(read_cert_names(&[0x30, 0x81, 0x05, 0, 0, 0, 0, 0]).is_err());
        assert!(read_cert_names(&[0x30, 0x02, 0x30, 0x00, 0xff]).is_err());
        assert!(read_cert_names(&[0x30, 0x84, 0xff, 0xff, 0xff, 0xff]).is_err());
        assert!(read_cert_names(&vec![0u8; MAX_CERT_LEN + 1]).is_err());
    }

    /// A test CA: its key, its name and its DER certificate.
    struct Ca {
        key: fstp_crypto::sig::EcdsaP256KeyPair,
        name: String,
        der: Vec<u8>,
    }

    fn dn(cn: &str, ou: Option<&str>) -> DistinguishedName {
        DistinguishedName {
            common_name: cn.to_owned(),
            organizational_unit: ou.map(str::to_owned),
        }
    }

    const VALIDITY: Validity = Validity {
        not_before: 1_800_000_000,
        not_after: 1_800_000_000 + 86_400,
    };

    impl Ca {
        fn new(name: &str) -> Ca {
            let key = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
            let spec = CertSpec {
                serial: vec![1; 16],
                issuer: dn(name, None),
                subject: dn(name, None),
                validity: VALIDITY,
                spki_der: key.spki_der().unwrap(),
                issuer_key_id: None,
                kind: CertKind::Ca,
                dns_names: Vec::new(),
                ip_addrs: Vec::new(),
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            };
            let t = tbs(&spec).unwrap();
            let der = assemble(&t, &key.sign(t.as_der()).unwrap()).unwrap();
            Ca {
                key,
                name: name.to_owned(),
                der,
            }
        }

        fn key_id(&self) -> KeyIdentifier {
            key_identifier(&self.key.spki_der().unwrap()).unwrap()
        }

        /// A client leaf signed by this CA, with issuer Name `issuer`,
        /// authorityKeyIdentifier `aki` and subject OU `ou`.
        fn leaf_as(&self, issuer: &str, aki: KeyIdentifier, ou: Option<&str>) -> Vec<u8> {
            let leaf = fstp_crypto::sig::EcdsaP256KeyPair::generate().unwrap();
            let spec = CertSpec {
                serial: vec![2; 16],
                issuer: dn(issuer, None),
                subject: dn("cell", ou),
                validity: VALIDITY,
                spki_der: leaf.spki_der().unwrap(),
                issuer_key_id: Some(aki),
                kind: CertKind::Client,
                dns_names: Vec::new(),
                ip_addrs: Vec::new(),
                algorithm: SignatureAlgorithm::EcdsaP256Sha256,
            };
            let t = tbs(&spec).unwrap();
            assemble(&t, &self.key.sign(t.as_der()).unwrap()).unwrap()
        }

        fn leaf(&self, ou: Option<&str>) -> Vec<u8> {
            self.leaf_as(&self.name.clone(), self.key_id(), ou)
        }

        fn pin(&self, cell: CellId) -> PinnedCa {
            PinnedCa::from_ca_der(cell, &self.der).unwrap()
        }
    }

    /// ADR-010 "Witnesses": the reader finds the OU and the
    /// authorityKeyIdentifier of a leaf, and the subjectKeyIdentifier of
    /// its CA, as `fstp-pki` writes them. A `cell-witness` leaf of a pinned
    /// CA is that cell's App chain writer, a `vault-witness` leaf its
    /// Vault chain writer.
    #[test]
    fn adr010_sender_is_the_pinned_ca_and_the_leaf_ou() {
        let cell = CellId([0x42; 16]);
        let ca = Ca::new("ca");
        for (ou, want) in [
            (OU_CELL_WITNESS, Sender::CellWitness { cell }),
            (OU_VAULT_WITNESS, Sender::VaultWitness { cell }),
        ] {
            let leaf = ca.leaf(Some(ou));
            let id = ca.key_id().to_vec();
            let names = read_cert_names(&ca.der).unwrap();
            assert_eq!(names.subject_key_id.as_deref(), Some(id.as_slice()));
            let names = read_cert_names(&leaf).unwrap();
            assert_eq!(names.subject_ou.as_deref(), Some(ou.as_bytes()));
            assert_eq!(names.authority_key_id.as_deref(), Some(id.as_slice()));
            assert_eq!(sender_of(&leaf, &[ca.pin(cell)]), Some(want));
        }
    }

    /// ADR-010 "Witnesses": a leaf of an unpinned CA, a leaf with another
    /// OU or none, and one CA pinned for two cells name no sender.
    #[test]
    fn adr010_unpinned_ca_or_other_ou_names_no_sender() {
        let cell = CellId([0x42; 16]);
        let ca = Ca::new("ca");
        let leaf = ca.leaf(Some(OU_CELL_WITNESS));
        assert_eq!(sender_of(&leaf, &[Ca::new("other").pin(cell)]), None);
        let twice = [ca.pin(cell), ca.pin(CellId([0x43; 16]))];
        assert_eq!(sender_of(&leaf, &twice), None);
        for ou in [Some("cell-app"), None] {
            let leaf = ca.leaf(ou);
            assert_eq!(sender_of(&leaf, &[ca.pin(cell)]), None, "{ou:?}");
        }
    }

    /// I-19, I-24, ADR-010 "Witnesses": the sender is the CA that signed
    /// the leaf. A leaf that cell A's CA signed, but whose
    /// authorityKeyIdentifier or issuer Name claims cell B's CA, sends for
    /// neither cell. A CA with B's name but A's key does not stand in for B.
    #[test]
    fn i24_sender_is_the_signing_ca_not_a_claimed_one() {
        let (a_cell, b_cell) = (CellId([0x51; 16]), CellId([0x52; 16]));
        let a = Ca::new("cell CA a");
        let b = Ca::new("cell CA b");
        let pins = [a.pin(a_cell), b.pin(b_cell)];
        let ou = Some(OU_CELL_WITNESS);
        assert_eq!(
            sender_of(&a.leaf(ou), &pins),
            Some(Sender::CellWitness { cell: a_cell })
        );
        // A's key, A's name, B's key identifier.
        let claims_b_key = a.leaf_as("cell CA a", b.key_id(), ou);
        assert_eq!(sender_of(&claims_b_key, &pins), None);
        // A's key, B's name and B's key identifier.
        let claims_b = a.leaf_as("cell CA b", b.key_id(), ou);
        assert_eq!(sender_of(&claims_b, &pins), None);
        // A's key, B's name, A's key identifier.
        let claims_b_name = a.leaf_as("cell CA b", a.key_id(), ou);
        assert_eq!(sender_of(&claims_b_name, &pins), None);
    }

    /// ADR-010 "Witnesses": a leaf whose signature does not verify under
    /// its pinned CA sends nothing, whatever its names.
    #[test]
    fn adr010_leaf_with_a_changed_signature_sends_nothing() {
        let cell = CellId([0x42; 16]);
        let ca = Ca::new("ca");
        let mut leaf = ca.leaf(Some(OU_CELL_WITNESS));
        let last = leaf.len() - 1;
        leaf[last] ^= 1;
        assert_eq!(sender_of(&leaf, &[ca.pin(cell)]), None);
    }
}
