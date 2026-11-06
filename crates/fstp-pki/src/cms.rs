//! CMS for PAdES baseline B-B signatures (M5 design section 3.1, steps 5
//! to 8; ADR-016; ADR-001 Tier B formats crates).
//!
//! The platform never creates a party's signature (`contracts.md`). This
//! module only:
//!
//! - encodes the signed attributes over the `/ByteRange` digest
//!   ([`signed_attributes`]): `contentType`, `messageDigest` and
//!   `signingCertificateV2` (RFC 5652, RFC 5035);
//! - verifies a signature value from the wallet, the QTSP or the seal key
//!   with aws-lc-rs through `fstp-crypto` ([`verify_signature`]);
//! - assembles the detached `SignedData` only after that check
//!   ([`signed_data`]);
//! - decodes a `SignedData` strictly ([`decode_signed_data`]).
//!
//! The `signingCertificateV2` value is written in-house with this crate's
//! DER writer. The structures around it come from the `cms`, `x509-cert`,
//! `spki` and `der` crates (Tier B, release-gated by I-74). Chain
//! validation against trusted lists is not done here; `fstp-sigval` owns
//! it (M5 design section 3.1 step 7).

use ::der::asn1::{Any, ObjectIdentifier, OctetString, SetOfVec, UintRef};
use ::der::{Decode, Encode, Reader, SliceReader};
use cms::cert::{CertificateChoices, IssuerAndSerialNumber};
use cms::content_info::{CmsVersion, ContentInfo};
use cms::signed_data::{
    CertificateSet, EncapsulatedContentInfo, SignedData, SignerIdentifier, SignerInfo, SignerInfos,
};
use spki::AlgorithmIdentifierOwned;
use x509_cert::Certificate;
use x509_cert::attr::{Attribute, Attributes};

use crate::der::{TAG_OCTET_STRING, TAG_SEQUENCE, tlv};

/// Largest DER input the decoder accepts, in bytes.
pub const MAX_CMS: usize = 65_536;
/// Most certificates in one `SignedData`.
pub const MAX_CHAIN: usize = 8;

const ID_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
const ID_SIGNED_DATA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.2");
const ID_CONTENT_TYPE: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.3");
const ID_MESSAGE_DIGEST: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.4");
const ID_SIGNING_CERTIFICATE_V2: ObjectIdentifier =
    ObjectIdentifier::new_unwrap("1.2.840.113549.1.9.16.2.47");
const ID_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("2.16.840.1.101.3.4.2.1");
const ID_EC_PUBLIC_KEY: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.2.1");
const SECP256R1: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.3.1.7");
const ECDSA_WITH_SHA256: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.10045.4.3.2");
const RSA_ENCRYPTION: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.1");
const SHA256_WITH_RSA: ObjectIdentifier = ObjectIdentifier::new_unwrap("1.2.840.113549.1.1.11");

/// Why a CMS operation failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CmsError {
    /// A certificate does not parse as X.509.
    Certificate,
    /// The signer key is neither P-256 nor RSA.
    UnsupportedKey,
    /// The signature value does not verify under the signer certificate.
    SignatureInvalid,
    /// The formats crates refused to encode a structure.
    Encoding,
    /// The input does not decode, or is not in DER.
    Decode,
    /// The content type is not `signedData`.
    NotSignedData,
    /// The encapsulated content is not detached `id-data`.
    NotDetached,
    /// Not exactly one signer.
    SignerCount,
    /// The digest algorithm is not SHA-256.
    DigestAlgorithm,
    /// The signature algorithm does not match the signer key.
    SignatureAlgorithm,
    /// A signed attribute is missing, repeated or malformed. It names it.
    Attribute(&'static str),
    /// No certificate, more than [`MAX_CHAIN`], or the signer is missing.
    Chain,
    /// The input is larger than [`MAX_CMS`].
    TooLarge,
}

impl std::fmt::Display for CmsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "CMS refused: {self:?}")
    }
}

impl std::error::Error for CmsError {}

/// The signature algorithms the signer key may use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureAlgorithm {
    /// ECDSA over P-256 with SHA-256.
    EcdsaP256Sha256,
    /// RSA PKCS#1 v1.5 with SHA-256, 2048 to 8192 bits.
    RsaPkcs1Sha256,
}

/// The DER `SignedAttributes`, as a `SET OF`, ready to be signed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedAttributes {
    der: Vec<u8>,
    message_digest: [u8; 32],
}

impl SignedAttributes {
    /// The bytes the signer signs (RFC 5652 section 5.4: the `SET OF`
    /// encoding, not the `[0]` tag).
    #[must_use]
    pub fn der(&self) -> &[u8] {
        &self.der
    }

    /// The SHA-256 of [`SignedAttributes::der`], for a remote signing
    /// interface that takes a hash.
    #[must_use]
    pub fn digest(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.der)
    }

    /// The `messageDigest` value: the `/ByteRange` digest.
    #[must_use]
    pub fn message_digest(&self) -> [u8; 32] {
        self.message_digest
    }
}

fn cert(der: &[u8]) -> Result<Certificate, CmsError> {
    if der.len() > MAX_CMS {
        return Err(CmsError::TooLarge);
    }
    Certificate::from_der(der).map_err(|_| CmsError::Certificate)
}

/// The `SigningCertificateV2` value for `cert_der` (RFC 5035): one
/// `ESSCertIDv2` with the default SHA-256 hash and the issuer and serial.
fn signing_certificate_v2(cert_der: &[u8], cert: &Certificate) -> Result<Vec<u8>, CmsError> {
    let issuer = cert
        .tbs_certificate
        .issuer
        .to_der()
        .map_err(|_| CmsError::Encoding)?;
    let serial = cert
        .tbs_certificate
        .serial_number
        .to_der()
        .map_err(|_| CmsError::Encoding)?;
    // GeneralNames ::= SEQUENCE OF GeneralName; directoryName [4] EXPLICIT Name.
    let general_names = tlv(TAG_SEQUENCE, &tlv(0xa4, &issuer));
    let issuer_serial = tlv(TAG_SEQUENCE, &[general_names, serial].concat());
    let hash = tlv(TAG_OCTET_STRING, &fstp_crypto::sha256(cert_der));
    let ess_cert_id = tlv(TAG_SEQUENCE, &[hash, issuer_serial].concat());
    let certs = tlv(TAG_SEQUENCE, &ess_cert_id);
    Ok(tlv(TAG_SEQUENCE, &certs))
}

fn attribute(oid: ObjectIdentifier, value_der: &[u8]) -> Result<Attribute, CmsError> {
    let value = Any::from_der(value_der).map_err(|_| CmsError::Encoding)?;
    let values = SetOfVec::try_from(vec![value]).map_err(|_| CmsError::Encoding)?;
    Ok(Attribute { oid, values })
}

/// Encodes the PAdES baseline B-B signed attributes for the `/ByteRange`
/// digest `message_digest` and the signer certificate `signer_cert_der`.
/// No signing time is included; PAdES carries the claimed time in `/M`.
///
/// # Errors
///
/// [`CmsError::Certificate`] when the certificate does not parse, and
/// [`CmsError::Encoding`] when an encoder fails.
pub fn signed_attributes(
    message_digest: &[u8; 32],
    signer_cert_der: &[u8],
) -> Result<SignedAttributes, CmsError> {
    let signer = cert(signer_cert_der)?;
    let content_type = ID_DATA.to_der().map_err(|_| CmsError::Encoding)?;
    let digest = OctetString::new(message_digest.to_vec())
        .and_then(|o| o.to_der())
        .map_err(|_| CmsError::Encoding)?;
    let ess = signing_certificate_v2(signer_cert_der, &signer)?;
    let attrs: Attributes = SetOfVec::try_from(vec![
        attribute(ID_CONTENT_TYPE, &content_type)?,
        attribute(ID_MESSAGE_DIGEST, &digest)?,
        attribute(ID_SIGNING_CERTIFICATE_V2, &ess)?,
    ])
    .map_err(|_| CmsError::Encoding)?;
    Ok(SignedAttributes {
        der: attrs.to_der().map_err(|_| CmsError::Encoding)?,
        message_digest: *message_digest,
    })
}

/// The RSA modulus and exponent of a PKCS#1 `RSAPublicKey`.
fn rsa_components(key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), CmsError> {
    let mut r = SliceReader::new(key).map_err(|_| CmsError::UnsupportedKey)?;
    let (n, e) = r
        .sequence(|r| {
            let n = UintRef::decode(r)?;
            let e = UintRef::decode(r)?;
            Ok((n.as_bytes().to_vec(), e.as_bytes().to_vec()))
        })
        .map_err(|_| CmsError::UnsupportedKey)?;
    if !r.is_finished() {
        return Err(CmsError::UnsupportedKey);
    }
    Ok((n, e))
}

/// Verifies `signature` over the DER signed attributes with the key of
/// `signer_cert_der`, through aws-lc-rs. Returns the algorithm used.
///
/// # Errors
///
/// [`CmsError::SignatureInvalid`] when it does not verify, and
/// [`CmsError::Certificate`] or [`CmsError::UnsupportedKey`] for the key.
pub fn verify_signature(
    signed_attributes_der: &[u8],
    signature: &[u8],
    signer_cert_der: &[u8],
) -> Result<SignatureAlgorithm, CmsError> {
    let signer = cert(signer_cert_der)?;
    let spki = &signer.tbs_certificate.subject_public_key_info;
    if spki.algorithm.oid == ID_EC_PUBLIC_KEY {
        let curve = spki
            .algorithm
            .parameters
            .as_ref()
            .and_then(|p| p.decode_as::<ObjectIdentifier>().ok());
        if curve != Some(SECP256R1) {
            return Err(CmsError::UnsupportedKey);
        }
        let spki_der = spki.to_der().map_err(|_| CmsError::UnsupportedKey)?;
        fstp_crypto::sig::ecdsa_p256_sha256_verify(&spki_der, signed_attributes_der, signature)
            .map_err(|e| match e {
                fstp_crypto::CryptoError::InvalidSignature => CmsError::SignatureInvalid,
                _ => CmsError::UnsupportedKey,
            })?;
        return Ok(SignatureAlgorithm::EcdsaP256Sha256);
    }
    if spki.algorithm.oid == RSA_ENCRYPTION {
        let key = spki
            .subject_public_key
            .as_bytes()
            .ok_or(CmsError::UnsupportedKey)?;
        let (n, e) = rsa_components(key)?;
        fstp_crypto::sig::rsa_pkcs1_sha256_verify(&n, &e, signed_attributes_der, signature)
            .map_err(|_| CmsError::SignatureInvalid)?;
        return Ok(SignatureAlgorithm::RsaPkcs1Sha256);
    }
    Err(CmsError::UnsupportedKey)
}

fn algorithm_identifier(alg: SignatureAlgorithm) -> AlgorithmIdentifierOwned {
    match alg {
        SignatureAlgorithm::EcdsaP256Sha256 => AlgorithmIdentifierOwned {
            oid: ECDSA_WITH_SHA256,
            parameters: None,
        },
        SignatureAlgorithm::RsaPkcs1Sha256 => AlgorithmIdentifierOwned {
            oid: SHA256_WITH_RSA,
            parameters: Some(Any::null()),
        },
    }
}

fn sha256_identifier() -> AlgorithmIdentifierOwned {
    AlgorithmIdentifierOwned {
        oid: ID_SHA256,
        parameters: None,
    }
}

/// Assembles the detached CMS `ContentInfo` with `SignedData` for
/// `/Contents`. The signature value is verified first, under `chain[0]`,
/// and a value that does not verify is refused. `chain` lists the signer
/// certificate first, then its issuers.
///
/// # Errors
///
/// [`CmsError::SignatureInvalid`] for a wrong value, [`CmsError::Chain`]
/// for an empty or overlong chain, and the certificate and encoding
/// errors.
pub fn signed_data(
    attrs: &SignedAttributes,
    signature: &[u8],
    chain: &[&[u8]],
) -> Result<Vec<u8>, CmsError> {
    if chain.is_empty() || chain.len() > MAX_CHAIN {
        return Err(CmsError::Chain);
    }
    let signer_der = chain.first().ok_or(CmsError::Chain)?;
    let alg = verify_signature(attrs.der(), signature, signer_der)?;
    // The attributes must name this signer.
    let expected = signed_attributes(&attrs.message_digest, signer_der)?;
    if expected.der != attrs.der {
        return Err(CmsError::Attribute("signingCertificateV2"));
    }
    let signer = cert(signer_der)?;
    let certs = chain
        .iter()
        .map(|c| cert(c).map(CertificateChoices::Certificate))
        .collect::<Result<Vec<_>, _>>()?;
    let signed_attrs = Attributes::from_der(attrs.der()).map_err(|_| CmsError::Encoding)?;
    let signer_info = SignerInfo {
        version: CmsVersion::V1,
        sid: SignerIdentifier::IssuerAndSerialNumber(IssuerAndSerialNumber {
            issuer: signer.tbs_certificate.issuer.clone(),
            serial_number: signer.tbs_certificate.serial_number.clone(),
        }),
        digest_alg: sha256_identifier(),
        signed_attrs: Some(signed_attrs),
        signature_algorithm: algorithm_identifier(alg),
        signature: OctetString::new(signature.to_vec()).map_err(|_| CmsError::Encoding)?,
        unsigned_attrs: None,
    };
    let sd = SignedData {
        version: CmsVersion::V1,
        digest_algorithms: SetOfVec::try_from(vec![sha256_identifier()])
            .map_err(|_| CmsError::Encoding)?,
        encap_content_info: EncapsulatedContentInfo {
            econtent_type: ID_DATA,
            econtent: None,
        },
        certificates: Some(CertificateSet(
            SetOfVec::try_from(certs).map_err(|_| CmsError::Encoding)?,
        )),
        crls: None,
        signer_infos: SignerInfos(
            SetOfVec::try_from(vec![signer_info]).map_err(|_| CmsError::Encoding)?,
        ),
    };
    let ci = ContentInfo {
        content_type: ID_SIGNED_DATA,
        content: Any::encode_from(&sd).map_err(|_| CmsError::Encoding)?,
    };
    ci.to_der().map_err(|_| CmsError::Encoding)
}

/// A strictly decoded detached `SignedData` with one signer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecodedSignedData {
    /// The DER signed attributes as a `SET OF`, the bytes that were signed.
    pub signed_attributes: Vec<u8>,
    /// The `messageDigest` attribute.
    pub message_digest: [u8; 32],
    /// The signature value.
    pub signature: Vec<u8>,
    /// The signer certificate, DER.
    pub signer_certificate: Vec<u8>,
    /// Every certificate, DER, in set order.
    pub certificates: Vec<Vec<u8>>,
}

/// The one value of the attribute `oid` in `attrs`.
fn single_value<'a>(
    attrs: &'a Attributes,
    oid: ObjectIdentifier,
    name: &'static str,
) -> Result<&'a Any, CmsError> {
    let mut found = attrs.iter().filter(|a| a.oid == oid);
    let attr = found.next().ok_or(CmsError::Attribute(name))?;
    if found.next().is_some() || attr.values.len() != 1 {
        return Err(CmsError::Attribute(name));
    }
    attr.values.get(0).ok_or(CmsError::Attribute(name))
}

/// Decodes `der` as a detached CMS `SignedData` with exactly one SHA-256
/// signer whose certificate it carries. The input must be in DER: it
/// must encode back to the same bytes.
///
/// # Errors
///
/// A [`CmsError`] naming the first fault. The signature is not verified
/// here; call [`verify_signature`] on the result.
pub fn decode_signed_data(der: &[u8]) -> Result<DecodedSignedData, CmsError> {
    if der.len() > MAX_CMS {
        return Err(CmsError::TooLarge);
    }
    let ci = ContentInfo::from_der(der).map_err(|_| CmsError::Decode)?;
    if ci.to_der().map_err(|_| CmsError::Decode)? != der {
        return Err(CmsError::Decode);
    }
    if ci.content_type != ID_SIGNED_DATA {
        return Err(CmsError::NotSignedData);
    }
    let sd: SignedData = ci.content.decode_as().map_err(|_| CmsError::Decode)?;
    // The content is kept as raw bytes above, so its DER form, sorted
    // sets included, is checked on its own.
    if Any::encode_from(&sd).map_err(|_| CmsError::Decode)? != ci.content {
        return Err(CmsError::Decode);
    }
    let econtent = &sd.encap_content_info;
    if econtent.econtent_type != ID_DATA || econtent.econtent.is_some() {
        return Err(CmsError::NotDetached);
    }
    if sd.digest_algorithms.len() != 1
        || sd.digest_algorithms.get(0).map(|a| a.oid) != Some(ID_SHA256)
    {
        return Err(CmsError::DigestAlgorithm);
    }
    if sd.signer_infos.0.len() != 1 {
        return Err(CmsError::SignerCount);
    }
    let si = sd.signer_infos.0.get(0).ok_or(CmsError::SignerCount)?;
    if si.digest_alg.oid != ID_SHA256 {
        return Err(CmsError::DigestAlgorithm);
    }
    let attrs = si
        .signed_attrs
        .as_ref()
        .ok_or(CmsError::Attribute("signedAttrs"))?;
    let ct: ObjectIdentifier = single_value(attrs, ID_CONTENT_TYPE, "contentType")?
        .decode_as()
        .map_err(|_| CmsError::Attribute("contentType"))?;
    if ct != ID_DATA {
        return Err(CmsError::Attribute("contentType"));
    }
    let md: OctetString = single_value(attrs, ID_MESSAGE_DIGEST, "messageDigest")?
        .decode_as()
        .map_err(|_| CmsError::Attribute("messageDigest"))?;
    let message_digest: [u8; 32] = md
        .as_bytes()
        .try_into()
        .map_err(|_| CmsError::Attribute("messageDigest"))?;
    let ess = single_value(attrs, ID_SIGNING_CERTIFICATE_V2, "signingCertificateV2")?
        .to_der()
        .map_err(|_| CmsError::Attribute("signingCertificateV2"))?;

    let certs: Vec<&Certificate> = sd
        .certificates
        .as_ref()
        .map(|set| {
            set.0
                .iter()
                .filter_map(|c| match c {
                    CertificateChoices::Certificate(c) => Some(c),
                    CertificateChoices::Other(_) => None,
                })
                .collect()
        })
        .unwrap_or_default();
    if certs.is_empty() || certs.len() > MAX_CHAIN {
        return Err(CmsError::Chain);
    }
    let SignerIdentifier::IssuerAndSerialNumber(sid) = &si.sid else {
        return Err(CmsError::Chain);
    };
    let signer = certs
        .iter()
        .find(|c| {
            c.tbs_certificate.issuer == sid.issuer
                && c.tbs_certificate.serial_number == sid.serial_number
        })
        .ok_or(CmsError::Chain)?;
    let signer_der = signer.to_der().map_err(|_| CmsError::Decode)?;
    if signing_certificate_v2(&signer_der, signer)? != ess {
        return Err(CmsError::Attribute("signingCertificateV2"));
    }
    let key_alg = &signer.tbs_certificate.subject_public_key_info.algorithm.oid;
    let expected_sig = if *key_alg == ID_EC_PUBLIC_KEY {
        algorithm_identifier(SignatureAlgorithm::EcdsaP256Sha256)
    } else if *key_alg == RSA_ENCRYPTION {
        algorithm_identifier(SignatureAlgorithm::RsaPkcs1Sha256)
    } else {
        return Err(CmsError::UnsupportedKey);
    };
    if si.signature_algorithm != expected_sig {
        return Err(CmsError::SignatureAlgorithm);
    }
    let certificates = certs
        .iter()
        .map(|c| c.to_der().map_err(|_| CmsError::Decode))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(DecodedSignedData {
        signed_attributes: attrs.to_der().map_err(|_| CmsError::Decode)?,
        message_digest,
        signature: si.signature.as_bytes().to_vec(),
        signer_certificate: signer_der,
        certificates,
    })
}
