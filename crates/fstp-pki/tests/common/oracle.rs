//! rustls-webpki as the reading oracle.
//!
//! The `rustls-pki-types` types that rustls-webpki takes are not named
//! here: their values come from type inference, so the tests need only the
//! rustls-webpki line that lane W1i was granted. rustls-webpki 0.103.16
//! does not re-export `pki_types`, and `UnixTime` has no constructor that
//! inference can reach. So [`verify_for_usage`] gets its `UnixTime` from
//! rustls-webpki's own CRL reader, as the revocation date of one entry in
//! a synthetic CRL. [`unix_secs_via_crl`] checks that conversion. If the
//! lead grants a `rustls-pki-types` dev-dependency line, this becomes
//! `UnixTime::since_unix_epoch`.

/// What rustls-webpki reads back from one certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Read {
    /// The serial INTEGER content octets.
    pub(crate) serial: Vec<u8>,
    /// The issuer Name, without its outer SEQUENCE tag and length.
    pub(crate) issuer: Vec<u8>,
    /// The subject Name, without its outer SEQUENCE tag and length.
    pub(crate) subject: Vec<u8>,
    /// The SubjectPublicKeyInfo, DER.
    pub(crate) spki: Vec<u8>,
    /// The valid `dNSName` entries of the subjectAltName.
    pub(crate) dns_names: Vec<String>,
}

/// Parses `der` as an end-entity certificate and reads its fields back.
///
/// # Errors
///
/// Returns the rustls-webpki error, formatted.
pub(crate) fn read(der: &[u8]) -> Result<Read, String> {
    let cert = der.into();
    // Pins the inferred type of `cert` to `CertificateDer`, since the
    // `TryFrom` call below alone leaves it open.
    let _ = webpki::anchor_from_trusted_cert(&cert);
    let ee = webpki::EndEntityCert::try_from(&cert).map_err(|e: webpki::Error| format!("{e:?}"))?;
    Ok(Read {
        serial: ee.serial().to_vec(),
        issuer: ee.issuer().to_vec(),
        subject: ee.subject().to_vec(),
        spki: ee.subject_public_key_info().as_ref().to_vec(),
        dns_names: ee.valid_dns_names().map(str::to_owned).collect(),
    })
}

/// Whether rustls-webpki accepts `der` as a trust anchor.
pub(crate) fn is_anchor(der: &[u8]) -> Result<(), String> {
    let cert = der.into();
    webpki::anchor_from_trusted_cert(&cert)
        .map(|_| ())
        .map_err(|e| format!("{e:?}"))
}

/// Checks with rustls-webpki that the subject key of `issuer_der` signed
/// `msg` with ECDSA P-256 SHA-256 as `signature`.
pub(crate) fn verify_by(issuer_der: &[u8], msg: &[u8], signature: &[u8]) -> Result<(), String> {
    let cert = issuer_der.into();
    let _ = webpki::anchor_from_trusted_cert(&cert);
    let ee = webpki::EndEntityCert::try_from(&cert).map_err(|e: webpki::Error| format!("{e:?}"))?;
    ee.verify_signature(webpki::aws_lc_rs::ECDSA_P256_SHA256, msg, signature)
        .map_err(|e| format!("{e:?}"))
}

/// Checks with rustls-webpki that `der` is valid for `name`, a DNS name or
/// an IP address, through its subjectAltName.
pub(crate) fn valid_for_name(der: &[u8], name: &str) -> Result<(), String> {
    let cert = der.into();
    let _ = webpki::anchor_from_trusted_cert(&cert);
    let ee = webpki::EndEntityCert::try_from(&cert).map_err(|e: webpki::Error| format!("{e:?}"))?;
    let server_name = match name.try_into() {
        Ok(n) => n,
        Err(_) => return Err(format!("{name} is not a server name")),
    };
    ee.verify_is_valid_for_subject_name(&server_name)
        .map_err(|e| format!("{e:?}"))
}

/// Checks with rustls-webpki that `der` is valid for the IP address `ip`
/// through an `iPAddress` entry of its subjectAltName.
pub(crate) fn valid_for_ip(der: &[u8], ip: std::net::IpAddr) -> Result<(), String> {
    let cert = der.into();
    let _ = webpki::anchor_from_trusted_cert(&cert);
    let ee = webpki::EndEntityCert::try_from(&cert).map_err(|e: webpki::Error| format!("{e:?}"))?;
    ee.verify_is_valid_for_subject_name(&ip.into())
        .map_err(|e| format!("{e:?}"))
}

/// `id-ce-cRLNumber` (2.5.29.20), encoded.
const OID_CRL_NUMBER: &[u8] = &[0x06, 0x03, 0x55, 0x1d, 0x14];

/// The serial of the one entry in [`time_crl`].
const CRL_ENTRY_SERIAL: &[u8] = &[0x01];

/// A CRL with one revoked entry whose revocationDate is `t`, written with
/// the reference DER writer. It is never verified or used for revocation:
/// it only carries `t` into rustls-webpki, whose CRL reader returns it as
/// a `UnixTime`. `None` when `t` is outside 1970 ..= 9999.
fn time_crl(t: i64) -> Option<Vec<u8>> {
    use super::der;
    if t < 0 {
        return None;
    }
    let at = super::time::time(t)?;
    let version_2 = [0x02, 0x01, 0x01];
    let entry = der::seq(&[&der::tlv(0x02, CRL_ENTRY_SERIAL), &at]);
    let crl_number = der::extension(OID_CRL_NUMBER, false, &[0x02, 0x01, 0x01]);
    let tbs = der::seq(&[
        &version_2,
        der::ALG_ECDSA_SHA256,
        &der::name("fstp-pki test time carrier", None),
        &at,
        &at,
        &der::seq(&[&entry]),
        &der::tlv(0xa0, &der::seq(&[&crl_number])),
    ]);
    Some(der::certificate(&tbs, der::ALG_ECDSA_SHA256, &[0x00]))
}

/// The seconds since the epoch that rustls-webpki reads from
/// [`time_crl`] for `t`. A self-test checks that it equals `t`, so
/// [`verify_for_usage`] checks at the instant it names.
pub(crate) fn unix_secs_via_crl(t: i64) -> Result<u64, String> {
    let crl = time_crl(t).ok_or_else(|| format!("{t} is outside 1970 ..= 9999"))?;
    let list = webpki::BorrowedCertRevocationList::from_der(&crl).map_err(|e| format!("{e:?}"))?;
    let list = webpki::CertRevocationList::from(list);
    let entry = list
        .find_serial(CRL_ENTRY_SERIAL)
        .map_err(|e| format!("{e:?}"))?
        .ok_or("the CRL entry is missing")?;
    Ok(entry.revocation_date.as_secs())
}

/// rustls-webpki `EndEntityCert::verify_for_usage` for the leaf `leaf`
/// under the one trust anchor `anchor`, with `intermediates`, at the
/// instant `t`, for `usage`, with ECDSA P-256 SHA-256.
pub(crate) fn verify_for_usage(
    anchor: &[u8],
    leaf: &[u8],
    intermediates: &[&[u8]],
    t: i64,
    usage: webpki::KeyUsage,
) -> Result<(), webpki::Error> {
    let crl = time_crl(t).ok_or(webpki::Error::BadDerTime)?;
    let list = webpki::BorrowedCertRevocationList::from_der(&crl)?;
    let list = webpki::CertRevocationList::from(list);
    let time = list
        .find_serial(CRL_ENTRY_SERIAL)?
        .ok_or(webpki::Error::BadDer)?
        .revocation_date;
    let anchor_der = anchor.into();
    let anchors = [webpki::anchor_from_trusted_cert(&anchor_der)?];
    let inter = intermediates
        .iter()
        .map(|d| {
            let c = (*d).into();
            let _ = webpki::anchor_from_trusted_cert(&c);
            c
        })
        .collect::<Vec<_>>();
    let leaf_der = leaf.into();
    let _ = webpki::anchor_from_trusted_cert(&leaf_der);
    let ee = webpki::EndEntityCert::try_from(&leaf_der)?;
    ee.verify_for_usage(
        &[webpki::aws_lc_rs::ECDSA_P256_SHA256],
        &anchors,
        &inter,
        time,
        usage,
        None,
        None,
    )
    .map(|_| ())
}
