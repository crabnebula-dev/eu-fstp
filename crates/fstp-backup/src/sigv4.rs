//! AWS Signature Version 4 for the S3 subset (ADR-012 "S3 subset",
//! record of lane L10).
//!
//! This composes HMAC-SHA256 and SHA-256 from `fstp-crypto`. It adds no
//! primitive. The signed headers are always `host`,
//! `x-amz-content-sha256` and `x-amz-date`, and the payload hash is
//! always the SHA-256 of the body.
//!
//! ```text
//! canonical = method \n path \n query \n
//!             "host:" host \n "x-amz-content-sha256:" hash \n "x-amz-date:" date \n
//!             \n "host;x-amz-content-sha256;x-amz-date" \n hash
//! scope     = yyyymmdd "/" region "/s3/aws4_request"
//! to_sign   = "AWS4-HMAC-SHA256" \n date \n scope \n hex(SHA-256(canonical))
//! key       = HMAC(HMAC(HMAC(HMAC("AWS4" || secret, yyyymmdd), region), "s3"), "aws4_request")
//! signature = hex(HMAC(key, to_sign))
//! ```

/// The signed header list.
pub const SIGNED_HEADERS: &str = "host;x-amz-content-sha256;x-amz-date";
/// The service name in the scope.
pub const SERVICE: &str = "s3";
/// The algorithm name.
pub const ALGORITHM: &str = "AWS4-HMAC-SHA256";

/// The request credentials: an access key id and its secret. The secret
/// never appears in `Debug` or in an error (R-NF-02).
#[derive(Clone)]
pub struct Credentials {
    access_key_id: String,
    secret: Vec<u8>,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Credentials").finish_non_exhaustive()
    }
}

impl Drop for Credentials {
    fn drop(&mut self) {
        // Best effort only: `fstp-backup` takes no direct dependency on
        // `zeroize` (ADR-001 record of the crates that use it).
        self.secret.fill(0);
    }
}

impl Credentials {
    /// Credentials from an access key id and a secret. Both must be
    /// printable ASCII without spaces, 1 to 128 bytes.
    ///
    /// # Errors
    ///
    /// [`crate::BackupError::Config`] naming the part, never its bytes.
    pub fn new(access_key_id: &str, secret: &str) -> Result<Credentials, crate::BackupError> {
        let ok = |s: &str| (1..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_graphic());
        if !ok(access_key_id) {
            return Err(crate::BackupError::Config("s3-access-key-id"));
        }
        if !ok(secret) {
            return Err(crate::BackupError::Config("s3-secret-access-key"));
        }
        Ok(Credentials {
            access_key_id: access_key_id.to_owned(),
            secret: secret.as_bytes().to_vec(),
        })
    }

    /// The access key id.
    #[must_use]
    pub fn access_key_id(&self) -> &str {
        &self.access_key_id
    }
}

/// What one request signs.
#[derive(Clone, Debug)]
pub struct Signed<'a> {
    /// The method, such as `PUT`.
    pub method: &'a str,
    /// The path, already encoded with [`uri_encode`] per segment.
    pub path: &'a str,
    /// The query parameters, not yet encoded.
    pub query: &'a [(&'a str, &'a str)],
    /// The value of the `host` header.
    pub host: &'a str,
    /// The lowercase hex SHA-256 of the body.
    pub payload_sha256: &'a str,
    /// The time, `yyyymmddThhmmssZ`.
    pub amz_date: &'a str,
    /// The region.
    pub region: &'a str,
}

/// Percent-encodes `s` as SigV4 asks: every byte but the unreserved
/// `A-Z a-z 0-9 - . _ ~` as `%XX` in uppercase hex, and `/` too unless
/// `keep_slash`.
#[must_use]
pub fn uri_encode(s: &str, keep_slash: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric()
            || matches!(b, b'-' | b'.' | b'_' | b'~')
            || (keep_slash && b == b'/')
        {
            out.push(char::from(b));
        } else {
            out.push('%');
            out.push(digit(HEX_UPPER, b >> 4));
            out.push(digit(HEX_UPPER, b));
        }
    }
    out
}

const HEX_UPPER: &[u8; 16] = b"0123456789ABCDEF";
const HEX_LOWER: &[u8; 16] = b"0123456789abcdef";

/// The hex digit of the low four bits of `n` in `table`.
fn digit(table: &[u8; 16], n: u8) -> char {
    char::from(table.get(usize::from(n & 0xf)).copied().unwrap_or(b'0'))
}

/// Lowercase hex.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        s.push(digit(HEX_LOWER, b >> 4));
        s.push(digit(HEX_LOWER, *b));
    }
    s
}

/// The canonical query string: each name and value encoded, sorted by
/// name and then value, joined with `&`.
#[must_use]
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> = query
        .iter()
        .map(|(k, v)| (uri_encode(k, false), uri_encode(v, false)))
        .collect();
    pairs.sort();
    pairs
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

/// The canonical request.
#[must_use]
pub fn canonical_request(s: &Signed<'_>) -> String {
    format!(
        "{}\n{}\n{}\nhost:{}\nx-amz-content-sha256:{}\nx-amz-date:{}\n\n{}\n{}",
        s.method,
        s.path,
        canonical_query(s.query),
        s.host,
        s.payload_sha256,
        s.amz_date,
        SIGNED_HEADERS,
        s.payload_sha256
    )
}

/// The credential scope of `amz_date` in `region`.
#[must_use]
pub fn scope(amz_date: &str, region: &str) -> String {
    let day = amz_date.get(..8).unwrap_or("");
    format!("{day}/{region}/{SERVICE}/aws4_request")
}

/// The string to sign.
#[must_use]
pub fn string_to_sign(s: &Signed<'_>) -> String {
    format!(
        "{ALGORITHM}\n{}\n{}\n{}",
        s.amz_date,
        scope(s.amz_date, s.region),
        hex(&fstp_crypto::sha256(canonical_request(s).as_bytes()))
    )
}

/// The signing key of `day` (`yyyymmdd`) and `region`.
fn signing_key(c: &Credentials, day: &str, region: &str) -> [u8; 32] {
    let mut k = b"AWS4".to_vec();
    k.extend_from_slice(&c.secret);
    let k_date = fstp_crypto::hmac_sha256(&k, day.as_bytes());
    k.fill(0);
    let k_region = fstp_crypto::hmac_sha256(&k_date, region.as_bytes());
    let k_service = fstp_crypto::hmac_sha256(&k_region, SERVICE.as_bytes());
    fstp_crypto::hmac_sha256(&k_service, b"aws4_request")
}

/// The signature, lowercase hex.
#[must_use]
pub fn signature(c: &Credentials, s: &Signed<'_>) -> String {
    let day = s.amz_date.get(..8).unwrap_or("");
    let key = signing_key(c, day, s.region);
    hex(&fstp_crypto::hmac_sha256(
        &key,
        string_to_sign(s).as_bytes(),
    ))
}

/// The `Authorization` header value.
#[must_use]
pub fn authorization(c: &Credentials, s: &Signed<'_>) -> String {
    format!(
        "{ALGORITHM} Credential={}/{}, SignedHeaders={SIGNED_HEADERS}, Signature={}",
        c.access_key_id,
        scope(s.amz_date, s.region),
        signature(c, s)
    )
}

/// `yyyymmddThhmmssZ` of `unix` seconds, in UTC (proleptic Gregorian).
#[must_use]
pub fn amz_date(unix: u64) -> String {
    // Years beyond 9999 cannot be spelled, and no clock gives them.
    let unix = unix.min(253_402_300_799);
    let days = unix.wrapping_div(86_400);
    let secs = unix.wrapping_rem(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z",
        secs.wrapping_div(3600),
        secs.wrapping_rem(3600).wrapping_div(60),
        secs.wrapping_rem(60)
    )
}

/// The year, month and day of `days` after 1970-01-01, by the
/// era-based civil calendar algorithm. `days` is at most 2 932 896
/// (9999-12-31), so no step overflows or underflows.
fn civil_from_days(days: u64) -> (u64, u64, u64) {
    let z = days.wrapping_add(719_468);
    let era = z.wrapping_div(146_097);
    let doe = z.wrapping_rem(146_097);
    let yoe = doe
        .wrapping_sub(doe.wrapping_div(1460))
        .wrapping_add(doe.wrapping_div(36_524))
        .wrapping_sub(doe.wrapping_div(146_096))
        .wrapping_div(365);
    let doy = doe.wrapping_sub(
        yoe.wrapping_mul(365)
            .wrapping_add(yoe.wrapping_div(4))
            .wrapping_sub(yoe.wrapping_div(100)),
    );
    let mp = doy.wrapping_mul(5).wrapping_add(2).wrapping_div(153);
    let d = doy
        .wrapping_sub(mp.wrapping_mul(153).wrapping_add(2).wrapping_div(5))
        .wrapping_add(1);
    let m = if mp < 10 {
        mp.wrapping_add(3)
    } else {
        mp.wrapping_sub(9)
    };
    let y = yoe
        .wrapping_add(era.wrapping_mul(400))
        .wrapping_add(u64::from(m <= 2));
    (y, m, d)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::arithmetic_side_effects)]

    use super::*;

    fn creds() -> Credentials {
        Credentials::new("EXAMPLEKEYID", "example/secret+key").unwrap()
    }

    fn input<'a>(query: &'a [(&'a str, &'a str)]) -> Signed<'a> {
        Signed {
            method: "PUT",
            path: "/bucket/00/wal/000000010000000000000001",
            query,
            host: "s3.example.eu",
            payload_sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            amz_date: "20261121T101500Z",
            region: "gra",
        }
    }

    /// ADR-012 "S3 subset": the UTC time of known instants.
    #[test]
    fn adr012_sigv4_amz_date_is_utc() {
        assert_eq!(amz_date(0), "19700101T000000Z");
        assert_eq!(amz_date(951_782_400), "20000229T000000Z");
        assert_eq!(amz_date(951_782_400 + 86_399), "20000229T235959Z");
        assert_eq!(amz_date(951_782_400 + 86_400), "20000301T000000Z");
        assert_eq!(amz_date(4_102_444_800), "21000101T000000Z");
    }

    /// ADR-012: the encoding keeps the unreserved bytes only.
    #[test]
    fn adr012_sigv4_uri_encoding() {
        assert_eq!(uri_encode("a-Z_0.9~", false), "a-Z_0.9~");
        assert_eq!(uri_encode("a/b c+=&", false), "a%2Fb%20c%2B%3D%26");
        assert_eq!(uri_encode("a/b c", true), "a/b%20c");
        assert_eq!(uri_encode("é", false), "%C3%A9");
        assert_eq!(
            canonical_query(&[("uploadId", "x y"), ("partNumber", "2")]),
            "partNumber=2&uploadId=x%20y"
        );
        assert_eq!(canonical_query(&[("uploads", "")]), "uploads=");
    }

    /// ADR-012: the canonical request has the documented form, and every
    /// signed element changes the signature.
    #[test]
    fn adr012_sigv4_every_signed_element_counts() {
        let q = [("partNumber", "1"), ("uploadId", "u")];
        let base = input(&q);
        assert_eq!(
            canonical_request(&base),
            "PUT\n/bucket/00/wal/000000010000000000000001\npartNumber=1&uploadId=u\n\
             host:s3.example.eu\n\
             x-amz-content-sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n\
             x-amz-date:20261121T101500Z\n\n\
             host;x-amz-content-sha256;x-amz-date\n\
             e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        let sig = signature(&creds(), &base);
        assert_eq!(sig.len(), 64);
        let q2 = [("partNumber", "2"), ("uploadId", "u")];
        let variants = [
            Signed {
                method: "GET",
                ..base.clone()
            },
            Signed {
                path: "/bucket/x",
                ..base.clone()
            },
            Signed {
                query: &q2,
                ..base.clone()
            },
            Signed {
                host: "s3.example.eu:444",
                ..base.clone()
            },
            Signed {
                payload_sha256: "00",
                ..base.clone()
            },
            Signed {
                amz_date: "20261121T101501Z",
                ..base.clone()
            },
            Signed {
                region: "sbg",
                ..base.clone()
            },
        ];
        for v in &variants {
            assert_ne!(signature(&creds(), v), sig, "{v:?}");
        }
        let other = Credentials::new("EXAMPLEKEYID", "another").unwrap();
        assert_ne!(signature(&other, &base), sig);
        let auth = authorization(&creds(), &base);
        assert_eq!(
            auth,
            format!(
                "AWS4-HMAC-SHA256 Credential=EXAMPLEKEYID/20261121/gra/s3/aws4_request, \
                 SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={sig}"
            )
        );
    }

    /// R-NF-02: credentials never show their secret.
    #[test]
    fn r_nf_02_credentials_debug_hides_the_secret() {
        let c = creds();
        assert!(!format!("{c:?}").contains("secret"));
        assert!(!format!("{c:?}").contains("EXAMPLEKEYID"));
        assert!(Credentials::new("id", "has space").is_err());
        let e = Credentials::new("id", "pass word").unwrap_err();
        assert!(!format!("{e} {e:?}").contains("word"));
    }
}
