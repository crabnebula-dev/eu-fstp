//! The record checks of the sending domain probe (ADR-027): SPF, DKIM and
//! DMARC, over the TXT records [`super::dns`] reads.
//!
//! - SPF (RFC 7208 section 4.5): exactly one record at the domain whose
//!   text is `v=spf1`, alone or followed by a space.
//! - DMARC (RFC 7489 section 6.6.3): exactly one record at
//!   `_dmarc.<domain>` that starts with `v=DMARC1`, with a `p` tag of
//!   `none`, `quarantine` or `reject`.
//! - DKIM (RFC 6376 section 3.6.1): a record at
//!   `<selector>._domainkey.<domain>` with a non-empty `p` tag. An empty
//!   `p` is a revoked key. A `v` tag, if present, is first and `DKIM1`.
//!
//! Each check reads bytes only and never panics.

/// The tags of a tag list (RFC 6376 section 3.2): `name=value` pairs
/// separated by semicolons, with whitespace around each part trimmed.
fn tags(record: &[u8]) -> Vec<(String, String)> {
    let text = String::from_utf8_lossy(record);
    text.split(';')
        .filter_map(|part| {
            let (name, value) = part.split_once('=')?;
            Some((
                name.trim().to_owned(),
                value
                    .chars()
                    .filter(|c| !c.is_ascii_whitespace())
                    .collect::<String>(),
            ))
        })
        .collect()
}

/// Whether `record` is an SPF record: `v=spf1` alone or followed by a
/// space, compared without case.
fn is_spf(record: &[u8]) -> bool {
    let Some(head) = record.get(..6) else {
        return false;
    };
    head.eq_ignore_ascii_case(b"v=spf1") && record.get(6).is_none_or(|b| *b == b' ')
}

/// SPF: exactly one SPF record among `records`, the TXT records at the
/// domain.
pub fn spf_ok(records: &[Vec<u8>]) -> bool {
    records.iter().filter(|r| is_spf(r)).count() == 1
}

/// Whether `record` is a DMARC record with a valid policy.
fn dmarc_record(record: &[u8]) -> Option<bool> {
    let t = tags(record);
    let (first, _) = t.first()?;
    let version = t.first().map(|(_, v)| v.as_str());
    if first != "v" || version != Some("DMARC1") {
        return None;
    }
    Some(t.iter().any(|(n, v)| {
        n == "p"
            && matches!(
                v.to_ascii_lowercase().as_str(),
                "none" | "quarantine" | "reject"
            )
    }))
}

/// DMARC: exactly one DMARC record among `records`, the TXT records at
/// `_dmarc.<domain>`, and it names a valid policy.
pub fn dmarc_ok(records: &[Vec<u8>]) -> bool {
    let found: Vec<bool> = records.iter().filter_map(|r| dmarc_record(r)).collect();
    found == [true]
}

/// Whether `record` is a DKIM key record with a key.
fn dkim_record(record: &[u8]) -> bool {
    let t = tags(record);
    let version_ok = match t.iter().position(|(n, _)| n == "v") {
        None => true,
        Some(0) => t.first().is_some_and(|(_, v)| v == "DKIM1"),
        Some(_) => false,
    };
    version_ok && t.iter().any(|(n, v)| n == "p" && !v.is_empty())
}

/// DKIM: a key record with a non-empty `p` among `records`, the TXT
/// records at `<selector>._domainkey.<domain>`.
pub fn dkim_ok(records: &[Vec<u8>]) -> bool {
    records.iter().any(|r| dkim_record(r))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(s: &str) -> Vec<u8> {
        s.as_bytes().to_vec()
    }

    /// ADR-027, RFC 7208 section 4.5: one SPF record passes, none or two
    /// fail, and a longer version word is not SPF.
    #[test]
    fn adr027_spf_needs_exactly_one_record() {
        assert!(spf_ok(&[
            r("v=spf1 include:_spf.example.org -all"),
            r("other")
        ]));
        assert!(spf_ok(&[r("V=SPF1")]));
        assert!(!spf_ok(&[]));
        assert!(!spf_ok(&[r("v=spf1 -all"), r("v=spf1 ~all")]));
        assert!(!spf_ok(&[r("v=spf10 -all")]));
    }

    /// ADR-027, RFC 7489 section 6.6.3: one record with a valid policy.
    #[test]
    fn adr027_dmarc_needs_one_record_with_a_policy() {
        assert!(dmarc_ok(&[r(
            "v=DMARC1; p=reject; rua=mailto:d@example.org"
        )]));
        assert!(dmarc_ok(&[r("v=DMARC1;p=none")]));
        assert!(!dmarc_ok(&[r("v=DMARC1; p=maybe")]));
        assert!(!dmarc_ok(&[r("p=reject; v=DMARC1")]));
        assert!(!dmarc_ok(&[r("v=DMARC1; p=reject"), r("v=DMARC1; p=none")]));
        assert!(!dmarc_ok(&[]));
    }

    /// ADR-027, RFC 6376 section 3.6.1: a key record with a key passes; a
    /// revoked key, a misplaced version or another version fails.
    #[test]
    fn adr027_dkim_needs_a_key() {
        assert!(dkim_ok(&[r("v=DKIM1; k=rsa; p=MIGfMA0G CSqGSIb3")]));
        assert!(dkim_ok(&[r("p=MIGfMA0GCSqGSIb3")]));
        assert!(!dkim_ok(&[r("v=DKIM1; p=")]));
        assert!(!dkim_ok(&[r("k=rsa; v=DKIM1; p=abc")]));
        assert!(!dkim_ok(&[r("v=DKIM2; p=abc")]));
        assert!(!dkim_ok(&[]));
    }
}
