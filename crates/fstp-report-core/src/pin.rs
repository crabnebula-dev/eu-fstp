//! The funder profile a document was generated under (M9 design section
//! 2.1, R-RP-01, P-53).
//!
//! `ReportGenerated` names the profile by id, version and the SHA-256 of
//! its shipped file. The P-53 value of a programme names the id and the
//! version only, so [`ProfilePin::matches_p53`] compares those two.

use fstp_domain::id::ContentDigest;
use fstp_json::Value;

/// The longest profile id accepted, in bytes.
pub const MAX_PROFILE_ID: usize = 40;

/// The profile of a generated document.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProfilePin {
    /// The profile id, such as `horizon-europe`.
    pub id: String,
    /// Its version, at least 1.
    pub version: u16,
    /// The SHA-256 of the profile file bytes.
    pub digest: ContentDigest,
}

/// Whether `id` is a profile id: 1 to [`MAX_PROFILE_ID`] bytes of
/// lower-case ASCII letters, digits and inner hyphens.
pub fn is_profile_id(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= MAX_PROFILE_ID
        && b.iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
        && b.first() != Some(&b'-')
        && b.last() != Some(&b'-')
}

/// The id and version a P-53 value names: the canonical text of
/// `{"profile": id, "version": n}` with `n` from 1 to 65535. Anything else
/// names no profile.
pub fn p53_profile(p53_text: &str) -> Option<(String, u16)> {
    let v = fstp_json::parse(p53_text.as_bytes()).ok()?;
    let o = v.as_object()?;
    if o.len() != 2 {
        return None;
    }
    let id = o.get("profile").and_then(Value::as_str)?;
    let version = o
        .get("version")
        .and_then(Value::as_u64)
        .and_then(|n| u16::try_from(n).ok())
        .filter(|n| *n >= 1)?;
    is_profile_id(id).then(|| (id.to_owned(), version))
}

impl ProfilePin {
    /// Whether this pin names the profile and version of the P-53 value
    /// `p53_text` (R-RP-01).
    pub fn matches_p53(&self, p53_text: &str) -> bool {
        p53_profile(p53_text).is_some_and(|(id, v)| id == self.id && v == self.version)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn r_rp_01_p53_names_id_and_version() {
        assert_eq!(
            p53_profile(r#"{"profile":"horizon-europe","version":1}"#),
            Some(("horizon-europe".to_owned(), 1))
        );
        for bad in [
            r#""synthetic funder profile""#,
            r#"{"profile":"horizon-europe","version":0}"#,
            r#"{"profile":"horizon-europe","version":70000}"#,
            r#"{"profile":"Horizon","version":1}"#,
            r#"{"profile":"horizon-europe","version":1,"x":1}"#,
            r#"{"profile":"horizon-europe"}"#,
        ] {
            assert_eq!(p53_profile(bad), None, "{bad}");
        }
        let pin = ProfilePin {
            id: "horizon-europe".to_owned(),
            version: 1,
            digest: ContentDigest::from_bytes([0; 32]),
        };
        assert!(pin.matches_p53(r#"{"profile":"horizon-europe","version":1}"#));
        assert!(!pin.matches_p53(r#"{"profile":"horizon-europe","version":2}"#));
    }

    #[test]
    fn profile_ids() {
        assert!(is_profile_id("horizon-europe"));
        assert!(is_profile_id("synthetic-funder"));
        let long = "a".repeat(41);
        for bad in ["", "-a", "a-", "A", "a_b", long.as_str()] {
            assert!(!is_profile_id(bad), "{bad}");
        }
    }
}
