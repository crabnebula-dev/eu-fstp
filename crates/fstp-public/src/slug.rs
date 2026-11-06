//! The public slug of each programme and the programme a `/p/{slug}/`
//! segment names (R-PB-01, R-PB-04; M4 design section 3.10).
//!
//! Interim reading, pending Daniel: nothing makes a draft's
//! `identity.public_slug` unique, and the slug rule allows one made only
//! of digits. So one programme could take over another's URL. These two
//! functions keep each URL to one programme:
//!
//! - A segment made only of ASCII digits names the programme with that
//!   id in decimal, and nothing else.
//! - A draft slug names its programme only when it holds a character that
//!   is not an ASCII digit and no other candidate's draft names the same
//!   slug. Otherwise the programme is public under its id in decimal.
//!
//! So no two programmes share a public slug, and an ambiguous draft slug
//! answers not found, never the lower-numbered programme.

use std::collections::BTreeMap;

use fstp_domain::id::ProgrammeId;

/// Whether `s` is non-empty and only ASCII digits.
fn all_digits(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// The public slug of each candidate (module documentation). A candidate
/// is a programme with its draft slug, `None` with no draft.
pub fn public_slugs(candidates: &[(ProgrammeId, Option<&str>)]) -> BTreeMap<ProgrammeId, String> {
    let mut uses: BTreeMap<&str, u32> = BTreeMap::new();
    for (_, slug) in candidates {
        if let Some(s) = slug.filter(|s| !s.is_empty() && !all_digits(s)) {
            let n = uses.entry(s).or_insert(0);
            *n = n.saturating_add(1);
        }
    }
    candidates
        .iter()
        .map(|(p, slug)| {
            let own = slug.filter(|s| uses.get(s).copied() == Some(1));
            (*p, own.map_or_else(|| p.raw().to_string(), str::to_owned))
        })
        .collect()
}

/// The candidate the path segment `segment` names, or `None` (module
/// documentation).
pub fn resolve_slug(
    candidates: &[(ProgrammeId, Option<&str>)],
    segment: &str,
) -> Option<ProgrammeId> {
    if all_digits(segment) {
        return candidates
            .iter()
            .map(|(p, _)| *p)
            .find(|p| p.raw().to_string() == segment);
    }
    public_slugs(candidates)
        .into_iter()
        .find(|(_, s)| s == segment)
        .map(|(p, _)| p)
}

#[cfg(test)]
mod tests {
    use super::*;

    const P1: ProgrammeId = ProgrammeId::from_raw(1);
    const P2: ProgrammeId = ProgrammeId::from_raw(2);
    const P3: ProgrammeId = ProgrammeId::from_raw(3);

    /// R-PB-04: two drafts naming the same slug make it ambiguous, so it
    /// names neither programme, and each stays public under its id.
    #[test]
    fn r_pb_04_duplicate_slug_names_no_programme() {
        let c = [(P1, Some("two")), (P2, Some("two"))];
        assert_eq!(resolve_slug(&c, "two"), None);
        assert_eq!(resolve_slug(&c, "1"), Some(P1));
        assert_eq!(resolve_slug(&c, "2"), Some(P2));
        let s = public_slugs(&c);
        assert_eq!(s.get(&P1).map(String::as_str), Some("1"));
        assert_eq!(s.get(&P2).map(String::as_str), Some("2"));
    }

    /// R-PB-04: a draft slug made only of digits never takes over the id
    /// of another programme.
    #[test]
    fn r_pb_04_digit_slug_never_takes_another_id() {
        let c = [(P1, Some("2")), (P2, None)];
        assert_eq!(resolve_slug(&c, "2"), Some(P2));
        assert_eq!(resolve_slug(&c, "1"), Some(P1));
        assert_eq!(public_slugs(&c).get(&P1).map(String::as_str), Some("1"));
    }

    /// R-PB-04: a unique draft slug names its programme, and the id in
    /// decimal still reaches it.
    #[test]
    fn r_pb_04_unique_slug_names_its_programme() {
        let c = [(P1, Some("supersafe")), (P2, Some("other")), (P3, None)];
        assert_eq!(resolve_slug(&c, "supersafe"), Some(P1));
        assert_eq!(resolve_slug(&c, "other"), Some(P2));
        assert_eq!(resolve_slug(&c, "3"), Some(P3));
        assert_eq!(resolve_slug(&c, "1"), Some(P1));
        assert_eq!(resolve_slug(&c, "missing"), None);
        assert_eq!(resolve_slug(&c, ""), None);
        assert_eq!(resolve_slug(&c, "01"), None);
    }
}
