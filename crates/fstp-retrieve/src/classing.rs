//! Source classing and the TH-12 verification rule (M7 design section
//! 3.2, T-LLM-RETRIEVAL).

use crate::url::SourceUrl;

/// Who controls a retrieved source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceClass {
    /// The host and path match a URL the proposal names as its own, or a
    /// repository whose maintainership it claims.
    ApplicantControlled,
    /// Any other source.
    Independent,
}

/// The URLs a proposal names as its own.
///
/// Matching is conservative. Host case, a leading `www.`, the scheme, the
/// port, the query, a trailing slash, path case and a `.git` suffix never
/// make an applicant source independent. A source matches when its host
/// equals a claimed host and its path segments start with the claimed
/// path segments.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplicantSources {
    claimed: Vec<(String, Vec<String>)>,
}

impl ApplicantSources {
    /// No claimed sources.
    #[must_use]
    pub fn new() -> ApplicantSources {
        ApplicantSources::default()
    }

    /// Adds a URL the proposal names as its own.
    pub fn add(&mut self, url: &SourceUrl) {
        let key = key(url);
        if !self.claimed.contains(&key) {
            self.claimed.push(key);
        }
    }

    /// Classes `url`.
    #[must_use]
    pub fn classify(&self, url: &SourceUrl) -> SourceClass {
        let (host, segs) = key(url);
        let hit = self
            .claimed
            .iter()
            .any(|(h, claimed)| *h == host && segs.starts_with(claimed));
        if hit {
            SourceClass::ApplicantControlled
        } else {
            SourceClass::Independent
        }
    }
}

fn key(url: &SourceUrl) -> (String, Vec<String>) {
    let host = url.host();
    let host = host.strip_prefix("www.").unwrap_or(host).to_owned();
    let segs = url
        .path()
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| {
            let s = s.to_ascii_lowercase();
            match s.strip_suffix(".git") {
                Some(base) if !base.is_empty() => base.to_owned(),
                _ => s,
            }
        })
        .collect();
    (host, segs)
}

/// What the model concluded about a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ClaimVerdict {
    /// The sources support the claim.
    Verified,
    /// The sources contradict the claim.
    Contradicted,
    /// The sources neither support nor contradict it.
    NotVerified,
}

/// Which kind of source a ruling rests on. The finding states it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Basis {
    /// At least one independent source.
    Independent,
    /// Only applicant-controlled sources.
    ApplicantControlledOnly,
    /// No source at all.
    NoSources,
}

/// The verdict after the TH-12 rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Ruling {
    /// The verdict to publish.
    pub verdict: ClaimVerdict,
    /// The kind of source it rests on.
    pub basis: Basis,
    /// The rule replaced a `Verified` from the model.
    pub downgraded: bool,
}

/// TH-12: a claim whose supporting sources are all applicant-controlled,
/// or that has none, is never `Verified`. The rule runs after the model
/// and overrides it. Other verdicts pass unchanged.
#[must_use]
pub fn th12_rule(model: ClaimVerdict, sources: &[SourceClass]) -> Ruling {
    let basis = if sources.contains(&SourceClass::Independent) {
        Basis::Independent
    } else if sources.is_empty() {
        Basis::NoSources
    } else {
        Basis::ApplicantControlledOnly
    };
    let downgraded = model == ClaimVerdict::Verified && basis != Basis::Independent;
    Ruling {
        verdict: if downgraded {
            ClaimVerdict::NotVerified
        } else {
            model
        },
        basis,
        downgraded,
    }
}
