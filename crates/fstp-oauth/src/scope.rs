//! The scopes issued in M4 (design section 3.8, ADR-013 "Scopes").

/// One scope issued in M4. A scope never adds a right that the roles lack.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// `calls:read`.
    CallsRead,
    /// `proposals:read`.
    ProposalsRead,
    /// `proposals:draft`.
    ProposalsDraft,
    /// `proposals:binding`.
    ProposalsBinding,
    /// `stage2:draft`.
    Stage2Draft,
    /// `review:read`.
    ReviewRead,
    /// `review:draft`.
    ReviewDraft,
    /// `ranking:read`.
    RankingRead,
    /// `findings:read`.
    FindingsRead,
    /// `creator:draft`.
    CreatorDraft,
    /// `calls:draft`.
    CallsDraft,
    /// `audit:read`.
    AuditRead,
}

impl Scope {
    /// Every scope issued in M4, in canonical order.
    pub const ALL: [Scope; 12] = [
        Scope::CallsRead,
        Scope::ProposalsRead,
        Scope::ProposalsDraft,
        Scope::ProposalsBinding,
        Scope::Stage2Draft,
        Scope::ReviewRead,
        Scope::ReviewDraft,
        Scope::RankingRead,
        Scope::FindingsRead,
        Scope::CreatorDraft,
        Scope::CallsDraft,
        Scope::AuditRead,
    ];

    /// The wire spelling.
    pub const fn as_str(self) -> &'static str {
        match self {
            Scope::CallsRead => "calls:read",
            Scope::ProposalsRead => "proposals:read",
            Scope::ProposalsDraft => "proposals:draft",
            Scope::ProposalsBinding => "proposals:binding",
            Scope::Stage2Draft => "stage2:draft",
            Scope::ReviewRead => "review:read",
            Scope::ReviewDraft => "review:draft",
            Scope::RankingRead => "ranking:read",
            Scope::FindingsRead => "findings:read",
            Scope::CreatorDraft => "creator:draft",
            Scope::CallsDraft => "calls:draft",
            Scope::AuditRead => "audit:read",
        }
    }

    /// The scope spelt `s`, if it is issued in M4.
    pub fn from_wire(s: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|x| x.as_str() == s)
    }

    const fn bit(self) -> u16 {
        1u16 << (self as u16)
    }
}

/// A set of scopes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ScopeSet(u16);

impl ScopeSet {
    /// The empty set.
    pub const EMPTY: ScopeSet = ScopeSet(0);

    /// Parses a `scope` parameter: scopes issued in M4, each once,
    /// separated by single spaces, at least one. Anything else is `None`.
    pub fn parse(s: &str) -> Option<ScopeSet> {
        let mut set = ScopeSet::EMPTY;
        for part in s.split(' ') {
            let scope = Scope::from_wire(part)?;
            if set.contains(scope) {
                return None;
            }
            set = set.with(scope);
        }
        (!set.is_empty()).then_some(set)
    }

    /// This set with `scope` added.
    pub const fn with(self, scope: Scope) -> ScopeSet {
        ScopeSet(self.0 | scope.bit())
    }

    /// Whether `scope` is in the set.
    pub const fn contains(self, scope: Scope) -> bool {
        self.0 & scope.bit() != 0
    }

    /// Whether every scope of this set is in `other`.
    pub const fn is_subset(self, other: ScopeSet) -> bool {
        self.0 & !other.0 == 0
    }

    /// Whether the set is empty.
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// The scopes, in canonical order.
    pub fn iter(self) -> impl Iterator<Item = Scope> {
        Scope::ALL.into_iter().filter(move |s| self.contains(*s))
    }

    /// The wire spelling: canonical order, single spaces.
    pub fn to_wire(self) -> String {
        let mut out = String::new();
        for s in self.iter() {
            if !out.is_empty() {
                out.push(' ');
            }
            out.push_str(s.as_str());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// ADR-013: every issued scope parses, and unknown, repeated or
    /// badly separated scopes are refused.
    #[test]
    fn adr013_scope_parse() {
        for s in Scope::ALL {
            assert_eq!(Scope::from_wire(s.as_str()), Some(s));
        }
        assert!(ScopeSet::parse("calls:read calls:draft").is_some());
        for bad in [
            "",
            " calls:read",
            "calls:read ",
            "calls:read  calls:draft",
            "calls:read calls:read",
            "offline_access",
            "openid calls:read",
        ] {
            assert_eq!(ScopeSet::parse(bad), None, "{bad:?} accepted");
        }
    }
}
