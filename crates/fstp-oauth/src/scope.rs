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
    /// `tenant:draft` (ADR-013 amendment of 2026-11-20).
    TenantDraft,
}

impl Scope {
    /// Every scope issued in M4, in canonical order.
    pub const ALL: [Scope; 13] = [
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
        Scope::TenantDraft,
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
            Scope::TenantDraft => "tenant:draft",
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

    /// The stored form of the set (lane L2, `mcp.family.scopes`): bit `i`
    /// is the scope at position `i` of [`Scope::ALL`]. The positions are a
    /// storage format, so a scope is only ever appended.
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// The set of the stored form `bits`, or `None` when it is empty or
    /// names a bit no scope has.
    pub fn from_bits(bits: u16) -> Option<ScopeSet> {
        let known = Scope::ALL.iter().fold(0u16, |a, s| a | s.bit());
        if bits == 0 || bits & !known != 0 {
            None
        } else {
            Some(ScopeSet(bits))
        }
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

    /// R-MC-01, lane L2: the stored form of a scope set is a storage
    /// format. Each scope keeps its bit, a set round-trips, and an empty
    /// set or an unknown bit is refused.
    #[test]
    fn r_mc_01_scope_bits_are_a_fixed_storage_format() {
        let pinned = [
            ("calls:read", 0),
            ("proposals:read", 1),
            ("proposals:draft", 2),
            ("proposals:binding", 3),
            ("stage2:draft", 4),
            ("review:read", 5),
            ("review:draft", 6),
            ("ranking:read", 7),
            ("findings:read", 8),
            ("creator:draft", 9),
            ("calls:draft", 10),
            ("audit:read", 11),
            ("tenant:draft", 12),
        ];
        assert_eq!(pinned.len(), Scope::ALL.len());
        for (wire, bit) in pinned {
            let set = ScopeSet::parse(wire).unwrap_or_default();
            assert_eq!(set.bits(), 1u16 << bit, "{wire}");
            assert_eq!(ScopeSet::from_bits(set.bits()), Some(set));
        }
        assert_eq!(ScopeSet::from_bits(0), None);
        assert_eq!(ScopeSet::from_bits(1 << 13), None);
        assert_eq!(ScopeSet::from_bits(u16::MAX), None);
    }
}
