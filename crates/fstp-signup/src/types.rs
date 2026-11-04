//! Ids, agreements and the decoded form types.

/// A tenant of the control plane.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TenantId(u128);

impl TenantId {
    /// The id with raw value `r`.
    pub const fn from_raw(r: u128) -> TenantId {
        TenantId(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// An operator staff member of the control plane. Operator staff hold no
/// role in any cell (SoD-08).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StaffId(u128);

impl StaffId {
    /// The id with raw value `r`.
    pub const fn from_raw(r: u128) -> StaffId {
        StaffId(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// The three agreements of the onboarding Agreements step.
///
/// TODO(legal): the texts of all three agreements are pending. The crate
/// records versions only and holds no agreement wording.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Agreement {
    /// The SaaS terms.
    SaasTerms,
    /// The data processing agreement.
    Dpa,
    /// The sub-processor list.
    SubProcessors,
}

impl Agreement {
    /// Every agreement, in the order the page renders them.
    pub const ALL: [Agreement; 3] = [
        Agreement::SaasTerms,
        Agreement::Dpa,
        Agreement::SubProcessors,
    ];

    /// The stored name, as in `cp.agreement_acceptances.agreement`.
    pub const fn name(self) -> &'static str {
        match self {
            Agreement::SaasTerms => "saas_terms",
            Agreement::Dpa => "dpa",
            Agreement::SubProcessors => "sub_processors",
        }
    }

    /// The agreement with stored name `s`.
    pub fn from_name(s: &str) -> Option<Agreement> {
        Agreement::ALL.into_iter().find(|a| a.name() == s)
    }
}

/// One version of each agreement.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AgreementVersions {
    /// The SaaS terms.
    pub saas_terms: u32,
    /// The data processing agreement.
    pub dpa: u32,
    /// The sub-processor list.
    pub sub_processors: u32,
}

impl AgreementVersions {
    /// The version of `a`.
    pub const fn of(self, a: Agreement) -> u32 {
        match a {
            Agreement::SaasTerms => self.saas_terms,
            Agreement::Dpa => self.dpa,
            Agreement::SubProcessors => self.sub_processors,
        }
    }

    /// Each agreement with its version, in rendering order.
    pub fn pairs(self) -> [(Agreement, u32); 3] {
        Agreement::ALL.map(|a| (a, self.of(a)))
    }
}

/// The fields of the sign-up form (Q22: the control plane keeps them).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SignupFields {
    /// The legal entity.
    pub legal_name: String,
    /// The billing address. It may hold CR LF line breaks.
    pub billing_address: String,
    /// The contracting signatory.
    pub contracting_signatory: String,
}

/// The fields of the agreement form.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct AgreementFields {
    /// The tenant that accepts.
    pub tenant: TenantId,
    /// The versions shown and accepted.
    pub versions: AgreementVersions,
    /// The person who accepts.
    pub accepted_by: String,
}

/// A decoded sign-up or agreement form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SignupForm {
    /// The sign-up form.
    Signup(SignupFields),
    /// The agreement form.
    Agreements(AgreementFields),
}

/// A staff member's review outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReviewOutcome {
    /// The tenant's identity is confirmed.
    Approved,
    /// The tenant's identity is not confirmed. This is final.
    Rejected,
}

impl ReviewOutcome {
    /// The stored name.
    pub const fn name(self) -> &'static str {
        match self {
            ReviewOutcome::Approved => "approved",
            ReviewOutcome::Rejected => "rejected",
        }
    }

    /// The outcome with stored name `s`.
    pub fn from_name(s: &str) -> Option<ReviewOutcome> {
        [ReviewOutcome::Approved, ReviewOutcome::Rejected]
            .into_iter()
            .find(|o| o.name() == s)
    }
}
