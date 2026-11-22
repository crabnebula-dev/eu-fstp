//! The tenant's legal details (ADR-037 section 1; Daniel, 2026-11-22,
//! `legal/README.md` Q4).
//!
//! One optional plain-text value per [`LegalField`]. The legal pages fill
//! the `{{controller.*}}` and `{{tenant.*}}` placeholders of the `legal/`
//! drafts from them, as text only (I-68). Shared code holds no value:
//! each tenant sets its own on the branding page.

use std::collections::BTreeMap;

/// The longest value, in bytes.
pub const MAX_LEGAL_BYTES: usize = 300;

/// Whether `s` may be a set legal value: 1 to [`MAX_LEGAL_BYTES`] bytes,
/// no control character, no angle bracket, and no leading or trailing
/// white space (I-68).
pub fn plain_value(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_LEGAL_BYTES
        && !s.chars().any(|c| c.is_control() || c == '<' || c == '>')
        && s.trim() == s
}

/// One field of the legal details, in the order of the form.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LegalField {
    /// The organisation's legal name.
    LegalName,
    /// The postal address.
    Address,
    /// The registered address.
    RegisteredAddress,
    /// The privacy contact.
    PrivacyContact,
    /// The Data Protection Officer's name.
    DpoName,
    /// The Data Protection Officer's contact.
    DpoContact,
    /// The data protection supervisory authority.
    SupervisoryAuthority,
    /// The accessibility contact.
    AccessibilityContact,
    /// The company registration number.
    CompanyNumber,
    /// The VAT number.
    VatNumber,
    /// The EU Transparency Register number.
    TransparencyRegister,
    /// The governing law.
    GoverningLaw,
}

impl LegalField {
    /// Every field, in the order of the form.
    pub const ALL: [LegalField; 12] = [
        LegalField::LegalName,
        LegalField::Address,
        LegalField::RegisteredAddress,
        LegalField::PrivacyContact,
        LegalField::DpoName,
        LegalField::DpoContact,
        LegalField::SupervisoryAuthority,
        LegalField::AccessibilityContact,
        LegalField::CompanyNumber,
        LegalField::VatNumber,
        LegalField::TransparencyRegister,
        LegalField::GoverningLaw,
    ];

    /// The field's key in requests, records and placeholders.
    pub const fn key(self) -> &'static str {
        match self {
            LegalField::LegalName => "legal_name",
            LegalField::Address => "address",
            LegalField::RegisteredAddress => "registered_address",
            LegalField::PrivacyContact => "privacy_contact",
            LegalField::DpoName => "dpo_name",
            LegalField::DpoContact => "dpo_contact",
            LegalField::SupervisoryAuthority => "supervisory_authority",
            LegalField::AccessibilityContact => "accessibility_contact",
            LegalField::CompanyNumber => "company_number",
            LegalField::VatNumber => "vat_number",
            LegalField::TransparencyRegister => "transparency_register",
            LegalField::GoverningLaw => "governing_law",
        }
    }

    /// The field whose key is `key`.
    pub fn from_key(key: &str) -> Option<LegalField> {
        LegalField::ALL.into_iter().find(|f| f.key() == key)
    }

    /// Whether `{{controller.<key>}}` names this field. The controller of
    /// a tenant's programmes is the tenant (Q1), so these read the same
    /// values as `{{tenant.<key>}}` (ADR-037, interim).
    const fn controller(self) -> bool {
        matches!(
            self,
            LegalField::LegalName
                | LegalField::Address
                | LegalField::PrivacyContact
                | LegalField::DpoName
                | LegalField::DpoContact
                | LegalField::SupervisoryAuthority
        )
    }
}

/// The tenant's legal details: the set fields only.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegalDetails {
    values: BTreeMap<LegalField, String>,
}

impl LegalDetails {
    /// The details of `pairs` (field key, value). An empty value leaves
    /// the field unset. `None` for an unknown key, a key named twice, or
    /// a value that is not [`plain_value`].
    pub fn from_pairs(pairs: &[(&str, &str)]) -> Option<LegalDetails> {
        let mut seen = std::collections::BTreeSet::new();
        let mut values = BTreeMap::new();
        for (k, v) in pairs {
            let f = LegalField::from_key(k)?;
            if !seen.insert(f) {
                return None;
            }
            if v.is_empty() {
                continue;
            }
            if !plain_value(v) {
                return None;
            }
            values.insert(f, (*v).to_owned());
        }
        Some(LegalDetails { values })
    }

    /// The value of `field`, if set.
    pub fn get(&self, field: LegalField) -> Option<&str> {
        self.values.get(&field).map(String::as_str)
    }

    /// The set fields and their values, in form order.
    pub fn pairs(&self) -> impl Iterator<Item = (LegalField, &str)> {
        self.values.iter().map(|(f, v)| (*f, v.as_str()))
    }

    /// Whether no field is set.
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The value a draft placeholder `name` names: `tenant.<key>` for
    /// every field, `controller.<key>` for the controller fields. `None`
    /// for an unset field or any other name.
    pub fn placeholder(&self, name: &str) -> Option<&str> {
        let field = if let Some(k) = name.strip_prefix("tenant.") {
            LegalField::from_key(k)?
        } else if let Some(k) = name.strip_prefix("controller.") {
            LegalField::from_key(k).filter(|f| f.controller())?
        } else {
            return None;
        };
        self.get(field)
    }
}
