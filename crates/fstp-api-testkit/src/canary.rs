//! The canary vault (I-86, M4 design section 8.4). Built by lane m4/i86.
//!
//! A [`CanaryVault`] holds the canaries the I-86 crawl looks for. Every
//! canary is synthetic and distinctive, so a hit can only be a leak:
//!
//! - identity attributes: one identity number per account, searched as
//!   decimal and as hexadecimal text;
//! - emails: one login email per account, under `canary.invalid`;
//! - bank-shaped strings: one IBAN-shaped canary per account, under bank
//!   code `00000000`, and any string of IBAN shape at all;
//! - vault facts: the verification, attestation and bank facts the vault
//!   holds for the world, planted by the crawl through the same numbers.
//!
//! [`CanaryVault::plant`] writes the identity numbers into a vault's facts
//! and the emails into the accounts port. M4 has no bank port, so no port
//! holds the IBAN canaries; the scan still refuses them and any IBAN shape.

use std::collections::BTreeMap;

use fstp_domain::id::AccountId;
use fstp_domain_testkit::vault::IdentityTag;

use crate::NotImplemented;

/// The first canary identity number.
pub const TAG_BASE: u64 = 0x0CA4_A41D_0086_0000;

/// A vault whose identity facts are canary strings.
#[derive(Clone, Debug)]
pub struct CanaryVault {
    tags: BTreeMap<AccountId, IdentityTag>,
    emails: BTreeMap<AccountId, String>,
    ibans: BTreeMap<AccountId, String>,
}

/// Builds the `CanaryVault` with no account. [`CanaryVault::over`] gives
/// each account its canaries.
pub fn canary_vault() -> Result<CanaryVault, NotImplemented> {
    Ok(CanaryVault::over(std::iter::empty()))
}

impl CanaryVault {
    /// The canary vault of `accounts`, in order.
    pub fn over(accounts: impl IntoIterator<Item = AccountId>) -> CanaryVault {
        let mut v = CanaryVault {
            tags: BTreeMap::new(),
            emails: BTreeMap::new(),
            ibans: BTreeMap::new(),
        };
        for (i, a) in (0u64..).zip(accounts) {
            let n = TAG_BASE.saturating_add(i);
            v.tags.insert(a, IdentityTag::new(n));
            v.emails
                .insert(a, format!("canary-id-{n:x}@canary.invalid"));
            // Synthetic: country XX, bank code 00000000, no real account.
            v.ibans.insert(a, format!("XX0000000000{i:010}"));
        }
        v
    }

    /// The accounts the vault knows.
    pub fn accounts(&self) -> impl Iterator<Item = AccountId> + '_ {
        self.tags.keys().copied()
    }

    /// The canary identity of `a`.
    pub fn tag(&self, a: AccountId) -> Option<IdentityTag> {
        self.tags.get(&a).copied()
    }

    /// The canary login email of `a`.
    pub fn email(&self, a: AccountId) -> Option<&str> {
        self.emails.get(&a).map(String::as_str)
    }

    /// Writes the canaries into a cell: each account's identity in
    /// `vault` is renamed to its canary number, keeping every relation and
    /// exclusion, and each account's login email becomes its canary email.
    pub fn plant(&self, vault: &crate::fake::FakeVault, accounts: &crate::fake::FakeAccounts) {
        vault.change(|t| {
            for (a, canary) in &self.tags {
                match t.identity_of(*a) {
                    Some(old) => t.rename_identity(old, *canary),
                    None => t.set_identity(*a, *canary),
                }
            }
        });
        for (a, e) in &self.emails {
            accounts.set_login_email(*a, e);
        }
    }

    /// Every canary string, each with what it stands for.
    pub fn canaries(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (a, t) in &self.tags {
            let n = t.raw();
            for text in [n.to_string(), format!("{n:x}"), format!("{n:X}")] {
                out.push((text, format!("identity of {a:?}")));
            }
        }
        for (a, e) in &self.emails {
            out.push((e.clone(), format!("email of {a:?}")));
        }
        for (a, b) in &self.ibans {
            out.push((b.clone(), format!("bank details of {a:?}")));
        }
        out
    }

    /// The leaks in `text`: each canary it holds, and an IBAN shape.
    pub fn leaks_in(&self, text: &str) -> Vec<String> {
        let mut out: Vec<String> = self
            .canaries()
            .into_iter()
            .filter(|(c, _)| text.contains(c.as_str()))
            .map(|(c, what)| format!("canary {c} ({what})"))
            .collect();
        if text.contains("@canary.invalid") && out.iter().all(|l| !l.contains("email")) {
            out.push("an email of the canary domain".to_owned());
        }
        if iban_shaped(text) {
            out.push("an IBAN-shaped string".to_owned());
        }
        out
    }
}

/// Whether `s` has IBAN shape somewhere in it: two capital letters, two
/// digits, then 11 to 30 capitals or digits.
pub fn iban_shaped(s: &str) -> bool {
    let b = s.as_bytes();
    (0..b.len()).any(|i| {
        let head = b.get(i..i.saturating_add(4)).is_some_and(|h| {
            h.first().is_some_and(u8::is_ascii_uppercase)
                && h.get(1).is_some_and(u8::is_ascii_uppercase)
                && h.get(2).is_some_and(u8::is_ascii_digit)
                && h.get(3).is_some_and(u8::is_ascii_digit)
        });
        let tail = b
            .iter()
            .skip(i.saturating_add(4))
            .take_while(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
            .count();
        head && (11..=30).contains(&tail)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-86: the canary predicates catch what they look for.
    #[test]
    fn i86_canary_vault_predicates() {
        let v = CanaryVault::over([AccountId::from_raw(1), AccountId::from_raw(2)]);
        assert!(iban_shaped("x DE89370400440532013000 y"));
        assert!(!iban_shaped("Proposal 11 in call 3"));
        for (c, _) in v.canaries() {
            assert!(!v.leaks_in(&format!("a {c} b")).is_empty(), "{c}");
        }
        assert!(v.leaks_in("nothing here").is_empty());
        assert_eq!(v.canaries().len(), 2 * 5);
    }
}
