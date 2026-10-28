//! The funds rule (I-16, `docs/handoff/m3-design.md` sections 2.4 rule 11
//! and 14.4).
//!
//! The platform never holds or controls funds. Structurally, no crate
//! builds a payment instruction or names a payment account type. A source
//! scan of every workspace member's `src/` and `build.rs` refuses the SEPA
//! credit transfer (ISO 20022 pain.001) element names, its document
//! namespace and the payment account and credential type names below.
//!
//! `deps/funds-allowed.txt` lists the crates that may name them, one per
//! line. It is empty in M3. The M5 payment adapter is its first entry. A
//! missing file counts as empty, which is the strictest reading.

use std::collections::BTreeSet;

use crate::allowlist::{LineError, valid_crate_name};
use crate::layering_m3::{SourceFile, occurrences};
use crate::report::Finding;

/// The policy file.
pub(crate) const FUNDS_ALLOWED: &str = "deps/funds-allowed.txt";

/// The payment terms no crate outside the list may name. The SEPA terms
/// are pain.001 element names. The type names are payment account and
/// credential types.
const TERMS: [&str; 17] = [
    // ISO 20022 pain.001 elements and the document namespace.
    "CstmrCdtTrfInitn",
    "CdtTrfTxInf",
    "PmtInf",
    "DbtrAcct",
    "CdtrAcct",
    "DbtrAgt",
    "CdtrAgt",
    "InstdAmt",
    "ReqdExctnDt",
    "urn:iso:std:iso:20022:tech:xsd:pain.",
    // Payment account and credential types.
    "DebtorAccount",
    "CreditorAccount",
    "PaymentInstruction",
    "CreditTransferInstruction",
    "PaymentInitiation",
    "BankCredential",
    "PaymentCredential",
];

/// Bytes that extend a scanned term, so the namespace is reported whole.
const TOKEN_EXTRA: &[u8] = b":.-";

/// Parses `deps/funds-allowed.txt`: one crate name per line, `#` comments.
pub(crate) fn parse_funds_allowed(text: &str) -> Result<BTreeSet<String>, Vec<LineError>> {
    let mut out = BTreeSet::new();
    let mut errors = Vec::new();
    for (i, raw) in text.lines().enumerate() {
        let line = i.saturating_add(1);
        let t = raw.trim();
        if t.is_empty() || t.starts_with('#') {
            continue;
        }
        if !valid_crate_name(t) {
            errors.push(LineError {
                line,
                message: format!("`{t}` is not a crate name"),
            });
        } else if !out.insert(t.to_owned()) {
            errors.push(LineError {
                line,
                message: format!("duplicate entry {t}"),
            });
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

/// Runs the rule over `sources`. `members` names every workspace member,
/// so a stale list entry is reported.
pub(crate) fn check(
    sources: &[SourceFile],
    allowed: &BTreeSet<String>,
    members: &BTreeSet<String>,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in sources {
        if allowed.contains(&f.krate) {
            continue;
        }
        for term in TERMS {
            for (line, token) in occurrences(&f.text, term, TOKEN_EXTRA) {
                out.push(Finding::error(
                    "funds",
                    format!(
                        "{} names the payment term `{token}` in {}:{line}; only crates in {FUNDS_ALLOWED} may (I-16)",
                        f.krate, f.rel
                    ),
                ));
            }
        }
    }
    for name in allowed {
        if !members.contains(name) {
            out.push(Finding::warning(
                "funds-stale",
                format!("{FUNDS_ALLOWED} lists {name}, which is not a workspace member"),
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file(krate: &str, text: &str) -> SourceFile {
        SourceFile {
            krate: krate.to_owned(),
            rel: format!("crates/{krate}/src/lib.rs"),
            text: text.to_owned(),
        }
    }

    /// I-16: a seeded payment element fails, and the list exempts a crate.
    #[test]
    fn i16_funds_rule_refuses_terms_outside_the_list() {
        let sources = [
            file("fstp-cell", "const X: &str = \"CdtTrfTxInf\";\n"),
            file("fstp-adapter", "struct DebtorAccount;\n"),
            file("fstp-domain", "pub fn approve_payment() {}\n"),
        ];
        let members: BTreeSet<String> = ["fstp-cell", "fstp-adapter", "fstp-domain"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let none = check(&sources, &BTreeSet::new(), &members);
        let msgs: Vec<&str> = none.iter().map(|f| f.message.as_str()).collect();
        assert_eq!(none.len(), 2, "{msgs:?}");
        assert!(
            msgs.iter().any(|m| m.starts_with(
                "fstp-cell names the payment term `CdtTrfTxInf` in crates/fstp-cell/src/lib.rs:1"
            )),
            "{msgs:?}"
        );
        let allowed: BTreeSet<String> = ["fstp-adapter".to_owned()].into_iter().collect();
        let listed = check(&sources, &allowed, &members);
        assert_eq!(listed.len(), 1, "{listed:?}");
    }

    /// I-16: the list file parses one crate per line and refuses others.
    #[test]
    fn i16_funds_allowed_parses_strictly() {
        assert_eq!(
            parse_funds_allowed("# c\n\nfstp-adapter\n"),
            Ok(["fstp-adapter".to_owned()].into_iter().collect())
        );
        assert!(parse_funds_allowed("fstp adapter\n").is_err());
        assert!(parse_funds_allowed("a\na\n").is_err());
    }
}
