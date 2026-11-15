//! R-AU-01, SA-08 (Daniel, 2026-11-15): the readers of a programme's
//! audit log in the registry.
//!
//! - `audit.entries` and `audit.vault_outcomes` share one rule,
//!   `ReadRule::AUDIT_READER`: the auditor of the programme, every tenant
//!   admin, and an FSTP coordinator of the programme. Both are reads, so
//!   every reader reads them read-only.
//! - I-86 exposure is unchanged: `audit.entries` keeps its MCP tool and
//!   `audit.vault_outcomes` stays web only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, RoleOrApplicant, op, read_rule};
use fstp_domain::StateTag;
use fstp_domain::roles::Role;

/// R-AU-01, SA-08: the audit reader rule is the auditor, the tenant
/// admins and the FSTP coordinator of the programme, and nobody else.
#[test]
fn r_au_01_sa08_audit_reader_rule_names_the_three_readers() {
    assert_eq!(
        ReadRule::AUDIT_READER,
        ReadRule::AnyOf(&[
            ReadRule::Auditor,
            ReadRule::TenantAdmin,
            ReadRule::Holder(Role::FstpCoordinator),
        ])
    );
}

/// R-AU-01, SA-08: both audit reads use the audit reader rule, open in
/// every state.
#[test]
fn r_au_01_sa08_both_audit_reads_use_the_audit_reader_rule() {
    for kind in [ReadKind::GetAuditLog, ReadKind::GetVaultOutcomes] {
        let (rule, open) = read_rule(kind).expect("a rule");
        assert_eq!(rule, ReadRule::AUDIT_READER, "{kind:?}");
        for s in StateTag::ALL {
            assert!(open.contains(&s), "{kind:?} is closed in {s:?}");
        }
    }
}

/// R-AU-01, SA-08, I-86: both operations act as the three readers, are
/// reads (read-only), and keep their exposure: a tool for the entries,
/// none for the vault outcomes.
#[test]
fn r_au_01_sa08_i86_audit_operations_act_as_the_readers_and_keep_exposure() {
    let readers = [
        RoleOrApplicant::Role(Role::Auditor),
        RoleOrApplicant::Role(Role::TenantAdmin),
        RoleOrApplicant::Role(Role::FstpCoordinator),
    ];
    let entries = op("audit.entries").expect("in the registry");
    assert_eq!(entries.kind, OpKind::Read(ReadKind::GetAuditLog));
    assert_eq!(entries.acting, &readers);
    assert_eq!(
        entries.tool.map(|t| t.name),
        Some("fstp_audit_list_entries")
    );
    let outcomes = op("audit.vault_outcomes").expect("in the registry");
    assert_eq!(outcomes.kind, OpKind::Read(ReadKind::GetVaultOutcomes));
    assert_eq!(outcomes.acting, &readers);
    assert!(outcomes.tool.is_none(), "I-86: vault outcomes got a tool");
    for spec in [entries, outcomes] {
        assert!(!spec.high_risk && !spec.binding, "{}", spec.name);
    }
}
