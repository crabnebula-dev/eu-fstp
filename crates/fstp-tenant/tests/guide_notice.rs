//! The Guide's data protection summary and privacy statement address
//! (R-GA-01, `{{gdpr.notice_summary}}` and `{{funder.privacy_statement_url}}`;
//! Daniel's answer of 2026-11-06 in section 15.0 of the M4 design).
//!
//! Both come from a platform default, whose wording is `TODO(legal)`
//! until Daniel supplies it. A tenant admin may override both. The
//! override is approved text set by a tenant admin: the summary is a text
//! reference, as every free text outside ledger bodies is (ADR-007), and
//! the address must be an `https:` address. Nobody outside the admin set
//! can set it, and a high-risk change never arrives through MCP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest, TextId, TextRef};
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    CellKind, GuideNotice, GuideNoticeOverride, PLATFORM_DATA_PROTECTION_SUMMARY,
    PLATFORM_PRIVACY_STATEMENT_URL, TenantAnswers, TenantCommand, TenantCtx, TenantRecord,
    TenantRefusal, TenantState, decide, decode_command, decode_record, encode_command,
    encode_record,
};

const ADMIN: AccountId = AccountId::from_raw(1);
const OUTSIDER: AccountId = AccountId::from_raw(99);

fn ctx(actor: AccountId, via: Via) -> TenantCtx {
    TenantCtx {
        actor,
        via,
        at: Timestamp::from_micros(1_000_000),
    }
}

fn summary_ref() -> TextRef {
    TextRef::new(TextId::from_raw(77), ContentDigest::from_bytes([7; 32]))
}

fn override_of(url: &str) -> GuideNoticeOverride {
    GuideNoticeOverride {
        summary: summary_ref(),
        privacy_statement_url: url.to_owned(),
    }
}

/// R-GA-01, 15.0 (2026-11-06): without an override the Guide reads the
/// platform default, whose wording carries `TODO(legal)` until Daniel
/// supplies it, and whose address is an `https:` address.
#[test]
fn r_ga_01_platform_default_carries_todo_legal() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    assert_eq!(state.settings().guide_notice(), GuideNotice::Platform);
    assert!(PLATFORM_DATA_PROTECTION_SUMMARY.contains("TODO(legal)"));
    assert!(PLATFORM_PRIVACY_STATEMENT_URL.starts_with("https://"));
}

/// R-GA-01, 15.0 (2026-11-06): a tenant admin's override replaces the
/// platform default, survives a fold of its record alone, and a clear
/// brings the default back.
#[test]
fn r_ga_01_tenant_override_replaces_the_platform_default() {
    let mut state = TenantState::genesis(ADMIN, CellKind::Saas);
    let notice = override_of("https://privacy.tenant.example/statement");
    let cmd = TenantCommand::SetGuideNotice {
        notice: Some(notice.clone()),
    };
    let records = decide(&state, &ctx(ADMIN, Via::Web), &cmd, &TenantAnswers::new())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        records,
        vec![TenantRecord::GuideNoticeSet {
            notice: Some(notice.clone()),
            by: ADMIN,
        }]
    );
    state.apply_all(&records).unwrap();
    assert_eq!(
        state.settings().guide_notice(),
        GuideNotice::Tenant(&notice)
    );
    let clear = TenantCommand::SetGuideNotice { notice: None };
    let records = decide(&state, &ctx(ADMIN, Via::Web), &clear, &TenantAnswers::new()).unwrap();
    state.apply_all(&records).unwrap();
    assert_eq!(state.settings().guide_notice(), GuideNotice::Platform);
}

/// R-GA-01, I-78, I-85: only a tenant admin sets the override, never
/// through MCP, and the address must be an `https:` address.
#[test]
fn r_ga_01_tenant_override_is_admin_only_web_only_and_https() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    let good = TenantCommand::SetGuideNotice {
        notice: Some(override_of("https://privacy.tenant.example/")),
    };
    assert_eq!(
        decide(
            &state,
            &ctx(OUTSIDER, Via::Web),
            &good,
            &TenantAnswers::new()
        ),
        Err(TenantRefusal::NotTenantAdmin)
    );
    assert!(decide(&state, &ctx(ADMIN, Via::Mcp), &good, &TenantAnswers::new()).is_err());
    assert!(good.high_risk() && good.web_only());
    for bad in ["http://privacy.tenant.example/", "javascript:alert(1)", ""] {
        let cmd = TenantCommand::SetGuideNotice {
            notice: Some(override_of(bad)),
        };
        assert_eq!(
            decide(&state, &ctx(ADMIN, Via::Web), &cmd, &TenantAnswers::new()),
            Err(TenantRefusal::InvalidAddress),
            "{bad:?} was accepted"
        );
    }
}

/// I-23: the command and the record round-trip through the tenant codec.
#[test]
fn r_ga_01_guide_notice_command_and_record_round_trip() {
    let notice = Some(override_of("https://privacy.tenant.example/statement"));
    for n in [notice.clone(), None] {
        let cmd = TenantCommand::SetGuideNotice { notice: n.clone() };
        let text = encode_command(&cmd).unwrap();
        assert_eq!(decode_command(&text), Ok(cmd));
        let rec = TenantRecord::GuideNoticeSet {
            notice: n,
            by: ADMIN,
        };
        let text = encode_record(&rec).unwrap();
        assert_eq!(decode_record(&text), Ok(rec));
    }
}
