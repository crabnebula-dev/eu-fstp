//! ADR-034 section 3: the tenant's default coordinator name and contact
//! for the funding card. Shared code holds no value; each tenant sets its
//! own. A tenant admin sets them on the web with a step-up, like the
//! other tenant settings. They fill an empty creator field and back a
//! card whose programme predates the contact field (I-69).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_brand::funding::FundingDefaults;
use fstp_domain::Via;
use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    CellKind, TenantAnswers, TenantCommand, TenantCtx, TenantKind, TenantRecord, TenantState,
    decide, decode_command, decode_record, encode_command, encode_record,
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

fn defaults() -> FundingDefaults {
    FundingDefaults::new("Synthetic coordinator org", "role@example.org").expect("valid")
}

/// ADR-034: a new tenant has no defaults. Nothing is hard-coded.
#[test]
fn adr034_new_tenant_has_no_funding_defaults() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    assert_eq!(state.funding_defaults(), None);
}

/// ADR-034, I-69: a tenant admin's defaults are recorded and survive a
/// fold of the record alone; a later set replaces them.
#[test]
fn i69_admin_sets_the_funding_defaults() {
    let mut state = TenantState::genesis(ADMIN, CellKind::Saas);
    let cmd = TenantCommand::SetFundingDefaults {
        defaults: defaults(),
    };
    let records = decide(&state, &ctx(ADMIN, Via::Web), &cmd, &TenantAnswers::new())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        records,
        vec![TenantRecord::FundingDefaultsSet {
            defaults: defaults(),
            by: ADMIN,
        }]
    );
    state.apply_all(&records).unwrap();
    assert_eq!(state.funding_defaults(), Some(&defaults()));

    let other = FundingDefaults::new("Another org", "other@example.org").expect("valid");
    let records = decide(
        &state,
        &ctx(ADMIN, Via::Web),
        &TenantCommand::SetFundingDefaults {
            defaults: other.clone(),
        },
        &TenantAnswers::new(),
    )
    .unwrap();
    state.apply_all(&records).unwrap();
    assert_eq!(state.funding_defaults(), Some(&other));
}

/// ADR-034, I-85: only a tenant admin sets them, on the web only, with a
/// step-up like the other tenant settings.
#[test]
fn adr034_only_an_admin_on_the_web_sets_the_defaults() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    let cmd = TenantCommand::SetFundingDefaults {
        defaults: defaults(),
    };
    assert!(
        decide(
            &state,
            &ctx(OUTSIDER, Via::Web),
            &cmd,
            &TenantAnswers::new()
        )
        .is_err()
    );
    assert!(decide(&state, &ctx(ADMIN, Via::Mcp), &cmd, &TenantAnswers::new()).is_err());
    assert_eq!(cmd.kind(), TenantKind::SetFundingDefaults);
    assert!(TenantKind::SetFundingDefaults.high_risk());
    assert!(TenantKind::SetFundingDefaults.web_only());
    assert!(TenantKind::SetFundingDefaults.admin_only());
    assert!(TenantKind::ALL.contains(&TenantKind::SetFundingDefaults));
}

/// I-68: the command and the record round-trip through the codec, and a
/// value that is not plain text does not decode.
#[test]
fn i68_funding_defaults_round_trip_and_refuse_markup() {
    let cmd = TenantCommand::SetFundingDefaults {
        defaults: defaults(),
    };
    let text = encode_command(&cmd).unwrap();
    assert_eq!(decode_command(&text), Ok(cmd));
    let rec = TenantRecord::FundingDefaultsSet {
        defaults: defaults(),
        by: ADMIN,
    };
    let text = encode_record(&rec).unwrap();
    assert_eq!(decode_record(&text), Ok(rec));

    let bad = String::from_utf8(
        encode_command(&TenantCommand::SetFundingDefaults {
            defaults: defaults(),
        })
        .unwrap(),
    )
    .unwrap()
    .replace("Synthetic coordinator org", "<b>org</b>");
    assert!(decode_command(bad.as_bytes()).is_err());
}

/// I-69: a record from someone outside the admin set does not fold.
#[test]
fn i69_outsider_record_does_not_fold() {
    let mut state = TenantState::genesis(ADMIN, CellKind::Saas);
    let rec = TenantRecord::FundingDefaultsSet {
        defaults: defaults(),
        by: OUTSIDER,
    };
    assert!(state.apply_all(&[rec]).is_err());
    assert_eq!(state.funding_defaults(), None);
}
