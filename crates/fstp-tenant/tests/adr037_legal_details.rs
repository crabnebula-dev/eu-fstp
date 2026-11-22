//! ADR-037 section 1: the tenant's legal details (Daniel, 2026-11-22,
//! `legal/README.md` Q4). Shared code holds no value; each tenant sets its
//! own. A tenant admin sets them on the web with a step-up, like the other
//! tenant settings. Values are plain text only (I-68).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_brand::legal::{LegalDetails, LegalField};
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

fn details() -> LegalDetails {
    LegalDetails::from_pairs(&[
        ("legal_name", "Synthetic Org Ltd"),
        ("address", "1 Example Street, Example Town"),
        ("privacy_contact", "privacy@example.org"),
    ])
    .expect("valid")
}

/// ADR-037: a new tenant has no legal details. Nothing is hard-coded.
#[test]
fn adr037_new_tenant_has_no_legal_details() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    assert_eq!(state.legal_details(), None);
}

/// ADR-037: a tenant admin's details are recorded and survive a fold of
/// the record alone; a later save replaces the whole set.
#[test]
fn adr037_admin_sets_the_legal_details() {
    let mut state = TenantState::genesis(ADMIN, CellKind::Saas);
    let cmd = TenantCommand::SetLegalDetails { details: details() };
    let records = decide(&state, &ctx(ADMIN, Via::Web), &cmd, &TenantAnswers::new())
        .unwrap_or_else(|e| panic!("{e:?}"));
    assert_eq!(
        records,
        vec![TenantRecord::LegalDetailsSet {
            details: details(),
            by: ADMIN,
        }]
    );
    state.apply_all(&records).unwrap();
    assert_eq!(state.legal_details(), Some(&details()));

    let other = LegalDetails::from_pairs(&[("vat_number", "XX0000")]).expect("valid");
    let records = decide(
        &state,
        &ctx(ADMIN, Via::Web),
        &TenantCommand::SetLegalDetails {
            details: other.clone(),
        },
        &TenantAnswers::new(),
    )
    .unwrap();
    state.apply_all(&records).unwrap();
    let now = state.legal_details().expect("set");
    assert_eq!(now, &other);
    assert_eq!(now.get(LegalField::LegalName), None);
}

/// ADR-037, I-85: only a tenant admin sets them, on the web only, with a
/// step-up like the other tenant settings.
#[test]
fn adr037_only_an_admin_on_the_web_sets_the_details() {
    let state = TenantState::genesis(ADMIN, CellKind::Saas);
    let cmd = TenantCommand::SetLegalDetails { details: details() };
    let outsider = decide(
        &state,
        &ctx(OUTSIDER, Via::Web),
        &cmd,
        &TenantAnswers::new(),
    );
    assert!(outsider.is_err());
    assert!(decide(&state, &ctx(ADMIN, Via::Mcp), &cmd, &TenantAnswers::new()).is_err());
    assert_eq!(cmd.kind(), TenantKind::SetLegalDetails);
    assert!(TenantKind::SetLegalDetails.high_risk());
    assert!(TenantKind::SetLegalDetails.web_only());
    assert!(TenantKind::SetLegalDetails.admin_only());
    assert!(TenantKind::ALL.contains(&TenantKind::SetLegalDetails));
}

/// I-68, ADR-037: the command and the record round-trip through the
/// codec, an empty set round-trips, and a value that is not plain text or
/// an unknown field does not decode.
#[test]
fn i68_adr037_legal_details_round_trip_and_refuse_markup() {
    let cmd = TenantCommand::SetLegalDetails { details: details() };
    let text = encode_command(&cmd).unwrap();
    assert_eq!(decode_command(&text), Ok(cmd));
    let rec = TenantRecord::LegalDetailsSet {
        details: details(),
        by: ADMIN,
    };
    let text = encode_record(&rec).unwrap();
    assert_eq!(decode_record(&text), Ok(rec));
    let empty = TenantRecord::LegalDetailsSet {
        details: LegalDetails::default(),
        by: ADMIN,
    };
    assert_eq!(decode_record(&encode_record(&empty).unwrap()), Ok(empty));

    let good = String::from_utf8(
        encode_command(&TenantCommand::SetLegalDetails { details: details() }).unwrap(),
    )
    .unwrap();
    let bad = good.replace("Synthetic Org Ltd", "<b>org</b>");
    assert!(decode_command(bad.as_bytes()).is_err());
    let unknown = good.replace("\"legal_name\"", "\"nickname\"");
    assert!(decode_command(unknown.as_bytes()).is_err());
}

/// I-69: a record from someone outside the admin set does not fold.
#[test]
fn adr037_outsider_record_does_not_fold() {
    let mut state = TenantState::genesis(ADMIN, CellKind::Saas);
    let rec = TenantRecord::LegalDetailsSet {
        details: details(),
        by: OUTSIDER,
    };
    assert!(state.apply_all(&[rec]).is_err());
    assert_eq!(state.legal_details(), None);
}
