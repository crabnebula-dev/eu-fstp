//! Tests of `tenant.terminology.set` and the `TerminologySet` record (M9
//! design sections 2.1 and 2.2, lane T1; I-72, R-LG-03, I-85, O-55).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

use std::collections::BTreeMap;

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ContentDigest};
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    CellKind, TenantAnswers, TenantCommand, TenantCtx, TenantKind, TenantRecord, TenantRefusal,
    TenantState, Terminology, decode_command, decode_record, encode_command, encode_record,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);
const DIGEST: ContentDigest = ContentDigest::from_bytes([0x3c; 32]);

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn ctx(actor: AccountId, via: Via) -> TenantCtx {
    TenantCtx { actor, via, at: T0 }
}

fn terminology(voyage_on: bool) -> Terminology {
    let mut labels = BTreeMap::new();
    labels.insert("vocab.call".to_owned(), "Subgrant call".to_owned());
    labels.insert("vocab.milestone".to_owned(), "Deliverable".to_owned());
    Terminology {
        labels,
        voyage_on,
        digest: DIGEST,
    }
}

fn set(t: Terminology) -> TenantCommand {
    TenantCommand::SetTerminology { terminology: t }
}

/// I-72, O-55: an accepted set records the labels and the Voyage switch, and
/// the state shows them. A later set replaces the earlier one.
#[test]
fn i72_terminology_set_folds_and_replaces() {
    let admin = acct(1);
    let mut s = TenantState::genesis(admin, CellKind::Saas);
    assert_eq!(s.terminology(), None);
    for voyage_on in [true, false] {
        let t = terminology(voyage_on);
        let records = fstp_tenant::decide(
            &s,
            &ctx(admin, Via::Web),
            &set(t.clone()),
            &TenantAnswers::new(),
        )
        .unwrap();
        assert_eq!(
            records,
            vec![TenantRecord::TerminologySet {
                terminology: t.clone(),
                by: admin
            }]
        );
        s.apply_all(&records).unwrap();
        assert_eq!(s.terminology(), Some(&t));
    }
}

/// R-LG-03, I-78, I-85: the set is high-risk, so it needs a fresh step-up and
/// is web only. Through MCP it is refused, and only a tenant admin sets it.
#[test]
fn r_lg_03_terminology_set_is_high_risk_with_step_up() {
    let k = TenantKind::SetTerminology;
    assert!(TenantKind::ALL.contains(&k));
    assert!(k.high_risk());
    assert!(k.web_only());
    assert!(k.admin_only());
    let admin = acct(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let r = fstp_tenant::decide(
        &s,
        &ctx(admin, Via::Mcp),
        &set(terminology(false)),
        &TenantAnswers::new(),
    );
    assert_eq!(r, Err(TenantRefusal::HighRiskViaMcp));
    let r = fstp_tenant::decide(
        &s,
        &ctx(acct(2), Via::Web),
        &set(terminology(false)),
        &TenantAnswers::new(),
    );
    assert_eq!(r, Err(TenantRefusal::NotTenantAdmin));
}

/// I-72, I-68: labels with markup, braces, control characters, an empty key
/// or text, or too many entries are refused, in the command and in a record.
#[test]
fn i72_terminology_with_markup_or_oversize_is_refused() {
    let admin = acct(1);
    let s = TenantState::genesis(admin, CellKind::Saas);
    let bad_texts = ["", "<b>x</b>", "{x}", "a\u{7}b", &"x".repeat(201)];
    for text in bad_texts {
        let mut t = terminology(false);
        t.labels.insert("vocab.team".to_owned(), text.to_owned());
        let r = fstp_tenant::decide(
            &s,
            &ctx(admin, Via::Web),
            &set(t.clone()),
            &TenantAnswers::new(),
        );
        assert_eq!(r, Err(TenantRefusal::TerminologyInvalid), "{text:?}");
        let mut s2 = s.clone();
        let rec = TenantRecord::TerminologySet {
            terminology: t,
            by: admin,
        };
        assert!(s2.apply_all(&[rec]).is_err(), "fold {text:?}");
    }
    let mut t = terminology(false);
    for i in 0..200 {
        t.labels.insert(format!("k{i:03}"), "x".to_owned());
    }
    let r = fstp_tenant::decide(&s, &ctx(admin, Via::Web), &set(t), &TenantAnswers::new());
    assert_eq!(r, Err(TenantRefusal::TerminologyInvalid));
}

/// I-72: the command and the record round-trip through the canonical codec.
#[test]
fn i72_terminology_codec_round_trip() {
    for voyage_on in [true, false] {
        let cmd = set(terminology(voyage_on));
        let bytes = encode_command(&cmd).unwrap();
        assert_eq!(decode_command(&bytes).unwrap(), cmd);
        let rec = TenantRecord::TerminologySet {
            terminology: terminology(voyage_on),
            by: acct(7),
        };
        let bytes = encode_record(&rec).unwrap();
        assert_eq!(decode_record(&bytes).unwrap(), rec);
    }
}
