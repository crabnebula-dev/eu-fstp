//! Unit tests of the codec that need crate-private constructors.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::num::NonZeroU64;

use fstp_json::{FromJson, ToJson, Value, parse, to_canonical};
use fstp_money::{Amount, Currency, NonNegAmount, Percent, Ratio};

use super::{CURRENT_SCHEMA, PUBLISHED_SCHEMAS, record_from_json_at};
use crate::decision::{Basis, EffectiveScoreSet, Stage1Closed};
use crate::grant::GrantDecided;
use crate::id::AssignmentId;
use crate::id::{
    AccountId, ContractId, DecisionId, PlanVersionId, ProposalId, RequestId, VaultEpoch,
};
use crate::payment::PaymentReleased;
use crate::record::{Record, RulesVersion};
use crate::scoring::{ScoreKey, Stage};

fn round_trip(r: &Record) -> String {
    let text = to_canonical(&r.to_json()).expect("canonical");
    let back = Record::from_json(&parse(text.as_bytes()).expect("parses")).expect("decodes");
    assert_eq!(&back, r, "decode(encode(r)) == r for {text}");
    assert_eq!(to_canonical(&back.to_json()).expect("canonical"), text);
    text
}

fn keys() -> BTreeSet<ScoreKey> {
    [u128::MAX, 1, 0]
        .into_iter()
        .map(|a| ScoreKey {
            assignment: AssignmentId::from_raw(a),
            stage: Stage::Two,
            plan: PlanVersionId::from_raw(u128::MAX),
        })
        .collect()
}

/// I-23, ADR-007: the four witness payloads round trip at the edges of
/// their domains, built through the `from_decoded` seams.
#[test]
fn i23_witness_payloads_round_trip_at_domain_edges() {
    let max = NonZeroU64::new(u64::MAX).unwrap();
    let records = [
        Record::Stage1Closed(Stage1Closed::from_decoded(
            ProposalId::from_raw(u128::MAX),
            AccountId::from_raw(0),
            Ratio::new(u64::MAX.saturating_sub(1), max),
            Percent::from_bp(10_000).unwrap(),
            keys(),
            false,
            RulesVersion(u16::MAX),
        )),
        Record::EffectiveScoreSet(EffectiveScoreSet::from_decoded(
            ProposalId::from_raw(0),
            PlanVersionId::from_raw(u128::MAX),
            Ratio::new(0, max),
            Basis::Original,
            BTreeSet::new(),
            RulesVersion(0),
        )),
        Record::GrantDecided(GrantDecided::from_decoded(
            ProposalId::from_raw(1),
            NonNegAmount::new(Amount::from_minor(Amount::MAX_ABS_MINOR, Currency::Eur).unwrap())
                .unwrap(),
            PlanVersionId::from_raw(2),
            DecisionId::from_raw(3),
            DecisionId::from_raw(u128::MAX),
            ContractId::from_raw(5),
            VaultEpoch::from_raw(u64::MAX),
            RulesVersion::M2,
        )),
        Record::PaymentReleased(PaymentReleased::from_decoded(
            RequestId::from_raw(u128::MAX),
            ProposalId::from_raw(0),
            [3u128, 1, u128::MAX]
                .into_iter()
                .map(AccountId::from_raw)
                .collect(),
            AccountId::from_raw(4),
            AccountId::from_raw(5),
        )),
    ];
    for r in &records {
        round_trip(r);
    }
}

/// ADR-006, P-02: a witness payload keeps its ratio in lowest terms and its
/// threshold as a two-decimal string. A ratio not in lowest terms is refused.
#[test]
fn adr006_stage1_closed_ratio_has_one_spelling() {
    let r = Record::Stage1Closed(Stage1Closed::from_decoded(
        ProposalId::from_raw(7),
        AccountId::from_raw(3),
        Ratio::new(6, NonZeroU64::new(8).unwrap()),
        Percent::from_bp(7_000).unwrap(),
        BTreeSet::new(),
        true,
        RulesVersion::M2,
    ));
    let text = round_trip(&r);
    assert!(text.contains(r#""score":{"den":"4","num":"3"}"#), "{text}");
    assert!(text.contains(r#""threshold":"70.00""#), "{text}");
    let unreduced = text.replace(r#"{"den":"4","num":"3"}"#, r#"{"den":"8","num":"6"}"#);
    assert!(Record::from_json(&parse(unreduced.as_bytes()).unwrap()).is_err());
    let zero_den = text.replace(r#"{"den":"4","num":"3"}"#, r#"{"den":"0","num":"3"}"#);
    assert!(Record::from_json(&parse(zero_den.as_bytes()).unwrap()).is_err());
}

/// Design section 5.1: every published schema version decodes, and an
/// unpublished version is refused without reading the body.
#[test]
fn i23_record_decode_refuses_unpublished_schema_versions() {
    assert_eq!(PUBLISHED_SCHEMAS, [CURRENT_SCHEMA]);
    let r = Record::VaultEpochProcessed {
        epoch: VaultEpoch::from_raw(9),
    };
    let v = r.to_json();
    for schema in PUBLISHED_SCHEMAS {
        assert_eq!(record_from_json_at(schema, &v), Ok(r.clone()));
    }
    for schema in [0, 2, u16::MAX] {
        assert!(record_from_json_at(schema, &v).is_err());
    }
}

/// R-NF-02: an unknown member is refused with an error that names neither
/// the member nor its value.
#[test]
fn r_nf_02_unknown_member_error_names_no_input() {
    let mut v = Record::VaultEpochProcessed {
        epoch: VaultEpoch::from_raw(9),
    }
    .to_json();
    v.as_object_mut()
        .unwrap()
        .insert("secret-name", Value::String("secret-value".to_owned()));
    let e = Record::from_json(&v).unwrap_err();
    for text in [format!("{e}"), format!("{e:?}"), e.path().full()] {
        assert!(!text.contains("secret"), "{text}");
    }
}

/// ADR-006: an amount string never carries a sign. The signed record
/// amount `CutOffRecorded::remaining_budget` writes a negative value as a
/// positive `shortfall`, so the decoder refuses the minus sign.
#[test]
fn adr006_negative_amount_is_refused_on_decode() {
    let v = Value::String("-1.00".to_owned());
    let cx = super::wire::Cx::with(Currency::Eur);
    assert!(<Amount as super::wire::Wire>::take(&v, cx).is_err());
}

/// ADR-006, ADR-007 and design 3.7: a negative signed amount is written as
/// a positive `shortfall` and reads back to itself. Zero and above stay
/// plain ADR-006 strings, and a zero shortfall is refused, so each signed
/// value has one spelling.
#[test]
fn adr006_signed_amount_has_one_spelling() {
    use super::wire::{Cx, Wire};
    let cx = Cx::with(Currency::Eur);
    for minor in [
        -Amount::MAX_ABS_MINOR,
        -100,
        -1,
        0,
        1,
        Amount::MAX_ABS_MINOR,
    ] {
        let a = Amount::from_minor(minor, Currency::Eur).unwrap();
        let v = a.put();
        assert_eq!(v.as_str().is_some(), minor >= 0, "{minor}");
        assert_eq!(<Amount as Wire>::take(&v, cx).ok(), Some(a), "{minor}");
    }
    let shortfall = |s: &str| parse(format!("{{\"shortfall\":\"{s}\"}}").as_bytes()).unwrap();
    assert_eq!(
        to_canonical(&Amount::from_minor(-100, Currency::Eur).unwrap().put()).unwrap(),
        "{\"shortfall\":\"1.00\"}"
    );
    for refused in [shortfall("0.00"), shortfall("-1.00"), shortfall("1")] {
        assert!(<Amount as Wire>::take(&refused, cx).is_err());
    }
    let extra = parse(b"{\"shortfall\":\"1.00\",\"zz\":null}").unwrap();
    assert!(<Amount as Wire>::take(&extra, cx).is_err());
}

/// ADR-007: a record with no amount names EUR, the one currency spelling
/// the encoder writes for it, and a decoded amount-free record writes the
/// same bytes back.
#[test]
fn adr007_amount_free_money_record_writes_eur() {
    let r = Record::PaymentRequested {
        request: RequestId::from_raw(1),
        grant: ProposalId::from_raw(2),
        lines: Vec::new(),
    };
    let text = round_trip(&r);
    assert!(text.contains("\"currency\":\"EUR\""), "{text}");
    assert!(super::wire::check_currency(Currency::Eur, &[]).is_ok());
    assert!(super::wire::check_currency(Currency::Eur, &[None, Some(Currency::Eur)]).is_ok());
}

/// TH-26: every seed of the three fuzz corpora decodes, except the plain
/// `empty_object` input, so the fuzzer starts from valid values.
#[test]
fn th26_every_named_seed_decodes() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds");
    for target in ["record_decode", "command_decode", "policy_decode"] {
        for entry in std::fs::read_dir(root.join(target)).unwrap() {
            let path = entry.unwrap().path();
            if path.file_name().is_some_and(|n| n == "empty_object") {
                continue;
            }
            let v = parse(&std::fs::read(&path).unwrap()).unwrap();
            let ok = match target {
                "record_decode" => Record::from_json(&v).is_ok(),
                "command_decode" => crate::command::Command::from_json(&v).is_ok(),
                _ => crate::policy::PolicyVersion::from_json(&v).is_ok(),
            };
            assert!(ok, "seed {} does not decode", path.display());
        }
    }
}
