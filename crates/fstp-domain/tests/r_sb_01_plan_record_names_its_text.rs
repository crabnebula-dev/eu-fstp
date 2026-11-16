//! The plan record names its stored work plan text (R-SB-01, ADR-007,
//! I-23; Daniel, 2026-11-16: the plan text reads back after a restart).
//!
//! A plan version holds the digest of its work plan text and, beside it,
//! the `TextRef` of the stored text. The `text` member was added after
//! the record was first published. A plan stored before it decodes with
//! no text, and a plan with no text is written in that same form, so
//! each value keeps one spelling. Every id and text is synthetic.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::Command;
use fstp_domain::id::{ContentDigest, MilestoneId, PlanVersionId, ProposalId, TextId, TextRef};
use fstp_domain::proposal::{Milestone, PlanOrigin, Task};
use fstp_domain::record::{PlanVersionRecorded, Record};
use fstp_domain::time::Timestamp;
use fstp_json::{FromJson, ToJson, parse, to_canonical};
use fstp_money::{Amount, Currency, PosAmount};

const DIGEST: [u8; 32] = [0x5a; 32];

fn tasks() -> Vec<Task> {
    let amount = PosAmount::new(Amount::from_minor(100_000, Currency::Eur).unwrap()).unwrap();
    vec![Task {
        milestones: vec![Milestone {
            id: MilestoneId::from_raw(601),
            amount,
            start: Timestamp::from_micros(86_400_000_000),
            due: Timestamp::from_micros(172_800_000_000),
            activity: None,
            deliverables: Vec::new(),
        }],
    }]
}

fn plan(text: Option<TextRef>) -> Record {
    Record::PlanVersionRecorded(PlanVersionRecorded {
        plan: PlanVersionId::from_raw(401),
        proposal: ProposalId::from_raw(1),
        origin: PlanOrigin::Submitted,
        supersedes: None,
        tasks: tasks(),
        content: ContentDigest::from_bytes(DIGEST),
        text,
    })
}

fn text_ref() -> TextRef {
    TextRef::new(TextId::from_raw(9_001), ContentDigest::from_bytes(DIGEST))
}

fn canonical(r: &Record) -> String {
    to_canonical(&r.to_json()).unwrap()
}

fn decode(text: &str) -> Result<Record, fstp_json::FromJsonError> {
    Record::from_json(&parse(text.as_bytes()).unwrap())
}

/// R-SB-01, ADR-007, I-23: a plan record that names its text reference
/// round trips with stable canonical bytes, and the reference sits in
/// the `text` member as id and digest.
#[test]
fn r_sb_01_adr007_plan_record_with_text_ref_round_trips() {
    let r = plan(Some(text_ref()));
    let text = canonical(&r);
    assert!(
        text.contains(&format!(
            r#""text":{{"digest":"{}","id":"9001"}}"#,
            "5a".repeat(32)
        )),
        "{text}"
    );
    let back = decode(&text).unwrap();
    assert_eq!(back, r);
    assert_eq!(canonical(&back), text);
}

/// ADR-007 section "Replay and schema versions", I-23: a plan record
/// stored before plans named their text has no `text` member. It decodes
/// with no text, and a plan with no text is written in exactly that
/// form, so stored bytes never change.
#[test]
fn adr007_plan_record_written_before_the_text_ref_decodes_unchanged() {
    let old = canonical(&plan(None));
    assert!(!old.contains(r#""text""#), "{old}");
    let back = decode(&old).unwrap();
    assert_eq!(back, plan(None));
    assert_eq!(canonical(&back), old);
}

/// I-23, ADR-007: the codec stays strict. A `null` text is refused, as
/// absence is the only spelling of no text, and a malformed or unknown
/// member is refused as before.
#[test]
fn i23_plan_record_text_has_one_spelling() {
    let old = canonical(&plan(None));
    let with_null = old.replacen(r#""tasks""#, r#""text":null,"tasks""#, 1);
    assert!(decode(&with_null).is_err(), "a null text was accepted");
    let with_string = old.replacen(r#""tasks""#, r#""text":"9001","tasks""#, 1);
    assert!(decode(&with_string).is_err(), "a bare id was accepted");
    let unknown = old.replacen(r#""tasks""#, r#""texts":{},"tasks""#, 1);
    assert!(decode(&unknown).is_err(), "an unknown member was accepted");
    let missing = old.replacen(&format!(r#""content":"{}","#, "5a".repeat(32)), "", 1);
    assert_ne!(missing, old);
    assert!(decode(&missing).is_err(), "a missing digest was accepted");
}

/// R-SB-01, I-23: `RecordPlanVersion` carries the text reference. The
/// command codec writes `text` always, as `null` when none was stored,
/// and refuses a command without it.
#[test]
fn r_sb_01_record_plan_version_command_carries_the_text_ref() {
    for text in [Some(text_ref()), None] {
        let cmd = Command::RecordPlanVersion {
            plan: PlanVersionId::from_raw(401),
            proposal: ProposalId::from_raw(1),
            origin: PlanOrigin::Submitted,
            supersedes: None,
            tasks: tasks(),
            content: ContentDigest::from_bytes(DIGEST),
            text,
        };
        let s = to_canonical(&cmd.to_json()).unwrap();
        let back = Command::from_json(&parse(s.as_bytes()).unwrap()).unwrap();
        assert_eq!(back, cmd);
        assert!(s.contains(r#""text":"#), "{s}");
        if text.is_none() {
            let without = s.replacen(r#""text":null,"#, "", 1);
            assert_ne!(without, s);
            assert!(
                Command::from_json(&parse(without.as_bytes()).unwrap()).is_err(),
                "a command without its text member was accepted"
            );
        }
    }
}
