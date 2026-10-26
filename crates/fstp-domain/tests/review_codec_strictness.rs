//! Review reproducers for lane L-CODEC (design sections 2.3, 2.10, 5.1, 7).
//!
//! Each test fails against the code under review and passes once the
//! named defect is fixed. Production code is not changed here.

use std::collections::BTreeSet;

use fstp_domain::id::{AccountId, CallId, ContentDigest, DecisionId, ProposalId, TextId, TextRef};
use fstp_domain::record::{CutOffRecorded, Record, RulesVersion};
use fstp_json::{FromJson, ToJson, parse, to_canonical};
use fstp_money::{Amount, Currency};

/// I-23, R-EV-08, design 3.7 and Q14 A: the call budget is display-only, so
/// a call can be over-nominated and its remaining budget is negative. The
/// type holds that value, the encoder writes it, and the decoder must read
/// it back. Today the encoder writes `"-1.00"` and the decoder refuses it,
/// so an appended cut-off record could never be replayed.
#[test]
fn review_i23_over_nominated_cut_off_round_trips() {
    let Ok(minus_one) = Amount::from_minor(-100, Currency::Eur) else {
        panic!("-1.00 EUR is representable");
    };
    let r = Record::CutOffRecorded(CutOffRecorded {
        decision: DecisionId::from_raw(1),
        call: CallId::from_raw(2),
        order: vec![ProposalId::from_raw(3), ProposalId::from_raw(4)],
        nominated: 2,
        rationale: TextRef::new(TextId::from_raw(5), ContentDigest::from_bytes([0; 32])),
        tie_breaks: None,
        ballots: Vec::new(),
        recused: BTreeSet::new(),
        remaining_budget: minus_one,
        recorder: AccountId::from_raw(6),
        rules: RulesVersion::M2,
    });
    let Ok(text) = to_canonical(&r.to_json()) else {
        panic!("the record has an RFC 8785 form");
    };
    let Ok(v) = parse(text.as_bytes()) else {
        panic!("canonical text parses");
    };
    assert_eq!(
        Record::from_json(&v).ok(),
        Some(r),
        "an over-nominated cut-off must decode to itself: {text}"
    );
}
