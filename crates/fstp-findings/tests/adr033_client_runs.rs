//! ADR-033: the store's rules for an assessment run by the FSTP
//! coordinator's connected agent (I-10, I-11, R-AU-01).

#![allow(clippy::unwrap_used, clippy::expect_used)]

use fstp_domain::id::{AccountId, CallId, ContentDigest, ProposalId};
use fstp_domain::policy::{InferenceBinding, ModelRef, OpaqueValue};
use fstp_findings::{ClientRun, FindingRecord, FindingRefusal, FindingStore, TraceRef, client_run};

const CALL: CallId = CallId::from_raw(2);
const X: ProposalId = ProposalId::from_raw(5);
const COORD: AccountId = AccountId::from_raw(8);
const OTHER: AccountId = AccountId::from_raw(9);

fn digest(b: u8) -> ContentDigest {
    ContentDigest::from_bytes([b; 32])
}

fn read(by: AccountId, input: u8) -> FindingRecord {
    FindingRecord::AssessmentInputRead {
        call: CALL,
        proposal: X,
        by,
        input: digest(input),
    }
}

fn assessed(by: AccountId, input: u8) -> FindingRecord {
    FindingRecord::ClientAssessed {
        call: CALL,
        proposal: X,
        by,
        run: ClientRun {
            model: ModelRef("claude-opus-5-5".to_owned()),
            prompt_set: digest(0xaa),
            input: digest(input),
            trace: TraceRef::from_raw(77),
        },
    }
}

fn binding(provider: &str) -> InferenceBinding {
    InferenceBinding {
        provider: OpaqueValue::from_value(&fstp_json::Value::from(provider)).unwrap(),
        primary: ModelRef("claude-opus-5-5".to_owned()),
        fallbacks: Vec::new(),
    }
}

/// ADR-033, I-11: only the reserved P-21 provider opens the client path.
#[test]
fn adr033_i11_only_the_reserved_provider_names_the_client_path() {
    assert!(client_run(&binding("coordinator_agent")));
    for other in [
        "placeholder",
        "anthropic",
        "coordinator_agent_x",
        "xcoordinator_agent",
        "",
    ] {
        assert!(!client_run(&binding(other)), "{other}");
    }
}

/// ADR-033, R-AU-01: a client assessment names the input its own account
/// read last. Another account's read, an older read and no read are refused,
/// and a refused record changes nothing.
#[test]
fn adr033_client_run_binds_the_runners_latest_input_read() {
    let mut s = FindingStore::genesis();
    let before = s.clone();
    assert_eq!(
        s.apply(&assessed(COORD, 1)),
        Err(FindingRefusal::InputNotRead { proposal: X })
    );
    assert_eq!(s, before);

    s.apply(&read(OTHER, 1)).unwrap();
    let before = s.clone();
    assert_eq!(
        s.apply(&assessed(COORD, 1)),
        Err(FindingRefusal::InputNotRead { proposal: X })
    );
    assert_eq!(s, before);

    s.apply(&read(COORD, 1)).unwrap();
    s.apply(&read(COORD, 2)).unwrap();
    assert_eq!(s.client_read(X, COORD), Some(digest(2)));
    let before = s.clone();
    assert_eq!(
        s.apply(&assessed(COORD, 1)),
        Err(FindingRefusal::InputNotRead { proposal: X })
    );
    assert_eq!(s, before);
    s.apply(&assessed(COORD, 2)).unwrap();
    assert_eq!(s.client_runs_of(X), 1);
}

/// ADR-033, I-10: a proposal takes one client assessment. Another is
/// accepted only while a coordinator's re-run is in flight, and the
/// refusal list that follows the run ends that re-run.
#[test]
fn adr033_i10_one_client_run_per_proposal_unless_a_rerun_is_in_flight() {
    let mut s = FindingStore::genesis();
    s.apply(&read(COORD, 1)).unwrap();
    s.apply(&assessed(COORD, 1)).unwrap();
    s.apply(&FindingRecord::RefusalsRecorded {
        call: CALL,
        proposal: X,
        refused: Vec::new(),
    })
    .unwrap();

    let before = s.clone();
    let r = s.apply(&assessed(COORD, 1));
    assert_eq!(r, Err(FindingRefusal::ClientRunTaken { proposal: X }));
    assert_eq!(
        r.map_err(FindingRefusal::rule),
        Err(fstp_domain::refusal::RuleRef::I10)
    );
    assert_eq!(s, before);

    s.apply(&FindingRecord::RerunRequested {
        call: CALL,
        proposal: X,
        by: COORD,
    })
    .unwrap();
    s.apply(&assessed(COORD, 1)).unwrap();
    s.apply(&FindingRecord::RefusalsRecorded {
        call: CALL,
        proposal: X,
        refused: Vec::new(),
    })
    .unwrap();
    assert_eq!(s.client_runs_of(X), 2);
    assert_eq!(s.rerun_in_flight(X), None);
    assert_eq!(
        s.apply(&assessed(COORD, 1)),
        Err(FindingRefusal::ClientRunTaken { proposal: X })
    );
}
