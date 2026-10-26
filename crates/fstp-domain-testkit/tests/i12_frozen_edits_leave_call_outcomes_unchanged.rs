//! I-12, TH-17, T-POLICY: the twin machine over the full engine (design 6.2 row I-12).
//!
//! Twins A and B are two reference drivers built from genesis by the
//! same production commands, with call 1 published and three proposals
//! submitted. Both run the same evaluation commands: knock-out, stage 1,
//! stage 2 with questions, revisions, expiry and re-entry, ranking, the
//! cut-off, IRC review, negotiation, the NOTE 9 decline, the grant,
//! deliverables, amendments and content reads. Some acts arrive through MCP. Both also run the same live edits of P-05, P-12,
//! P-13 and P-38, binding ends and the publication of call 2.
//! Twin B alone receives random edits of frozen parameters after
//! publication, interleaved anywhere. Every frozen programme parameter of
//! `SPEC/02-domain/policy-parameters.md` can be edited, interpreted or
//! opaque, except P-24, whose type has one value only.
//!
//! After every command, `fstp_domain_testkit::gen::twin` checks:
//! - identical records or refusals on both twins for every evaluation
//!   command, so identical transitions, scores, effective scores and decisions;
//! - identical vault questions on both twins for every evaluation command;
//! - identical effective scores in both projections;
//! - every published call's frozen policy equal to its copy at
//!   publication, and call 1's identical on both twins;
//! - each frozen edit appends exactly one policy version, the one sent;
//! - call 2, published after the edits, freezes twin B's edited values;
//! - a binding end pins the head P-12, and every cap question carries
//!   the lower of the call snapshot and the head P-05 at decision time;
//! - every exclusion question carries the union of the P-13 snapshot and
//!   head, and every proximity question the head P-38 list.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use fstp_domain::policy::PolicyVersion;
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain_testkit::r#gen::money::{PA, PB, PC, nonneg};
use fstp_domain_testkit::r#gen::policy::base_version;
use fstp_domain_testkit::r#gen::roster::{P1, call};
use fstp_domain_testkit::r#gen::twin::{
    TWIN_PLAN_CENTS, TwinMachine, apply_frozen, editable_frozen, frozen_diff, witness_decline_run,
    witness_repeat_grant_run, witness_run,
};
use fstp_domain_testkit::reference::policy::{TYPED_FROZEN, expected_frozen_opaque};
use fstp_prop::{Config, check_machine_with};

/// Commands per machine case.
const COMMANDS: usize = 120;

/// Cases of the machine.
const CASES: u32 = 128;

/// I-12, TH-17: random frozen edits after publication, interleaved with
/// the whole evaluation, never change the published call's transitions,
/// scores, effective scores, decisions or frozen policy. Each edit
/// appends one version, a later call uses the new values, and live
/// values used by a decision equal the head at decision time.
#[test]
fn i12_frozen_edits_leave_call_outcomes_unchanged() {
    check_machine_with(
        "i12_frozen_edits_leave_call_outcomes_unchanged",
        Config::default().with_cases(CASES),
        &TwinMachine::new(COMMANDS),
    );
}

/// I-12: the edits reach every frozen programme parameter the spec lists,
/// typed or opaque, except P-24, and each edit changes exactly the
/// parameter it names.
#[test]
fn i12_twin_edits_reach_every_frozen_parameter() {
    let editable: BTreeSet<String> = editable_frozen()
        .into_iter()
        .map(|p| p.spec_id().to_owned())
        .collect();
    let mut spec: BTreeSet<String> = expected_frozen_opaque().unwrap_or_else(|e| panic!("{e}"));
    spec.extend(TYPED_FROZEN.iter().map(|s| (*s).to_owned()));
    spec.remove("P-24");
    assert_eq!(
        editable, spec,
        "the twin edits every frozen programme parameter of the spec except P-24"
    );
    let base = base_version(fstp_domain::id::PolicyVersionId::from_raw(1), P1, None).unwrap();
    for p in editable_frozen() {
        for pick in 0..5 {
            let mut v: PolicyVersion = base.clone();
            apply_frozen(&mut v, p, pick).unwrap_or_else(|e| panic!("{}: {e}", p.spec_id()));
            assert_eq!(
                frozen_diff(&base.frozen, &v.frozen),
                BTreeSet::from([p]),
                "{} pick {pick} must change exactly that parameter",
                p.spec_id()
            );
            assert_eq!(
                v.live,
                base.live,
                "{} pick {pick} changed a live value",
                p.spec_id()
            );
        }
    }
    assert!(
        apply_frozen(&mut base.clone(), ParamId::P24, 0).is_err(),
        "P-24 has one value, so an edit of it is refused by the generator"
    );
}

/// I-12: the scripted witness run edits every editable frozen parameter
/// between evaluation commands, and every machine check holds after each
/// command. It reaches GRANTED, a deferral with re-entry into call 2, an
/// INELIGIBLE proposal, call 2 published with twin B's values, and a
/// binding end after a live P-12 edit. So the machine cannot pass by
/// refusing everything.
#[test]
fn i12_twin_witness_reaches_grant_and_reentry() {
    let w = witness_run().unwrap_or_else(|e| panic!("{e}"));
    let edited: BTreeSet<ParamId> = w.ghost.edited.clone();
    let all: BTreeSet<ParamId> = editable_frozen().into_iter().collect();
    assert_eq!(
        edited, all,
        "the witness edits every editable frozen parameter"
    );
    assert_eq!(w.ghost.state(PA), StateTag::Granted, "PA reaches GRANTED");
    assert_eq!(w.ghost.state(PB), StateTag::Stage2, "PB re-enters STAGE2");
    assert_eq!(w.ghost.call_of(PB), call(2), "PB re-entered call 2");
    assert_eq!(w.ghost.state(PC), StateTag::Ineligible, "PC is INELIGIBLE");
    assert!(w.ghost.published2, "call 2 is published");
    assert!(!w.ghost.ended.is_empty(), "a spare binding ended");
    let a2 = w.pair.a.snapshots.get(&call(2)).expect("call 2 in twin A");
    let b2 = w.pair.b.snapshots.get(&call(2)).expect("call 2 in twin B");
    assert_eq!(
        frozen_diff(a2.values(), b2.values()),
        all,
        "call 2 of twin B freezes every edited value, each one differing from twin A's"
    );
}

/// I-12, I-13, NOTE 9: after twin B edits P-04 to [0, 1.00] in
/// NEGOTIATION, the decline of PA is refused, since call 1's P-04 admits
/// its plan total. A live P-05 edit below call 1's P-04 minimum then
/// declines PA (NOTE 9, decided 2026-10-26). PB is granted under call 1's P-04. After twin B edits P-15 to one,
/// an amendment with one IRC member stays inactive and one with two is
/// activated. Every machine check holds, so both twins ask the same cap
/// questions, carrying the head P-05 at decision time.
#[test]
fn i12_twin_decline_and_amendment_read_the_frozen_p04_and_p15() {
    let w = witness_decline_run().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.ghost.state(PA), StateTag::Declined, "PA is DECLINED");
    assert_eq!(w.ghost.state(PB), StateTag::Granted, "PB is GRANTED");
    assert_eq!(w.ghost.activated, 1, "one amendment is activated");
    assert!(
        w.ghost.edited.contains(&ParamId::P04) && w.ghost.edited.contains(&ParamId::P15),
        "twin B edits P-04 and P-15"
    );
    let head = w.pair.b.head().unwrap_or_else(|e| panic!("{e}"));
    let frozen = w.pair.b.frozen(call(1)).expect("call 1 is published");
    let total = nonneg(TWIN_PLAN_CENTS).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(
        (
            frozen.values().p04.contains(total).ok(),
            head.frozen.p04.contains(total).ok()
        ),
        (Some(true), Some(false)),
        "call 1's P-04 admits the plan total and twin B's head does not"
    );
    assert_ne!(
        frozen.values().p15,
        head.frozen.p15,
        "twin B's head P-15 differs from call 1's"
    );
}

/// I-12, I-15: a repeat grant after twin B edits P-26 checks the earlier
/// grant's deliverable against call 1's P-26, not the head. PA and PB are
/// both GRANTED, PA's Apache-2.0 deliverable stays accepted, and twin B's
/// head P-26 no longer lists Apache-2.0. Every machine check holds, so
/// both twins ask the same I-15 vault questions.
#[test]
fn i12_i15_twin_repeat_grant_reads_the_frozen_p26() {
    let w = witness_repeat_grant_run().unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(w.ghost.state(PA), StateTag::Granted, "PA reaches GRANTED");
    assert_eq!(w.ghost.state(PB), StateTag::Granted, "PB reaches GRANTED");
    assert_eq!(w.ghost.deliverables, 1, "PA records one deliverable");
    assert!(w.ghost.edited.contains(&ParamId::P26), "twin B edits P-26");
    let head = w.pair.b.head().unwrap_or_else(|e| panic!("{e}"));
    let frozen = w.pair.b.frozen(call(1)).expect("call 1 is published");
    assert!(
        frozen.values().p26.0.iter().any(|l| l.0 == "Apache-2.0")
            && !head.frozen.p26.0.iter().any(|l| l.0 == "Apache-2.0"),
        "call 1 allows Apache-2.0 and twin B's head does not"
    );
}
