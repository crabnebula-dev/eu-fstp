//! ADR-036 section 8 (Daniel, 2026-11-23, "everything v2"): a draft opened
//! on horizon-europe profile v1 moves to v2 at its next policy version. The
//! creator composes the core `EditPolicy` with P-53 v2, so the move is
//! recorded in the ledger, and nobody takes a step for it (P-53, R-PG-01).

use fstp_creator::{CreatorCommand, CreatorRecord, decide_creator};
use fstp_domain::state::State;
use fstp_domain::{Answers, Command};
use fstp_programme::{CompileIds, FieldId, FunderProfile, compile};

use crate::harness::{Cell, M1, P, Rec, TA, V1, adr006, decode, edit};

/// A cell whose draft TA opened on profile v1, as before 2026-11-23, with
/// M1 granted the programme manager role.
fn opened_on_v1() -> Cell {
    let v1 = FunderProfile::horizon_europe_v1();
    let policy = compile(&v1.blank(), &v1, CompileIds::new(P, V1, None))
        .unwrap()
        .policy;
    assert!(policy.frozen.p53.0.as_str().contains(r#""version":1"#));
    let mut c = Cell::genesis();
    let ctx = c.ctx(TA);
    let create = Command::CreateProgramme {
        policy: Box::new(policy.clone()),
    };
    let core = fstp_domain::decide(&State::genesis(), &create, &ctx, &Answers::new()).unwrap();
    let mut entry = vec![Rec::Creator(CreatorRecord::DraftOpened {
        programme: P,
        profile: policy.frozen.p53,
        by: TA,
    })];
    entry.extend(core.into_iter().map(Rec::Core));
    c.append(&entry, ctx.now);
    c.grant(M1, fstp_domain::roles::Role::ProgrammeManager, 1);
    c
}

/// ADR-036 section 8: the first policy save of a v1 draft composes an
/// `EditPolicy` whose P-53 pins v2, and the head pins v2 once it is in
/// the ledger.
#[test]
fn adr036_q2_v1_draft_moves_to_v2_at_its_next_policy_version() {
    let mut cell = opened_on_v1();
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: cell.head(),
        fields: vec![edit(
            decode(FieldId::P05, &format!("\"{}\"", adr006(30_000_000))),
            2,
        )],
        clear: Vec::new(),
    };
    let ctx = cell.ctx(M1);
    let inputs = cell.inputs(&cmd, &ctx);
    let d = decide_creator(&cell.core, &cell.creator, &cmd, &ctx, &inputs)
        .unwrap_or_else(|r| panic!("{r:?}"));
    let p53: Vec<String> = d
        .core
        .iter()
        .filter_map(|c| match c {
            Command::EditPolicy { version, .. } => Some(version.frozen.p53.0.as_str().to_owned()),
            _ => None,
        })
        .collect();
    assert_eq!(p53.len(), 1, "{:?}", d.core);
    assert!(p53[0].contains(r#""version":2"#), "{p53:?}");
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert_eq!(
        Some(&cell.policy().frozen.p53),
        FunderProfile::horizon_europe().policy_ref().as_ref()
    );
}
