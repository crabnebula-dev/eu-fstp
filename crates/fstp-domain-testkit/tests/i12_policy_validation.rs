//! I-12 and I-50 at programme creation: a policy version carries every
//! frozen parameter, and validation refuses only inconsistent or unsafe
//! values (design 2.4).
//!
//! `CreateProgramme` needs no vault answer, so these properties run
//! without any other lane. Each case starts from genesis, draws one defect
//! from `gen::policy::gen_defect` and compares the engine with the
//! reference verdict in both directions.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command as CoreCommand};
use fstp_domain::id::{PolicyVersionId, ProgrammeId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::policy::{
    ADMIN, Defect, apply_defect, base_version, core_records, gen_defect,
};
use fstp_domain_testkit::harness::prop::two_way_exec;
use fstp_domain_testkit::reference::policy::{Ghost, Verdict};
use fstp_domain_testkit::scenario::Scenario;
use fstp_domain_testkit::vault::GroundTruth;
use fstp_engine::Command;
use fstp_prop::{Gen, check};

/// Creates a programme with `defect` from genesis and checks the engine
/// against the reference, including the records of an accepted creation.
fn create_with(defect: Defect) -> Result<(), String> {
    let mut v = base_version(PolicyVersionId::from_raw(1), ProgrammeId::from_raw(1), None)?;
    apply_defect(&mut v, defect);
    let cmd = CoreCommand::CreateProgramme {
        policy: Box::new(v),
    };
    let ghost = Ghost::new();
    let actor = Actor::Account(ADMIN);
    let verdict = ghost.verdict(actor, true, &cmd)?;
    let mut s = Scenario::new(GroundTruth::new()).map_err(|e| format!("{e}"))?;
    let mut ctx = s.ctx(Timestamp::from_micros(1_000), actor);
    ctx.tenant_admin = true;
    let r = s.execute(Command::Core(cmd.clone()), ctx);
    let context = format!("CreateProgramme with {defect:?}");
    match verdict {
        Verdict::Accept => two_way_exec(&context, true, &r)?,
        Verdict::Refuse => two_way_exec(&context, false, &r)?,
        Verdict::Either => {}
    }
    if r.is_ok() {
        let records = core_records(&s.entries().map_err(|e| format!("{e:?}"))?);
        for expected in ghost.expected_records(actor, &cmd)? {
            if !records.contains(&expected) {
                return Err(format!("{context}: missing record {expected:?}"));
            }
        }
    }
    Ok(())
}

/// Draws a defect of the opaque maps only, or none.
fn gen_key_defect(g: &mut Gen) -> Defect {
    loop {
        let d = gen_defect(g);
        if matches!(
            d,
            Defect::None
                | Defect::DropFrozenOpaque(_)
                | Defect::TypedInFrozenOpaque(_)
                | Defect::LiveInFrozenOpaque(_)
                | Defect::FrozenInLiveOpaque(_)
                | Defect::TenantInLiveOpaque(_)
        ) {
            return d;
        }
    }
}

/// I-12: a policy version whose frozen opaque keys are not exactly the
/// untyped frozen parameters, or whose live map holds a frozen or
/// tenant-level key, is refused. A complete version is accepted.
#[test]
fn i12_policy_versions_must_carry_every_frozen_parameter() {
    check(
        "i12_policy_versions_must_carry_every_frozen_parameter",
        |g| {
            let d = gen_key_defect(g);
            g.note("defect", &d);
            create_with(d)
        },
    );
}

/// I-50 and design 2.4: validation refuses P-05 above P-58 and P-03 above
/// 64, and accepts the warning-only cases P-39 above P-03, P-04 max above
/// P-05, P-05 equal to P-58 and no P-58.
#[test]
fn i50_policy_validation_matches_reference() {
    check("i50_policy_validation_matches_reference", |g| {
        let d = gen_defect(g);
        g.note("defect", &d);
        create_with(d)
    });
}
