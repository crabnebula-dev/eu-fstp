//! The live SoD check of creator step 9: `preview_grant` on a draft equals `GrantRole` on an activated copy (M4 design sections 3.2 and 3.4, D3).
//!
//! Verifies SoD-01 to SoD-13 previews for I-67 creator step 9, through
//! the I-01, I-06 and SoD-09 guards that `GrantRole` runs. Q13 A interim
//! reading, pending Daniel: `preview_grant` runs the `GrantRole` SoD
//! guards and their vault questions without the draft gate, and appends
//! no record.
//!
//! Each case starts from genesis: ADMIN creates P1, then up to four draft
//! actions run, programme manager grants by tenant admins and policy
//! edits. The activated copy is the same state after a core
//! `ActivateProgramme` by an admin who built nothing. A grant is then
//! generated over every role, accounts that are verified, unverified, a
//! second account of the opener or a tenant admin, self-grants, missing
//! terms and organisations, backdated starts and reused binding ids.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::id::{AccountId, BindingId, CommandId, OrganisationId, PolicyVersionId};
use fstp_domain::oracle::Answers;
use fstp_domain::refusal::{Refusal, RefusalReason, RuleRef};
use fstp_domain::roles::{Role, preview_grant, preview_grant_queries};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::activation::{
    ADMIN_3, APPROVER, SYBIL_OF_ADMIN, activate_command, activation_truth, draft_scenario,
};
use fstp_domain_testkit::r#gen::policy::{Edit, apply_edit, next_version, text};
use fstp_domain_testkit::r#gen::review::{R1, R2, run_records};
use fstp_domain_testkit::r#gen::roster::{
    ADMIN, Flags, P1, STAFF_DRAFTER, STAFF_PM, Step, T0, grant,
};
use fstp_domain_testkit::vault::{GroundTruth, IdentityTag};
use fstp_prop::{Gen, check};

/// A tenant admin who builds nothing and activates the copies.
const ACTIVATOR: AccountId = AccountId::from_raw(7);

/// An account the vault has never verified.
const UNVERIFIED: AccountId = AccountId::from_raw(9);

/// The tenant admins.
const ADMINS: [AccountId; 3] = [ADMIN, APPROVER, ADMIN_3];

/// The accounts a generated grant binds.
const ACCOUNTS: [AccountId; 8] = [
    R1,
    R2,
    STAFF_PM,
    STAFF_DRAFTER,
    SYBIL_OF_ADMIN,
    UNVERIFIED,
    ADMIN,
    APPROVER,
];

fn truth() -> GroundTruth {
    let mut t = activation_truth();
    for (a, n) in [(ACTIVATOR, 907), (R1, 9_211), (R2, 9_212)] {
        t.set_identity(a, IdentityTag::new(n));
        t.verify(a);
    }
    t
}

/// The draft and its activated copy, with the vault.
struct Pair {
    draft: State,
    active: State,
    truth: GroundTruth,
}

fn answered(truth: &GroundTruth, queries: &[fstp_domain::oracle::Query]) -> Answers {
    let mut a = Answers::new();
    for q in queries {
        if truth.answers(q) {
            a.insert(q.clone(), truth.answer(q));
        }
    }
    a
}

fn ctx(actor: AccountId, second: Option<AccountId>, binds_admin: bool) -> Ctx {
    Ctx {
        now: T0,
        actor: Actor::Account(actor),
        command: CommandId::from_bytes(*b"test:d3:preview!"),
        via: Via::Web,
        tenant_admin: true,
        second_tenant_admin: second,
        binds_tenant_admin: binds_admin,
    }
}

/// A generated draft history and its activated copy.
fn pair(g: &mut Gen) -> Result<Pair, String> {
    let truth = truth();
    let mut s = draft_scenario(truth.clone(), P1)?;
    let mut binding: u128 = 11;
    let mut version: u128 = 2;
    for _ in 0..g.usize_in(0..=4) {
        let step = if g.weighted(&[2, 1]) == 0 {
            let mut st = grant(
                BindingId::from_raw(binding),
                *g.pick(&[STAFF_PM, STAFF_DRAFTER]),
                P1,
                Role::ProgrammeManager,
                T0,
            );
            binding = binding.saturating_add(1);
            st.actor = Actor::Account(*g.pick(&ADMINS));
            st
        } else {
            let head = fstp_domain::policy::head(&s.state().core, P1)
                .ok_or("no head")?
                .clone();
            let mut v = next_version(&head, PolicyVersionId::from_raw(version));
            version = version.saturating_add(1);
            apply_edit(&mut v, Edit::P02(6_000));
            Step::by(
                *g.pick(&[STAFF_PM, STAFF_DRAFTER]),
                Flags::NONE,
                Command::EditPolicy {
                    base: head.id,
                    version: Box::new(v),
                },
            )
        };
        g.note("draft step", &step);
        let _ = run_records(&mut s, &step, T0)?;
    }
    let draft = s.state().core.clone();
    let activation = activate_command(P1);
    let c = ctx(ACTIVATOR, None, false);
    let qs = fstp_domain::queries(&draft, &activation, &c)
        .map_err(|r| format!("activation queries refused: {r}"))?;
    let records = fstp_domain::decide(&draft, &activation, &c, &answered(&truth, &qs))
        .map_err(|r| format!("the activated copy cannot be built: {r}"))?;
    let mut active = draft.clone();
    for r in &records {
        fstp_domain::apply(&mut active, fstp_ledger::Seq::from_raw(1), T0, r)
            .map_err(|e| format!("fold of the activation: {e}"))?;
    }
    Ok(Pair {
        draft,
        active,
        truth,
    })
}

/// A generated grant of `role`, or of any role when it is `None`, its
/// context, and whether it grants a programme manager binding.
fn grant_case(g: &mut Gen, role: Option<Role>) -> (Command, Ctx, bool) {
    let role = role.unwrap_or_else(|| *g.pick(&Role::ALL));
    let account = *g.pick(&ACCOUNTS);
    let actor = if g.weighted(&[6, 1]) == 0 {
        *g.pick(&ADMINS)
    } else {
        account
    };
    let second = match g.weighted(&[4, 1, 1]) {
        0 => None,
        1 => ADMINS.iter().copied().find(|a| *a != actor),
        _ => Some(actor),
    };
    let binding = if g.weighted(&[6, 1]) == 0 { 90 } else { 11 };
    let start = if g.weighted(&[8, 1]) == 0 {
        T0
    } else {
        Timestamp::from_micros(T0.micros().saturating_sub(1))
    };
    let cmd = Command::GrantRole {
        binding: BindingId::from_raw(binding),
        account,
        programme: P1,
        role,
        start,
        second_admin: second,
        confidentiality: (g.weighted(&[6, 1]) == 0).then(|| text(91_000)),
        organisation: (g.weighted(&[3, 1]) == 0).then(|| OrganisationId::from_raw(account.raw())),
        end: (g.weighted(&[6, 1]) == 1)
            .then(|| Timestamp::from_micros(T0.micros().saturating_add(5))),
    };
    let c = ctx(actor, second, ADMINS.contains(&account));
    (cmd, c, role == Role::ProgrammeManager)
}

/// D3, SoD-01 to SoD-13 via `GrantRole`'s guards, Q13 A: on every generated
/// draft and grant, `preview_grant_queries` on the draft equals `queries`
/// on the activated copy, and `preview_grant` on the draft under the same
/// answers accepts exactly when `decide` on the copy accepts, with the
/// same refusal otherwise.
#[test]
fn d3_preview_grant_equals_grant_on_activated_copy() {
    check("d3_preview_grant_equals_grant_on_activated_copy", |g| {
        let p = pair(g)?;
        let (cmd, c, _) = grant_case(g, None);
        g.note("grant", &cmd);
        let qa = fstp_domain::queries(&p.active, &cmd, &c);
        let qp = preview_grant_queries(&p.draft, &cmd, &c);
        if qa != qp {
            return Err(format!(
                "D3: the preview asks {qp:?}, the grant on the copy {qa:?}"
            ));
        }
        let answers = answered(&p.truth, qa.as_deref().unwrap_or(&[]));
        let da = fstp_domain::decide(&p.active, &cmd, &c, &answers).map(|_| ());
        let dp = preview_grant(&p.draft, &cmd, &c, &answers);
        if da != dp {
            return Err(format!(
                "D3: the preview gives {dp:?}, the grant on the copy {da:?}"
            ));
        }
        Ok(())
    });
}

/// D3: a programme manager grant on the draft is decided exactly as on the
/// activated copy, records included, so builders hold their binding on the
/// draft (I-65 "named programme manager").
#[test]
fn d3_programme_manager_grant_on_a_draft_equals_the_activated_copy() {
    check(
        "d3_programme_manager_grant_on_a_draft_equals_the_activated_copy",
        |g| {
            let p = pair(g)?;
            let (cmd, c, _) = grant_case(g, Some(Role::ProgrammeManager));
            g.note("grant", &cmd);
            let qa = fstp_domain::queries(&p.active, &cmd, &c);
            let qd = fstp_domain::queries(&p.draft, &cmd, &c);
            if qa != qd {
                return Err(format!("D3: the draft asks {qd:?}, the copy {qa:?}"));
            }
            let answers = answered(&p.truth, qa.as_deref().unwrap_or(&[]));
            let da = fstp_domain::decide(&p.active, &cmd, &c, &answers);
            let dd = fstp_domain::decide(&p.draft, &cmd, &c, &answers);
            if da != dd {
                return Err(format!("D3: the draft gives {dd:?}, the copy {da:?}"));
            }
            Ok(())
        },
    );
}

/// D3, I-66: every other grant that the preview admits is refused on the
/// draft by the draft gate, `RuleRef::I66` with `WrongState`
/// (test-author choice).
#[test]
fn d3_draft_gate_refuses_every_other_grant_the_preview_admits() {
    check(
        "d3_draft_gate_refuses_every_other_grant_the_preview_admits",
        |g| {
            let p = pair(g)?;
            let (cmd, c, pm) = grant_case(g, None);
            g.assume(!pm);
            g.note("grant", &cmd);
            let Ok(qs) = preview_grant_queries(&p.draft, &cmd, &c) else {
                return Ok(());
            };
            let answers = answered(&p.truth, &qs);
            if preview_grant(&p.draft, &cmd, &c, &answers).is_err() {
                return Ok(());
            }
            let draft_queries = fstp_domain::queries(&p.draft, &cmd, &c).unwrap_or_default();
            let answers = answered(&p.truth, &draft_queries);
            let dd = fstp_domain::decide(&p.draft, &cmd, &c, &answers);
            if dd != Err(Refusal::new(RuleRef::I66, RefusalReason::WrongState)) {
                return Err(format!(
                    "D3: a grant the preview admits gave {dd:?} on the draft"
                ));
            }
            Ok(())
        },
    );
}
