//! Shared world and steps of the M5 payment invariant tests (I-31, I-32,
//! I-33, I-58, M5 design section 8).
//!
//! The world is M-PAY's (`fstp_domain_testkit::mc::pay_model`): lead c is
//! granted 4.00 over two milestones of 2.00 and starts execution. R1 and
//! R2 are assigned reviewers, FINREL a finance approver and REL a payment
//! releaser who reviews nothing. Each step runs through `MoneyWorld`, so
//! production is compared with the references in both directions.

#![allow(dead_code, reason = "each test binary uses part of the shared support")]

use fstp_domain::id::{HardshipEvidenceId, LineId, MilestoneId, RequestId};
use fstp_domain::payment::PaymentKind;
use fstp_domain::record::Record;
use fstp_domain::time::{MICROS_PER_DAY, Timestamp};
use fstp_domain_testkit::r#gen::money::{
    FINREL, LC, MoneyWorld, PC, REL, accept_line, approve_payment, milestone_n, release_payment,
    request_payment_as,
};
use fstp_domain_testkit::r#gen::review::{R1, R3, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, Step};
use fstp_domain_testkit::mc::money_model::{Fact, McAction, McState, run_action};
use fstp_domain_testkit::mc::pay_model::pay_setup;
use fstp_domain_testkit::vault::{GroundTruth, Relation};

/// The P-36 hold of the synthetic policy, in microseconds (7 days).
pub(crate) const HOLD: i64 = 7 * MICROS_PER_DAY;

/// The hardship evidence the vault holds verified for grant c.
pub(crate) const EVIDENCE: HardshipEvidenceId = HardshipEvidenceId::from_raw(71);

/// Hardship evidence the vault holds but has not verified.
pub(crate) const UNVERIFIED: HardshipEvidenceId = HardshipEvidenceId::from_raw(72);

/// The world of M-PAY over `backend`. With `unbanked`, the payee of grant
/// c has no bank details in the vault yet.
pub(crate) fn world(backend: Backend, unbanked: bool) -> Result<MoneyWorld, String> {
    let mut setup = pay_setup();
    if unbanked {
        setup.unbanked = vec![PC];
    }
    let mut s = McState {
        world: setup.world(backend)?,
        edited: false,
        cap_blocked: false,
        grant_blocked: false,
        superseded: false,
        contract_cleared: false,
        deliverables: 0,
        divergence: None,
    };
    for a in [
        McAction::Determine(PC, 0),
        McAction::Grant(PC, Fact::Contract),
        McAction::Start(PC),
    ] {
        s = match run_action(&s, &a) {
            Some(n) if n.divergence.is_none() => n,
            Some(n) => return Err(format!("{a:?}: {}", n.divergence.unwrap_or_default())),
            None => return Err(format!("{a:?} was refused")),
        };
    }
    let mut w = s.world;
    w.vault(|t: &mut GroundTruth| {
        t.relate(tag(R3), tag(LC), Relation::Mentoring);
        t.verify_hardship(PC, EVIDENCE);
    })?;
    Ok(w)
}

/// Milestone `n` of grant c.
pub(crate) fn milestone(n: u8) -> MilestoneId {
    milestone_n(PC, u128::from(n))
}

/// The `n`-th request id of a test.
pub(crate) fn request_id(n: u128) -> RequestId {
    RequestId::from_raw(41_000u128.saturating_add(n))
}

/// The only line of the `n`-th request.
pub(crate) fn line_id(n: u128) -> LineId {
    LineId::from_raw(141_000u128.saturating_add(n))
}

/// The kind of a request: hardship with `evidence`, or a milestone claim.
pub(crate) fn kind(hardship: Option<HardshipEvidenceId>) -> PaymentKind {
    match hardship {
        Some(e) => PaymentKind::Hardship(e),
        None => PaymentKind::Milestone,
    }
}

/// Lead c's request `n` of one line of `cents` on milestone `m`.
pub(crate) fn ask(
    n: u128,
    m: u8,
    cents: i64,
    hardship: Option<HardshipEvidenceId>,
    replaces: Option<RequestId>,
) -> Result<Step, String> {
    request_payment_as(
        LC,
        request_id(n),
        PC,
        kind(hardship),
        &[(line_id(n), milestone(m), cents)],
        replaces,
    )
}

/// Runs `step`. `Ok(Some(records))` when both sides accept it, `Ok(None)`
/// when both refuse, and `Err` on a divergence.
pub(crate) fn run(w: &mut MoneyWorld, step: &Step) -> Result<Option<Vec<Record>>, String> {
    match w.step(step)? {
        Some((next, records)) => {
            *w = next;
            Ok(Some(records))
        }
        None => Ok(None),
    }
}

/// Runs `step`, which both sides must accept.
pub(crate) fn must(w: &mut MoneyWorld, step: &Step) -> Result<Vec<Record>, String> {
    run(w, step)?.ok_or_else(|| format!("{:?} by {:?} was refused", step.cmd, step.actor))
}

/// Request `n` of `cents` on milestone `m`, its line accepted in full by
/// R1 and the payment approved by FINREL, so REL may release it. `Ok(false)`
/// when a step was refused by both sides.
pub(crate) fn prepare(
    w: &mut MoneyWorld,
    n: u128,
    m: u8,
    cents: i64,
    hardship: Option<HardshipEvidenceId>,
) -> Result<bool, String> {
    for step in [
        ask(n, m, cents, hardship, None)?,
        accept_line(R1, request_id(n), line_id(n), cents, false)?,
        approve_payment(FINREL, request_id(n)),
    ] {
        if run(w, &step)?.is_none() {
            return Ok(false);
        }
    }
    Ok(true)
}

/// REL's release of request `n`.
pub(crate) fn release(n: u128) -> Step {
    release_payment(REL, request_id(n))
}

/// The instant `micros` after `t`.
pub(crate) fn later(t: Timestamp, micros: i64) -> Timestamp {
    Timestamp::from_micros(t.micros().saturating_add(micros))
}

/// The releases in `records`.
pub(crate) fn releases(records: &[Record]) -> Vec<RequestId> {
    records
        .iter()
        .filter_map(|r| match r {
            Record::PaymentReleased(x) => Some(x.request()),
            _ => None,
        })
        .collect()
}
