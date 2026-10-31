//! Recorded dry-run vault answers (M4 design section 3.7 step 5,
//! `overview.md` NOTE 5, H-07).
//!
//! Before a command becomes a pending action, or executes, dispatch dry
//! runs it with web semantics. Every vault answer the dry run obtains is
//! recorded through `VaultAudit` as the query digest and the answer bit,
//! with no identity attribute. If recording fails, the dry run refuses and
//! nothing happens. Dry runs that ask the vault have their own rate limit
//! per account.
//!
//! The vault-asking operation is `proposal.add_member`: adding a team
//! member asks whether the account is in an excluded class (I-04) and
//! whether it shares an identity with programme staff (SoD-03).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeMap;

use fstp_api_core::ErrorCode;
use fstp_api_core::port::{LoginMethod, QueryDigest};
use fstp_api_core::rate::DRY_RUN_VAULT_PER_ACCOUNT;
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{LEAD, PX, new_member};
use fstp_api_testkit::fake::{FakeCell, VaultAuditRecord, requests};
use fstp_domain::command::CommandKind;
use fstp_engine::Command;
use fstp_prop::{check, prop_assert, prop_assert_eq};

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// The vault answers every dry run of the engine port obtained, as the
/// records NOTE 5 asks for, with their multiplicity.
fn dry_run_answers(c: &FakeCell) -> BTreeMap<VaultAuditRecord, usize> {
    let mut out = BTreeMap::new();
    for run in c.ports.engine.dry_runs() {
        for (_, a) in run.asks {
            let rec = VaultAuditRecord {
                query: QueryDigest(a.digest.bytes()),
                answer: a.holds,
                epoch: a.epoch,
            };
            let n = out.entry(rec).or_insert(0usize);
            *n = n.saturating_add(1);
        }
    }
    out
}

/// The records of the vault audit port, with their multiplicity.
fn recorded(c: &FakeCell) -> BTreeMap<VaultAuditRecord, usize> {
    let mut out = BTreeMap::new();
    for rec in c.ports.vault_audit.records() {
        let n = out.entry(rec).or_insert(0usize);
        *n = n.saturating_add(1);
    }
    out
}

/// Overview NOTE 5, H-07, R-CF-03: every vault answer a dispatch dry run
/// obtains is recorded through `VaultAudit` as the query digest and the
/// answer bit, at least as often as the dry runs obtained it. Random runs
/// of one to five team member additions by the lead through the web.
#[test]
fn i85_dry_run_vault_answers_are_recorded_as_digest_and_bit() {
    check(
        "i85_dry_run_vault_answers_are_recorded_as_digest_and_bit",
        |g| {
            let n = g.u32_in(1..=5);
            let c = FakeCell::new().map_err(|e| e.to_string())?;
            let lead = c.login(LEAD, LoginMethod::Passkey);
            for i in 0..n {
                let r = c.web(&lead, requests::add_member_web(PX, new_member(i)));
                prop_assert_eq!(class(&r), Class::Done, "addition {}: {:?}", i, r);
            }
            let runs = c.ports.engine.dry_runs();
            let added = runs
            .iter()
            .filter(|d| matches!(&d.cmd, Command::Core(x) if x.kind() == CommandKind::AddTeamMember))
            .count();
            prop_assert!(
                added >= usize::try_from(n).unwrap_or(usize::MAX),
                "dispatch ran {} dry runs of {} additions",
                added,
                n
            );
            let asked = dry_run_answers(&c);
            prop_assert!(!asked.is_empty(), "the dry runs asked the vault nothing");
            let have = recorded(&c);
            for (rec, times) in &asked {
                let got = have.get(rec).copied().unwrap_or(0);
                prop_assert!(
                    got >= *times,
                    "the answer {:?} was obtained {} times and recorded {} times",
                    rec,
                    times,
                    got
                );
            }
            Ok(())
        },
    );
}

/// Overview NOTE 2 and NOTE 5: when recording a dry run's vault answer
/// fails, the call is refused and nothing is executed. It fails closed.
#[test]
fn i85_dry_run_fails_closed_when_recording_fails() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let head = c.ports.engine.head();
    c.ports.vault_audit.set_failing(true);
    let r = c.web(&lead, requests::add_member_web(PX, new_member(0)));
    assert!(class(&r).refused(), "recording failed, yet: {r:?}");
    assert!(
        c.ports.vault_audit.refused() > 0,
        "the dry run recorded nothing"
    );
    assert!(
        c.ports.engine.appended().is_empty(),
        "the addition executed"
    );
    assert_eq!(c.ports.engine.head(), head);

    c.ports.vault_audit.set_failing(false);
    let r = c.web(&lead, requests::add_member_web(PX, new_member(0)));
    assert_eq!(class(&r), Class::Done, "once recording works: {r:?}");
}

/// H-07, design section 3.7 step 5: dry runs that ask the vault are rate
/// limited per account. The lead's additions within one window are
/// admitted up to the limit, the next is refused with `RateLimited`
/// before anything executes, and once the window has passed the lead is
/// admitted again.
#[test]
fn i85_h07_dry_runs_that_ask_the_vault_are_rate_limited() {
    let c = cell();
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let limit = DRY_RUN_VAULT_PER_ACCOUNT;
    assert!(limit.count > 0 && limit.window_micros > 0, "{limit:?}");
    for i in 0..limit.count {
        let r = c.web(&lead, requests::add_member_web(PX, new_member(i)));
        assert_eq!(
            class(&r),
            Class::Done,
            "addition {i} within the limit: {r:?}"
        );
    }
    let appended = c.ports.engine.appended().len();
    let r = c.web(&lead, requests::add_member_web(PX, new_member(limit.count)));
    assert_eq!(
        class(&r),
        Class::Refused(ErrorCode::RateLimited),
        "the addition past the limit: {r:?}"
    );
    assert_eq!(
        c.ports.engine.appended().len(),
        appended,
        "the refused addition executed"
    );

    c.ports.clock.advance(limit.window_micros.saturating_add(1));
    let r = c.web(&lead, requests::add_member_web(PX, new_member(limit.count)));
    assert_eq!(class(&r), Class::Done, "after the window: {r:?}");
}
