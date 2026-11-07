//! The vault-only statements of an applicant lead (lane mapp): the date
//! of birth of Q23 B (I-18, I-86, R-ID-04, R-SB-01) and the declared
//! affiliations (R-NG-01).
//!
//! Each statement goes to the vault port and nowhere else: no ledger
//! entry, no stored text, no audit text and no reply member carries it.
//! The vault answers one bit about the date of birth, relative to the call
//! deadline, through the query the domain derives its minor flag from.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_api_core::decode::{Method, decode_route};
use fstp_api_core::model::ReadModel;
use fstp_api_core::port::{AsyncEngine, LoginMethod};
use fstp_api_core::{ApiError, OpResult};
use fstp_api_testkit::fake::FakeCell;
use fstp_api_testkit::fake::cell::{Class, class};
use fstp_api_testkit::fake::fixture::{CALL_OPEN, LEAD};
use fstp_api_testkit::fake::vault::IntakeKind;
use fstp_domain::id::ProposalId;
use fstp_domain::oracle::Query;
use fstp_domain::time::Timestamp;
use fstp_engine::IdentityOracle;

fn cell() -> FakeCell {
    FakeCell::new().unwrap_or_else(|e| panic!("the fake cell: {e}"))
}

/// A new draft of LEAD in the open call, created through the page.
fn draft(c: &FakeCell) -> ProposalId {
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let r = c.web(
        &lead,
        decode_route(
            Method::Post,
            &format!("/calls/{}/proposals", CALL_OPEN.raw()),
            b"{}",
        ),
    );
    match r {
        Ok(OpResult::Done {
            body: ReadModel::Created(ids),
            ..
        }) => ProposalId::from_raw(ids.iter().find(|(n, _)| *n == "proposal").unwrap().1),
        other => panic!("proposal.create gave {other:?}"),
    }
}

/// What the cell holds outside the vault: the ledger head, the stored
/// texts, the engine calls and the audit entries.
fn outside(c: &FakeCell) -> (fstp_ledger::Seq, usize, usize, usize, String) {
    (
        c.ports.engine.head(),
        c.ports.texts.len(),
        c.ports.engine.executions().len(),
        c.ports.engine.dry_runs().len(),
        format!("{:?}", c.ports.audit.entries()),
    )
}

/// Asserts that nothing outside the vault holds `canary`, and that the
/// statement appended nothing and stored no text.
fn reaches_only_the_vault(
    c: &FakeCell,
    before: &(fstp_ledger::Seq, usize, usize, usize, String),
    reply: &Result<OpResult, ApiError>,
    canaries: &[&str],
) {
    let after = outside(c);
    assert_eq!(after.0, before.0, "no ledger entry");
    assert_eq!(after.1, before.1, "no stored text");
    assert_eq!(after.2, before.2, "no engine execution");
    assert_eq!(after.3, before.3, "no dry run");
    let ledger = format!("{:?}", c.ports.engine.ledger());
    let reply = format!("{reply:?}");
    for canary in canaries {
        assert!(!ledger.contains(canary), "the ledger holds {canary}");
        assert!(!after.4.contains(canary), "the audit holds {canary}");
        assert!(!reply.contains(canary), "the reply holds {canary}");
    }
}

/// I-86, I-18, R-ID-04, R-SB-01 and Q23 B (design section 15.0,
/// 2026-11-06): the lead states a date of birth at submission, to the
/// vault only. The cell appends nothing, stores no text and answers
/// `accepted` alone. The vault then answers one bit, relative to the
/// deadline: is the lead 18 or older then? The domain's minor flag comes
/// from that bit (`IsVerifiedAdultAtDeadline`, state-machine NOTE 14).
#[test]
fn i86_i18_date_of_birth_reaches_only_the_vault_and_yields_one_bit() {
    let c = cell();
    let p = draft(&c);
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let before = outside(&c);
    let reply = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{}/vault/birth_date", p.raw()),
            br#"{"date_of_birth":"2009-07-14"}"#,
        ),
    );
    assert!(
        matches!(
            reply,
            Ok(OpResult::Done {
                body: ReadModel::Accepted,
                seq: None
            })
        ),
        "the statement: {reply:?}"
    );
    reaches_only_the_vault(&c, &before, &reply, &["2009-07-14", "2009", "20090714"]);
    assert!(
        c.ports
            .vault
            .intake()
            .contains(&(IntakeKind::BirthDate, LEAD, p)),
        "the vault received the date: {:?}",
        c.ports.vault.intake()
    );

    // One bit, relative to the deadline: 18 from noon UTC of the 18th
    // birthday, the start of that day in the latest time zone.
    let oracle = c.ports.vault.oracle();
    let adult_from = Timestamp::from_micros(1_815_566_400 * 1_000_000);
    let ask = |deadline: Timestamp| {
        oracle
            .ask(&Query::IsVerifiedAdultAtDeadline {
                account: LEAD,
                deadline,
            })
            .map(|a| (a.holds, a.accounts.is_none()))
    };
    assert_eq!(
        ask(adult_from.checked_pred().unwrap()),
        Ok((false, true)),
        "a minor at a deadline before the 18th birthday"
    );
    assert_eq!(ask(adult_from), Ok((true, true)), "18 at the deadline");
}

/// R-SB-01, Q23 B: the date of birth is one strict member, a real
/// calendar day. A malformed or impossible date, or an extra member, is
/// refused and reaches neither the vault nor the ledger.
#[test]
fn r_sb_01_date_of_birth_is_one_strict_member() {
    let c = cell();
    let p = draft(&c);
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let before = outside(&c);
    for body in [
        &br#"{"date_of_birth":"2009-02-30"}"#[..],
        br#"{"date_of_birth":"14/07/2009"}"#,
        br#"{"date_of_birth":"2009-07-14","country":"BE"}"#,
        br#"{"dob":"2009-07-14"}"#,
        br#"{"date_of_birth":20090714}"#,
    ] {
        let r = c.web(
            &lead,
            decode_route(
                Method::Put,
                &format!("/proposals/{}/vault/birth_date", p.raw()),
                body,
            ),
        );
        assert_ne!(
            class(&r),
            Class::Done,
            "{}: {r:?}",
            String::from_utf8_lossy(body)
        );
        reaches_only_the_vault(&c, &before, &r, &["2009"]);
    }
    assert!(
        c.ports.vault.intake().is_empty(),
        "the vault received nothing"
    );
}

/// R-NG-01, I-86 (design section 2.2 J4, `VaultBound<T>`): the declared
/// affiliations go to the vault route only. The cell appends nothing,
/// stores no text and answers `accepted` alone.
#[test]
fn r_ng_01_affiliations_reach_only_the_vault() {
    let c = cell();
    let p = draft(&c);
    let lead = c.login(LEAD, LoginMethod::Passkey);
    let before = outside(&c);
    let reply = c.web(
        &lead,
        decode_route(
            Method::Put,
            &format!("/proposals/{}/vault/affiliations", p.raw()),
            br#"{"affiliations":"Synthetic organisation AFFCANARY7"}"#,
        ),
    );
    assert!(
        matches!(
            reply,
            Ok(OpResult::Done {
                body: ReadModel::Accepted,
                seq: None
            })
        ),
        "the declaration: {reply:?}"
    );
    reaches_only_the_vault(&c, &before, &reply, &["AFFCANARY7"]);
    assert!(
        c.ports
            .vault
            .intake()
            .contains(&(IntakeKind::Affiliations, LEAD, p)),
        "the vault received the affiliations: {:?}",
        c.ports.vault.intake()
    );
}

/// R-NG-01: an empty declaration, or one with another member, is refused
/// and reaches neither the vault nor the ledger.
#[test]
fn r_ng_01_affiliations_are_one_strict_member() {
    let c = cell();
    let p = draft(&c);
    let lead = c.login(LEAD, LoginMethod::Passkey);
    for body in [
        &br#"{"affiliations":"   "}"#[..],
        br#"{"affiliations":"AFFCANARY8","lists":[]}"#,
        br#"{"lists":[]}"#,
    ] {
        let before = outside(&c);
        let r = c.web(
            &lead,
            decode_route(
                Method::Put,
                &format!("/proposals/{}/vault/affiliations", p.raw()),
                body,
            ),
        );
        assert_ne!(
            class(&r),
            Class::Done,
            "{}: {r:?}",
            String::from_utf8_lossy(body)
        );
        reaches_only_the_vault(&c, &before, &r, &["AFFCANARY8"]);
    }
    assert!(
        c.ports.vault.intake().is_empty(),
        "the vault received nothing"
    );
}
