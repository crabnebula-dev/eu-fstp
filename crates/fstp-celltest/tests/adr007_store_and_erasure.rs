//! ADR-007 store seams (design sections 5.3, 5.6 and 14.6): the PostgreSQL
//! record store against the in-memory one, erased text references, and who
//! reads the erasure log.
//!
//! Lane W1c wrote these tests before the production code. They are red
//! until lanes W2c (`AsyncRecordStore`, the gate and the text records) and
//! W2e (`PgRecordStore`) land. The reference store test is green now.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::gate::{self, Action, Deny, ReadAction};
use fstp_cell_core::text::{TextCommand, TextRecord};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_celltest::NotImplemented;
use fstp_celltest::mc::auth_model::ProdCell;
use fstp_celltest::mc::driver_model::{POLICY, session_of};
use fstp_domain::id::{AccountId, BindingId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::roster::{A, ADMIN, B, C, P1, STAFF_PM, T0, grant};
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert_eq};

// ---------------------------------------------------------------------------
// The record store (ADR-007 "Decision").

/// The largest magnitude of an entry time (`fstp_ledger::MAX_AT`).
const MAX_AT: i64 = 9_007_199_254_740_991;

/// The refusals of an append, in the order ADR-007 fixes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Refused {
    DuplicateCommand,
    StaleHead { head: u64 },
    TimeOutOfRange,
    EmptyBatch,
}

/// The reference insert-only store: written from ADR-007 and the
/// `RecordStore` contract text, not from `fstp_ledger::MemStore`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RefStore {
    entries: Vec<(u64, i64, [u8; 16], u32)>,
}

impl RefStore {
    fn head(&self) -> u64 {
        self.entries.last().map_or(0, |e| e.0)
    }

    /// Appends `n` records under `command` at `at` if the head is still
    /// `expected`. The command id is checked before the head.
    fn append(
        &mut self,
        expected: u64,
        at: i64,
        command: [u8; 16],
        n: u32,
    ) -> Result<u64, Refused> {
        if self.entries.iter().any(|e| e.2 == command) {
            return Err(Refused::DuplicateCommand);
        }
        if self.head() != expected {
            return Err(Refused::StaleHead { head: self.head() });
        }
        if !(-MAX_AT..=MAX_AT).contains(&at) {
            return Err(Refused::TimeOutOfRange);
        }
        if n == 0 {
            return Err(Refused::EmptyBatch);
        }
        for i in 0..n {
            let seq = self.head() + 1;
            self.entries.push((seq, at, command, i));
        }
        Ok(self.head())
    }
}

/// One append request of the store property.
#[derive(Clone, Copy, Debug)]
struct Req {
    expected: u64,
    at: i64,
    command: [u8; 16],
    n: u32,
}

fn req(g: &mut Gen, head: u64) -> Req {
    Req {
        expected: if g.bool() {
            head
        } else {
            g.u64_in(0..=head + 2)
        },
        at: *g.pick(&[0, 1_000_000, MAX_AT, MAX_AT + 1, -MAX_AT - 1]),
        command: [g.u8_in(0..=3); 16],
        n: g.u32_in(0..=3),
    }
}

/// The seam of the PostgreSQL side: `fstp_pgstore::Pool` has no
/// constructor and `fstp_ledger::AsyncRecordStore` does not exist yet, so
/// no append reaches `PgRecordStore` (lanes W2c and W2e).
const PG_STORE_SEAM: &str = "fstp_pgstore::Pool has no constructor and fstp_ledger::AsyncRecordStore does not exist (lanes W2c and W2e)";

/// The PostgreSQL store's answer to `r`.
fn pg_append(r: Req) -> Result<Result<u64, Refused>, NotImplemented> {
    let _ = r;
    Err(NotImplemented::new(PG_STORE_SEAM))
}

/// ADR-007, design section 14.6: `PgRecordStore` gives the same results
/// and the same refusal order as the in-memory store, for any sequence of
/// appends with stale heads, repeated command ids, empty batches and
/// times at and past the bound.
///
/// Gap: `fstp_ledger::MemStore` cannot be named here (no `fstp-ledger`
/// dependency, see `mc::driver_model::LEDGER_SEAM`), so the in-memory side
/// is this file's reference store, written from the same contract.
#[test]
fn adr007_pg_store_matches_mem_store() {
    fstp_prop::check("adr007_pg_store_matches_mem_store", |g: &mut Gen| {
        let mut mem = RefStore::default();
        for _ in 0..g.usize_in(1..=8) {
            let r = req(g, mem.head());
            let want = mem.append(r.expected, r.at, r.command, r.n);
            let got = pg_append(r).map_err(|e| format!("{e} (NotImplemented)"))?;
            prop_assert_eq!(got, want, "ADR-007: {r:?}");
        }
        Ok(())
    });
}

/// ADR-007: the reference store reports a repeated command id as a
/// duplicate whatever the expected head, so a retry after a lost
/// acknowledgement learns that its command was applied.
#[test]
fn adr007_reference_store_refuses_duplicate_before_stale_head() {
    fstp_prop::check(
        "adr007_reference_store_refuses_duplicate_before_stale_head",
        |g: &mut Gen| {
            let mut s = RefStore::default();
            let id = [7u8; 16];
            s.append(0, 0, id, 1 + g.u32_in(0..=2)).unwrap();
            let expected = g.u64_in(0..=10);
            prop_assert_eq!(
                s.append(expected, g.i64_in(0..=10), id, g.u32_in(0..=3)),
                Err(Refused::DuplicateCommand)
            );
            Ok(())
        },
    );
}

/// ADR-007 teeth: a store that checks the head before the command id
/// fails the store property against the reference.
#[test]
fn adr007_teeth_head_checked_before_command_is_caught() {
    let outcome = fstp_prop::run(
        "adr007_teeth_head_checked_before_command_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            let mut mem = RefStore::default();
            let mut bad = RefStore::default();
            for _ in 0..g.usize_in(1..=8) {
                let r = req(g, mem.head());
                let want = mem.append(r.expected, r.at, r.command, r.n);
                let got = if bad.head() != r.expected {
                    Err(Refused::StaleHead { head: bad.head() })
                } else {
                    bad.append(r.expected, r.at, r.command, r.n)
                };
                prop_assert_eq!(got, want, "ADR-007: {r:?}");
            }
            Ok(())
        },
    );
    if let Err(e) = expect_prop_failure(&outcome, "ADR-007") {
        panic!("{e}");
    }
}

// ---------------------------------------------------------------------------
// Erasure (ADR-007 "Retention and erasure", design section 5.6).

/// The seam of text resolution: the stubs have no `TextStore::get` and no
/// erasure-log entry type with its id, request time, `completed_at`, cause
/// and authoriser (lanes W2c and W2e).
const TEXT_SEAM: &str = "no TextStore::get and no erasure-log entry type in the stubs (design section 5.6, lanes W2c and W2e)";

/// How a text reference resolves.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Resolved {
    Text,
    Erased { id: [u8; 16], cause: u16 },
}

fn resolve(cell: &ProdCell, id: [u8; 16]) -> Result<Resolved, NotImplemented> {
    let _ = (cell, id);
    Err(NotImplemented::new(TEXT_SEAM))
}

/// The erasure causes of design section 5.6, as closed codes.
const CAUSES: [u16; 4] = [1, 2, 3, 4];

/// ADR-007, design section 5.6: once an erasure is recorded, a `TextRef`
/// resolves to its erasure-log entry, never to the text, and the ledger
/// entry that holds the reference is unchanged. A text not erased still
/// resolves to its text.
#[test]
fn adr007_erased_textref_resolves_to_its_log_entry() {
    fstp_prop::check(
        "adr007_erased_textref_resolves_to_its_log_entry",
        |g: &mut Gen| {
            let mut cell = ProdCell::bootstrapped().map_err(|e| e.to_string())?;
            let ids: Vec<[u8; 16]> = (0..g.u8_in(1..=3)).map(|i| [0xA0 + i; 16]).collect();
            for id in &ids {
                cell.exec(
                    CellCommand::Text(TextCommand::PutText { id: *id }),
                    ADMIN,
                    T0,
                )
                .map_err(|e| e.to_string())?;
            }
            let erased: Vec<[u8; 16]> = ids.iter().copied().filter(|_| g.bool()).collect();
            let cause = *g.pick(&CAUSES);
            let before = cell.log().to_vec();
            if !erased.is_empty() {
                let batch = cell
                    .exec(
                        CellCommand::Text(TextCommand::EraseTexts {
                            ids: erased.clone(),
                            cause,
                        }),
                        ADMIN,
                        Timestamp::from_micros(T0.micros() + 1),
                    )
                    .map_err(|e| e.to_string())?;
                prop_assert_eq!(
                batch.iter().any(|r| matches!(r, CellRecord::Text(TextRecord::TextsErased { ids }) if *ids == erased)),
                true,
                "ADR-007: the erasure batch names the erased texts"
            );
            }
            prop_assert_eq!(
                cell.log()[..before.len()].to_vec(),
                before,
                "I-23: earlier entries changed"
            );
            for id in &ids {
                let got = resolve(&cell, *id).map_err(|e| format!("{e} (NotImplemented)"))?;
                let want = if erased.contains(id) {
                    Resolved::Erased { id: *id, cause }
                } else {
                    Resolved::Text
                };
                prop_assert_eq!(got, want, "ADR-007: text {id:?}");
            }
            Ok(())
        },
    );
}

/// An Auditor of P1 for the erasure-log property.
const AUDITOR: AccountId = AccountId::from_raw(601);
/// A finance approver of P1.
const FINANCE: AccountId = AccountId::from_raw(602);

/// The holders of the erasure-log property and their roles in P1.
fn holders() -> Vec<(AccountId, Option<Role>)> {
    vec![
        (ADMIN, None),
        (AUDITOR, Some(Role::Auditor)),
        (FINANCE, Some(Role::FinanceApprover)),
        (A, Some(Role::CommitteeMember)),
        (B, Some(Role::IrcMember)),
        (C, None),
        (STAFF_PM, None),
    ]
}

/// The reference rule: tenant admins and Auditors read the erasure log
/// (ADR-007 "Retention and erasure", G30).
///
/// Reading: the Auditor's programme scope (Q42, interim) filters the
/// entries an Auditor sees. It is not a gate rule, so the gate admits any
/// current Auditor.
fn may_read_erasure_log(account: AccountId, role: Option<Role>) -> bool {
    account == ADMIN || role == Some(Role::Auditor)
}

/// ADR-007, design section 5.6: the gate admits `ReadErasureLog` for
/// tenant admins and Auditors only. Every other role holder is refused.
///
/// Gap: the programme filter of an Auditor's view (Q42) needs an erasure
/// log read API, which the stubs lack (`TEXT_SEAM`).
#[test]
fn adr007_erasure_log_visible_to_auditor_and_tenant_admin_only() {
    fstp_prop::check(
        "adr007_erasure_log_visible_to_auditor_and_tenant_admin_only",
        |g: &mut Gen| {
            let mut cell = ProdCell::bootstrapped().map_err(|e| e.to_string())?;
            for (i, (account, role)) in holders().into_iter().enumerate() {
                if let Some(r) = role {
                    let binding = BindingId::from_raw(9_600 + u128::try_from(i).unwrap());
                    cell.exec_step(&grant(binding, account, P1, r, T0), T0)
                        .map_err(|e| e.to_string())?;
                }
            }
            let (account, role) = *g.pick(&holders());
            let now = Timestamp::from_micros(T0.micros() + 1);
            let got = match gate::admit(
                cell.state(),
                &session_of(account, now),
                Action::Read(ReadAction::ReadErasureLog),
                None,
                now,
                &POLICY,
            ) {
                Ok(_) => true,
                Err(Deny::NotImplemented(op)) => return Err(format!("{op} is NotImplemented")),
                Err(_) => false,
            };
            prop_assert_eq!(
                got,
                may_read_erasure_log(account, role),
                "ADR-007: ReadErasureLog by {account:?} holding {role:?}"
            );
            Ok(())
        },
    );
}
