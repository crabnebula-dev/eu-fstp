//! SoD-07, TH-05: the "grant awaiting approval" record (Daniel,
//! 2026-11-15). A tenant admin's self-grant appends a pending record that
//! names the grantee, the programme, the role and the dates. A second
//! tenant admin's approval names it by its id. The record, its approval
//! and their fold are checked here through the production API, with every
//! shell answer stated in the test.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

use fstp_domain::Via;
use fstp_domain::id::{AccountId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_domain::time::Timestamp;
use fstp_tenant::{
    ApprovalId, CellKind, GrantRef, InvitationId, PendingSelfGrant, TenantAnswers, TenantCommand,
    TenantCtx, TenantQuery, TenantRecord, TenantRefusal, TenantState, TokenDigest, decide,
    decode_command, decode_record, encode_command, encode_record, queries,
};

const T0: Timestamp = Timestamp::from_micros(1_767_225_600_000_000);
const DAY: i64 = 86_400_000_000;
const D1: TokenDigest = TokenDigest::from_bytes([0x11; 32]);

fn acct(n: u128) -> AccountId {
    AccountId::from_raw(n)
}

fn at(days: i64) -> Timestamp {
    Timestamp::from_micros(T0.micros() + days * DAY)
}

/// A tenant with its records, folded again after every command.
struct Tenant {
    state: TenantState,
    ledger: Vec<TenantRecord>,
}

impl Tenant {
    /// Admin 1, and admin 2 when `second` holds.
    fn new(second: bool) -> Tenant {
        let mut t = Tenant {
            state: TenantState::genesis(acct(1), CellKind::Saas),
            ledger: Vec::new(),
        };
        if second {
            t.run(
                acct(1),
                T0,
                &TenantCommand::InviteAdmin {
                    invitation: InvitationId::from_raw(1),
                    invitee: acct(2),
                    token_digest: D1,
                },
            )
            .unwrap();
            t.run(
                acct(2),
                T0,
                &TenantCommand::AcceptAdminInvitation {
                    invitation: InvitationId::from_raw(1),
                    token_digest: D1,
                },
            )
            .unwrap();
        }
        t
    }

    fn run(
        &mut self,
        actor: AccountId,
        when: Timestamp,
        cmd: &TenantCommand,
    ) -> Result<Vec<TenantRecord>, TenantRefusal> {
        let mut answers = TenantAnswers::new();
        for q in queries(&self.state, cmd) {
            match q {
                TenantQuery::AdminVerified(a) => answers.verified(a, true),
                TenantQuery::HoldsReceiving(a) => answers.holds_receiving(a, false),
                TenantQuery::Probe(_)
                | TenantQuery::Agreements
                | TenantQuery::ProgrammeManagers(_) => {}
            }
        }
        let ctx = TenantCtx {
            actor,
            via: Via::Web,
            at: when,
        };
        let recs = decide(&self.state, &ctx, cmd, &answers)?;
        self.state.apply_all(&recs).unwrap();
        self.ledger.extend(recs.iter().cloned());
        let replayed = TenantState::replay(acct(1), CellKind::Saas, &self.ledger).unwrap();
        assert_eq!(replayed, self.state, "a fold of the ledger differs");
        Ok(recs)
    }
}

fn grant_of(grantee: AccountId) -> GrantRef {
    GrantRef {
        grantee,
        programme: ProgrammeId::from_raw(9),
        role: Role::Auditor,
    }
}

fn request(id: u128, grantee: AccountId) -> TenantCommand {
    TenantCommand::RequestSelfGrant {
        request: ApprovalId::from_raw(id),
        grant: grant_of(grantee),
        start: at(1),
        end: Some(at(30)),
    }
}

fn approve(id: u128, grantee: AccountId) -> TenantCommand {
    TenantCommand::ApproveSelfGrant {
        approval: ApprovalId::from_raw(id),
        grant: grant_of(grantee),
    }
}

/// SoD-07 (Daniel, 2026-11-15): a self-grant appends a record naming the
/// grantee, programme, role and dates, and the state lists it as pending
/// under its id until a second admin approves it.
#[test]
fn sod07_self_grant_request_records_grantee_programme_role_and_dates() {
    let mut t = Tenant::new(true);
    let recs = t.run(acct(1), T0, &request(7, acct(1))).unwrap();
    assert_eq!(
        recs,
        vec![TenantRecord::SelfGrantRequested {
            request: ApprovalId::from_raw(7),
            grant: grant_of(acct(1)),
            start: at(1),
            end: Some(at(30)),
            at: T0,
        }]
    );
    assert_eq!(
        t.state.pending_self_grants().get(&ApprovalId::from_raw(7)),
        Some(&PendingSelfGrant {
            grant: grant_of(acct(1)),
            start: at(1),
            end: Some(at(30)),
            requested_at: T0,
            approved: false,
        })
    );
}

/// SoD-07: only a self-grant awaits approval. A request for another
/// account, a reused id, an end before the start and a non-admin are
/// refused, and none of them leaves a record.
#[test]
fn sod07_self_grant_request_refusals() {
    let mut t = Tenant::new(true);
    assert_eq!(
        t.run(acct(1), T0, &request(7, acct(2))),
        Err(TenantRefusal::NotSelfGrant)
    );
    assert_eq!(
        t.run(acct(3), T0, &request(7, acct(3))),
        Err(TenantRefusal::NotTenantAdmin)
    );
    let backwards = TenantCommand::RequestSelfGrant {
        request: ApprovalId::from_raw(7),
        grant: grant_of(acct(1)),
        start: at(30),
        end: Some(at(1)),
    };
    assert_eq!(
        t.run(acct(1), T0, &backwards),
        Err(TenantRefusal::InvalidInstant)
    );
    t.run(acct(1), T0, &request(7, acct(1))).unwrap();
    assert_eq!(
        t.run(acct(1), T0, &request(7, acct(1))),
        Err(TenantRefusal::ApprovalTaken)
    );
    assert_eq!(t.state.pending_self_grants().len(), 1);
}

/// SoD-07: the second admin's approval names the pending record by its
/// id. It approves exactly that grant, once, and never by the grantee.
#[test]
fn sod07_second_admin_approves_the_pending_record_by_id() {
    let mut t = Tenant::new(true);
    t.run(acct(1), T0, &request(7, acct(1))).unwrap();
    assert_eq!(
        t.run(acct(1), T0, &approve(7, acct(1))),
        Err(TenantRefusal::SelfApproval)
    );
    let other = TenantCommand::ApproveSelfGrant {
        approval: ApprovalId::from_raw(7),
        grant: GrantRef {
            role: Role::FinanceApprover,
            ..grant_of(acct(1))
        },
    };
    assert_eq!(
        t.run(acct(2), T0, &other),
        Err(TenantRefusal::ApprovalNotOpen)
    );
    t.run(acct(2), at(1), &approve(7, acct(1))).unwrap();
    let pending = t.state.pending_self_grants()[&ApprovalId::from_raw(7)];
    assert!(pending.approved);
    assert_eq!(
        t.state.approvals()[&ApprovalId::from_raw(7)].approver,
        acct(2)
    );
    assert_eq!(
        t.run(acct(2), at(1), &approve(7, acct(1))),
        Err(TenantRefusal::ApprovalTaken)
    );
}

/// SoD-07, ADR-007: a ledger whose approval names another grant than its
/// pending record, or a request for another account, does not fold.
#[test]
fn sod07_fold_refuses_a_forged_pending_record() {
    let mut t = Tenant::new(true);
    t.run(acct(1), T0, &request(7, acct(1))).unwrap();
    let mut forged = t.ledger.clone();
    forged.push(TenantRecord::SelfGrantApproved {
        approval: ApprovalId::from_raw(7),
        grant: GrantRef {
            role: Role::FinanceApprover,
            ..grant_of(acct(1))
        },
        by: acct(2),
        at: T0,
    });
    assert_eq!(
        TenantState::replay(acct(1), CellKind::Saas, &forged)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::ApprovalNotOpen)
    );
    let mut forged = t.ledger.clone();
    forged.push(TenantRecord::SelfGrantRequested {
        request: ApprovalId::from_raw(8),
        grant: grant_of(acct(3)),
        start: at(1),
        end: None,
        at: T0,
    });
    assert_eq!(
        TenantState::replay(acct(1), CellKind::Saas, &forged)
            .err()
            .map(|e| e.0),
        Some(TenantRefusal::NotTenantAdmin)
    );
}

/// I-85: the request completes a role grant's first half, so it is web
/// only, as the role grant that issues it is high-risk.
#[test]
fn sod07_i85_self_grant_request_is_web_only() {
    let t = Tenant::new(true);
    let ctx = TenantCtx {
        actor: acct(1),
        via: Via::Mcp,
        at: T0,
    };
    assert_eq!(
        decide(&t.state, &ctx, &request(7, acct(1)), &TenantAnswers::new()),
        Err(TenantRefusal::HighRiskViaMcp)
    );
}

/// ADR-007, TH-26: the request and its record have one spelling each.
#[test]
fn adr007_self_grant_request_round_trips() {
    for end in [Some(at(30)), None] {
        let cmd = TenantCommand::RequestSelfGrant {
            request: ApprovalId::from_raw(7),
            grant: grant_of(acct(1)),
            start: at(1),
            end,
        };
        let bytes = encode_command(&cmd).unwrap();
        assert_eq!(decode_command(&bytes).unwrap(), cmd);
        let rec = TenantRecord::SelfGrantRequested {
            request: ApprovalId::from_raw(7),
            grant: grant_of(acct(1)),
            start: at(1),
            end,
            at: T0,
        };
        let bytes = encode_record(&rec).unwrap();
        assert_eq!(decode_record(&bytes).unwrap(), rec);
    }
}
