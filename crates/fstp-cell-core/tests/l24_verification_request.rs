//! The verification request (ADR-008 and ADR-026 record of lane L24,
//! decided by Daniel on 2026-11-22: "Request, staff record it").
//!
//! The cell's vault port records `VerificationRequested { account }` when
//! a person presses "Start verification". Only the system task
//! `IdentityPort` is admitted for it, so no session appends one directly.
//! The record holds the account id only (I-17). The state knows the
//! accounts that asked, and a repeat changes nothing.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{NOW, cid, ledger, passkey, state_of};
use fstp_cell_core::gate::{self, Action, Deny};
use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::{
    CellCommand, CellRecord, SystemCtx, SystemTask, decide_system, decode_cell_record,
    encode_cell_record,
};
use fstp_domain::oracle::Answers;
use fstp_domain_testkit::r#gen::roster::A;

fn request() -> CellCommand {
    CellCommand::Release(ReleaseCommand::RequestVerification { account: A })
}

/// I-17, ADR-026 record of lane L24, row "Record": the identity port's
/// request becomes one `VerificationRequested` record of the account,
/// which round-trips through the cell codec and folds into the state.
/// A second record of the same account folds, and the state still holds
/// one open request.
#[test]
fn adr008_verification_request_records_one_open_request() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    assert!(!s.verification_requested(A));
    let ctx = SystemCtx {
        task: SystemTask::IdentityPort,
        at: NOW.micros(),
    };
    let batch = decide_system(&s, &request(), &ctx, cid(1), &Answers::new()).unwrap();
    let want = CellRecord::Release(ReleaseRecord::VerificationRequested { account: A });
    assert_eq!(batch, vec![want.clone()]);
    assert_eq!(
        decode_cell_record(&encode_cell_record(&want)).unwrap(),
        want
    );
    let entries = ledger(&[(NOW, cid(1), batch.clone()), (NOW, cid(2), batch)]).unwrap();
    let s = state_of(&entries).unwrap();
    assert!(s.verification_requested(A));
    assert_eq!(s.verification_requests().count(), 1);
}

/// I-78, ADR-026 record of lane L24, row "Record": only the identity
/// port is admitted for the request. A session and every other system
/// task are refused, and the identity port is admitted for nothing else.
#[test]
fn adr008_only_the_identity_port_records_a_request() {
    let s = fstp_cell_core::replay(&[]).unwrap();
    let admit = |task| gate::admit_system(&s, Action::Command(request()), task, cid(3), NOW);
    assert!(admit(SystemTask::IdentityPort).is_ok());
    for task in [
        SystemTask::ErasureRunner,
        SystemTask::Timeline,
        SystemTask::Provisioning,
        SystemTask::ContractPort,
        SystemTask::PaymentPort,
        SystemTask::LoginVerifier,
    ] {
        assert_eq!(admit(task).err(), Some(Deny::NotPermitted), "{task:?}");
    }
    let other = CellCommand::Release(ReleaseCommand::IssueWriteTicket { kind: 6 });
    assert_eq!(
        gate::admit_system(
            &s,
            Action::Command(other),
            SystemTask::IdentityPort,
            cid(4),
            NOW
        )
        .err(),
        Some(Deny::NotPermitted)
    );
    let r = gate::admit_command(
        &s,
        &passkey(A),
        Action::Command(request()),
        cid(5),
        None,
        NOW,
        &common::POLICY,
    );
    assert_eq!(r.err(), Some(Deny::NotPermitted));
}

/// ADR-026 record of lane L24, row "Open request" (lead reading,
/// 2026-11-22): an issued but unused verification ticket leaves the
/// request open. Only the vault's confirmation closes it: the timeline's
/// `CloseVerificationRequest` asks `IsVerified` and appends
/// `VerificationRequestClosed` only when it holds. A new request then
/// opens again, with the next ordinal.
#[test]
fn adr008_only_the_vaults_confirmation_closes_the_request() {
    use fstp_domain::id::{ContentDigest, VaultEpoch};
    use fstp_domain::oracle::{Answer, Query};
    let asked = CellRecord::Release(ReleaseRecord::VerificationRequested { account: A });
    let ticket = CellRecord::Release(ReleaseRecord::VerificationTicketIssued {
        id: [9; 16],
        holder: fstp_domain_testkit::r#gen::roster::ADMIN,
        subject: A,
        proposal: None,
    });
    let s = state_of(&ledger(&[(NOW, cid(1), vec![asked.clone()]), (NOW, cid(2), vec![ticket])]).unwrap())
        .unwrap();
    assert!(s.verification_requested(A), "an unused ticket closed the request");
    assert_eq!(s.verification_request_ordinal(A), Some(1));

    let close = CellCommand::Release(ReleaseCommand::CloseVerificationRequest { account: A });
    let ctx = SystemCtx {
        task: SystemTask::Timeline,
        at: NOW.micros(),
    };
    let q = Query::IsVerified { account: A };
    assert_eq!(
        fstp_cell_core::queries_system(&s, &close, &ctx, cid(3)).unwrap(),
        vec![q.clone()]
    );
    let answer = |holds| {
        let mut a = Answers::new();
        a.insert(
            q.clone(),
            Answer {
                holds,
                accounts: None,
                epoch: VaultEpoch::from_raw(1),
                digest: ContentDigest::from_bytes([0; 32]),
            },
        );
        a
    };
    assert!(decide_system(&s, &close, &ctx, cid(3), &answer(false)).is_err());
    let batch = decide_system(&s, &close, &ctx, cid(3), &answer(true)).unwrap();
    assert_eq!(
        batch,
        vec![CellRecord::Release(ReleaseRecord::VerificationRequestClosed { account: A })]
    );
    let entries = ledger(&[
        (NOW, cid(1), vec![asked.clone()]),
        (NOW, cid(3), batch),
        (NOW, cid(4), vec![asked]),
    ])
    .unwrap();
    let s = state_of(&entries).unwrap();
    assert!(s.verification_requested(A));
    assert_eq!(s.verification_request_ordinal(A), Some(2));
    assert!(gate::admit_system(&s, Action::Command(close.clone()), SystemTask::Timeline, cid(5), NOW).is_ok());
    assert_eq!(
        gate::admit_system(&s, Action::Command(close), SystemTask::IdentityPort, cid(5), NOW).err(),
        Some(Deny::NotPermitted)
    );
}
