//! The cell's verification ticket (ADR-008 "Manual identity checks",
//! ADR-004 record of lane L13b, row "Cell ticket", R-ID-02, I-17).
//!
//! The recorder enters a verification on the vault origin under a
//! `write:verification_recorded` ticket of the cell. The cell issues it,
//! for a proposal, only to a tenant admin who holds no Judging binding and
//! no binding on the proposal, for a proposal in NEGOTIATION or later,
//! when the vault answers that the recorder is verified and shares no
//! identity with the proposal's accounts. Production
//! `fstp_cell_core::decide` against that rule, over states and actors,
//! each built from genesis with the vault's ground truth.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::release::{ReleaseCommand, ReleaseRecord};
use fstp_cell_core::{CellCommand, CellRecord};
use fstp_celltest::mc::auth_model::{ProdCell, ProdError};
use fstp_celltest::mc::driver_model::paths;
use fstp_domain::id::AccountId;
use fstp_domain::rules::StateTag;
use fstp_domain_testkit::r#gen::review::{IRC, L1, PR1, R1, tag};
use fstp_domain_testkit::r#gen::roster::{ADMIN, STAFF_PM, T0};
use fstp_prop::{Gen, prop_assert_eq};

/// The write kind code of `VerificationRecorded` (ADR-009).
const KIND_6: u16 = 6;

/// How the tenant admin stands at the vault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Recorder {
    Verified,
    Unverified,
    SameIdentityAsLead,
}

const RECORDERS: [Recorder; 3] = [
    Recorder::Verified,
    Recorder::Unverified,
    Recorder::SameIdentityAsLead,
];

/// The other actors: the lead, a reviewer, an IRC member and a staff
/// programme manager. None is a tenant admin.
const OTHERS: [AccountId; 4] = [L1, R1, IRC, STAFF_PM];

fn truth(r: Recorder) -> fstp_domain_testkit::vault::GroundTruth {
    let mut t = paths::truth(true);
    match r {
        Recorder::Verified => {
            t.set_identity(ADMIN, tag(ADMIN));
            t.verify(ADMIN);
        }
        Recorder::Unverified => {}
        Recorder::SameIdentityAsLead => {
            t.set_identity(ADMIN, tag(L1));
            t.verify(ADMIN);
        }
    }
    t
}

/// Whether production issues the verification ticket of PR1 to `actor`,
/// with PR1 in `state` and the tenant admin standing as `r`.
fn issues(state: StateTag, r: Recorder, actor: AccountId) -> Result<bool, String> {
    let path = paths::to(state)?;
    let mut cell = ProdCell::genesis(truth(r)).map_err(|e| e.to_string())?;
    cell.exec_tenant_admin_grant(ADMIN, ADMIN, T0)
        .map_err(|e| e.to_string())?;
    for p in &path {
        cell.exec_step(&p.step, p.at).map_err(|e| e.to_string())?;
    }
    let at = path.last().map_or(T0, |p| p.at);
    let cmd = CellCommand::Release(ReleaseCommand::IssueVerificationTicket {
        proposal: PR1.raw(),
    });
    match cell.exec(cmd, actor, at) {
        Ok(batch) => Ok(batch.iter().any(|rec| {
            matches!(
                rec,
                CellRecord::Release(ReleaseRecord::TicketIssued { kind, proposal, holder, .. })
                    if *kind == KIND_6 && *proposal == PR1.raw() && *holder == actor
            )
        })),
        Err(ProdError::Refused(_)) => Ok(false),
        Err(e @ ProdError::NotImplemented(_)) => Err(e.to_string()),
    }
}

/// The rule of ADR-004 record of lane L13b, row "Cell ticket".
fn reference(state: StateTag, r: Recorder, actor: AccountId) -> bool {
    actor == ADMIN && r == Recorder::Verified && state == StateTag::Negotiation
}

/// R-ID-02, I-17, ADR-008 rules 1 and 2, ADR-004 record of lane L13b:
/// over states, the tenant admin's standing at the vault and other
/// actors, production issues the verification ticket exactly when the
/// rule does.
#[test]
fn adr008_verification_ticket_rules() {
    fstp_prop::check("adr008_verification_ticket_rules", |g: &mut Gen| {
        let state = *g.pick(&paths::STATES);
        let r = *g.pick(&RECORDERS);
        let actor = if g.bool() { ADMIN } else { *g.pick(&OTHERS) };
        let got = issues(state, r, actor)?;
        prop_assert_eq!(
            got,
            reference(state, r, actor),
            "a verification ticket for PR1 in {state:?} to {actor:?}, admin {r:?}"
        );
        Ok(())
    });
}

/// R-ID-02: the ticket is issued in NEGOTIATION to a verified tenant
/// admin, so the property above has a case that holds.
#[test]
fn adr008_verification_ticket_issued_in_negotiation() {
    assert_eq!(
        issues(StateTag::Negotiation, Recorder::Verified, ADMIN),
        Ok(true)
    );
    assert_eq!(
        issues(StateTag::Negotiation, Recorder::SameIdentityAsLead, ADMIN),
        Ok(false)
    );
}
