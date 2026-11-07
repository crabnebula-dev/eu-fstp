//! Shared world of the I-37 calibration consent tests (R-LA-09, R-LA-10,
//! M10 to M12 design section 3.1, lane L12-I37).
//!
//! The world starts from genesis through production commands: three
//! submitted proposals in call 1 (`ledger_setup`), and P-42 switched on by
//! the programme manager's live `EditPolicy` when asked. No production
//! command writes an outcome notice record yet (M6 dispatch), so the tests
//! append the notice record `OutboxEnqueued(ProposalOutcome)` themselves.
//! From there each consent command runs through `fstp_domain::decide`, and
//! its records fold through `fstp_domain::apply` at the next sequence
//! numbers. The world keeps the ledger tail it appended, so the tests can
//! check I-37 on the records and not only on the projection.

#![allow(dead_code, reason = "each test binary uses part of the shared support")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::id::{CommandId, PolicyVersionId, ProposalId, TextRef};
use fstp_domain::oracle::Answers;
use fstp_domain::policy::OpaqueValue;
use fstp_domain::record::{OutboxEvent, Record};
use fstp_domain::refusal::Refusal;
use fstp_domain::rules::{ParamId, StateTag};
use fstp_domain::state::State;
use fstp_domain::time::Timestamp;
use fstp_domain::{FoldError, apply, decide, queries};
use fstp_domain_testkit::r#gen::policy::text;
use fstp_domain_testkit::r#gen::review::{L1, L2, L3, PR1, PR2, PR3};
use fstp_domain_testkit::r#gen::roster::{P1, STAFF_PM, edit_policy};
use fstp_domain_testkit::mc::ledger_model::{
    LedgerRun, genesis_steps, ledger_judges, ledger_setup, ledger_truth,
};
use fstp_domain_testkit::mc::life_model::T_EVAL;
use fstp_ledger::Seq;

/// The three proposals of the world with their leads.
pub(crate) const LEADS: [(fstp_domain::id::AccountId, ProposalId); 3] =
    [(L1, PR1), (L2, PR2), (L3, PR3)];

/// The consent wording the applicant is shown. TODO(legal): the consent
/// text and the legal basis for pseudonymised use come from Daniel. The
/// tests reference a synthetic text id only.
pub(crate) fn wording() -> TextRef {
    text(37_000)
}

/// The lead of `proposal`.
pub(crate) fn lead_of(proposal: ProposalId) -> fstp_domain::id::AccountId {
    LEADS
        .iter()
        .find(|(_, p)| *p == proposal)
        .map(|(l, _)| *l)
        .unwrap_or(L1)
}

/// The world: the projection after genesis, and the records this test appended.
#[derive(Clone, Debug)]
pub(crate) struct ConsentWorld {
    /// The projection.
    pub state: State,
    /// The sequence number of the next entry.
    pub next: Seq,
    /// The instant of every command and record here.
    pub now: Timestamp,
    /// The entries this test appended, in order.
    pub tail: Vec<(Seq, Record)>,
    /// The command ids drawn.
    drawn: u64,
}

/// The programme manager's `EditPolicy` that sets P-42 to `true`.
fn p42_on(run: &mut LedgerRun) -> Result<(), String> {
    let head = fstp_domain::policy::head(&run.scenario.state().core, P1)
        .ok_or("no head of programme 1")?
        .clone();
    let on =
        OpaqueValue::from_value(&fstp_json::Value::Bool(true)).map_err(|e| format!("{e:?}"))?;
    let step = edit_policy(&head, PolicyVersionId::from_raw(3_700), |v| {
        v.live.opaque.insert(ParamId::P42, on);
    });
    run.checked(T_EVAL, &step)?;
    Ok(())
}

impl ConsentWorld {
    /// The world from genesis, with P-42 on when `p42` holds.
    pub(crate) fn new(p42: bool) -> Result<ConsentWorld, String> {
        let setup = ledger_setup(ledger_judges(), &LEADS, 1);
        let steps = genesis_steps(&setup)?;
        let mut run = LedgerRun::new(ledger_truth(&setup), &steps)?;
        if p42 {
            p42_on(&mut run)?;
        }
        let state = run.scenario.state().core.clone();
        let last = run.ledger.last().map(|e| e.seq).ok_or("empty ledger")?;
        Ok(ConsentWorld {
            state,
            next: Seq::from_raw(last.raw().saturating_add(1)),
            now: T_EVAL,
            tail: Vec::new(),
            drawn: 0,
        })
    }

    /// Folds `record` at the next sequence number and keeps it in the tail.
    pub(crate) fn append(&mut self, record: Record) -> Result<Seq, FoldError> {
        let seq = self.next;
        apply(&mut self.state, seq, self.now, &record)?;
        self.tail.push((seq, record));
        self.next = Seq::from_raw(seq.raw().saturating_add(1));
        Ok(seq)
    }

    /// The outcome notice record of `proposal`, appended as M6 would
    /// (`OutboxEnqueued(ProposalOutcome)`, the stricter reading of the design).
    pub(crate) fn notice(&mut self, proposal: ProposalId) -> Result<Seq, String> {
        self.append(Record::OutboxEnqueued(OutboxEvent::ProposalOutcome {
            proposal,
            state: StateTag::NotSelected,
        }))
        .map_err(|e| format!("notice: {e}"))
    }

    /// A context for `actor` through the web.
    pub(crate) fn ctx(&mut self, actor: fstp_domain::id::AccountId) -> Ctx {
        self.drawn = self.drawn.saturating_add(1);
        let mut id = [0u8; 16];
        let (head, tail) = id.split_at_mut(8);
        head.copy_from_slice(b"i37world");
        tail.copy_from_slice(&self.drawn.to_be_bytes());
        Ctx {
            now: self.now,
            actor: Actor::Account(actor),
            command: CommandId::from_bytes(id),
            via: Via::Web,
            tenant_admin: false,
            second_tenant_admin: None,
            binds_tenant_admin: false,
        }
    }

    /// Runs `cmd` by `actor`: production decides it, and its records fold
    /// at the next sequence numbers. A consent command asks the vault nothing.
    pub(crate) fn exec(
        &mut self,
        actor: fstp_domain::id::AccountId,
        cmd: Command,
    ) -> Result<Result<Vec<(Seq, Record)>, Refusal>, String> {
        let ctx = self.ctx(actor);
        match queries(&self.state, &cmd, &ctx) {
            Ok(q) if !q.is_empty() => return Err(format!("{cmd:?} asked the vault {q:?}")),
            Ok(_) => {}
            Err(r) => return Ok(Err(r)),
        }
        let records = match decide(&self.state, &cmd, &ctx, &Answers::new()) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        let mut out = Vec::new();
        for r in records {
            let seq = self
                .append(r.clone())
                .map_err(|e| format!("fold of {r:?}: {e}"))?;
            out.push((seq, r));
        }
        Ok(Ok(out))
    }

    /// The programme manager's request of consent on `proposal`.
    pub(crate) fn request(
        &mut self,
        proposal: ProposalId,
    ) -> Result<Result<Vec<(Seq, Record)>, Refusal>, String> {
        self.exec(STAFF_PM, Command::RequestCalibrationConsent { proposal })
    }

    /// The lead's consent on `proposal`.
    pub(crate) fn give(
        &mut self,
        proposal: ProposalId,
    ) -> Result<Result<Vec<(Seq, Record)>, Refusal>, String> {
        self.exec(
            lead_of(proposal),
            Command::GiveCalibrationConsent {
                proposal,
                wording: wording(),
            },
        )
    }

    /// The lead's revocation on `proposal`.
    pub(crate) fn revoke(
        &mut self,
        proposal: ProposalId,
    ) -> Result<Result<Vec<(Seq, Record)>, Refusal>, String> {
        self.exec(
            lead_of(proposal),
            Command::RevokeCalibrationConsent { proposal },
        )
    }
}

/// The ledger reading of I-37 for set membership: `proposal` has a
/// recorded consent in `tail` and no later revocation.
pub(crate) fn ledger_consented(tail: &[(Seq, Record)], proposal: ProposalId) -> Option<Seq> {
    let mut given = None;
    for (seq, r) in tail {
        match r {
            Record::CalibrationConsentGiven { proposal: p, .. } if *p == proposal => {
                given = Some(*seq);
            }
            Record::CalibrationConsentRevoked { proposal: p, .. } if *p == proposal => {
                given = None;
            }
            _ => {}
        }
    }
    given
}

/// The ledger reading of I-37 for requests: every request in `tail` names
/// the proposal's outcome notice, which sits at a strictly lower sequence
/// number. `Err` names the first request that breaks it.
pub(crate) fn requests_follow_notices(tail: &[(Seq, Record)]) -> Result<(), String> {
    for (seq, r) in tail {
        if let Record::CalibrationConsentRequested {
            proposal, notice, ..
        } = r
        {
            let found = tail.iter().any(|(s, n)| {
                *s == *notice
                    && s < seq
                    && matches!(
                        n,
                        Record::OutboxEnqueued(OutboxEvent::ProposalOutcome { proposal: p, .. })
                            if p == proposal
                    )
            });
            if !found {
                return Err(format!(
                    "I-37: the request at {seq:?} on {proposal:?} names no earlier outcome notice ({notice:?})"
                ));
            }
        }
    }
    Ok(())
}

/// One generated step of the I-37 sequences.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Act {
    /// The outcome notice record of the proposal is committed.
    Notice(ProposalId),
    /// The programme manager requests consent.
    Request(ProposalId),
    /// The lead gives consent.
    Give(ProposalId),
    /// The lead revokes consent.
    Revoke(ProposalId),
    /// A calibration run builds its set.
    Build,
}

/// A generated sequence of up to 24 steps over the three proposals.
pub(crate) fn acts(g: &mut fstp_prop::Gen) -> Vec<Act> {
    g.vec(0..=24, |g| {
        let p = g.pick(&LEADS).1;
        match g.weighted(&[2, 3, 3, 2, 2]) {
            0 => Act::Notice(p),
            1 => Act::Request(p),
            2 => Act::Give(p),
            3 => Act::Revoke(p),
            _ => Act::Build,
        }
    })
}

/// The test's own reading of one proposal's consent, kept beside production.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Ghost {
    /// The first outcome notice.
    pub notice: Option<Seq>,
    /// A request was recorded.
    pub requested: bool,
    /// A consent was recorded.
    pub given: bool,
    /// The consent was revoked.
    pub revoked: bool,
}

/// What one step did.
#[derive(Clone, Debug)]
pub(crate) enum Did {
    /// A command was accepted with these entries.
    Accepted(Vec<(Seq, Record)>),
    /// A command was refused.
    Refused(Refusal),
    /// A notice was appended, or a set was built.
    Other,
}

/// Runs `act` on `w`, compares production's verdict with the ghost reading
/// of R-LA-09, R-LA-10 and I-37, and updates the ghost.
pub(crate) fn step(
    w: &mut ConsentWorld,
    ghosts: &mut std::collections::BTreeMap<ProposalId, Ghost>,
    act: Act,
) -> Result<Did, String> {
    let (p, out) = match act {
        Act::Build => return Ok(Did::Other),
        Act::Notice(p) => {
            let seq = w.notice(p)?;
            let g = ghosts.entry(p).or_default();
            g.notice = g.notice.or(Some(seq));
            return Ok(Did::Other);
        }
        Act::Request(p) => (p, w.request(p)?),
        Act::Give(p) => (p, w.give(p)?),
        Act::Revoke(p) => (p, w.revoke(p)?),
    };
    let g = ghosts.entry(p).or_default();
    let legal = match act {
        Act::Request(_) => g.notice.is_some() && !g.requested,
        Act::Give(_) => g.requested && !g.given && !g.revoked,
        Act::Revoke(_) => g.given && !g.revoked,
        Act::Notice(_) | Act::Build => true,
    };
    match (legal, out) {
        (true, Ok(entries)) => {
            match act {
                Act::Request(_) => g.requested = true,
                Act::Give(_) => g.given = true,
                Act::Revoke(_) => g.revoked = true,
                Act::Notice(_) | Act::Build => {}
            }
            Ok(Did::Accepted(entries))
        }
        (false, Err(r)) => Ok(Did::Refused(r)),
        (true, Err(r)) => Err(format!("{act:?} is legal ({g:?}) but refused: {r}")),
        (false, Ok(e)) => Err(format!("{act:?} is illegal ({g:?}) but accepted: {e:?}")),
    }
}
