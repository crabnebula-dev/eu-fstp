//! A driver for the grantee choice commands of M9 lane P1 (R-PB-02,
//! I-41, I-42, I-43).
//!
//! The money references model no public choice, so [`ChoiceDriver`] runs
//! `SetPublicChoice` and `WithdrawPublicChoice` through production
//! `queries`, `decide` and `apply` on a copy of a production core state.
//! The records it folds are the real records. Each text reference names a
//! synthetic text id, which a test maps to a synthetic public text.

use std::collections::BTreeSet;

use fstp_domain::command::{Actor, Command, Ctx, Via};
use fstp_domain::id::{
    AccountId, CommandId, ContentDigest, DeliverableId, ProposalId, TextId, TextRef,
};
use fstp_domain::oracle::Answers;
use fstp_domain::publicity::{PublicLevel, PublicPhase};
use fstp_domain::record::Record;
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_domain::{State, apply, decide, queries};
use fstp_ledger::Seq;

/// The first sequence number the driver folds at. It lies above every
/// sequence number a generated world reaches.
const FIRST_SEQ: u64 = 1_000_000_000;

/// The synthetic title, summary and grantee text ids of `proposal`'s
/// choice for `phase`.
pub fn choice_text_ids(proposal: ProposalId, phase: PublicPhase) -> [TextId; 3] {
    let phase_offset: u128 = match phase {
        PublicPhase::Funded => 0,
        PublicPhase::Finished => 5,
    };
    let base = proposal
        .raw()
        .saturating_mul(10)
        .saturating_add(910_000)
        .saturating_add(phase_offset);
    [
        TextId::from_raw(base.saturating_add(1)),
        TextId::from_raw(base.saturating_add(2)),
        TextId::from_raw(base.saturating_add(3)),
    ]
}

/// The synthetic title, summary and grantee texts of `proposal`'s choice
/// for `phase`.
pub fn choice_texts(proposal: ProposalId, phase: PublicPhase) -> [String; 3] {
    let n = proposal.raw();
    let p = match phase {
        PublicPhase::Funded => "funded",
        PublicPhase::Finished => "finished",
    };
    [
        format!("Synthetic {p} title {n}"),
        format!("Synthetic {p} public summary {n}, written by the grantee."),
        format!("Synthetic Grantee Org {n}"),
    ]
}

/// The `SetPublicChoice` of `proposal` for `phase` at `level`, naming the
/// synthetic texts of [`choice_text_ids`].
pub fn set_choice(
    proposal: ProposalId,
    phase: PublicPhase,
    level: PublicLevel,
    deliverables: BTreeSet<DeliverableId>,
) -> Command {
    let [title, summary, grantee] = choice_text_ids(proposal, phase)
        .map(|id| TextRef::new(id, ContentDigest::from_bytes([9; 32])));
    Command::SetPublicChoice {
        proposal,
        phase,
        level,
        title,
        summary,
        grantee,
        deliverables,
    }
}

/// Runs publicity commands on a copy of a production core state.
#[derive(Clone, Debug)]
pub struct ChoiceDriver {
    /// The production core state, with every folded record.
    pub state: State,
    /// The instant of every command.
    pub now: Timestamp,
    next: u64,
    drawn: u64,
}

impl ChoiceDriver {
    /// A driver over a copy of `state` at `now`.
    pub fn new(state: &State, now: Timestamp) -> ChoiceDriver {
        ChoiceDriver {
            state: state.clone(),
            now,
            next: FIRST_SEQ,
            drawn: 0,
        }
    }

    fn ctx(&mut self, actor: AccountId) -> Ctx {
        self.drawn = self.drawn.saturating_add(1);
        let mut id = [0u8; 16];
        let (head, tail) = id.split_at_mut(8);
        head.copy_from_slice(b"publicty");
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

    /// Folds `record` as a stored log would, with no decision first. A
    /// filter test uses it to put choice records the commands refuse,
    /// such as one for a proposal that never reached GRANTED, in front of
    /// the public filter.
    pub fn fold(&mut self, record: &Record) -> Result<(), String> {
        let seq = Seq::from_raw(self.next);
        self.next = self.next.saturating_add(1);
        apply(&mut self.state, seq, self.now, record)
            .map_err(|e| format!("fold of {record:?}: {e}"))
    }

    /// Runs `cmd` by `actor`: production decides it and its records fold.
    /// The outer error names a defect of the driver or the fold.
    pub fn exec(
        &mut self,
        actor: AccountId,
        cmd: &Command,
    ) -> Result<Result<Vec<Record>, Refusal>, String> {
        let ctx = self.ctx(actor);
        match queries(&self.state, cmd, &ctx) {
            Ok(q) if !q.is_empty() => return Err(format!("{cmd:?} asked the vault {q:?}")),
            Ok(_) => {}
            Err(r) => return Ok(Err(r)),
        }
        let records = match decide(&self.state, cmd, &ctx, &Answers::new()) {
            Ok(r) => r,
            Err(r) => return Ok(Err(r)),
        };
        for r in &records {
            let seq = Seq::from_raw(self.next);
            self.next = self.next.saturating_add(1);
            apply(&mut self.state, seq, self.now, r).map_err(|e| format!("fold of {r:?}: {e}"))?;
        }
        Ok(Ok(records))
    }
}
