//! The projection `State` (design section 2.14).
//!
//! - The projection holds current, decision-relevant facts only. Two
//!   histories that reach the same situation give equal projections, which
//!   keeps `fstp-mc` state spaces small. The ledger keeps every record.
//! - Each sub-state is defined in the module that owns it, so lanes never
//!   share a file. Their fields are crate-visible here so each lane's fold
//!   and guards reach their own part.
//! - `State` is `Clone + Eq + Hash + Debug` and never `Default`.
//! - Command-id deduplication lives in the store, not in the state.

use std::collections::{BTreeMap, BTreeSet};

use crate::assignment::ReviewState;
use crate::grant::MoneyState;
use crate::id::{
    AmendmentId, AssignmentId, BindingId, CallId, ContentDigest, DecisionId, DeliverableId, LineId,
    MilestoneId, PlanVersionId, PolicyVersionId, ProgrammeId, ProposalId, RequestId, TextId,
    VaultEpoch,
};
use crate::payment::PaymentState;
use crate::policy::PolicyState;
use crate::programme::CallState;
use crate::proposal::ProposalStore;
use crate::roles::RosterState;
use crate::time::Timestamp;

/// A shell-supplied id that a record has taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UsedId {
    /// A programme.
    Programme(ProgrammeId),
    /// A call.
    Call(CallId),
    /// A policy version.
    PolicyVersion(PolicyVersionId),
    /// A binding.
    Binding(BindingId),
    /// A proposal.
    Proposal(ProposalId),
    /// A plan version.
    PlanVersion(PlanVersionId),
    /// A milestone.
    Milestone(MilestoneId),
    /// A deliverable.
    Deliverable(DeliverableId),
    /// An assignment.
    Assignment(AssignmentId),
    /// A decision.
    Decision(DecisionId),
    /// An amendment.
    Amendment(AmendmentId),
    /// A payment request.
    Request(RequestId),
    /// A payment line.
    Line(LineId),
}

/// The shell-supplied ids already taken. `decide` refuses a reused id.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UsedIds {
    taken: BTreeSet<UsedId>,
}

impl UsedIds {
    /// Whether `id` is taken.
    pub fn contains(&self, id: UsedId) -> bool {
        self.taken.contains(&id)
    }

    /// Marks `id` as taken. Returns false if it already was.
    pub fn insert(&mut self, id: UsedId) -> bool {
        self.taken.insert(id)
    }

    /// The number of ids taken.
    pub fn len(&self) -> usize {
        self.taken.len()
    }

    /// Whether no id is taken.
    pub fn is_empty(&self) -> bool {
        self.taken.is_empty()
    }
}

/// Text references known to the ledger: ids and digests only, never text.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TextIndex {
    digests: BTreeMap<TextId, ContentDigest>,
}

impl TextIndex {
    /// The digest recorded for `id`.
    pub fn digest(&self, id: TextId) -> Option<ContentDigest> {
        self.digests.get(&id).copied()
    }

    /// Records the digest of `id`. Returns the earlier digest, if any.
    pub fn insert(&mut self, id: TextId, digest: ContentDigest) -> Option<ContentDigest> {
        self.digests.insert(id, digest)
    }
}

/// The projection that `decide` reads and `apply` folds records into.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct State {
    /// The latest recorded time. `decide` refuses an earlier `ctx.now`.
    pub(crate) now_floor: Timestamp,
    /// The last vault epoch processed.
    pub(crate) epoch: VaultEpoch,
    /// Shell-supplied ids already taken.
    pub(crate) used_ids: UsedIds,
    /// Lane L-POL: per programme head, versions referenced, last author per parameter.
    pub(crate) policy: PolicyState,
    /// Lane L-POL: calls.
    pub(crate) calls: CallState,
    /// Lane L-SOD: bindings and cooling-off bars.
    pub(crate) roster: RosterState,
    /// Lane L-REV: assignments, conflict facts, handles and reviewed-by facts.
    pub(crate) review: ReviewState,
    /// Lane L-LIFE: proposals.
    pub(crate) proposals: ProposalStore,
    /// Lane L-MONEY: granted and reserved sums, deliverable completeness.
    pub(crate) money: MoneyState,
    /// Lane L-MONEY: payment requests.
    pub(crate) payments: PaymentState,
    /// Lane L12-I37: calibration consent (I-37).
    pub(crate) calibration: crate::calibration::ConsentState,
    /// Lane M9 P1: grantee choices for the public pages (I-43).
    pub(crate) publicity: crate::publicity::PublicityState,
    /// Text ids and digests.
    pub(crate) texts: TextIndex,
}

impl State {
    /// The state before any record: time at the Unix epoch and vault epoch 0.
    pub fn genesis() -> State {
        State {
            now_floor: Timestamp::from_micros(0),
            epoch: VaultEpoch::GENESIS,
            used_ids: UsedIds {
                taken: BTreeSet::new(),
            },
            policy: PolicyState::genesis(),
            calls: CallState::genesis(),
            roster: RosterState::genesis(),
            review: ReviewState::genesis(),
            proposals: ProposalStore::genesis(),
            money: MoneyState::genesis(),
            payments: PaymentState::genesis(),
            calibration: crate::calibration::ConsentState::genesis(),
            publicity: crate::publicity::PublicityState::genesis(),
            texts: TextIndex {
                digests: BTreeMap::new(),
            },
        }
    }

    /// The latest recorded time.
    pub fn now_floor(&self) -> Timestamp {
        self.now_floor
    }

    /// The last vault epoch processed.
    pub fn epoch(&self) -> VaultEpoch {
        self.epoch
    }

    /// The ids already taken.
    pub fn used_ids(&self) -> &UsedIds {
        &self.used_ids
    }

    /// The policy part.
    pub fn policy(&self) -> &PolicyState {
        &self.policy
    }

    /// The call part.
    pub fn calls(&self) -> &CallState {
        &self.calls
    }

    /// The roster part.
    pub fn roster(&self) -> &RosterState {
        &self.roster
    }

    /// The review part.
    pub fn review(&self) -> &ReviewState {
        &self.review
    }

    /// The proposal part.
    pub fn proposals(&self) -> &ProposalStore {
        &self.proposals
    }

    /// The money part.
    pub fn money(&self) -> &MoneyState {
        &self.money
    }

    /// The payment part.
    pub fn payments(&self) -> &PaymentState {
        &self.payments
    }

    /// The publicity part: grantee choices for the public pages.
    pub fn publicity(&self) -> &crate::publicity::PublicityState {
        &self.publicity
    }

    /// The calibration consent part.
    pub fn calibration(&self) -> &crate::calibration::ConsentState {
        &self.calibration
    }

    /// The text index.
    pub fn texts(&self) -> &TextIndex {
        &self.texts
    }
}
