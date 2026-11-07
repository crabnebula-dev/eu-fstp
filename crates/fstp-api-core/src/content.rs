//! Proposal content beside the ledger: the private workspace, the content
//! frozen at submission, and the texts this core stored (I-21, R-CF-02,
//! Q9, design sections 2.2 J4 and 3.6).
//!
//! The domain holds no proposal text. A `RecordPlanVersion` carries the
//! digest of its plan text only, and a command names stored texts by
//! `TextRef`. So the read models that show a title, a neutral summary or
//! the proposal content read them here:
//!
//! - the **workspace** is the team's latest autosave of the form, by
//!   section (`proposal.save_workspace`, I-21);
//! - the **submitted content** is the workspace as it stood when the
//!   proposal's `Submit` appended. The Judging reads show it, never a
//!   later draft;
//! - the **texts** are the free texts this core stored through the text
//!   store, such as ranking summaries and stage 2 questions, by reference.
//!
//! # Fail closed
//!
//! The store holds a proposal's workspace only when this core created the
//! proposal or saved its workspace, since a save replaces every section.
//! Such a proposal is *known*. The workspace of an unknown proposal, the
//! content of a proposal frozen by no submission through this core, and a
//! text this core did not store all read as absent, and dispatch refuses
//! the read with `NotImplemented`. A restarted core, or a second process,
//! never shows an empty draft in place of a saved one.
//!
//! Interim readings, pending Daniel and the lead:
//!
//! - The store is memory of the cell process, as the pending actions are
//!   (`pending.rs`). Lane W6 moves the workspace to `workspace.drafts`,
//!   sealed through the M3 `Sealer`, and the frozen content to its own
//!   record. That needs a workspace port and a `ReadClearance` that
//!   dispatch can pass, which only the lead can add in `port.rs`.
//! - Sealing and reading back through the M3 ports need the clearance
//!   that `authorize_read` returns. `port.rs` still takes a W0 placeholder
//!   clearance that no module outside `port.rs` can build, so this store
//!   keeps the bytes it was given. Every read of it passes
//!   `authorize_read` first, in `dispatch`.
//! - The R-NG-06 acknowledgement is kept here only, so it is lost on a
//!   restart and leaves no audit record of its own. It belongs in a
//!   ledger or outbox record once its port exists (lane W6).
//! - A workspace has exactly the sections `title`, `summary` and
//!   `narrative`, each bounded by [`TITLE_LIMIT`], [`SUMMARY_LIMIT`] and
//!   [`crate::forms::TEXT_LIMIT`].

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::{AccountId, ProposalId, TextRef};

/// The longest title, in bytes (interim, pending Daniel).
pub(crate) const TITLE_LIMIT: usize = 300;

/// The longest neutral summary, in bytes (Q9 A, interim, pending Daniel).
pub(crate) const SUMMARY_LIMIT: usize = 1_200;

/// The most proposals whose content the store holds.
const MAX_PROPOSALS: usize = 100_000;

/// The most texts the store holds.
const MAX_TEXTS: usize = 1_000_000;

/// One proposal's form, by section.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Workspace {
    /// The title.
    pub(crate) title: String,
    /// The applicant-written neutral summary (Q9).
    pub(crate) summary: String,
    /// The narrative: the proposal content proper.
    pub(crate) narrative: String,
}

/// Why a save was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SaveError {
    /// A section is over its limit.
    TooLong,
    /// The store is full.
    Full,
}

/// The content store of one cell process.
#[derive(Debug, Default)]
pub(crate) struct ContentStore {
    known: BTreeSet<ProposalId>,
    workspace: BTreeMap<ProposalId, Workspace>,
    submitted: BTreeMap<ProposalId, Workspace>,
    texts: BTreeMap<u128, String>,
    acknowledged: BTreeSet<(AccountId, ProposalId)>,
}

impl ContentStore {
    /// Records that this core created `proposal`, whose workspace starts
    /// empty. A full store leaves it unknown, so its reads fail closed.
    pub(crate) fn created(&mut self, proposal: ProposalId) {
        if self.known.len() < MAX_PROPOSALS {
            self.known.insert(proposal);
        }
    }

    /// Replaces the workspace of `proposal` with `w`.
    pub(crate) fn save(&mut self, proposal: ProposalId, w: Workspace) -> Result<(), SaveError> {
        if w.title.len() > TITLE_LIMIT
            || w.summary.len() > SUMMARY_LIMIT
            || w.narrative.len() > crate::forms::TEXT_LIMIT
        {
            return Err(SaveError::TooLong);
        }
        let new = !self.known.contains(&proposal);
        if (new && self.known.len() >= MAX_PROPOSALS)
            || (!self.workspace.contains_key(&proposal) && self.workspace.len() >= MAX_PROPOSALS)
        {
            return Err(SaveError::Full);
        }
        self.known.insert(proposal);
        self.workspace.insert(proposal, w);
        Ok(())
    }

    /// The workspace of `proposal`: empty sections when this core created
    /// it and none was saved, `None` when the proposal is unknown.
    pub(crate) fn workspace(&self, proposal: ProposalId) -> Option<Workspace> {
        if !self.known.contains(&proposal) {
            return None;
        }
        Some(self.workspace.get(&proposal).cloned().unwrap_or_default())
    }

    /// Freezes the workspace of `proposal` as its submitted content. A
    /// second submission of the same proposal, after a re-entry, freezes
    /// the workspace again. An unknown workspace freezes nothing, and any
    /// earlier frozen content is dropped, so the Judging reads fail
    /// closed instead of showing stale content.
    pub(crate) fn freeze(&mut self, proposal: ProposalId) {
        let Some(w) = self.workspace(proposal) else {
            self.submitted.remove(&proposal);
            return;
        };
        if !self.submitted.contains_key(&proposal) && self.submitted.len() >= MAX_PROPOSALS {
            return;
        }
        self.submitted.insert(proposal, w);
    }

    /// The content `proposal` was submitted with, if it was submitted
    /// through this core.
    pub(crate) fn submitted(&self, proposal: ProposalId) -> Option<&Workspace> {
        self.submitted.get(&proposal)
    }

    /// The title of `proposal`: the submitted one, else the draft's, else
    /// `None` for an unknown proposal.
    pub(crate) fn title_of(&self, proposal: ProposalId) -> Option<String> {
        match self.submitted(proposal) {
            Some(w) => Some(w.title.clone()),
            None => self.workspace(proposal).map(|w| w.title),
        }
    }

    /// Records that `account` acknowledged the negotiation notice of
    /// `proposal` (R-NG-06). `false` when the store is full.
    pub(crate) fn acknowledge(&mut self, account: AccountId, proposal: ProposalId) -> bool {
        if self.acknowledged.contains(&(account, proposal)) || self.acknowledged.len() < MAX_TEXTS {
            self.acknowledged.insert((account, proposal));
            return true;
        }
        false
    }

    /// Whether `account` acknowledged the negotiation notice of `proposal`.
    pub(crate) fn acknowledged(&self, account: AccountId, proposal: ProposalId) -> bool {
        self.acknowledged.contains(&(account, proposal))
    }

    /// Remembers the text stored under `r`.
    pub(crate) fn remember(&mut self, r: TextRef, text: &str) {
        if self.texts.contains_key(&r.id().raw()) || self.texts.len() < MAX_TEXTS {
            self.texts.insert(r.id().raw(), text.to_owned());
        }
    }

    /// The text this core stored under `r`.
    pub(crate) fn text(&self, r: TextRef) -> Option<&str> {
        self.texts.get(&r.id().raw()).map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn w(title: &str) -> Workspace {
        Workspace {
            title: title.to_owned(),
            summary: "s".to_owned(),
            narrative: "n".to_owned(),
        }
    }

    /// R-CF-02, Q9: the content a Judging read shows is the one frozen at
    /// submission. A later save changes the workspace only.
    #[test]
    fn r_cf_02_submitted_content_is_frozen_at_submission() {
        let mut s = ContentStore::default();
        let p = ProposalId::from_raw(1);
        assert_eq!(s.save(p, w("first")), Ok(()));
        s.freeze(p);
        assert_eq!(s.save(p, w("second")), Ok(()));
        assert_eq!(s.submitted(p).map(|c| c.title.as_str()), Some("first"));
        assert_eq!(s.workspace(p).map(|c| c.title), Some("second".to_owned()));
        assert_eq!(s.submitted(ProposalId::from_raw(2)), None);
    }

    /// I-21, Q9: a section over its limit is refused and changes nothing.
    #[test]
    fn i21_save_refuses_a_section_over_its_limit() {
        let mut s = ContentStore::default();
        let p = ProposalId::from_raw(1);
        s.created(p);
        let long = "x".repeat(TITLE_LIMIT.saturating_add(1));
        assert_eq!(s.save(p, w(&long)), Err(SaveError::TooLong));
        assert_eq!(s.workspace(p), Some(Workspace::default()));
    }

    /// I-21: the workspace of a proposal this store neither created nor
    /// saved is unknown, never an empty draft, and freezing it freezes
    /// nothing.
    #[test]
    fn i21_an_unknown_workspace_is_absent() {
        let mut s = ContentStore::default();
        let p = ProposalId::from_raw(1);
        assert_eq!(s.workspace(p), None);
        assert_eq!(s.title_of(p), None);
        s.freeze(p);
        assert_eq!(s.submitted(p), None);
    }
}
