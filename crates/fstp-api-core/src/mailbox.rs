//! The platform mailbox (lane m6/mailbox, `docs/handoff/mailbox-design.md`).
//!
//! `me.mailbox` lists the work and the notices the platform holds for the
//! caller. Each message is derived from state that already exists: the
//! engine state, the API core's journal and content projections, and the
//! pending store. No record, store or table is added. A work message is
//! computed again on every read, so it is gone once its action is done.
//!
//! A message carries ids, a kind, optional instants, a flag and a path
//! under `/app/` (I-27, I-86). It holds no title, text, score, name or
//! email. The page it links to runs its own read.
//!
//! This module holds the kinds, the route table and the view. The
//! derivation lives in `dispatch/mailbox.rs`, beside the reads it shares.

use fstp_access::ReadKind;
use fstp_domain::time::Timestamp;
use fstp_json::{Array, Object, ToJson, Value};

/// The kind of one message (design section 2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MailKind {
    /// An open pending action to confirm or discard (I-85).
    PendingConfirm,
    /// The lead's own draft in an open call.
    ProposalSubmit,
    /// The lead's proposal in STAGE2.
    Stage2Respond,
    /// The negotiation notice to acknowledge (R-NG-06).
    NegotiationAcknowledge,
    /// A reviewer assignment awaiting its declaration (R-CF-02).
    ReviewDeclare,
    /// An active reviewer assignment with no score for the current stage.
    ReviewScore,
    /// An IRC assignment awaiting its declaration (R-CF-02).
    IrcDeclare,
    /// An active IRC assignment with no review recorded (R-IR-01).
    IrcReview,
    /// A call with proposals awaiting their knock-out (R-EV-01).
    IntakeKnockOut,
    /// An open cut-off round the caller has not voted in (R-EV-08).
    RoundVote,
    /// A programme activation the caller may approve (I-67).
    AdminApproveActivation,
    /// A contract version the caller signs next (R-CT-02).
    ContractSign,
    /// A payment request under the caller's line review.
    PaymentReview,
    /// An accepted payment request for the finance approver.
    PaymentApprove,
    /// An approved payment request for the releaser (SoD-04, I-05).
    PaymentRelease,
    /// A released payment request to confirm as paid.
    PaymentConfirm,
    /// A proposal outcome notice (R-EV-04).
    NoticeOutcome,
    /// An IRC concern notice (R-IR-02).
    NoticeIrcConcern,
    /// An invitation the caller's existing account holds, not yet
    /// granted (MB-Q3, SoD-09).
    InvitationOpen,
    /// A role granted to the caller's existing account (MB-Q3).
    RoleGranted,
}

impl MailKind {
    /// Every kind, in the order the mailbox lists them.
    pub const ALL: [MailKind; 20] = [
        MailKind::PendingConfirm,
        MailKind::ContractSign,
        MailKind::PaymentReview,
        MailKind::PaymentApprove,
        MailKind::PaymentRelease,
        MailKind::PaymentConfirm,
        MailKind::AdminApproveActivation,
        MailKind::ProposalSubmit,
        MailKind::Stage2Respond,
        MailKind::NegotiationAcknowledge,
        MailKind::ReviewDeclare,
        MailKind::ReviewScore,
        MailKind::IrcDeclare,
        MailKind::IrcReview,
        MailKind::IntakeKnockOut,
        MailKind::RoundVote,
        MailKind::NoticeOutcome,
        MailKind::NoticeIrcConcern,
        MailKind::InvitationOpen,
        MailKind::RoleGranted,
    ];

    /// The kind as the wire spells it (`fstp_access::MAILBOX_KINDS`).
    pub const fn wire(self) -> &'static str {
        match self {
            MailKind::PendingConfirm => "pending.confirm",
            MailKind::ProposalSubmit => "proposal.submit",
            MailKind::Stage2Respond => "stage2.respond",
            MailKind::NegotiationAcknowledge => "negotiation.acknowledge",
            MailKind::ReviewDeclare => "review.declare",
            MailKind::ReviewScore => "review.score",
            MailKind::IrcDeclare => "irc.declare",
            MailKind::IrcReview => "irc.review",
            MailKind::IntakeKnockOut => "intake.knock_out",
            MailKind::RoundVote => "round.vote",
            MailKind::AdminApproveActivation => "admin.approve_activation",
            MailKind::ContractSign => "contract.sign",
            MailKind::PaymentReview => "payment.review",
            MailKind::PaymentApprove => "payment.approve",
            MailKind::PaymentRelease => "payment.release",
            MailKind::PaymentConfirm => "payment.confirm",
            MailKind::NoticeOutcome => "notice.outcome",
            MailKind::NoticeIrcConcern => "notice.irc_concern",
            MailKind::InvitationOpen => "invitation.open",
            MailKind::RoleGranted => "role.granted",
        }
    }

    /// Whether the caller must act. A notice is to read, and never closes
    /// (MB-D2).
    pub const fn action(self) -> bool {
        !matches!(
            self,
            MailKind::NoticeOutcome
                | MailKind::NoticeIrcConcern
                | MailKind::InvitationOpen
                | MailKind::RoleGranted
        )
    }

    /// The read behind the message's page. The mailbox keeps a message
    /// only when `authorize_read` admits the caller to it (design
    /// section 3, D11).
    pub const fn read(self) -> ReadKind {
        match self {
            MailKind::PendingConfirm => ReadKind::ListMyPendingActions,
            MailKind::ProposalSubmit => ReadKind::GetOwnWorkspace,
            MailKind::Stage2Respond => ReadKind::GetOwnStage2Thread,
            MailKind::NegotiationAcknowledge => ReadKind::GetNegotiationLanding,
            MailKind::ReviewDeclare | MailKind::IrcDeclare => ReadKind::ListMyAssignments,
            MailKind::ReviewScore => ReadKind::GetScoreSheet,
            MailKind::IrcReview => ReadKind::GetIrcCase,
            MailKind::IntakeKnockOut => ReadKind::GetIntakeQueue,
            MailKind::RoundVote => ReadKind::GetCutOffRound,
            MailKind::AdminApproveActivation => ReadKind::ListApprovals,
            MailKind::ContractSign => ReadKind::GetContract,
            MailKind::PaymentReview
            | MailKind::PaymentApprove
            | MailKind::PaymentRelease
            | MailKind::PaymentConfirm => ReadKind::ListMyPaymentQueue,
            MailKind::NoticeOutcome | MailKind::NoticeIrcConcern => ReadKind::GetOwnNotices,
            // MB-Q3: the home page lists the caller's own roles.
            MailKind::InvitationOpen | MailKind::RoleGranted => ReadKind::ListMyRoles,
        }
    }

    /// The route of the message's page, with `{name}` for each id.
    pub fn route(self) -> &'static str {
        MAILBOX_ROUTES
            .iter()
            .find(|(k, _)| *k == self)
            .map_or("/app/", |(_, r)| *r)
    }
}

/// The page of each kind (design section 4). Each `{name}` is filled from
/// the message's id of that name. The M5 pages mirror their API paths
/// (MB-D7).
pub const MAILBOX_ROUTES: &[(MailKind, &str)] = &[
    (MailKind::PendingConfirm, "/app/pending/{pending}"),
    (MailKind::ProposalSubmit, "/app/proposals/{proposal}/submit"),
    (MailKind::Stage2Respond, "/app/proposals/{proposal}/stage2"),
    (
        MailKind::NegotiationAcknowledge,
        "/app/proposals/{proposal}/negotiation",
    ),
    (MailKind::ReviewDeclare, "/app/assignments/{assignment}"),
    (MailKind::ReviewScore, "/app/assignments/{assignment}"),
    (MailKind::IrcDeclare, "/app/irc-assignments/{assignment}"),
    (MailKind::IrcReview, "/app/irc-assignments/{assignment}"),
    (MailKind::IntakeKnockOut, "/app/calls/{call}/intake"),
    (MailKind::RoundVote, "/app/cut-off-rounds/{round}"),
    (MailKind::AdminApproveActivation, "/app/admin/approvals"),
    (MailKind::ContractSign, "/app/grants/{proposal}/contract"),
    (MailKind::PaymentReview, "/app/operations"),
    (MailKind::PaymentApprove, "/app/operations"),
    (MailKind::PaymentRelease, "/app/operations"),
    (MailKind::PaymentConfirm, "/app/operations"),
    (MailKind::NoticeOutcome, "/app/notices"),
    (MailKind::NoticeIrcConcern, "/app/notices"),
    (MailKind::InvitationOpen, "/app/"),
    (MailKind::RoleGranted, "/app/"),
];

/// The ids a message names. Only those its page needs are set.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MailRefs {
    /// The proposal or grant.
    pub proposal: Option<u128>,
    /// The call.
    pub call: Option<u128>,
    /// The reviewer or IRC assignment.
    pub assignment: Option<u128>,
    /// The cut-off round.
    pub round: Option<u128>,
    /// The contract.
    pub contract: Option<u128>,
    /// The contract version, part of the id only.
    pub version: Option<u32>,
    /// The payment request.
    pub request: Option<u128>,
    /// The pending action.
    pub pending: Option<u128>,
    /// The programme.
    pub programme: Option<u128>,
    /// The ordinal of an unanswered stage 2 question in its thread, from 1
    /// (MB-Q2). Part of the id, and shown in the label.
    pub question: Option<u128>,
    /// The role binding a grant made (MB-Q3).
    pub binding: Option<u128>,
    /// The invitation (MB-Q3).
    pub invitation: Option<u128>,
}

impl MailRefs {
    /// The members as the wire names them, with their values.
    fn members(&self) -> [(&'static str, Option<u128>); 11] {
        [
            ("proposal", self.proposal),
            ("call", self.call),
            ("assignment", self.assignment),
            ("round", self.round),
            ("contract", self.contract),
            ("request", self.request),
            ("pending", self.pending),
            ("programme", self.programme),
            ("question", self.question),
            ("binding", self.binding),
            ("invitation", self.invitation),
        ]
    }

    fn get(&self, name: &str) -> Option<u128> {
        self.members()
            .into_iter()
            .find(|(n, _)| *n == name)
            .and_then(|(_, v)| v)
    }
}

/// The page of `kind` for `refs`: its route with every `{name}` filled.
/// `None` when an id the route names is missing, so no message links to
/// a page that cannot load.
pub fn href_of(kind: MailKind, refs: &MailRefs) -> Option<String> {
    let route = kind.route();
    let mut out = String::with_capacity(route.len().saturating_add(16));
    let mut rest = route;
    while let Some(open) = rest.find('{') {
        let (head, tail) = rest.split_at(open);
        out.push_str(head);
        let close = tail.find('}')?;
        let name = tail.get(1..close)?;
        out.push_str(&refs.get(name)?.to_string());
        rest = tail.get(close.saturating_add(1)..)?;
    }
    out.push_str(rest);
    Some(out)
}

/// One message (design section 1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MailItem {
    /// The kind.
    pub kind: MailKind,
    /// The ids.
    pub refs: MailRefs,
    /// When the work arrived, when the source holds it.
    pub since: Option<Timestamp>,
    /// When it is due or expires, when the source holds it.
    pub due: Option<Timestamp>,
    /// A notice's per-account read mark (MB-Q1, ADR-020). `None` for a
    /// work message, which closes itself instead.
    pub read: Option<bool>,
}

impl MailItem {
    /// A message of `kind` naming `refs`.
    pub fn new(kind: MailKind, refs: MailRefs) -> MailItem {
        MailItem {
            kind,
            refs,
            since: None,
            due: None,
            read: None,
        }
    }

    /// The stable id: the kind, then each id it names, in member order.
    pub fn id(&self) -> String {
        let mut s = self.kind.wire().to_owned();
        for (_, v) in self.refs.members() {
            if let Some(v) = v {
                s.push(':');
                s.push_str(&v.to_string());
            }
        }
        if let Some(v) = self.refs.version {
            s.push_str(":v");
            s.push_str(&v.to_string());
        }
        s
    }

    /// The page, or `None` when an id it needs is missing.
    pub fn href(&self) -> Option<String> {
        href_of(self.kind, &self.refs)
    }
}

impl ToJson for MailItem {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", Value::String(self.id()));
        let _ = o.insert("kind", Value::from(self.kind.wire()));
        let _ = o.insert("action", Value::Bool(self.kind.action()));
        let _ = o.insert(
            "href",
            Value::String(self.href().unwrap_or_else(|| "/app/".to_owned())),
        );
        if let Some(t) = self.since {
            let _ = o.insert("since", Value::String(t.micros().to_string()));
        }
        if let Some(t) = self.due {
            let _ = o.insert("due", Value::String(t.micros().to_string()));
        }
        if let Some(r) = self.read {
            let _ = o.insert("read", Value::Bool(r));
        }
        for (name, v) in self.refs.members() {
            if let Some(v) = v {
                let _ = o.insert(name, Value::String(v.to_string()));
            }
        }
        Value::Object(o)
    }
}

/// `me.mailbox`: the count of messages to act on, and every message.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MailboxView {
    /// The messages, work first, in [`MailKind::ALL`] order, then by id.
    pub messages: Vec<MailItem>,
}

impl MailboxView {
    /// A view of `messages`, ordered and without repeats. A message whose
    /// page cannot be built is left out.
    pub fn new(mut messages: Vec<MailItem>) -> MailboxView {
        messages.retain(|m| m.href().is_some());
        let rank = |k: MailKind| {
            MailKind::ALL
                .iter()
                .position(|x| *x == k)
                .unwrap_or(usize::MAX)
        };
        messages.sort_by(|a, b| {
            (!a.kind.action(), rank(a.kind), a.refs).cmp(&(!b.kind.action(), rank(b.kind), b.refs))
        });
        messages.dedup_by(|a, b| a.id() == b.id());
        MailboxView { messages }
    }

    /// The number of messages to act on.
    pub fn open(&self) -> usize {
        self.messages.iter().filter(|m| m.kind.action()).count()
    }
}

impl ToJson for MailboxView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let open = i64::try_from(self.open()).unwrap_or(i64::MAX);
        let _ = o.insert("open", Value::from(open));
        let mut list = Array::new();
        for m in &self.messages {
            list.push(m.to_json());
        }
        let _ = o.insert("messages", Value::Array(list));
        Value::Object(o)
    }
}

impl crate::McpSafe for MailboxView {}

/// The most read marks one account holds (ADR-020).
pub(crate) const MAX_MARKS_PER_ACCOUNT: usize = 4_096;

/// The most read marks this core holds in all (ADR-020).
pub(crate) const MAX_MARKS: usize = 1_000_000;

/// The per-account read marks of notices (MB-Q1, ADR-020, Proposed).
///
/// Each mark is a message id, which holds only a kind and decimal ids
/// (I-27, I-86). Interim, pending Daniel: the marks live in memory in the
/// API core, as the negotiation acknowledgement does (`content.rs`), until
/// lane W6 gives them a cell table.
#[derive(Debug, Default)]
pub(crate) struct ReadMarks {
    marks:
        std::collections::BTreeMap<fstp_domain::id::AccountId, std::collections::BTreeSet<String>>,
    total: usize,
}

impl ReadMarks {
    /// Marks `id` read for `account`. Idempotent. `false` when a bound is
    /// reached, and nothing is evicted.
    pub(crate) fn mark(&mut self, account: fstp_domain::id::AccountId, id: &str) -> bool {
        let set = self.marks.entry(account).or_default();
        if set.contains(id) {
            return true;
        }
        if set.len() >= MAX_MARKS_PER_ACCOUNT || self.total >= MAX_MARKS {
            return false;
        }
        set.insert(id.to_owned());
        self.total = self.total.saturating_add(1);
        true
    }

    /// Whether `account` marked `id` read.
    pub(crate) fn is_read(&self, account: fstp_domain::id::AccountId, id: &str) -> bool {
        self.marks.get(&account).is_some_and(|s| s.contains(id))
    }

    /// Sets the read mark of every notice of `view` for `account`. Work
    /// messages keep no mark (MB-D2).
    pub(crate) fn apply(&self, account: fstp_domain::id::AccountId, view: &mut MailboxView) {
        for m in &mut view.messages {
            m.read = (!m.kind.action()).then(|| self.is_read(account, &m.id()));
        }
    }
}

/// A view with one message of every kind and every member set, for the
/// reply shape check of `model.rs` (TH-26).
#[cfg(test)]
pub(crate) fn samples() -> MailboxView {
    let refs = MailRefs {
        proposal: Some(1),
        call: Some(2),
        assignment: Some(3),
        round: Some(4),
        contract: Some(5),
        version: Some(1),
        request: Some(6),
        pending: Some(7),
        programme: Some(8),
        question: Some(9),
        binding: Some(10),
        invitation: Some(11),
    };
    MailboxView::new(
        MailKind::ALL
            .iter()
            .map(|k| MailItem {
                kind: *k,
                refs,
                since: Some(Timestamp::from_micros(1)),
                due: Some(Timestamp::from_micros(2)),
                read: (!k.action()).then_some(false),
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn full() -> MailRefs {
        MailRefs {
            proposal: Some(11),
            call: Some(12),
            assignment: Some(13),
            round: Some(14),
            contract: Some(15),
            version: Some(2),
            request: Some(16),
            pending: Some(17),
            programme: Some(18),
            question: Some(19),
            binding: Some(20),
            invitation: Some(21),
        }
    }

    /// Design section 2: the kinds are exactly the wire kinds of the
    /// reply shape, each once, and each has one route and one read.
    #[test]
    fn i86_mailbox_kinds_match_the_reply_shape_and_each_has_one_route() {
        let wire: Vec<&str> = MailKind::ALL.iter().map(|k| k.wire()).collect();
        let mut sorted = wire.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(sorted.len(), wire.len());
        let mut shape: Vec<&str> = fstp_access::MAILBOX_KINDS.to_vec();
        shape.sort_unstable();
        assert_eq!(sorted, shape);
        for k in MailKind::ALL {
            assert_eq!(
                MAILBOX_ROUTES.iter().filter(|(x, _)| *x == k).count(),
                1,
                "{k:?}"
            );
            assert!(fstp_access::read_rule(k.read()).is_some(), "{k:?}");
        }
    }

    /// I-27, design section 4: every page is under `/app/`, holds only the
    /// filled ids, and a missing id builds no page.
    #[test]
    fn i27_mailbox_every_href_is_an_app_path_with_ids_only() {
        for k in MailKind::ALL {
            let h = href_of(k, &full()).unwrap();
            assert!(h.starts_with("/app/"), "{h}");
            assert!(!h.contains('{') && !h.contains('}'), "{h}");
            assert!(
                h.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"/-_".contains(&b)),
                "{h}"
            );
            if k.route().contains('{') {
                assert_eq!(href_of(k, &MailRefs::default()), None, "{k:?}");
            }
        }
        assert_eq!(
            href_of(MailKind::ContractSign, &full()).as_deref(),
            Some("/app/grants/11/contract")
        );
    }

    /// MB-D2: `open` counts the work messages only, notices are listed
    /// after the work, a repeat is dropped, and the id is stable.
    #[test]
    fn i27_mailbox_open_counts_work_only_and_ids_are_stable() {
        let refs = MailRefs {
            proposal: Some(5),
            ..MailRefs::default()
        };
        let v = MailboxView::new(vec![
            MailItem::new(MailKind::NoticeOutcome, refs),
            MailItem::new(MailKind::Stage2Respond, refs),
            MailItem::new(MailKind::Stage2Respond, refs),
            MailItem::new(MailKind::ReviewScore, MailRefs::default()),
        ]);
        assert_eq!(v.open(), 1);
        let kinds: Vec<MailKind> = v.messages.iter().map(|m| m.kind).collect();
        assert_eq!(kinds, [MailKind::Stage2Respond, MailKind::NoticeOutcome]);
        assert_eq!(v.messages[0].id(), "stage2.respond:5");
        let j = v.to_json();
        assert_eq!(j.get("open"), Some(&Value::from(1i64)));
    }

    /// I-27, I-86: a message carries only the members of the reply shape,
    /// every id as a decimal string.
    #[test]
    fn i27_i86_mailbox_message_members_are_ids_kinds_times_and_a_path() {
        let mut m = MailItem::new(MailKind::ContractSign, full());
        m.since = Some(Timestamp::from_micros(1));
        m.due = Some(Timestamp::from_micros(2));
        let j = m.to_json();
        let keys: Vec<&str> = j.as_object().unwrap().keys().collect();
        for k in &keys {
            assert!(
                [
                    "id",
                    "kind",
                    "action",
                    "href",
                    "since",
                    "due",
                    "proposal",
                    "call",
                    "assignment",
                    "round",
                    "contract",
                    "request",
                    "pending",
                    "programme",
                    "question",
                    "binding",
                    "invitation",
                    "read",
                ]
                .contains(k),
                "{k}"
            );
        }
        assert_eq!(j.get("proposal").and_then(Value::as_str), Some("11"));
    }

    /// MB-Q1, ADR-020, I-86: a mark is per account and idempotent, only
    /// notices carry it, and the per-account bound refuses without
    /// evicting.
    #[test]
    fn adr020_i86_read_marks_are_per_account_and_bounded() {
        let a = fstp_domain::id::AccountId::from_raw(1);
        let b = fstp_domain::id::AccountId::from_raw(2);
        let refs = MailRefs {
            proposal: Some(5),
            ..MailRefs::default()
        };
        let mut marks = ReadMarks::default();
        assert!(marks.mark(a, "notice.outcome:5"));
        assert!(marks.mark(a, "notice.outcome:5"));
        let mut v = MailboxView::new(vec![
            MailItem::new(MailKind::NoticeOutcome, refs),
            MailItem::new(MailKind::Stage2Respond, refs),
        ]);
        marks.apply(a, &mut v);
        let read: Vec<Option<bool>> = v.messages.iter().map(|m| m.read).collect();
        assert_eq!(read, [None, Some(true)]);
        marks.apply(b, &mut v);
        assert_eq!(v.messages[1].read, Some(false), "I-86: b's own marks");
        for n in 0..MAX_MARKS_PER_ACCOUNT {
            let _ = marks.mark(b, &format!("notice.outcome:{n}"));
        }
        assert!(!marks.mark(b, "notice.irc_concern:1"), "the bound");
        assert!(marks.is_read(b, "notice.outcome:0"), "nothing evicted");
        assert!(marks.mark(b, "notice.outcome:0"), "a repeat still answers");
    }
}
