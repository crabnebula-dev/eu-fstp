//! Pending actions (I-85, design section 3.7).
//!
//! An MCP call that `channel_policy` answers with `Prepare` is stored as a
//! pending action with its canonical request and its [`ActionDigest`].
//! Only `pending.confirm` executes it, through the web, by the same
//! account, while it is open and unexpired, when the digest the user was
//! shown equals the stored one, and for high-risk kinds with a fresh
//! step-up proof for that digest. The confirmation replays the stored
//! request, never arguments resent by the browser.
//!
//! Rule A2: the confirmation runs inside `dispatch`. [`PendingAction`] and
//! its store are crate-private, so no public item here names `CellPorts`
//! or the principal. The designed `PendingAction::confirm` is the
//! crate-private confirmation step of `dispatch`.
//!
//! Interim readings, pending Daniel:
//!
//! - Pending actions expire after [`PENDING_LIFETIME_MICROS`], with no
//!   batch confirmation (Q25).
//! - The store is in memory in the API core until lane W6 moves it to
//!   `api.pending_actions`. A lost action fails closed: nothing executes,
//!   and the agent prepares it again. "At most once" is enforced by the
//!   engine port, which refuses a second execution naming the same
//!   pending action in the transaction of the append (design section
//!   4.3).
//! - Revoking the agent leaves its prepared actions confirmable by the
//!   user, who reviews each one in the platform.
//! - An expired action can no longer be discarded. It shows as expired.
//! - A confirmation claims its action before its first await. While it
//!   is claimed, a discard, an expiry mark and a second confirmation are
//!   refused. A refused confirmation releases the claim.
//! - The store is bounded per account and in time (see [`PendingStore`]).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::id::AccountId;
use fstp_domain::time::Timestamp;
use fstp_json::{Object, ToJson, Value};

use crate::ActionDigest;
use crate::port::{AgentClientId, PendingId};

/// How long a pending action stays confirmable, in microseconds.
///
/// Interim, pending Daniel (Q25): pending actions expire after 24 hours,
/// with no batch confirmation.
pub const PENDING_LIFETIME_MICROS: i64 = 86_400_000_000;

/// How long an ended action stays in the store, in microseconds.
///
/// Interim, pending lane W6: an action that was confirmed, discarded or
/// expired is listed for 7 days after it ended, then dropped.
pub const PENDING_RETENTION_MICROS: i64 = 7 * 86_400_000_000;

/// The most open actions one account holds (interim: 100). A further
/// preparation is refused until one closes or expires.
pub const OPEN_PER_ACCOUNT: usize = 100;

/// The most ended actions a preparation leaves its account (interim:
/// 100). The oldest are dropped first.
pub const ENDED_PER_ACCOUNT: usize = 100;

/// How often the retention sweep runs, in microseconds (interim: once a
/// minute).
pub(crate) const SWEEP_INTERVAL_MICROS: i64 = 60_000_000;

/// The status of a pending action, as `api.pending_actions` stores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PendingStatus {
    /// Awaiting a confirmation.
    Open,
    /// Executed by its one confirmation.
    Confirmed,
    /// Past its expiry without a confirmation.
    Expired,
    /// Discarded by the user.
    Discarded,
}

impl PendingStatus {
    /// The status as JSON spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            PendingStatus::Open => "open",
            PendingStatus::Confirmed => "confirmed",
            PendingStatus::Expired => "expired",
            PendingStatus::Discarded => "discarded",
        }
    }
}

/// What the agent receives for a prepared call:
/// `{status: "awaiting_confirmation", confirm_path, expires}`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingReceipt {
    /// The pending action.
    pub id: PendingId,
    /// The web path where the user confirms it.
    pub confirm_path: String,
    /// When it stops being confirmable.
    pub expires: Timestamp,
}

/// `{"id", "confirm_path", "expires"}`, with decimal strings.
impl ToJson for PendingReceipt {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", Value::String(self.id.raw().to_string()));
        let _ = o.insert("confirm_path", Value::from(self.confirm_path.as_str()));
        let _ = o.insert("expires", Value::String(self.expires.micros().to_string()));
        Value::Object(o)
    }
}

impl crate::McpSafe for PendingReceipt {}

/// The answer of a prepared action as an MCP tool result carries it in
/// `structuredContent.data` (I-85, lane W3c):
/// `{"status":"awaiting_confirmation","confirm_path","expires"}`, as the
/// web answers [`crate::OpResult::Pending`], except that `confirm_path`
/// names the platform page `/app/pending/{id}`. The agent holds no
/// session, so only the user can confirm there, with a step-up. It holds
/// nothing the user typed. Interim, pending Daniel: the web app builds
/// that page in a later lane, and the `/app/` shell serves the path now.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingAnswer(pub PendingReceipt);

/// The platform page where the user confirms pending action `id`.
pub(crate) fn confirm_page(id: PendingId) -> String {
    format!("/app/pending/{}", id.raw())
}

impl ToJson for PendingAnswer {
    fn to_json(&self) -> Value {
        let receipt = PendingReceipt {
            confirm_path: confirm_page(self.0.id),
            ..self.0.clone()
        };
        crate::OpResult::Pending(receipt).to_json()
    }
}

impl crate::McpSafe for PendingAnswer {}

/// One pending action as `pending.list` shows it to its own account.
/// It carries the full canonical rendering and the agent (TW-9).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingView {
    /// The pending action.
    pub id: PendingId,
    /// The agent client that prepared it.
    pub agent: AgentClientId,
    /// The operation name in the registry, such as `call.publish`.
    pub op: String,
    /// The canonical request JSON (RFC 8785) that a confirmation replays.
    pub request: String,
    /// The digest the step-up and the confirmation are bound to.
    pub digest: ActionDigest,
    /// When the agent prepared it.
    pub created: Timestamp,
    /// When it stops being confirmable.
    pub expires: Timestamp,
    /// Its status.
    pub status: PendingStatus,
}

/// The view as JSON. The request is carried as its canonical text, so
/// the user sees exactly what a confirmation executes. It is untrusted
/// user text (TW-9).
impl ToJson for PendingView {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        let _ = o.insert("id", Value::String(self.id.raw().to_string()));
        let _ = o.insert("agent", Value::String(self.agent.raw().to_string()));
        let _ = o.insert("op", Value::from(self.op.as_str()));
        let _ = o.insert("request", Value::from(self.request.as_str()));
        let _ = o.insert("digest", Value::String(self.digest.hex()));
        let _ = o.insert("created", Value::String(self.created.micros().to_string()));
        let _ = o.insert("expires", Value::String(self.expires.micros().to_string()));
        let _ = o.insert("status", Value::from(self.status.as_str()));
        let _ = o.insert("confirm_path", Value::String(confirm_path(self.id)));
        Value::Object(o)
    }
}

/// The web path that confirms `id`.
pub(crate) fn confirm_path(id: PendingId) -> String {
    format!("/api/v1/pending-actions/{}/confirmation", id.raw())
}

/// One stored pending action (design section 3.7).
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PendingAction {
    /// The id.
    pub(crate) id: PendingId,
    /// The account whose agent prepared it, the only one who confirms.
    pub(crate) account: AccountId,
    /// The agent client.
    pub(crate) agent: AgentClientId,
    /// The operation name.
    pub(crate) op: &'static str,
    /// The canonical pending request text, `{"op", "request"}`.
    pub(crate) request: String,
    /// The canonical request object alone, as the user sees it.
    pub(crate) shown: String,
    /// The digest.
    pub(crate) digest: ActionDigest,
    /// When it was prepared.
    pub(crate) created: Timestamp,
    /// When it stops being confirmable.
    pub(crate) expires: Timestamp,
    /// Its stored status. An open action past its expiry reads as
    /// expired.
    pub(crate) status: PendingStatus,
    /// When it was confirmed, discarded or marked expired.
    pub(crate) closed: Option<Timestamp>,
}

impl PendingAction {
    /// The status at `now`.
    pub(crate) fn status_at(&self, now: Timestamp) -> PendingStatus {
        if self.status == PendingStatus::Open && now >= self.expires {
            PendingStatus::Expired
        } else {
            self.status
        }
    }

    /// When it ended, at `now`: when it closed, or its expiry once that
    /// has passed. `None` while it is open.
    pub(crate) fn ended_at(&self, now: Timestamp) -> Option<Timestamp> {
        match self.status_at(now) {
            PendingStatus::Open => None,
            PendingStatus::Expired => Some(self.expires),
            PendingStatus::Confirmed | PendingStatus::Discarded => {
                Some(self.closed.unwrap_or(self.created))
            }
        }
    }

    /// The view at `now`.
    pub(crate) fn view(&self, now: Timestamp) -> PendingView {
        PendingView {
            id: self.id,
            agent: self.agent,
            op: self.op.to_owned(),
            request: self.shown.clone(),
            digest: self.digest,
            created: self.created,
            expires: self.expires,
            status: self.status_at(now),
        }
    }
}

/// The pending actions of one cell, by id.
///
/// Memory stays bounded (interim, until lane W6 moves the store to
/// `api.pending_actions`). A preparation is refused while its account
/// holds [`OPEN_PER_ACCOUNT`] open actions. It drops the account's oldest
/// ended actions beyond [`ENDED_PER_ACCOUNT`], so an account holds at most
/// the sum of both. An ended action is dropped
/// [`PENDING_RETENTION_MICROS`] after it ended. A dropped action is not
/// found, so it fails closed.
#[derive(Debug, Default)]
pub(crate) struct PendingStore {
    actions: BTreeMap<PendingId, PendingAction>,
    /// The ids of each account's actions.
    by_account: BTreeMap<AccountId, BTreeSet<PendingId>>,
    /// The actions a confirmation is executing. Nothing else closes them.
    claimed: BTreeSet<PendingId>,
    /// The earliest time of the next retention sweep.
    next_sweep: i64,
}

/// Why a new action was not stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InsertError {
    /// The id is taken.
    Taken,
    /// The account holds [`OPEN_PER_ACCOUNT`] open actions.
    Full,
}

impl PendingStore {
    /// Stores a new action at `now`. An id that is taken is refused, and
    /// so is an account at its open limit. The account's oldest ended
    /// actions beyond [`ENDED_PER_ACCOUNT`] are dropped.
    pub(crate) fn insert(&mut self, a: PendingAction, now: Timestamp) -> Result<(), InsertError> {
        self.sweep(now);
        if self.actions.contains_key(&a.id) {
            return Err(InsertError::Taken);
        }
        let mut open = 0usize;
        let mut ended: Vec<(Timestamp, PendingId)> = Vec::new();
        for id in self.by_account.get(&a.account).into_iter().flatten() {
            let Some(x) = self.actions.get(id) else {
                continue;
            };
            match x.ended_at(now) {
                None => open = open.saturating_add(1),
                Some(_) if self.claimed.contains(id) => {}
                Some(t) => ended.push((t, *id)),
            }
        }
        if open >= OPEN_PER_ACCOUNT {
            return Err(InsertError::Full);
        }
        ended.sort_unstable();
        let excess = ended.len().saturating_sub(ENDED_PER_ACCOUNT);
        for (_, id) in ended.into_iter().take(excess) {
            self.drop_action(id);
        }
        self.by_account.entry(a.account).or_default().insert(a.id);
        self.actions.insert(a.id, a);
        Ok(())
    }

    /// Removes `id` entirely, such as a preparation whose audit entry
    /// could not be written.
    pub(crate) fn remove(&mut self, id: PendingId) {
        self.claimed.remove(&id);
        self.drop_action(id);
    }

    fn drop_action(&mut self, id: PendingId) {
        if let Some(a) = self.actions.remove(&id)
            && let Some(ids) = self.by_account.get_mut(&a.account)
        {
            ids.remove(&id);
            if ids.is_empty() {
                self.by_account.remove(&a.account);
            }
        }
    }

    /// Drops every unclaimed action that ended more than
    /// [`PENDING_RETENTION_MICROS`] before `now`, at most once per
    /// [`SWEEP_INTERVAL_MICROS`].
    fn sweep(&mut self, now: Timestamp) {
        if now.micros() < self.next_sweep {
            return;
        }
        self.next_sweep = now.micros().saturating_add(SWEEP_INTERVAL_MICROS);
        let floor = now.micros().saturating_sub(PENDING_RETENTION_MICROS);
        let old: Vec<PendingId> = self
            .actions
            .values()
            .filter(|a| !self.claimed.contains(&a.id))
            .filter(|a| a.ended_at(now).is_some_and(|t| t.micros() <= floor))
            .map(|a| a.id)
            .collect();
        for id in old {
            self.drop_action(id);
        }
    }

    /// The action `id` of `account`. Another account's action is not
    /// found, so its existence is not disclosed.
    pub(crate) fn get(&self, id: PendingId, account: AccountId) -> Option<&PendingAction> {
        self.actions.get(&id).filter(|a| a.account == account)
    }

    /// Claims the open, unexpired action `id` of `account` for one
    /// confirmation. While it is claimed, no discard, expiry mark or
    /// second confirmation closes it. `false` when it is not open or is
    /// claimed already.
    pub(crate) fn claim(&mut self, id: PendingId, account: AccountId, now: Timestamp) -> bool {
        let open = self
            .get(id, account)
            .is_some_and(|a| a.status_at(now) == PendingStatus::Open);
        open && self.claimed.insert(id)
    }

    /// Releases a claim whose confirmation did not execute.
    pub(crate) fn release(&mut self, id: PendingId) {
        self.claimed.remove(&id);
    }

    /// Closes the claimed action `id` as confirmed at `now`.
    pub(crate) fn confirm(&mut self, id: PendingId, now: Timestamp) -> bool {
        if !self.claimed.remove(&id) {
            return false;
        }
        match self.actions.get_mut(&id) {
            Some(a) if a.status == PendingStatus::Open => {
                a.status = PendingStatus::Confirmed;
                a.closed = Some(now);
                true
            }
            _ => false,
        }
    }

    /// Sets the status of `id` at `now`, if it is open and unclaimed.
    pub(crate) fn close(&mut self, id: PendingId, to: PendingStatus, now: Timestamp) -> bool {
        if self.claimed.contains(&id) {
            return false;
        }
        match self.actions.get_mut(&id) {
            Some(a) if a.status == PendingStatus::Open => {
                a.status = to;
                a.closed = Some(now);
                true
            }
            _ => false,
        }
    }

    /// The views of `account`'s actions at `now`, in id order.
    pub(crate) fn list(&self, account: AccountId, now: Timestamp) -> Vec<PendingView> {
        self.by_account
            .get(&account)
            .into_iter()
            .flatten()
            .filter_map(|id| self.actions.get(id))
            .map(|a| a.view(now))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    fn action(id: u128, account: u128) -> PendingAction {
        PendingAction {
            id: PendingId::from_raw(id),
            account: AccountId::from_raw(account),
            agent: AgentClientId::from_raw(9),
            op: "call.publish",
            request: String::new(),
            shown: String::new(),
            digest: ActionDigest([1; 32]),
            created: Timestamp::from_micros(0),
            expires: Timestamp::from_micros(PENDING_LIFETIME_MICROS),
            status: PendingStatus::Open,
            closed: None,
        }
    }

    /// I-85: an action is found only by its own account, closes once, and
    /// reads as expired from its expiry on.
    #[test]
    fn i85_pending_store_is_per_account_and_closes_once() {
        let mut s = PendingStore::default();
        let t0 = Timestamp::from_micros(0);
        assert_eq!(s.insert(action(1, 7), t0), Ok(()));
        assert_eq!(s.insert(action(1, 8), t0), Err(InsertError::Taken));
        assert!(
            s.get(PendingId::from_raw(1), AccountId::from_raw(8))
                .is_none()
        );
        let a = s
            .get(PendingId::from_raw(1), AccountId::from_raw(7))
            .unwrap();
        let end = Timestamp::from_micros(PENDING_LIFETIME_MICROS);
        assert_eq!(
            a.status_at(Timestamp::from_micros(PENDING_LIFETIME_MICROS - 1)),
            PendingStatus::Open
        );
        assert_eq!(a.status_at(end), PendingStatus::Expired);
        assert!(s.close(PendingId::from_raw(1), PendingStatus::Confirmed, t0));
        assert!(!s.close(PendingId::from_raw(1), PendingStatus::Discarded, t0));
        assert_eq!(s.list(AccountId::from_raw(7), end).len(), 1);
        assert!(s.list(AccountId::from_raw(8), end).is_empty());
    }

    /// I-85: a claimed action is closed only by its confirmation. A
    /// discard, an expiry mark and a second claim during the confirmation
    /// are refused. A released claim leaves it open.
    #[test]
    fn i85_claimed_action_closes_only_by_its_confirmation() {
        let mut s = PendingStore::default();
        let t0 = Timestamp::from_micros(0);
        let id = PendingId::from_raw(1);
        let owner = AccountId::from_raw(7);
        assert_eq!(s.insert(action(1, 7), t0), Ok(()));
        assert!(!s.claim(id, AccountId::from_raw(8), t0), "another account");
        assert!(s.claim(id, owner, t0));
        assert!(!s.claim(id, owner, t0), "a second confirmation");
        assert!(!s.close(id, PendingStatus::Discarded, t0), "a discard");
        assert!(!s.close(id, PendingStatus::Expired, t0), "an expiry mark");
        s.release(id);
        assert!(!s.confirm(id, t0), "a released claim confirms nothing");
        assert_eq!(
            s.get(id, owner).map(|a| a.status),
            Some(PendingStatus::Open)
        );
        assert!(s.claim(id, owner, t0));
        assert!(s.confirm(id, t0));
        assert!(!s.close(id, PendingStatus::Discarded, t0));
        assert!(!s.claim(id, owner, t0), "a confirmed action");
        let late = Timestamp::from_micros(PENDING_LIFETIME_MICROS);
        assert_eq!(s.insert(action(2, 7), t0), Ok(()));
        assert!(
            !s.claim(PendingId::from_raw(2), owner, late),
            "an expired action"
        );
    }

    /// I-85, bounded memory: an account holds at most `OPEN_PER_ACCOUNT`
    /// open actions and `ENDED_PER_ACCOUNT` ended ones, and ended actions
    /// are dropped once their retention has passed.
    #[test]
    fn i85_pending_store_is_bounded_per_account_and_in_time() {
        let mut s = PendingStore::default();
        let t0 = Timestamp::from_micros(0);
        let owner = AccountId::from_raw(7);
        let cap = u128::try_from(OPEN_PER_ACCOUNT).unwrap();
        for i in 0..cap {
            assert_eq!(s.insert(action(i, 7), t0), Ok(()));
        }
        assert_eq!(s.insert(action(cap, 7), t0), Err(InsertError::Full));
        assert_eq!(s.insert(action(cap, 8), t0), Ok(()), "another account");
        for i in 0..cap {
            assert!(s.close(PendingId::from_raw(i), PendingStatus::Discarded, t0));
        }
        let extra = cap.saturating_add(1);
        for i in extra..extra.saturating_add(cap) {
            assert_eq!(s.insert(action(i, 7), t0), Ok(()));
        }
        let most = OPEN_PER_ACCOUNT.saturating_add(ENDED_PER_ACCOUNT);
        assert_eq!(s.list(owner, t0).len(), most);
        assert!(s.close(PendingId::from_raw(extra), PendingStatus::Discarded, t0));
        let next = extra.saturating_add(cap);
        assert_eq!(s.insert(action(next, 7), t0), Ok(()));
        assert_eq!(s.list(owner, t0).len(), most);
        assert!(
            s.get(PendingId::from_raw(0), owner).is_none(),
            "the oldest ended is dropped"
        );
        assert!(s.get(PendingId::from_raw(1), owner).is_some());
        let gone = Timestamp::from_micros(
            PENDING_LIFETIME_MICROS.saturating_add(PENDING_RETENTION_MICROS),
        );
        assert_eq!(s.insert(action(u128::MAX, 9), gone), Ok(()));
        assert!(
            s.list(owner, gone).is_empty(),
            "every ended action is dropped"
        );
        assert_eq!(s.list(AccountId::from_raw(9), gone).len(), 1);
    }
}
