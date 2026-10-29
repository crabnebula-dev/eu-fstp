//! The holdings rule of I-77 and I-79 (design section 8.2, ADR-008
//! "Methods in M3", m3-base re-derivation 2).
//!
//! A holding is a Drafting, Judging or Operations binding, or a tenant
//! admin grant. Active, scheduled and suspended bindings count, and
//! voided bindings do not. A binding with an end counts until that
//! instant, and not at it.
//!
//! The M2 roster's `Binding::held` drops a binding under a
//! conflict-of-interest suspension (rule I-06). This rule counts it, the
//! stricter reading, so it reads the binding status itself.
//!
//! Reading, shared with the W1b reference: a binding counts from its
//! grant, even when its start lies later. [`BindingFact`] has no start.
//! This is the stricter reading for I-77 and I-79, since a holder then
//! needs a passkey before the start. It is interim, pending Daniel,
//! together with the Q16 session rule that reads the same end instants
//! ([`crate::session::admit_session_at`]).

use fstp_domain::id::AccountId;
use fstp_domain::roles::{BindingStatus, Group, Role, RosterState};
use fstp_domain::time::Timestamp;

use crate::{RosterView, TenantView};

/// Whether a binding of `role` is a management holding: any group but
/// Receiving.
pub const fn is_management_role(role: Role) -> bool {
    !matches!(role.group(), Group::Receiving)
}

/// One role binding as the holdings rule reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BindingFact {
    /// The account.
    pub account: AccountId,
    /// The role.
    pub role: Role,
    /// The end instant, recorded or scheduled. The binding holds before it.
    pub end: Option<Timestamp>,
    /// Whether the binding is suspended. A suspended binding still holds.
    pub suspended: bool,
    /// Whether the binding is voided. A voided binding never holds.
    pub voided: bool,
}

impl BindingFact {
    /// Whether the binding is a management holding at `now`.
    pub fn holds_at(&self, now: Timestamp) -> bool {
        !self.voided && is_management_role(self.role) && before_end(self.end, now)
    }
}

/// One tenant admin grant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AdminGrant {
    /// The account.
    pub account: AccountId,
    /// The end instant, if the grant ended or its end is scheduled. It
    /// holds before it.
    pub end: Option<Timestamp>,
}

/// Whether an interval that ends at `end` still holds at `now`.
fn before_end(end: Option<Timestamp>, now: Timestamp) -> bool {
    end.is_none_or(|e| now.micros() < e.micros())
}

fn sorted(mut v: Vec<AccountId>) -> Vec<AccountId> {
    v.sort();
    v.dedup();
    v
}

impl RosterView {
    /// The accounts that hold a management binding at `now`, by the rule
    /// of design section 8.2. Sorted, without duplicates.
    pub fn at(bindings: &[BindingFact], now: Timestamp) -> RosterView {
        RosterView {
            management: sorted(
                bindings
                    .iter()
                    .filter(|b| b.holds_at(now))
                    .map(|b| b.account)
                    .collect(),
            ),
        }
    }

    /// The facts of every held or voided binding of the M2 roster. An
    /// ended binding has left the roster, so it is not listed.
    ///
    /// A scheduled end is the binding's end instant. Every suspension is
    /// marked suspended, and it still holds: this does not read
    /// `Binding::held`, which drops a conflict-of-interest suspension.
    pub fn facts(roster: &RosterState) -> Vec<BindingFact> {
        roster
            .bindings()
            .map(|(_, b)| BindingFact {
                account: b.account,
                role: b.role,
                end: b.scheduled_end,
                suspended: matches!(b.status, BindingStatus::Suspended(_)),
                voided: matches!(b.status, BindingStatus::Voided(_)),
            })
            .collect()
    }

    /// The view of the M2 roster at `now` ([`RosterView::facts`], then
    /// [`RosterView::at`]).
    pub fn from_roster(roster: &RosterState, now: Timestamp) -> RosterView {
        RosterView::at(&RosterView::facts(roster), now)
    }
}

impl TenantView {
    /// The tenant admins at `now`. Sorted, without duplicates.
    pub fn at(grants: &[AdminGrant], now: Timestamp) -> TenantView {
        TenantView {
            admins: sorted(
                grants
                    .iter()
                    .filter(|g| before_end(g.end, now))
                    .map(|g| g.account)
                    .collect(),
            ),
        }
    }

    /// Whether `a` is a tenant admin in the view.
    pub fn is_admin(&self, a: AccountId) -> bool {
        self.admins.contains(&a)
    }

    /// The number of distinct tenant admins in the view other than `a`.
    pub fn others(&self, a: AccountId) -> usize {
        let mut v: Vec<AccountId> = self.admins.iter().copied().filter(|x| *x != a).collect();
        v.sort();
        v.dedup();
        v.len()
    }
}
