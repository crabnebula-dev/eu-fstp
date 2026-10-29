//! The authorisation matrix generator (design section 8.3). Lane W3a owns
//! this file.
//!
//! The matrix is the product of operation, principal and state, expanded
//! by policy row and session. The operations are every entry of
//! `fstp_access::OPS` together with every operation of the independent
//! reference, so an operation missing on either side is reported. Cells
//! are produced lazily, since the full product holds millions.
//!
//! A cell exists only where its target and its principal can exist in the
//! state, as `reference::authz::{target_exists, feasible}` decide. Every
//! operation, principal and state cell that can exist is kept. Policy
//! rows follow the covering array of design section 8.3, and reads run
//! every P-10 value at each row. Web cells vary the login method for
//! account principals, and the step-up for high-risk operations. MCP
//! cells use a passkey-strength token, since a weaker session cannot
//! connect an agent (I-78). They run with and without the scope where the
//! operation has a scoped tool.
//!
//! A [`Channel`] runs one cell through the system and reports what it
//! observed. [`compare`] checks every cell against the reference in both
//! directions:
//!
//! - for `Deny(c)`, the system refuses with a rule that maps to `c`;
//! - for `Allow`, it completes or refuses with a rule outside
//!   authorisation, such as a transition guard;
//! - for `Pending`, it stores a pending action or refuses with such a
//!   rule in its dry run.
//!
//! A refusal whose rule maps to no class is a mismatch in every cell, so
//! an unknown rule never passes as "outside authorisation".

use std::collections::{BTreeMap, BTreeSet};

use crate::NotImplemented;
use crate::reference::authz::{
    AuthClass, AuthzReference, CellKey, Channel as Via, Expected, Login, P10, Policy, RefOp,
    Session, StateProfile, StepUp, Who, feasible, target_exists,
};

/// One cell of the matrix.
pub type Cell = CellKey;

/// The generated matrix of operations, principals and states.
#[derive(Debug)]
pub struct Matrix {
    reference: AuthzReference,
    ops: Vec<&'static str>,
    missing_from_ops: Vec<&'static str>,
    unknown_to_reference: Vec<&'static str>,
}

impl Matrix {
    /// Every operation the matrix covers, in name order.
    pub fn ops(&self) -> &[&'static str] {
        &self.ops
    }

    /// Reference operations that `OPS` lacks.
    pub fn missing_from_ops(&self) -> &[&'static str] {
        &self.missing_from_ops
    }

    /// `OPS` entries that the reference does not know. Their cells are
    /// unjudged, which fails the comparison.
    pub fn unknown_to_reference(&self) -> &[&'static str] {
        &self.unknown_to_reference
    }

    /// The reference this matrix was built against.
    pub fn reference(&self) -> &AuthzReference {
        &self.reference
    }

    /// Every cell, lazily, in a fixed order.
    pub fn cells(&self) -> impl Iterator<Item = Cell> + '_ {
        self.ops
            .iter()
            .filter_map(|name| self.reference.op(name).copied())
            .flat_map(op_cells)
    }
}

/// The policy rows of one operation: the covering array, and for reads
/// every P-10 value at each row.
fn policy_rows(op: &RefOp) -> Vec<Policy> {
    let rows = Policy::covering_rows();
    if !op.read {
        return rows.to_vec();
    }
    let mut set = BTreeSet::new();
    for row in rows {
        for p10 in [P10::AssignedOnly, P10::AllCommittee, P10::OperatorStaffOnly] {
            set.insert(Policy { p10, ..row });
        }
    }
    set.into_iter().collect()
}

/// The sessions of one operation and principal.
fn sessions(op: &RefOp, who: Who) -> Vec<Session> {
    let mut out = Vec::new();
    if !who.account() {
        out.push(Session {
            login: None,
            step_up: StepUp::Absent,
            channel: Via::Web,
        });
        if op.public {
            out.push(Session {
                login: None,
                step_up: StepUp::Absent,
                channel: Via::Mcp { scope: true },
            });
        }
        return out;
    }
    let steps: &[StepUp] = if op.high_risk {
        &[StepUp::Fresh, StepUp::Stale, StepUp::Absent]
    } else {
        &[StepUp::Absent]
    };
    for login in [Login::Passkey, Login::MagicLink, Login::Opaque] {
        for step_up in steps {
            out.push(Session {
                login: Some(login),
                step_up: *step_up,
                channel: Via::Web,
            });
        }
    }
    let scopes: &[bool] = match op.tool {
        Some(t) if t.scoped => &[true, false],
        _ => &[true],
    };
    for scope in scopes {
        out.push(Session {
            login: Some(Login::Passkey),
            step_up: StepUp::Absent,
            channel: Via::Mcp { scope: *scope },
        });
    }
    out
}

/// Every cell of one operation.
fn op_cells(op: RefOp) -> impl Iterator<Item = Cell> {
    let rows = policy_rows(&op);
    StateProfile::all()
        .into_iter()
        .filter(move |s| target_exists(op.target, *s))
        .flat_map(move |state| {
            let rows = rows.clone();
            Who::ALL
                .into_iter()
                .filter(move |w| feasible(*w, state))
                .flat_map(move |who| {
                    let rows = rows.clone();
                    let sessions = sessions(&op, who);
                    rows.into_iter().flat_map(move |policy| {
                        sessions.clone().into_iter().map(move |session| CellKey {
                            op: op.name,
                            who,
                            state,
                            policy,
                            session,
                        })
                    })
                })
        })
}

/// Builds the matrix over `registry`, the operation names of the system,
/// and the reference.
pub fn matrix_over(registry: &[&'static str], reference: AuthzReference) -> Matrix {
    let registry: BTreeSet<&'static str> = registry.iter().copied().collect();
    let known: BTreeSet<&'static str> = reference.ops().map(|o| o.name).collect();
    let missing_from_ops = known.difference(&registry).copied().collect();
    let unknown_to_reference = registry.difference(&known).copied().collect();
    let ops = registry.union(&known).copied().collect();
    Matrix {
        reference,
        ops,
        missing_from_ops,
        unknown_to_reference,
    }
}

/// Builds the `Matrix` over `fstp_access::OPS` and the reference. An empty
/// registry refuses, since a matrix over it would judge nothing of the
/// system.
pub fn matrix() -> Result<Matrix, NotImplemented> {
    let names: Vec<&'static str> = fstp_access::OPS.iter().map(|o| o.name).collect();
    if names.is_empty() {
        return Err(NotImplemented::new(
            "fstp_api_testkit::matrix::matrix: fstp_access::OPS is empty",
        ));
    }
    let reference = crate::reference::authz::authz_reference()?;
    Ok(matrix_over(&names, reference))
}

/// A channel denial that dispatch returns before the dry run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Denial {
    /// The operation has no tool.
    NotExposed,
    /// The token lacks the scope.
    Scope,
    /// P-74 refuses.
    P74,
}

/// What a channel observed for one cell.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Observed {
    /// The call completed.
    Completed,
    /// The call became a pending action.
    Pending,
    /// The call needs a step-up first (I-78).
    StepUpRequired,
    /// The account needs a phishing-resistant method first.
    StrongMethodRequired,
    /// `channel_policy` denied the call.
    ChannelDenied(Denial),
    /// A refusal with its rule text as `ApiError` carries it, such as
    /// `"I-03"`. `None` when the refusal names no rule.
    Refused(Option<String>),
}

/// Why a channel could not run a cell.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ChannelFault {
    /// The channel cannot build valid inputs for the cell.
    Setup(String),
    /// The operation is not reachable through this channel's adapter.
    UnknownOp(&'static str),
}

/// One way to run a cell through the system: dispatch directly, the HTTP
/// routes or the MCP handler (design section 8.3).
pub trait Channel {
    /// The channel's name, for reports.
    fn name(&self) -> &'static str;
    /// Runs the cell from a fresh state built for it and reports the
    /// outcome.
    fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault>;
}

/// The class of an observed outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservedClass {
    /// The call completed.
    Done,
    /// A pending action was stored.
    Pending,
    /// An authorisation refusal of this class.
    Auth(AuthClass),
    /// A refusal by a rule outside authorisation.
    Guard,
    /// A refusal whose rule maps to no class.
    Unmapped,
}

/// The rules whose refusals are authorisation refusals, by class. The
/// rule texts are the spec identifiers that `RuleRef::spec_id` and the
/// M4 additions name.
///
/// Readings: separation of duties, I-36 and the builder rule of I-67 bar
/// the actor. A refusal of a draft programme names I-66 (change D3), since
/// only activation lifts it. The non-spec `RuleRef::Actor` travels as
/// `"actor"`.
const AUTH_RULES: [(&str, AuthClass); 30] = [
    ("actor", AuthClass::Actor),
    ("I-01", AuthClass::Actor),
    ("I-02", AuthClass::Actor),
    ("I-04", AuthClass::Actor),
    ("I-05", AuthClass::Actor),
    ("I-06", AuthClass::Actor),
    ("I-36", AuthClass::Actor),
    ("I-65", AuthClass::Actor),
    ("I-67", AuthClass::Actor),
    ("SoD-01", AuthClass::Actor),
    ("SoD-02", AuthClass::Actor),
    ("SoD-03", AuthClass::Actor),
    ("SoD-04", AuthClass::Actor),
    ("SoD-05", AuthClass::Actor),
    ("SoD-06", AuthClass::Actor),
    ("SoD-07", AuthClass::Actor),
    ("SoD-09", AuthClass::Actor),
    ("SoD-12", AuthClass::Actor),
    ("R-PC-03", AuthClass::Actor),
    ("R-AC-01", AuthClass::Visibility),
    ("I-17", AuthClass::Visibility),
    ("I-21", AuthClass::Visibility),
    ("P-75", AuthClass::Visibility),
    ("R-IR-03", AuthClass::Visibility),
    ("I-03", AuthClass::Conflict),
    ("R-CF-02", AuthClass::Conflict),
    ("I-77", AuthClass::LoginStrength),
    ("I-78", AuthClass::StepUp),
    ("P-74", AuthClass::P74),
    ("I-66", AuthClass::Draft),
];

/// Rules whose refusals are guards outside authorisation: transition
/// guards, money, scoring, policy validation, the ledger and input
/// checks. SoD-10 and SoD-11 refuse an assignment for the reviewer's
/// organisation, which is the assignment's input, not the actor.
const GUARD_RULES: [&str; 47] = [
    "I-07",
    "I-08",
    "I-09",
    "I-10",
    "I-11",
    "I-12",
    "I-13",
    "I-14",
    "I-15",
    "I-18",
    "I-23",
    "I-34",
    "I-35",
    "I-50",
    "I-64",
    "SoD-10",
    "SoD-11",
    "R-PC-01",
    "R-PC-02",
    "R-SB-01",
    "R-SB-02",
    "R-SB-03",
    "R-SB-05",
    "R-EV-01",
    "R-EV-02",
    "R-EV-03",
    "R-EV-05",
    "R-EV-06",
    "R-EV-07",
    "R-EV-08",
    "R-EV-09",
    "R-IR-01",
    "R-IR-02",
    "R-IR-04",
    "R-NG-02",
    "R-NG-03",
    "R-NG-05",
    "R-NG-06",
    "R-CF-04",
    "R-AN-01",
    "R-LA-03",
    "R-LA-05",
    "R-EX-04",
    "Row",
    "Input",
    "FactsIncomplete",
    "StaleFacts",
];

/// The class of a refusal rule. Rules outside both tables, such as I-84,
/// I-85 and R-MC-05, are unmapped: dispatch must turn those calls into
/// pending actions or channel denials before the domain sees them.
pub fn class_of_rule(rule: &str) -> ObservedClass {
    if let Some((_, c)) = AUTH_RULES.iter().find(|(r, _)| *r == rule) {
        return ObservedClass::Auth(*c);
    }
    if GUARD_RULES.contains(&rule) {
        return ObservedClass::Guard;
    }
    // A parameter rule other than the P-10, P-74, P-75 and P-77 rules is a
    // policy guard, such as P-04 on an amount.
    if let Some(n) = rule.strip_prefix("P-")
        && n.len() == 2
        && n.bytes().all(|b| b.is_ascii_digit())
        && !matches!(n, "10" | "74" | "75" | "77")
    {
        return ObservedClass::Guard;
    }
    ObservedClass::Unmapped
}

/// The class of an observed outcome.
pub fn class_of(observed: &Observed) -> ObservedClass {
    match observed {
        Observed::Completed => ObservedClass::Done,
        Observed::Pending => ObservedClass::Pending,
        Observed::StepUpRequired => ObservedClass::Auth(AuthClass::StepUp),
        Observed::StrongMethodRequired => ObservedClass::Auth(AuthClass::LoginStrength),
        Observed::ChannelDenied(Denial::NotExposed) => ObservedClass::Auth(AuthClass::NotExposed),
        Observed::ChannelDenied(Denial::Scope) => ObservedClass::Auth(AuthClass::Scope),
        Observed::ChannelDenied(Denial::P74) => ObservedClass::Auth(AuthClass::P74),
        Observed::Refused(Some(rule)) => class_of_rule(rule),
        Observed::Refused(None) => ObservedClass::Unmapped,
    }
}

/// Whether an observed class agrees with the reference, both ways.
pub fn agrees(expected: Expected, observed: ObservedClass) -> bool {
    match expected {
        Expected::Allow => matches!(observed, ObservedClass::Done | ObservedClass::Guard),
        Expected::Pending => matches!(observed, ObservedClass::Pending | ObservedClass::Guard),
        Expected::Deny(c) => observed == ObservedClass::Auth(c),
    }
}

/// A part of the matrix: cell `i` belongs to shard `index` when
/// `i % count == index`. CI shards the matrix job this way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    /// This shard.
    pub index: u64,
    /// The number of shards, at least one.
    pub count: u64,
}

impl Shard {
    /// The whole matrix.
    pub const ALL: Shard = Shard { index: 0, count: 1 };

    /// The shard named by `FSTP_MATRIX_SHARD`, written `index/count`, or
    /// the whole matrix when it is unset. A malformed value refuses, so a
    /// typo never runs an empty shard.
    pub fn from_env() -> Result<Shard, String> {
        let Ok(text) = std::env::var("FSTP_MATRIX_SHARD") else {
            return Ok(Shard::ALL);
        };
        let bad = || format!("FSTP_MATRIX_SHARD={text:?} is not index/count");
        let (i, n) = text.split_once('/').ok_or_else(bad)?;
        let index: u64 = i.parse().map_err(|_| bad())?;
        let count: u64 = n.parse().map_err(|_| bad())?;
        if count == 0 || index >= count {
            return Err(bad());
        }
        Ok(Shard { index, count })
    }

    fn holds(self, i: u64) -> bool {
        i.checked_rem(self.count) == Some(self.index)
    }
}

/// One disagreement between the system and the reference.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Mismatch {
    /// The cell.
    pub cell: Cell,
    /// What the reference expects, or `None` when it does not judge.
    pub expected: Option<Expected>,
    /// What the channel observed, or the fault that stopped it.
    pub observed: Result<Observed, ChannelFault>,
}

/// The result of one comparison.
#[derive(Clone, Debug, Default)]
pub struct Comparison {
    /// Cells compared.
    pub cells: u64,
    /// Cells that disagreed, faulted or were unjudged.
    pub failures: u64,
    /// The first disagreements, at most [`Comparison::KEPT`].
    pub first: Vec<Mismatch>,
    /// Failures per operation.
    pub by_op: BTreeMap<&'static str, u64>,
}

impl Comparison {
    /// How many mismatches a comparison keeps for its report.
    pub const KEPT: usize = 40;

    /// Whether every cell agreed.
    pub fn clean(&self) -> bool {
        self.failures == 0 && self.cells > 0
    }

    fn fail(&mut self, m: Mismatch) {
        self.failures = self.failures.saturating_add(1);
        let n = self.by_op.entry(m.cell.op).or_insert(0);
        *n = n.saturating_add(1);
        if self.first.len() < Comparison::KEPT {
            self.first.push(m);
        }
    }
}

/// Runs every cell of `shard` through `channel` and compares each with
/// the reference of `m`, or with `reference` when one is given (the teeth
/// test passes a flipped one).
pub fn compare(
    m: &Matrix,
    reference: Option<&AuthzReference>,
    channel: &mut dyn Channel,
    shard: Shard,
) -> Comparison {
    let reference = reference.unwrap_or(&m.reference);
    let mut out = Comparison::default();
    for (i, cell) in (0u64..).zip(m.cells()) {
        if !shard.holds(i) {
            continue;
        }
        out.cells = out.cells.saturating_add(1);
        let expected = reference.expected(&cell);
        let observed = channel.observe(&cell);
        let ok = match (&expected, &observed) {
            (Some(e), Ok(o)) => agrees(*e, class_of(o)),
            _ => false,
        };
        if !ok {
            out.fail(Mismatch {
                cell,
                expected,
                observed,
            });
        }
    }
    // An operation the reference does not know has no cells at all, so it
    // fails here once.
    for name in &m.unknown_to_reference {
        out.fail(Mismatch {
            cell: CellKey {
                op: name,
                who: Who::Anonymous,
                state: StateProfile::ProgrammeActive,
                policy: Policy::SUPERSAFE,
                session: Session {
                    login: None,
                    step_up: StepUp::Absent,
                    channel: Via::Web,
                },
            },
            expected: None,
            observed: Err(ChannelFault::UnknownOp(name)),
        });
    }
    out
}

/// The direct channel: every cell through `ApiCore::dispatch` on the fake
/// cell of the three-channel harness.
///
/// Gap: lane W3b owns the harness, whose W0 stub refuses and offers no
/// direct channel yet. Once `crate::harness::Harness` implements
/// [`Channel`] for dispatch, this function returns it. Until then it
/// refuses, first with the harness's own refusal.
pub fn direct_channel() -> Result<Box<dyn Channel>, NotImplemented> {
    let _harness = crate::harness::harness()?;
    Err(NotImplemented::new(
        "fstp_api_testkit::matrix::direct_channel: the harness has no direct Channel yet",
    ))
}

#[cfg(test)]
mod tests {
    //! The matrix tests of design section 8.3 that lane W3a owns, and
    //! self-tests of the generator, the comparison and the reference.

    use super::*;
    use crate::reference::authz::{REFERENCE_OPS, authz_reference, expected as judge};
    use fstp_access::{OPS, OpKind, READ_RULES};
    use fstp_domain::StateTag;

    fn reference() -> AuthzReference {
        authz_reference().unwrap_or_else(|e| panic!("{e}"))
    }

    fn report(c: &Comparison) -> String {
        let mut s = format!(
            "{} of {} cells failed; by op {:?}\n",
            c.failures, c.cells, c.by_op
        );
        for m in &c.first {
            s.push_str(&format!(
                "  {} {:?} {:?} {:?} {:?}: expected {:?}, observed {:?}\n",
                m.cell.op,
                m.cell.who,
                m.cell.state,
                m.cell.session,
                m.cell.policy,
                m.expected,
                m.observed
            ));
        }
        s
    }

    /// An oracle channel that answers each cell as the reference expects,
    /// with one optional mutant answer.
    struct Oracle {
        reference: AuthzReference,
        mutant: Option<(Cell, Observed)>,
    }

    fn canonical(e: Expected) -> Observed {
        match e {
            Expected::Allow => Observed::Completed,
            Expected::Pending => Observed::Pending,
            Expected::Deny(c) => match c {
                AuthClass::Actor => Observed::Refused(Some("actor".into())),
                AuthClass::Visibility => Observed::Refused(Some("R-AC-01".into())),
                AuthClass::Conflict => Observed::Refused(Some("I-03".into())),
                AuthClass::Scope => Observed::ChannelDenied(Denial::Scope),
                AuthClass::P74 => Observed::ChannelDenied(Denial::P74),
                AuthClass::LoginStrength => Observed::StrongMethodRequired,
                AuthClass::StepUp => Observed::StepUpRequired,
                AuthClass::NotExposed => Observed::ChannelDenied(Denial::NotExposed),
                AuthClass::Draft => Observed::Refused(Some("I-66".into())),
            },
        }
    }

    impl Channel for Oracle {
        fn name(&self) -> &'static str {
            "oracle"
        }

        fn observe(&mut self, cell: &Cell) -> Result<Observed, ChannelFault> {
            if let Some((c, o)) = &self.mutant
                && c == cell
            {
                return Ok(o.clone());
            }
            self.reference
                .expected(cell)
                .map(canonical)
                .ok_or(ChannelFault::UnknownOp(cell.op))
        }
    }

    /// The reference catalogue as a registry, for the self-tests.
    fn reference_names() -> Vec<&'static str> {
        REFERENCE_OPS.iter().map(|o| o.name).collect()
    }

    fn small_matrix() -> Matrix {
        matrix_over(
            &[
                "call.publish",
                "review.read_content",
                "proposal.submit",
                "public.call",
            ],
            reference(),
        )
    }

    fn first_cell(m: &Matrix, want: impl Fn(Expected) -> bool) -> Cell {
        m.cells()
            .find(|c| m.reference().expected(c).is_some_and(&want))
            .unwrap_or_else(|| panic!("no such cell"))
    }

    /// Design section 8.3 `t_authz_matrix_direct`: every cell through
    /// `dispatch` equals the reference, both ways. The registry and the
    /// reference hold the same operations. Red until the registry, the
    /// API core and the harness's direct channel exist.
    #[test]
    fn t_authz_matrix_direct() {
        let m = matrix().unwrap_or_else(|e| panic!("{e}"));
        assert!(
            m.missing_from_ops().is_empty(),
            "reference operations OPS lacks: {:?}",
            m.missing_from_ops()
        );
        assert!(
            m.unknown_to_reference().is_empty(),
            "OPS entries the reference does not judge: {:?}",
            m.unknown_to_reference()
        );
        let shard = Shard::from_env().unwrap_or_else(|e| panic!("{e}"));
        let mut channel = direct_channel().unwrap_or_else(|e| panic!("{e}"));
        let c = compare(&m, None, channel.as_mut(), shard);
        assert!(c.clean(), "direct channel: {}", report(&c));
    }

    /// Design section 8.3 `t_authz_matrix_covers_every_rule`: every `OPS`
    /// entry, every `READ_RULES` row and every actor-rule row of a routed
    /// command kind appears at least once as allowed and once as denied.
    /// Red until the registry exists.
    #[test]
    fn t_authz_matrix_covers_every_rule() {
        let m = matrix().unwrap_or_else(|e| panic!("{e}"));
        assert!(!READ_RULES.is_empty(), "READ_RULES is empty");
        let mut seen: BTreeMap<&str, (bool, bool)> = BTreeMap::new();
        for cell in m.cells() {
            let Some(e) = m.reference().expected(&cell) else {
                continue;
            };
            let entry = seen.entry(cell.op).or_insert((false, false));
            match e {
                Expected::Allow | Expected::Pending => entry.0 = true,
                Expected::Deny(_) => entry.1 = true,
            }
        }
        let both = |name: &str| seen.get(name).copied() == Some((true, true));
        let ops: Vec<&str> = OPS.iter().map(|o| o.name).filter(|n| !both(n)).collect();
        assert!(
            ops.is_empty(),
            "OPS entries not both allowed and denied: {ops:?}"
        );
        for (kind, _, _) in READ_RULES {
            let named: Vec<&str> = OPS
                .iter()
                .filter(|o| o.kind == OpKind::Read(*kind))
                .map(|o| o.name)
                .collect();
            assert!(
                !named.is_empty() && named.iter().all(|n| both(n)),
                "READ_RULES row {kind:?}: {named:?}"
            );
        }
        for (kind, _) in fstp_domain::ACTOR_RULES {
            let named: Vec<&str> = OPS
                .iter()
                .filter(|o| o.kind == OpKind::Command(*kind))
                .map(|o| o.name)
                .collect();
            assert!(
                named.iter().all(|n| both(n)),
                "actor-rule row {kind:?}: {named:?}"
            );
        }
    }

    /// Design section 8.3 `t_authz_teeth_reference_flip_is_caught`:
    /// flipping one reference cell fails the comparison, in that cell only.
    /// The channel answers as the unflipped reference, so the comparison
    /// is clean before the flip.
    #[test]
    fn t_authz_teeth_reference_flip_is_caught() {
        let m = small_matrix();
        let mut oracle = Oracle {
            reference: reference(),
            mutant: None,
        };
        let clean = compare(&m, None, &mut oracle, Shard::ALL);
        assert!(clean.clean(), "unflipped: {}", report(&clean));
        for want_allowed in [true, false] {
            let cell = first_cell(&m, |e| matches!(e, Expected::Deny(_)) != want_allowed);
            let flipped = reference().with_flip(cell);
            let c = compare(&m, Some(&flipped), &mut oracle, Shard::ALL);
            assert_eq!(c.failures, 1, "flipped {cell:?}: {}", report(&c));
            assert_eq!(c.first.first().map(|x| x.cell), Some(cell));
        }
    }

    /// Design section 8.3, `t_authz_teeth_extra_cell_is_caught` at the
    /// comparison level: a channel that completes one denied cell fails.
    #[test]
    fn t_authz_teeth_channel_extra_cell_is_caught() {
        let m = small_matrix();
        let cell = first_cell(&m, |e| matches!(e, Expected::Deny(_)));
        let mut oracle = Oracle {
            reference: reference(),
            mutant: Some((cell, Observed::Completed)),
        };
        let c = compare(&m, None, &mut oracle, Shard::ALL);
        assert_eq!(c.failures, 1, "{}", report(&c));
    }

    /// Design section 8.3, `t_authz_teeth_missing_cell_is_caught` at the
    /// comparison level: a channel that refuses one allowed cell with an
    /// authorisation rule fails, and so does one that refuses it with an
    /// unmapped rule.
    #[test]
    fn t_authz_teeth_channel_missing_cell_is_caught() {
        let m = small_matrix();
        let cell = first_cell(&m, |e| e == Expected::Allow);
        for answer in [
            Observed::Refused(Some("I-03".into())),
            Observed::Refused(Some("I-85".into())),
            Observed::Refused(None),
            Observed::Pending,
        ] {
            let mut oracle = Oracle {
                reference: reference(),
                mutant: Some((cell, answer.clone())),
            };
            let c = compare(&m, None, &mut oracle, Shard::ALL);
            assert_eq!(c.failures, 1, "{answer:?}: {}", report(&c));
        }
    }

    /// Design section 8.3: a denial with the wrong class is a mismatch, so
    /// the two-way check compares classes, not only allow and deny.
    #[test]
    fn t_authz_teeth_wrong_denial_class_is_caught() {
        let m = small_matrix();
        let cell = first_cell(&m, |e| e == Expected::Deny(AuthClass::Actor));
        let mut oracle = Oracle {
            reference: reference(),
            mutant: Some((cell, Observed::Refused(Some("R-AC-01".into())))),
        };
        let c = compare(&m, None, &mut oracle, Shard::ALL);
        assert_eq!(c.failures, 1, "{}", report(&c));
    }

    /// Design section 8.3: an operation on one side only is reported, and
    /// a registry operation the reference does not know fails the
    /// comparison.
    #[test]
    fn t_authz_matrix_reports_ops_on_one_side() {
        let m = matrix_over(&["call.publish", "made.up"], reference());
        assert_eq!(m.unknown_to_reference(), ["made.up"]);
        assert!(m.missing_from_ops().contains(&"proposal.submit"));
        let mut oracle = Oracle {
            reference: reference(),
            mutant: None,
        };
        let c = compare(&m, None, &mut oracle, Shard::ALL);
        assert_eq!(c.by_op.get("made.up"), Some(&1), "{}", report(&c));
        assert_eq!(c.failures, 1);
    }

    /// Design section 8.3: shards partition the cells.
    #[test]
    fn t_authz_matrix_shards_partition_the_cells() {
        let m = small_matrix();
        let total = m.cells().count() as u64;
        let mut sum = 0u64;
        for index in 0..3 {
            let mut oracle = Oracle {
                reference: reference(),
                mutant: None,
            };
            let c = compare(&m, None, &mut oracle, Shard { index, count: 3 });
            assert!(c.clean());
            sum += c.cells;
        }
        assert_eq!(sum, total);
    }

    /// Design section 8.3: the 9 policy rows cover every pair of values of
    /// every two of P-10, P-74, P-11, P-28, P-75 and P-77, and row 0 is
    /// the SuperSAFE row.
    #[test]
    fn t_authz_policy_rows_cover_every_pair() {
        let rows = Policy::covering_rows();
        assert_eq!(rows[0], Policy::SUPERSAFE);
        let cols = |p: &Policy| -> [u8; 6] {
            [
                p.p10 as u8,
                p.p74 as u8,
                u8::from(p.p11_anonymous),
                u8::from(p.p28_on),
                u8::from(p.p75_on),
                u8::from(p.p77_draft_only),
            ]
        };
        let levels = [3u8, 3, 2, 2, 2, 2];
        for i in 0..6 {
            for j in (i + 1)..6 {
                let seen: BTreeSet<(u8, u8)> =
                    rows.iter().map(|r| (cols(r)[i], cols(r)[j])).collect();
                assert_eq!(
                    seen.len(),
                    usize::from(levels[i]) * usize::from(levels[j]),
                    "columns {i} and {j}"
                );
            }
        }
    }

    /// Design section 8.3: over the reference's own catalogue, every
    /// operation has at least one allowed and one denied cell, every
    /// principal and every state appears, and every class is produced.
    #[test]
    fn t_authz_reference_judges_every_op_both_ways() {
        let m = matrix_over(&reference_names(), reference());
        let mut seen: BTreeMap<&str, (bool, bool)> = BTreeMap::new();
        let mut whos = BTreeSet::new();
        let mut states = BTreeSet::new();
        let mut classes = BTreeSet::new();
        let mut n = 0u64;
        for cell in m.cells() {
            n += 1;
            let e = m
                .reference()
                .expected(&cell)
                .unwrap_or_else(|| panic!("{cell:?}"));
            let entry = seen.entry(cell.op).or_insert((false, false));
            match e {
                Expected::Allow | Expected::Pending => entry.0 = true,
                Expected::Deny(c) => {
                    entry.1 = true;
                    classes.insert(c);
                }
            }
            whos.insert(cell.who);
            states.insert(cell.state);
        }
        let one_sided: Vec<(&str, (bool, bool))> = seen
            .into_iter()
            .filter(|(_, v)| *v != (true, true))
            .collect();
        assert!(one_sided.is_empty(), "one-sided operations: {one_sided:?}");
        assert_eq!(whos.len(), Who::ALL.len(), "principals");
        assert_eq!(states.len(), StateProfile::all().len(), "states");
        assert_eq!(classes.len(), 9, "classes {classes:?}");
        assert!(n > 100_000, "only {n} cells");
    }

    fn web(login: Login, step_up: StepUp) -> Session {
        Session {
            login: Some(login),
            step_up,
            channel: Via::Web,
        }
    }

    fn mcp(scope: bool) -> Session {
        Session {
            login: Some(Login::Passkey),
            step_up: StepUp::Absent,
            channel: Via::Mcp { scope },
        }
    }

    fn at(op: &str, who: Who, state: StateProfile, policy: Policy, session: Session) -> Expected {
        let r = reference();
        let op = r.op(op).copied().unwrap_or_else(|| panic!("no {op}"));
        assert!(
            target_exists(op.target, state) && feasible(who, state),
            "infeasible"
        );
        judge(&op, who, state, &policy, &session)
    }

    const PASS: Session = Session {
        login: Some(Login::Passkey),
        step_up: StepUp::Absent,
        channel: Via::Web,
    };
    const S1: StateProfile = StateProfile::Proposal(StateTag::Stage1);
    const SS: Policy = Policy::SUPERSAFE;

    /// R-PC-03: a programme manager who drafted the call cannot approve
    /// its publication, and another programme manager can.
    #[test]
    fn r_pc_03_reference_drafter_cannot_approve() {
        let s = StateProfile::CallDrafted;
        assert_eq!(
            at("call.approve", Who::ProgrammeManagerDrafter, s, SS, PASS),
            Expected::Deny(AuthClass::Actor)
        );
        assert_eq!(
            at("call.approve", Who::ProgrammeManager, s, SS, PASS),
            Expected::Allow
        );
    }

    /// I-85, I-78: publishing through MCP becomes a pending action, and
    /// through the web it needs a fresh step-up.
    #[test]
    fn i85_reference_publication_prepares_through_mcp() {
        let s = StateProfile::CallApproved;
        let pm = Who::ProgrammeManager;
        assert_eq!(at("call.publish", pm, s, SS, mcp(true)), Expected::Pending);
        assert_eq!(
            at(
                "call.publish",
                pm,
                s,
                SS,
                web(Login::Passkey, StepUp::Stale)
            ),
            Expected::Deny(AuthClass::StepUp)
        );
        assert_eq!(
            at(
                "call.publish",
                pm,
                s,
                SS,
                web(Login::Passkey, StepUp::Fresh)
            ),
            Expected::Allow
        );
        assert_eq!(
            at("call.publish", Who::CallDrafter, s, SS, mcp(true)),
            Expected::Deny(AuthClass::Actor),
            "an agent prepares only what its user could do"
        );
    }

    /// I-77: a magic-link session of a reviewer is refused, and a
    /// magic-link session of a lead can submit.
    #[test]
    fn i77_reference_weak_sessions() {
        let s = StateProfile::Proposal(StateTag::Draft);
        let magic = web(Login::MagicLink, StepUp::Absent);
        assert_eq!(
            at("proposal.submit", Who::Lead, s, SS, magic),
            Expected::Allow
        );
        assert_eq!(
            at("review.score", Who::AssignedReviewer, S1, SS, magic),
            Expected::Deny(AuthClass::LoginStrength)
        );
        assert_eq!(
            at("agents.consent", Who::Lead, s, SS, magic),
            Expected::Deny(AuthClass::LoginStrength),
            "a magic-link session cannot connect an agent"
        );
    }

    /// R-AC-01, P-10 NOTE 1, O-43: content reads in STAGE1 under each P-10
    /// value.
    #[test]
    fn r_ac_01_reference_p10_options() {
        let with = |p10| Policy { p10, ..SS };
        let read = |who, p10| at("review.read_content", who, S1, with(p10), PASS);
        assert_eq!(
            read(Who::AssignedReviewer, P10::AssignedOnly),
            Expected::Allow
        );
        assert_eq!(
            read(Who::CommitteeMember, P10::AssignedOnly),
            Expected::Deny(AuthClass::Visibility)
        );
        assert_eq!(
            read(Who::CommitteeMember, P10::AllCommittee),
            Expected::Allow
        );
        assert_eq!(
            read(Who::AssignedReviewer, P10::OperatorStaffOnly),
            Expected::Deny(AuthClass::Visibility)
        );
        assert_eq!(
            read(Who::Coordinator, P10::OperatorStaffOnly),
            Expected::Allow
        );
        assert_eq!(
            read(Who::CoordinatorUndeclared, P10::OperatorStaffOnly),
            Expected::Deny(AuthClass::Conflict)
        );
    }

    /// I-03, R-CF-02: a conflicted or undeclared reviewer neither reads
    /// nor scores.
    #[test]
    fn i03_reference_conflicts_bar_reads_and_acts() {
        for who in [
            Who::AssignedReviewerConflicted,
            Who::AssignedReviewerUndeclared,
        ] {
            assert_eq!(
                at("review.read_content", who, S1, SS, PASS),
                Expected::Deny(AuthClass::Conflict)
            );
            assert_eq!(
                at("review.score", who, S1, SS, PASS),
                Expected::Deny(AuthClass::Conflict)
            );
        }
    }

    /// D6, P-75, I-84: through MCP with P-75 off, a reviewer's agent cannot
    /// read content, while the team reads its own proposal as on the web.
    #[test]
    fn i84_reference_p75_and_the_team_exception() {
        assert_eq!(
            at(
                "review.read_content",
                Who::AssignedReviewer,
                S1,
                SS,
                mcp(true)
            ),
            Expected::Deny(AuthClass::Visibility)
        );
        let on = Policy { p75_on: true, ..SS };
        assert_eq!(
            at(
                "review.read_content",
                Who::AssignedReviewer,
                S1,
                on,
                mcp(true)
            ),
            Expected::Allow
        );
        assert_eq!(
            at("proposal.view", Who::Lead, S1, SS, mcp(true)),
            Expected::Allow
        );
        assert_eq!(
            at("review.read_content", Who::Lead, S1, SS, mcp(true)),
            Expected::Allow
        );
    }

    /// Q39, D11: in RANKED and the terminal states only the team reads
    /// content.
    #[test]
    fn d11_reference_ranked_content_is_team_only() {
        for s in [StateTag::Ranked, StateTag::NotSelected, StateTag::Deferred] {
            let st = StateProfile::Proposal(s);
            assert_eq!(
                at("review.read_content", Who::AssignedReviewer, st, SS, PASS),
                Expected::Deny(AuthClass::Visibility)
            );
            assert_eq!(
                at("review.read_content", Who::TeamMember, st, SS, PASS),
                Expected::Allow
            );
        }
    }

    /// I-67, Q1: a builder admin cannot approve activation, a non-builder
    /// admin can, with a fresh step-up.
    #[test]
    fn i67_reference_builder_cannot_approve_activation() {
        let s = StateProfile::ProgrammeDraft;
        let fresh = web(Login::Passkey, StepUp::Fresh);
        assert_eq!(
            at(
                "creator.approve_activation",
                Who::TenantAdminBuilder,
                s,
                SS,
                fresh
            ),
            Expected::Deny(AuthClass::Actor)
        );
        assert_eq!(
            at("creator.approve_activation", Who::TenantAdmin, s, SS, fresh),
            Expected::Allow
        );
        assert_eq!(
            at(
                "creator.approve_activation",
                Who::TenantAdmin,
                s,
                SS,
                mcp(true)
            ),
            Expected::Deny(AuthClass::NotExposed)
        );
    }

    /// SoD-07, I-67, design section 8.3: a sole tenant admin walks every
    /// onboarding step and invites the second admin, but approves no
    /// self-grant, finishes no onboarding and approves no activation of the
    /// draft it opened. With a second admin, each is allowed.
    #[test]
    fn sod07_i67_reference_sole_admin_needs_a_second_admin() {
        use crate::reference::authz::OnboardStep;
        let fresh = web(Login::Passkey, StepUp::Fresh);
        let admins = StateProfile::Onboarding(OnboardStep::Administrators);
        let sole = Who::SoleTenantAdmin;
        for step in OnboardStep::ALL {
            let s = StateProfile::Onboarding(step);
            assert_eq!(at("tenant.get_step", sole, s, SS, PASS), Expected::Allow);
            assert_eq!(at("tenant.save_step", sole, s, SS, PASS), Expected::Allow);
        }
        assert_eq!(
            at("tenant.invite_admin", sole, admins, SS, fresh),
            Expected::Allow
        );
        for op in ["tenant.complete", "admin.approve_self_grant"] {
            assert_eq!(
                at(op, sole, admins, SS, fresh),
                Expected::Deny(AuthClass::Actor),
                "{op} with a sole admin"
            );
            assert_eq!(
                at(op, Who::TenantAdmin, admins, SS, fresh),
                Expected::Allow,
                "{op} with a second admin"
            );
        }
        assert_eq!(
            at(
                "creator.approve_activation",
                sole,
                StateProfile::ProgrammeDraft,
                SS,
                fresh
            ),
            Expected::Deny(AuthClass::Actor)
        );
        assert!(
            !feasible(sole, StateProfile::ProgrammeActive),
            "activation needs a second admin"
        );
        assert!(
            !feasible(Who::TenantAdminBuilder, admins),
            "no draft exists while the tenant onboards"
        );
    }

    /// R-AC-01, R-GA-01, I-87, D11: a call and its Guide are public only
    /// from publication. Before it, the reference judges the read and
    /// refuses anyone, with or without an account.
    #[test]
    fn r_ac_01_reference_unpublished_call_is_not_public() {
        let anon = Session {
            login: None,
            step_up: StepUp::Absent,
            channel: Via::Web,
        };
        for op in ["calls.get", "calls.guide"] {
            for s in [StateProfile::CallDrafted, StateProfile::CallApproved] {
                assert_eq!(
                    at(op, Who::Anonymous, s, SS, anon),
                    Expected::Deny(AuthClass::Visibility),
                    "{op} {s:?} anonymous"
                );
                assert_eq!(
                    at(
                        op,
                        Who::Lead,
                        StateProfile::Proposal(StateTag::Draft),
                        SS,
                        PASS
                    ),
                    Expected::Allow,
                    "{op} on a published call"
                );
                assert_eq!(
                    at(op, Who::ProgrammeManager, s, SS, PASS),
                    Expected::Deny(AuthClass::Visibility),
                    "{op} {s:?}: staff read the draft call through the board"
                );
            }
            assert_eq!(
                at(op, Who::Anonymous, StateProfile::CallOpen, SS, anon),
                Expected::Allow
            );
        }
    }

    /// D3: drafting a call on a draft programme is refused for the draft,
    /// after the actor rule.
    #[test]
    fn d3_reference_draft_programme_refuses_calls() {
        let s = StateProfile::ProgrammeDraft;
        assert_eq!(
            at("call.draft", Who::ProgrammeManager, s, SS, PASS),
            Expected::Deny(AuthClass::Draft)
        );
        assert_eq!(
            at("call.draft", Who::Unbound, s, SS, PASS),
            Expected::Deny(AuthClass::Actor)
        );
    }

    /// R-MC-05, P-77, P-74, Q42: a binding tool prepares under "draft
    /// only" and completes under "allowed"; a disabled MCP server and a
    /// Receiving-only limit refuse a reviewer; a token without the scope
    /// is refused.
    #[test]
    fn r_mc_05_reference_p77_p74_and_scope() {
        let r = Who::AssignedReviewer;
        assert_eq!(at("review.score", r, S1, SS, mcp(true)), Expected::Pending);
        let allowed = Policy {
            p77_draft_only: false,
            ..SS
        };
        assert_eq!(
            at("review.score", r, S1, allowed, mcp(true)),
            Expected::Allow
        );
        assert_eq!(
            at("review.score", r, S1, SS, mcp(false)),
            Expected::Deny(AuthClass::Scope)
        );
        let off = Policy {
            p74: crate::reference::authz::P74::Disabled,
            ..SS
        };
        assert_eq!(
            at("review.score", r, S1, off, mcp(true)),
            Expected::Deny(AuthClass::P74)
        );
        let lim = Policy {
            p74: crate::reference::authz::P74::ReceivingOnly,
            ..SS
        };
        assert_eq!(
            at("review.score", r, S1, lim, mcp(true)),
            Expected::Deny(AuthClass::P74)
        );
        let draft = StateProfile::Proposal(StateTag::Draft);
        assert_eq!(
            at("proposal.submit", Who::Lead, draft, lim, mcp(true)),
            Expected::Pending
        );
        assert_eq!(
            at("proposal.record_plan", Who::Lead, draft, lim, mcp(true)),
            Expected::Allow
        );
    }

    /// I-21, I-87: the workspace is the team's alone, and public pages
    /// admit anyone without a credential.
    #[test]
    fn i21_i87_reference_workspace_and_public() {
        let draft = StateProfile::Proposal(StateTag::Draft);
        assert_eq!(
            at("proposal.get_workspace", Who::TenantAdmin, draft, SS, PASS),
            Expected::Deny(AuthClass::Visibility)
        );
        assert_eq!(
            at("proposal.get_workspace", Who::TeamMember, draft, SS, PASS),
            Expected::Allow
        );
        let anon = Session {
            login: None,
            step_up: StepUp::Absent,
            channel: Via::Web,
        };
        assert_eq!(
            at(
                "public.call",
                Who::Anonymous,
                StateProfile::CallOpen,
                SS,
                anon
            ),
            Expected::Allow
        );
        assert_eq!(
            at(
                "proposal.list_own",
                Who::Anonymous,
                StateProfile::CallOpen,
                SS,
                anon
            ),
            Expected::Deny(AuthClass::Actor)
        );
        assert_eq!(
            at(
                "calls.list_open",
                Who::Anonymous,
                StateProfile::CallOpen,
                SS,
                anon
            ),
            Expected::Allow,
            "the open calls admit anyone"
        );
    }

    /// R-EV-09 NOTE, R-CF-02: a member with a conflict on a ranked
    /// proposal of the call recuses from its cut-off vote. A conflict on a
    /// proposal that was never ranked recuses nobody.
    #[test]
    fn r_ev_09_reference_recused_members_cannot_vote() {
        let ranked = StateProfile::Proposal(StateTag::Ranked);
        let cast = |who, st| at("committee.cast", who, st, SS, PASS);
        assert_eq!(
            cast(Who::RecusedCommitteeMember, ranked),
            Expected::Deny(AuthClass::Conflict)
        );
        assert_eq!(
            cast(Who::AssignedReviewerConflicted, ranked),
            Expected::Deny(AuthClass::Conflict)
        );
        assert_eq!(cast(Who::CommitteeMember, ranked), Expected::Allow);
        assert_eq!(cast(Who::CommitteeChair, ranked), Expected::Allow);
        assert_eq!(
            cast(Who::IrcMember, ranked),
            Expected::Deny(AuthClass::Actor)
        );
        let open = |who, st| at("committee.open_round", who, st, SS, PASS);
        assert_eq!(open(Who::AssignedReviewerConflicted, S1), Expected::Allow);
    }
}

#[cfg(test)]
mod read_rules_over_built_states {
    //! Tests of `fstp_access::authorize_read` and the principal over
    //! states built from genesis through production commands (design
    //! section 8.1). Written by the W3a production agent, beside the
    //! matrix, since `fstp-access` takes no dependency on the domain
    //! testkit. They check the rules the matrix reference judges, cell by
    //! cell, until the direct channel can run the whole matrix.

    use std::collections::BTreeSet;

    use fstp_access::{
        AgentClientId, DenyRule, GrantFacts, LoginMethod, Principal, ReadKind, ReadOp, ReadTarget,
        RoleOrApplicant, Scope, SessionFacts, SessionId, authorize_read, op, session_admits,
    };
    use fstp_domain::command::DeclarationSubject;
    use fstp_domain::id::{AccountId, ProgrammeId};
    use fstp_domain::policy::ReadAccess;
    use fstp_domain::roles::Role;
    use fstp_domain_testkit::r#gen::review::{
        COORDINATOR, DraftSpec, L1, PR1, R1, ReviewSetup, declare, machine_judges, review_truth,
        run_records, scenario_from,
    };
    use fstp_domain_testkit::r#gen::roster::{ADMIN, P1, STAFF_PM, SodSetup, T0, call};
    use fstp_domain_testkit::scenario::Scenario;
    use fstp_engine::EngineState;

    fn admins(set: &[AccountId]) -> BTreeSet<AccountId> {
        set.iter().copied().collect()
    }

    fn web(
        account: AccountId,
        method: LoginMethod,
        admin: &[AccountId],
        s: &EngineState,
    ) -> Principal {
        let facts = SessionFacts {
            account,
            session: SessionId::from_raw(1),
            method,
        };
        Principal::web(&facts, &admins(admin), s, T0)
    }

    fn mcp(account: AccountId, s: &EngineState) -> Principal {
        let grant = GrantFacts {
            account,
            agent: AgentClientId::from_raw(9),
            scopes: Scope::ALL.into_iter().collect(),
            consent_method: LoginMethod::Passkey,
        };
        Principal::mcp(&grant, &admins(&[]), s, T0).unwrap_or_else(|e| panic!("{e}"))
    }

    fn read(
        kind: ReadKind,
        target: ReadTarget,
        p: &Principal,
        s: &EngineState,
    ) -> Result<(), DenyRule> {
        authorize_read(&ReadOp { kind, target }, p, s, T0)
            .map(|_| ())
            .map_err(|d| d.rule())
    }

    /// A programme with one published call, the machine's Judging
    /// bindings and one submitted proposal PR1 led by L1.
    fn submitted() -> Scenario {
        let mut base = SodSetup::one(0, &[1]);
        base.published = vec![call(1)];
        let setup = ReviewSetup {
            base,
            p38: std::collections::BTreeMap::new(),
            p10: ReadAccess::AssignedReviewersOnly,
            judges: machine_judges(),
            drafts: vec![DraftSpec {
                lead: L1,
                proposal: PR1,
                call: call(1),
                team: Vec::new(),
                minor: false,
                submit: true,
            }],
        };
        scenario_from(&setup, review_truth(setup.accounts())).unwrap_or_else(|e| panic!("{e}"))
    }

    /// I-84, design section 3.6: roles come from the bindings active at
    /// the call's instant, and I-77 covers a committee member's account.
    #[test]
    fn i84_principal_roles_come_from_active_bindings() {
        let s = submitted();
        let st = s.state();
        let r1 = web(R1, LoginMethod::Passkey, &[], st);
        assert!(
            r1.roles()
                .contains(RoleOrApplicant::Role(Role::CommitteeMember))
        );
        assert!(!r1.roles().contains(RoleOrApplicant::Applicant));
        assert!(r1.holds_management_role());
        let lead = web(L1, LoginMethod::Passkey, &[], st);
        assert!(
            lead.roles()
                .contains(RoleOrApplicant::Role(Role::Applicant))
        );
        assert!(!lead.holds_management_role());
    }

    /// I-77: a weak session of a committee member is refused on every
    /// operation, and a phishing-resistant one is admitted.
    #[test]
    fn i77_weak_session_of_a_reviewer_is_refused() {
        let s = submitted();
        let st = s.state();
        let assignments = op("me.assignments").unwrap_or_else(|| panic!("no me.assignments"));
        let weak = web(R1, LoginMethod::MagicLink, &[], st);
        assert!(!session_admits(assignments, &weak));
        let strong = web(R1, LoginMethod::Passkey, &[], st);
        assert!(session_admits(assignments, &strong));
    }

    /// I-21: the workspace is the team's alone, and a refusal names I-21.
    #[test]
    fn i21_workspace_is_the_teams_alone() {
        let s = submitted();
        let st = s.state();
        let target = ReadTarget::Proposal(PR1);
        let lead = web(L1, LoginMethod::Passkey, &[], st);
        assert_eq!(read(ReadKind::GetOwnWorkspace, target, &lead, st), Ok(()));
        let admin = web(ADMIN, LoginMethod::Passkey, &[ADMIN], st);
        assert_eq!(
            read(ReadKind::GetOwnWorkspace, target, &admin, st),
            Err(DenyRule::I21)
        );
        let reviewer = web(R1, LoginMethod::Passkey, &[], st);
        assert_eq!(
            read(ReadKind::GetOwnWorkspace, target, &reviewer, st),
            Err(DenyRule::I21)
        );
    }

    /// R-AC-01, R-CF-02, I-03: in SUBMITTED the team reads its proposal, the
    /// coordinator reads only after declaring, and a committee member does
    /// not read at all.
    #[test]
    fn r_ac_01_submitted_content_needs_the_declared_coordinator() {
        let mut s = submitted();
        let target = ReadTarget::Proposal(PR1);
        {
            let st = s.state();
            let lead = web(L1, LoginMethod::Passkey, &[], st);
            assert_eq!(read(ReadKind::GetContent, target, &lead, st), Ok(()));
            let coordinator = web(COORDINATOR, LoginMethod::Passkey, &[], st);
            assert_eq!(
                read(ReadKind::GetContent, target, &coordinator, st),
                Err(DenyRule::Rcf02)
            );
            let reviewer = web(R1, LoginMethod::Passkey, &[], st);
            assert_eq!(
                read(ReadKind::GetContent, target, &reviewer, st),
                Err(DenyRule::Rac01)
            );
        }
        let step = declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false);
        run_records(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|r| panic!("declaration refused: {r}"));
        let st = s.state();
        let coordinator = web(COORDINATOR, LoginMethod::Passkey, &[], st);
        assert_eq!(read(ReadKind::GetContent, target, &coordinator, st), Ok(()));
    }

    /// D6, I-84: through MCP the team reads its own proposal whatever P-75
    /// says, and the coordinator's agent is refused under P-75 off.
    #[test]
    fn i84_mcp_team_reads_own_content_while_p75_bars_others() {
        let mut s = submitted();
        let step = declare(COORDINATOR, DeclarationSubject::Proposal(PR1), false, false);
        run_records(&mut s, &step, T0)
            .unwrap_or_else(|e| panic!("{e}"))
            .unwrap_or_else(|r| panic!("declaration refused: {r}"));
        let st = s.state();
        let target = ReadTarget::Proposal(PR1);
        let lead = mcp(L1, st);
        assert_eq!(read(ReadKind::GetContent, target, &lead, st), Ok(()));
        let coordinator = mcp(COORDINATOR, st);
        assert_eq!(
            read(ReadKind::GetContent, target, &coordinator, st),
            Err(DenyRule::P75)
        );
    }

    /// R-AC-01, R-GA-01, I-87: the public call and Guide reads clear a
    /// published call for anyone, and refuse a drafted, unpublished one
    /// with R-AC-01, as they refuse a call that does not exist.
    #[test]
    fn r_ac_01_public_call_reads_need_a_published_call() {
        let published = submitted();
        let st = published.state();
        let anyone = Principal::anonymous();
        for kind in [ReadKind::GetPublicCall, ReadKind::GetGuide] {
            assert_eq!(read(kind, ReadTarget::Call(call(1)), &anyone, st), Ok(()));
            assert_eq!(
                read(kind, ReadTarget::Call(call(9)), &anyone, st),
                Err(DenyRule::Rac01),
                "{kind:?} on an unknown call"
            );
        }
        let base = SodSetup::one(0, &[1]);
        let setup = ReviewSetup {
            base,
            p38: std::collections::BTreeMap::new(),
            p10: ReadAccess::AssignedReviewersOnly,
            judges: Vec::new(),
            drafts: Vec::new(),
        };
        let drafted =
            scenario_from(&setup, review_truth(setup.accounts())).unwrap_or_else(|e| panic!("{e}"));
        let st = drafted.state();
        let pm = web(STAFF_PM, LoginMethod::Passkey, &[], st);
        for kind in [ReadKind::GetPublicCall, ReadKind::GetGuide] {
            for p in [&anyone, &pm] {
                assert_eq!(
                    read(kind, ReadTarget::Call(call(1)), p, st),
                    Err(DenyRule::Rac01),
                    "{kind:?} on the unpublished call"
                );
            }
        }
    }

    /// D11, R-NG-06: the negotiation landing is closed outside NEGOTIATION,
    /// even to the team.
    #[test]
    fn d11_negotiation_landing_is_closed_outside_negotiation() {
        let s = submitted();
        let st = s.state();
        let lead = web(L1, LoginMethod::Passkey, &[], st);
        assert_eq!(
            read(
                ReadKind::GetNegotiationLanding,
                ReadTarget::Proposal(PR1),
                &lead,
                st
            ),
            Err(DenyRule::Rac01)
        );
    }

    /// R-CF-02, Q9: the coordinator sees the declaration view in SUBMITTED
    /// before declaring, and a committee member who is not assigned does not.
    #[test]
    fn r_cf_02_declaration_view_opens_before_the_declaration() {
        let s = submitted();
        let st = s.state();
        let target = ReadTarget::Proposal(PR1);
        let coordinator = web(COORDINATOR, LoginMethod::Passkey, &[], st);
        assert_eq!(
            read(ReadKind::GetDeclarationView, target, &coordinator, st),
            Ok(())
        );
        let reviewer = web(R1, LoginMethod::Passkey, &[], st);
        assert_eq!(
            read(ReadKind::GetDeclarationView, target, &reviewer, st),
            Err(DenyRule::Rac01)
        );
    }

    /// R-PG-01, I-65: the draft reads open to the programme's manager and to
    /// tenant admins, and to no Judging role.
    #[test]
    fn r_pg_01_draft_reads_open_to_managers_and_admins() {
        let s = submitted();
        let st = s.state();
        let target = ReadTarget::Programme(P1);
        let pm = web(STAFF_PM, LoginMethod::Passkey, &[], st);
        assert_eq!(read(ReadKind::GetDraft, target, &pm, st), Ok(()));
        let admin = web(ADMIN, LoginMethod::Passkey, &[ADMIN], st);
        assert_eq!(read(ReadKind::GetDraft, target, &admin, st), Ok(()));
        let reviewer = web(R1, LoginMethod::Passkey, &[], st);
        assert_eq!(
            read(ReadKind::GetDraft, target, &reviewer, st),
            Err(DenyRule::Rac01)
        );
        let elsewhere = ReadTarget::Programme(ProgrammeId::from_raw(4_242));
        assert_eq!(
            read(ReadKind::GetDraft, elsewhere, &pm, st),
            Err(DenyRule::Rac01),
            "a manager of P1 is no manager of another programme"
        );
    }

    /// I-84, I-85, R-MC-05, P-74: on every operation both sides know, the
    /// registry's flags equal the reference's: high-risk, read or act, the
    /// tool and whether it needs a scope, the acting roles, and binding
    /// wherever a tool makes P-77 bear on it. The matrix checks the same
    /// through dispatch once the direct channel exists.
    #[test]
    fn i84_registry_flags_equal_the_reference() {
        let reference =
            crate::reference::authz::authz_reference().unwrap_or_else(|e| panic!("{e}"));
        let mut compared = 0usize;
        for o in fstp_access::OPS {
            let Some(r) = reference.op(o.name) else {
                panic!("{} is unknown to the reference", o.name);
            };
            assert_eq!(o.high_risk, r.high_risk, "{} high_risk", o.name);
            let read = matches!(
                o.kind,
                fstp_access::OpKind::Read(_) | fstp_access::OpKind::Public(_)
            );
            assert_eq!(read, r.read, "{} read", o.name);
            assert_eq!(
                matches!(o.kind, fstp_access::OpKind::Public(_)),
                r.public,
                "{} public",
                o.name
            );
            assert_eq!(
                o.tool.map(|t| t.name),
                r.tool.map(|t| t.name),
                "{} tool",
                o.name
            );
            if let Some(t) = r.tool {
                assert_eq!(o.scope.is_some(), t.scoped, "{} scope", o.name);
                assert_eq!(o.binding, r.binding, "{} binding", o.name);
            }
            if !r.public {
                let want: BTreeSet<RoleOrApplicant> = r
                    .rule
                    .acting()
                    .iter()
                    .map(|x| x.map_or(RoleOrApplicant::Applicant, RoleOrApplicant::Role))
                    .collect();
                let got: BTreeSet<RoleOrApplicant> = o.acting.iter().copied().collect();
                assert_eq!(got, want, "{} acting", o.name);
            }
            compared += 1;
        }
        assert!(compared >= 117, "only {compared} operations compared");
    }
}
