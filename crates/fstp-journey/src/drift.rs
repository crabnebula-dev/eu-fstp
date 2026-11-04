//! The drift check: a journey definition must equal the state machine (I-95, R-JV-02).
//!
//! [`drift`] builds the graph the domain core implies from a state list
//! and a transition table, normally `StateTag::ALL` and `TRANSITIONS`. It
//! compares that graph with a parsed definition in both directions:
//!
//! - every state is a node with the state's terminal flag, and every node
//!   is a state;
//! - every row other than withdrawal is one edge per source state, with id
//!   `T-<FROM>-<TO>`, the row's endpoints and the row's actor role key, and
//!   every edge is such a row;
//! - the withdrawal row is one rule with id `T-ANY-<TO>`, the row's target
//!   and actor. Its source states must equal the non-terminal nodes that
//!   GRANTED cannot reach through the definition's edges, GRANTED excluded.
//!
//! It also checks what ties copy to the graph: the graph name, each node's
//! kind and keys, and each edge's label key.
//!
//! Last, it checks that the definition names every side track of
//! `SPEC/12-journey-ui.md` section 9. The parser accepts only those five
//! names, each at most once. So a side track can be missing but never extra.
//!
//! Readings taken here, pending Daniel (`SPEC/12-journey-ui.md` section 5.3):
//!
//! - Actor role keys follow [`role_key`]. Section 5.3 fixes `applicant`,
//!   `assigned_reviewer` and `system`. The others are the snake case of the
//!   transitions table's actor column.
//! - Keys are `journey.node.<state>`, `journey.help.<state>` and
//!   `journey.edge.<from>_<to>`, in lower case
//!   (`docs/design/07-vocabulary-pack.md`).

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::roles::Role;
use fstp_domain::rules::{ActorRule, Row, StateTag, TRANSITIONS, TransitionRule};

use crate::definition::{Definition, NodeKind, SideTrack};

/// The graph name of the proposal definition.
pub const PROPOSAL_GRAPH: &str = "proposal";

/// The formal name of the state that bounds the withdrawal rule.
const GRANTED: &str = StateTag::Granted.spec_name();

/// The stable actor role key of a transition actor, or `None` for an actor
/// rule that no transition row uses.
pub const fn role_key(actor: ActorRule) -> Option<&'static str> {
    let key = match actor {
        ActorRule::Lead => "applicant",
        ActorRule::Holder(Role::FstpCoordinator) => "fstp_coordinator",
        ActorRule::Holder(Role::ProgrammeManager) => "programme_manager",
        ActorRule::SystemRecordedBy(Role::FstpCoordinator) => "system_recorded_by_fstp_coordinator",
        ActorRule::AssignedReviewers => "assigned_reviewer",
        ActorRule::System => "system",
        ActorRule::Committee => "committee",
        ActorRule::IrcMembers => "irc_members",
        ActorRule::IrcMember => "irc_member",
        ActorRule::LeadAndProgrammeManager => "applicant_and_programme_manager",
        _ => return None,
    };
    Some(key)
}

/// The edge id of a transition row: `T-<FROM>-<TO>`.
pub fn edge_id(from: StateTag, to: StateTag) -> String {
    format!("T-{}-{}", from.spec_name(), to.spec_name())
}

/// The id of an "any non-terminal state before GRANTED" rule: `T-ANY-<TO>`.
pub fn any_rule_id(to: StateTag) -> String {
    format!("T-ANY-{}", to.spec_name())
}

/// The label key of a node: `journey.node.<id>` in lower case.
pub fn node_label_key(id: &str) -> String {
    format!("journey.node.{}", id.to_ascii_lowercase())
}

/// The help key of a node: `journey.help.<id>` in lower case.
pub fn node_help_key(id: &str) -> String {
    format!("journey.help.{}", id.to_ascii_lowercase())
}

/// The label key of an edge: `journey.edge.<from>_<to>` in lower case.
pub fn edge_label_key(from: &str, to: &str) -> String {
    format!(
        "journey.edge.{}_{}",
        from.to_ascii_lowercase(),
        to.to_ascii_lowercase()
    )
}

/// An edge as the drift check compares it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeShape {
    /// The state it leaves.
    pub from: String,
    /// The state it reaches.
    pub to: String,
    /// The actor role key. `None` on the domain side for an actor without one.
    pub actor_role: Option<String>,
}

impl core::fmt::Display for EdgeShape {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let actor = self.actor_role.as_deref().unwrap_or("<no role key>");
        write!(f, "{} to {} by {actor}", self.from, self.to)
    }
}

/// An "any non-terminal state before GRANTED" rule as the drift check compares it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnyShape {
    /// The source states: the row's own on the domain side, derived from
    /// the graph on the definition side.
    pub from: BTreeSet<String>,
    /// The state it reaches.
    pub to: String,
    /// The actor role key. `None` on the domain side for an actor without one.
    pub actor_role: Option<String>,
}

impl core::fmt::Display for AnyShape {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let actor = self.actor_role.as_deref().unwrap_or("<no role key>");
        let from: Vec<&str> = self.from.iter().map(String::as_str).collect();
        write!(f, "{{{}}} to {} by {actor}", from.join(", "), self.to)
    }
}

/// One difference between the domain core and a definition.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Drift {
    /// The definition is not of the proposal graph.
    Graph(String),
    /// A domain state has no node.
    NodeMissing(String),
    /// A node names no domain state.
    NodeExtra(String),
    /// A node's terminal flag differs from the state's.
    NodeTerminal {
        /// The node id.
        id: String,
        /// The domain's flag.
        domain: bool,
    },
    /// A node's kind does not follow the state's terminal flag.
    NodeKind {
        /// The node id.
        id: String,
        /// The kind the state needs.
        domain: NodeKind,
    },
    /// A node's label or help key is not the one its id implies.
    NodeKeys(String),
    /// A domain row has no edge.
    EdgeMissing(String),
    /// An edge has no domain row.
    EdgeExtra(String),
    /// An edge's endpoints or actor differ from its row's.
    EdgeChanged {
        /// The edge id.
        id: String,
        /// The row's shape.
        domain: EdgeShape,
        /// The edge's shape.
        definition: EdgeShape,
    },
    /// An edge's label key is not the one its endpoints imply.
    EdgeLabelKey(String),
    /// The domain's withdrawal row has no rule.
    AnyRuleMissing(String),
    /// A rule has no domain row.
    AnyRuleExtra(String),
    /// A rule's target, actor or derived source states differ from the row's.
    AnyRuleChanged {
        /// The rule id.
        id: String,
        /// The row's shape.
        domain: AnyShape,
        /// The rule's shape, with derived source states.
        definition: AnyShape,
    },
    /// An id occurs more than once on the domain side, so edges cannot map
    /// one to one to rows.
    DomainDuplicate(String),
    /// A side track of section 9 is not in the definition.
    SideTrackMissing(String),
}

impl Drift {
    /// The node, edge or rule id the difference is about. For
    /// [`Drift::Graph`] it is the definition's graph name. For
    /// [`Drift::SideTrackMissing`] it is the side track name.
    pub fn id(&self) -> &str {
        match self {
            Drift::Graph(id)
            | Drift::NodeMissing(id)
            | Drift::NodeExtra(id)
            | Drift::NodeKeys(id)
            | Drift::EdgeMissing(id)
            | Drift::EdgeExtra(id)
            | Drift::EdgeLabelKey(id)
            | Drift::AnyRuleMissing(id)
            | Drift::AnyRuleExtra(id)
            | Drift::DomainDuplicate(id)
            | Drift::SideTrackMissing(id) => id,
            Drift::NodeTerminal { id, .. }
            | Drift::NodeKind { id, .. }
            | Drift::EdgeChanged { id, .. }
            | Drift::AnyRuleChanged { id, .. } => id,
        }
    }
}

impl core::fmt::Display for Drift {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Drift::Graph(name) => write!(f, "graph {name} is not {PROPOSAL_GRAPH}"),
            Drift::NodeMissing(id) => write!(f, "state {id} has no node"),
            Drift::NodeExtra(id) => write!(f, "node {id} names no domain state"),
            Drift::NodeTerminal { id, domain } => {
                write!(f, "node {id} terminal flag differs (domain {domain})")
            }
            Drift::NodeKind { id, domain } => {
                write!(f, "node {id} kind is not {}", domain.as_str())
            }
            Drift::NodeKeys(id) => write!(f, "node {id} label or help key differs"),
            Drift::EdgeMissing(id) => write!(f, "row {id} has no edge"),
            Drift::EdgeExtra(id) => write!(f, "edge {id} has no row"),
            Drift::EdgeChanged {
                id,
                domain,
                definition,
            } => write!(f, "edge {id} is {definition}, row is {domain}"),
            Drift::EdgeLabelKey(id) => write!(f, "edge {id} label key differs"),
            Drift::AnyRuleMissing(id) => write!(f, "withdrawal row {id} has no rule"),
            Drift::AnyRuleExtra(id) => write!(f, "rule {id} has no row"),
            Drift::AnyRuleChanged {
                id,
                domain,
                definition,
            } => write!(f, "rule {id} is {definition}, row is {domain}"),
            Drift::DomainDuplicate(id) => write!(f, "id {id} occurs twice in the table"),
            Drift::SideTrackMissing(id) => write!(f, "side track {id} is missing"),
        }
    }
}

/// The graph the domain side implies.
struct DomainGraph {
    nodes: BTreeMap<String, bool>,
    edges: BTreeMap<String, EdgeShape>,
    any_rules: BTreeMap<String, AnyShape>,
    duplicates: BTreeSet<String>,
}

impl DomainGraph {
    fn build(states: &[StateTag], table: &[TransitionRule]) -> DomainGraph {
        let mut g = DomainGraph {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            any_rules: BTreeMap::new(),
            duplicates: BTreeSet::new(),
        };
        for s in states {
            let name = s.spec_name().to_owned();
            if g.nodes.insert(name.clone(), s.is_terminal()).is_some() {
                g.duplicates.insert(name);
            }
        }
        for rule in table {
            let actor_role = role_key(rule.actor).map(str::to_owned);
            if rule.row == Row::Withdraw {
                let id = any_rule_id(rule.to);
                let shape = AnyShape {
                    from: rule.from.iter().map(|s| s.spec_name().to_owned()).collect(),
                    to: rule.to.spec_name().to_owned(),
                    actor_role,
                };
                g.add_any(id, shape);
            } else {
                for from in rule.from {
                    let shape = EdgeShape {
                        from: from.spec_name().to_owned(),
                        to: rule.to.spec_name().to_owned(),
                        actor_role: actor_role.clone(),
                    };
                    g.add_edge(edge_id(*from, rule.to), shape);
                }
            }
        }
        g
    }

    fn add_edge(&mut self, id: String, shape: EdgeShape) {
        if self.any_rules.contains_key(&id) || self.edges.insert(id.clone(), shape).is_some() {
            self.duplicates.insert(id);
        }
    }

    fn add_any(&mut self, id: String, shape: AnyShape) {
        if self.edges.contains_key(&id) || self.any_rules.insert(id.clone(), shape).is_some() {
            self.duplicates.insert(id);
        }
    }
}

/// The non-terminal nodes of `def` that GRANTED cannot reach through its
/// edges, GRANTED excluded: the sources of an "any non-terminal state
/// before GRANTED" rule.
pub fn before_granted(def: &Definition) -> BTreeSet<String> {
    let mut after = BTreeSet::from([GRANTED.to_owned()]);
    let mut queue = vec![GRANTED.to_owned()];
    while let Some(at) = queue.pop() {
        for e in def.edges() {
            if e.from == at && after.insert(e.to.clone()) {
                queue.push(e.to.clone());
            }
        }
    }
    def.nodes()
        .iter()
        .filter(|n| !n.terminal && !after.contains(&n.id))
        .map(|n| n.id.clone())
        .collect()
}

/// Every difference between the domain side and `def`, in a stable order.
/// An empty list means no drift.
pub fn drift(def: &Definition, states: &[StateTag], table: &[TransitionRule]) -> Vec<Drift> {
    let domain = DomainGraph::build(states, table);
    let mut out = Vec::new();

    if def.graph() != PROPOSAL_GRAPH {
        out.push(Drift::Graph(def.graph().to_owned()));
    }
    for id in &domain.duplicates {
        out.push(Drift::DomainDuplicate(id.clone()));
    }

    // Nodes, both directions.
    for (id, terminal) in &domain.nodes {
        let Some(node) = def.node(id) else {
            out.push(Drift::NodeMissing(id.clone()));
            continue;
        };
        if node.terminal != *terminal {
            out.push(Drift::NodeTerminal {
                id: id.clone(),
                domain: *terminal,
            });
        }
        let kind = if *terminal {
            NodeKind::Outcome
        } else {
            NodeKind::Stage
        };
        if node.kind != kind {
            out.push(Drift::NodeKind {
                id: id.clone(),
                domain: kind,
            });
        }
    }
    for node in def.nodes() {
        if !domain.nodes.contains_key(&node.id) {
            out.push(Drift::NodeExtra(node.id.clone()));
        }
        if node.label_key != node_label_key(&node.id) || node.help_key != node_help_key(&node.id) {
            out.push(Drift::NodeKeys(node.id.clone()));
        }
    }

    // Edges, both directions.
    let edges: BTreeMap<&str, EdgeShape> = def
        .edges()
        .iter()
        .map(|e| {
            let shape = EdgeShape {
                from: e.from.clone(),
                to: e.to.clone(),
                actor_role: Some(e.actor_role.clone()),
            };
            (e.id.as_str(), shape)
        })
        .collect();
    for (id, shape) in &domain.edges {
        match edges.get(id.as_str()) {
            None => out.push(Drift::EdgeMissing(id.clone())),
            Some(found) if found != shape => out.push(Drift::EdgeChanged {
                id: id.clone(),
                domain: shape.clone(),
                definition: found.clone(),
            }),
            Some(_) => {}
        }
    }
    for e in def.edges() {
        if !domain.edges.contains_key(&e.id) {
            out.push(Drift::EdgeExtra(e.id.clone()));
        }
        if e.label_key != edge_label_key(&e.from, &e.to) {
            out.push(Drift::EdgeLabelKey(e.id.clone()));
        }
    }

    // The "any non-terminal state before GRANTED" rules, both directions.
    let before = before_granted(def);
    let rules: BTreeMap<&str, AnyShape> = def
        .any_nonterminal_before_granted()
        .iter()
        .map(|r| {
            let shape = AnyShape {
                from: before.clone(),
                to: r.to.clone(),
                actor_role: Some(r.actor_role.clone()),
            };
            (r.id.as_str(), shape)
        })
        .collect();
    for (id, shape) in &domain.any_rules {
        match rules.get(id.as_str()) {
            None => out.push(Drift::AnyRuleMissing(id.clone())),
            Some(found) if found != shape => out.push(Drift::AnyRuleChanged {
                id: id.clone(),
                domain: shape.clone(),
                definition: found.clone(),
            }),
            Some(_) => {}
        }
    }
    for r in def.any_nonterminal_before_granted() {
        if !domain.any_rules.contains_key(&r.id) {
            out.push(Drift::AnyRuleExtra(r.id.clone()));
        }
    }

    // The side tracks of section 9.
    for track in SideTrack::ALL {
        if !def.side_tracks().contains(&track) {
            out.push(Drift::SideTrackMissing(track.as_str().to_owned()));
        }
    }

    out
}

/// Checks `def` against the domain core's `StateTag::ALL` and `TRANSITIONS`.
/// It fails with every difference when there is any.
pub fn check(def: &Definition) -> Result<(), Vec<Drift>> {
    let found = drift(def, &StateTag::ALL, TRANSITIONS);
    if found.is_empty() { Ok(()) } else { Err(found) }
}
