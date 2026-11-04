//! Independent reference for the journey graph drift test (I-95, R-JV-02, R-JV-01).
//!
//! Written from `SPEC/12-journey-ui.md` sections 5.1 to 5.3 and 13,
//! ADR-015 and `docs/design/07-vocabulary-pack.md`. It shares only the
//! domain core's state and transition types with production code. It
//! reads a journey definition as a plain `fstp_json::Value`, never through
//! the production parser.
//!
//! - [`Graph::from_domain`] builds the graph the definition must equal from
//!   a state list and a transition table, normally `StateTag::ALL` and
//!   `TRANSITIONS`. Tests pass mutated copies to check the other direction.
//! - [`Graph::from_definition`] reads the graph out of a definition value.
//! - [`diff`] lists every difference. An empty list means no drift.
//! - [`definition_mutations`] and [`domain_mutations`] are the teeth: each
//!   changes one side only, and the drift check must name what changed.
//! - [`generated_definition`] builds a section 5.3 definition from the
//!   domain table, so the reference's own teeth run without a shipped file.
//!
//! Readings taken here, pending Daniel:
//!
//! - Edge ids are `T-<FROM>-<TO>` over the formal state names, as the
//!   section 5.3 example shows. The withdrawal rule is `T-ANY-<TO>`.
//! - Label keys are `journey.node.<state>`, `journey.help.<state>` and
//!   `journey.edge.<from>_<to>`, in lower case (`07-vocabulary-pack.md`).
//! - Actor role keys follow [`role_key`]. Section 5.3 fixes three of them:
//!   `applicant`, `assigned_reviewer` and `system`. The others are the
//!   snake case of the actor column, and each actor rule keeps its own key.
//! - "Before GRANTED" means a non-terminal node that GRANTED cannot reach
//!   through the definition's edges, GRANTED itself excluded.
//! - The shipped file lives at [`DEFINITION_PATH`], under the journey crate.

use std::collections::{BTreeMap, BTreeSet};

use fstp_domain::roles::Role;
use fstp_domain::rules::{ActorRule, Row, StateTag, TransitionRule};
use fstp_json::{Array, Object, Value};

/// The shipped proposal definition, relative to the repository root.
pub const DEFINITION_PATH: &str = "crates/fstp-journey/definitions/proposal.v1.json";

/// The definition format version this reference reads (`journey_def_version`).
pub const JOURNEY_DEF_VERSION: u64 = 1;

/// The graph name of the proposal definition.
pub const PROPOSAL_GRAPH: &str = "proposal";

/// The member that holds the "any non-terminal state before GRANTED" rules.
pub const ANY_RULE_MEMBER: &str = "any_nonterminal_before_granted";

/// The side tracks of `SPEC/12-journey-ui.md` section 9, in the section 5.3 spelling.
pub const SIDE_TRACKS: [&str; 5] = [
    "amendment",
    "payment_request",
    "complaint",
    "support",
    "event_notice",
];

/// The formal name of the state that bounds the withdrawal rule.
const GRANTED: &str = "GRANTED";

/// The stable actor role key of a transition actor, or `None` for an actor
/// rule that no transition row uses.
pub fn role_key(actor: ActorRule) -> Option<&'static str> {
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

/// The actor role string the reference compares: the key, or a marker no
/// definition can match when the actor has no key.
fn actor_string(actor: ActorRule) -> String {
    match role_key(actor) {
        Some(k) => k.to_owned(),
        None => format!("<actor without a role key: {actor:?}>"),
    }
}

/// The edge id of a transition row: `T-<FROM>-<TO>`.
pub fn edge_id(from: StateTag, to: StateTag) -> String {
    format!("T-{}-{}", from.spec_name(), to.spec_name())
}

/// The id of an "any non-terminal state before GRANTED" rule: `T-ANY-<TO>`.
pub fn any_rule_id(to: StateTag) -> String {
    format!("T-ANY-{}", to.spec_name())
}

/// The label key of a node: `journey.node.<state>`.
pub fn node_label_key(state: StateTag) -> String {
    format!("journey.node.{}", state.spec_name().to_ascii_lowercase())
}

/// The help key of a node: `journey.help.<state>`.
pub fn node_help_key(state: StateTag) -> String {
    format!("journey.help.{}", state.spec_name().to_ascii_lowercase())
}

/// The label key of an edge: `journey.edge.<from>_<to>`.
pub fn edge_label_key(from: StateTag, to: StateTag) -> String {
    format!(
        "journey.edge.{}_{}",
        from.spec_name().to_ascii_lowercase(),
        to.spec_name().to_ascii_lowercase()
    )
}

/// The state with this formal name.
pub fn state_named(name: &str) -> Option<StateTag> {
    StateTag::ALL.into_iter().find(|s| s.spec_name() == name)
}

/// One edge as the drift test compares it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct EdgeShape {
    /// The formal name of the state it leaves.
    pub from: String,
    /// The formal name of the state it reaches.
    pub to: String,
    /// The actor role key.
    pub actor_role: String,
}

/// One "any non-terminal state before GRANTED" rule as the drift test compares it.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct AnyShape {
    /// The states it leaves from. On the definition side these are derived
    /// from the nodes and edges. On the domain side they are the row's own.
    pub from: BTreeSet<String>,
    /// The formal name of the state it reaches.
    pub to: String,
    /// The actor role key.
    pub actor_role: String,
}

/// A journey graph: nodes, edges and the withdrawal rule, keyed by id.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Graph {
    /// Node id (the formal state name) to its terminal flag.
    pub nodes: BTreeMap<String, bool>,
    /// Edge id to its shape.
    pub edges: BTreeMap<String, EdgeShape>,
    /// Rule id to its shape.
    pub any_rules: BTreeMap<String, AnyShape>,
    /// Ids that occur more than once on this side, which breaks the one to
    /// one mapping between edges and rows.
    pub duplicates: BTreeSet<String>,
}

impl Graph {
    fn empty() -> Graph {
        Graph {
            nodes: BTreeMap::new(),
            edges: BTreeMap::new(),
            any_rules: BTreeMap::new(),
            duplicates: BTreeSet::new(),
        }
    }

    fn add_node(&mut self, id: String, terminal: bool) {
        if self.nodes.insert(id.clone(), terminal).is_some() {
            self.duplicates.insert(id);
        }
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

    /// The graph a definition must equal, built from the domain side.
    ///
    /// Every state is a node with its terminal flag. The withdrawal row
    /// becomes one rule with the row's own source states. Every other row
    /// becomes one edge per source state.
    pub fn from_domain(states: &[StateTag], table: &[TransitionRule]) -> Graph {
        let mut g = Graph::empty();
        for s in states {
            g.add_node(s.spec_name().to_owned(), s.is_terminal());
        }
        for rule in table {
            if rule.row == Row::Withdraw {
                let shape = AnyShape {
                    from: rule.from.iter().map(|s| s.spec_name().to_owned()).collect(),
                    to: rule.to.spec_name().to_owned(),
                    actor_role: actor_string(rule.actor),
                };
                g.add_any(any_rule_id(rule.to), shape);
            } else {
                for from in rule.from {
                    let shape = EdgeShape {
                        from: from.spec_name().to_owned(),
                        to: rule.to.spec_name().to_owned(),
                        actor_role: actor_string(rule.actor),
                    };
                    g.add_edge(edge_id(*from, rule.to), shape);
                }
            }
        }
        g
    }

    /// The graph of a definition's parts. The source states of each rule
    /// are derived: the non-terminal nodes that GRANTED cannot reach
    /// through `edges`, GRANTED excluded.
    pub fn from_parts(
        nodes: &[(String, bool)],
        edges: &[(String, EdgeShape)],
        any_rules: &[(String, String, String)],
    ) -> Graph {
        let mut g = Graph::empty();
        for (id, terminal) in nodes {
            g.add_node(id.clone(), *terminal);
        }
        for (id, shape) in edges {
            g.add_edge(id.clone(), shape.clone());
        }
        let after = reachable_from(GRANTED, edges);
        let before: BTreeSet<String> = nodes
            .iter()
            .filter(|(id, terminal)| !*terminal && !after.contains(id))
            .map(|(id, _)| id.clone())
            .collect();
        for (id, to, actor_role) in any_rules {
            let shape = AnyShape {
                from: before.clone(),
                to: to.clone(),
                actor_role: actor_role.clone(),
            };
            g.add_any(id.clone(), shape);
        }
        g
    }

    /// Reads the graph out of a definition value of the section 5.3 shape.
    ///
    /// It reads only what the drift test compares and refuses a value it
    /// cannot read. Strictness on unknown members is the production
    /// parser's job, which the parser tests check.
    pub fn from_definition(def: &Value) -> Result<Graph, String> {
        let nodes = array(def, "nodes")?
            .iter()
            .enumerate()
            .map(|(i, n)| {
                let at = format!("nodes[{i}]");
                Ok((string(n, "id", &at)?, boolean(n, "terminal", &at)?))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let edges = array(def, "edges")?
            .iter()
            .enumerate()
            .map(|(i, e)| {
                let at = format!("edges[{i}]");
                let shape = EdgeShape {
                    from: string(e, "from", &at)?,
                    to: string(e, "to", &at)?,
                    actor_role: string(e, "actor_role", &at)?,
                };
                Ok((string(e, "id", &at)?, shape))
            })
            .collect::<Result<Vec<_>, String>>()?;
        let any_rules = array(def, ANY_RULE_MEMBER)?
            .iter()
            .enumerate()
            .map(|(i, r)| {
                let at = format!("{ANY_RULE_MEMBER}[{i}]");
                Ok((
                    string(r, "id", &at)?,
                    string(r, "to", &at)?,
                    string(r, "actor_role", &at)?,
                ))
            })
            .collect::<Result<Vec<_>, String>>()?;
        Ok(Graph::from_parts(&nodes, &edges, &any_rules))
    }
}

/// Every node reachable from `start` through `edges`, `start` included.
fn reachable_from(start: &str, edges: &[(String, EdgeShape)]) -> BTreeSet<String> {
    let mut seen = BTreeSet::from([start.to_owned()]);
    let mut queue = vec![start.to_owned()];
    while let Some(at) = queue.pop() {
        for (_, e) in edges {
            if e.from == at && seen.insert(e.to.clone()) {
                queue.push(e.to.clone());
            }
        }
    }
    seen
}

/// One difference between the domain side and the definition side.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Difference {
    /// A domain state has no node.
    NodeMissing(String),
    /// A node names no domain state.
    NodeExtra(String),
    /// A node's terminal flag differs from the domain's.
    NodeTerminal {
        /// The node id.
        id: String,
        /// The domain's flag.
        domain: bool,
    },
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
    /// The domain's withdrawal rule has no definition rule.
    AnyRuleMissing(String),
    /// A definition rule has no domain row.
    AnyRuleExtra(String),
    /// A rule's target, actor or source states differ from the row's.
    AnyRuleChanged {
        /// The rule id.
        id: String,
        /// The row's shape.
        domain: AnyShape,
        /// The rule's shape, with derived source states.
        definition: AnyShape,
    },
    /// An id occurs more than once on the domain side.
    DomainDuplicate(String),
    /// An id occurs more than once on the definition side.
    DefinitionDuplicate(String),
}

impl Difference {
    /// The node, edge or rule id the difference is about.
    pub fn id(&self) -> &str {
        match self {
            Difference::NodeMissing(id)
            | Difference::NodeExtra(id)
            | Difference::EdgeMissing(id)
            | Difference::EdgeExtra(id)
            | Difference::AnyRuleMissing(id)
            | Difference::AnyRuleExtra(id)
            | Difference::DomainDuplicate(id)
            | Difference::DefinitionDuplicate(id) => id,
            Difference::NodeTerminal { id, .. }
            | Difference::EdgeChanged { id, .. }
            | Difference::AnyRuleChanged { id, .. } => id,
        }
    }
}

impl core::fmt::Display for Difference {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Difference::NodeMissing(id) => write!(f, "state {id} has no node"),
            Difference::NodeExtra(id) => write!(f, "node {id} names no domain state"),
            Difference::NodeTerminal { id, domain } => {
                write!(f, "node {id} terminal flag differs (domain {domain})")
            }
            Difference::EdgeMissing(id) => write!(f, "row {id} has no edge"),
            Difference::EdgeExtra(id) => write!(f, "edge {id} has no row"),
            Difference::EdgeChanged {
                id,
                domain,
                definition,
            } => write!(f, "edge {id} is {definition:?}, row is {domain:?}"),
            Difference::AnyRuleMissing(id) => write!(f, "withdrawal row {id} has no rule"),
            Difference::AnyRuleExtra(id) => write!(f, "rule {id} has no row"),
            Difference::AnyRuleChanged {
                id,
                domain,
                definition,
            } => write!(f, "rule {id} is {definition:?}, row is {domain:?}"),
            Difference::DomainDuplicate(id) => write!(f, "id {id} occurs twice in the table"),
            Difference::DefinitionDuplicate(id) => {
                write!(f, "id {id} occurs twice in the definition")
            }
        }
    }
}

/// Every difference between the domain graph and the definition graph, in order.
pub fn diff(domain: &Graph, definition: &Graph) -> Vec<Difference> {
    let mut out = Vec::new();
    for id in &domain.duplicates {
        out.push(Difference::DomainDuplicate(id.clone()));
    }
    for id in &definition.duplicates {
        out.push(Difference::DefinitionDuplicate(id.clone()));
    }
    for (id, terminal) in &domain.nodes {
        match definition.nodes.get(id) {
            None => out.push(Difference::NodeMissing(id.clone())),
            Some(t) if t != terminal => out.push(Difference::NodeTerminal {
                id: id.clone(),
                domain: *terminal,
            }),
            Some(_) => {}
        }
    }
    for id in definition.nodes.keys() {
        if !domain.nodes.contains_key(id) {
            out.push(Difference::NodeExtra(id.clone()));
        }
    }
    for (id, shape) in &domain.edges {
        match definition.edges.get(id) {
            None => out.push(Difference::EdgeMissing(id.clone())),
            Some(d) if d != shape => out.push(Difference::EdgeChanged {
                id: id.clone(),
                domain: shape.clone(),
                definition: d.clone(),
            }),
            Some(_) => {}
        }
    }
    for id in definition.edges.keys() {
        if !domain.edges.contains_key(id) {
            out.push(Difference::EdgeExtra(id.clone()));
        }
    }
    for (id, shape) in &domain.any_rules {
        match definition.any_rules.get(id) {
            None => out.push(Difference::AnyRuleMissing(id.clone())),
            Some(d) if d != shape => out.push(Difference::AnyRuleChanged {
                id: id.clone(),
                domain: shape.clone(),
                definition: d.clone(),
            }),
            Some(_) => {}
        }
    }
    for id in definition.any_rules.keys() {
        if !domain.any_rules.contains_key(id) {
            out.push(Difference::AnyRuleExtra(id.clone()));
        }
    }
    out
}

/// The drift between a definition value and a domain side.
pub fn drift(
    def: &Value,
    states: &[StateTag],
    table: &[TransitionRule],
) -> Result<Vec<Difference>, String> {
    let definition = Graph::from_definition(def)?;
    Ok(diff(&Graph::from_domain(states, table), &definition))
}

/// The label and help keys of each node, by node id.
pub fn node_keys(def: &Value) -> Result<BTreeMap<String, (String, String)>, String> {
    let mut out = BTreeMap::new();
    for (i, n) in array(def, "nodes")?.iter().enumerate() {
        let at = format!("nodes[{i}]");
        let id = string(n, "id", &at)?;
        let keys = (string(n, "label_key", &at)?, string(n, "help_key", &at)?);
        if out.insert(id.clone(), keys).is_some() {
            return Err(format!("{at}: node {id} occurs twice"));
        }
    }
    Ok(out)
}

/// The label key of each edge, by edge id, with its endpoints.
pub fn edge_keys(def: &Value) -> Result<BTreeMap<String, (String, String, String)>, String> {
    let mut out = BTreeMap::new();
    for (i, e) in array(def, "edges")?.iter().enumerate() {
        let at = format!("edges[{i}]");
        let id = string(e, "id", &at)?;
        let row = (
            string(e, "from", &at)?,
            string(e, "to", &at)?,
            string(e, "label_key", &at)?,
        );
        if out.insert(id.clone(), row).is_some() {
            return Err(format!("{at}: edge {id} occurs twice"));
        }
    }
    Ok(out)
}

/// One row of Catalogue 1 of `docs/design/07-vocabulary-pack.md`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogueRow {
    /// The formal state name.
    pub formal: String,
    /// The plain label, the platform default pack (O-55 as amended).
    pub plain: String,
    /// The Voyage label, the optional pack.
    pub voyage: String,
}

/// The heading of the node label catalogue in `07-vocabulary-pack.md`.
pub const NODE_CATALOGUE_HEADING: &str = "## Catalogue 1: proposal states (node labels)";

/// Catalogue 1 of `docs/design/07-vocabulary-pack.md`, keyed by label key.
pub fn node_catalogue(markdown: &str) -> Result<BTreeMap<String, CatalogueRow>, String> {
    let mut lines = markdown.lines();
    if !lines
        .by_ref()
        .any(|l| l.trim_end() == NODE_CATALOGUE_HEADING)
    {
        return Err(format!("heading {NODE_CATALOGUE_HEADING:?} not found"));
    }
    let mut out = BTreeMap::new();
    for line in lines.take_while(|l| !l.starts_with("## ")) {
        let line = line.trim();
        if !line.starts_with('|') || line.contains("---") {
            continue;
        }
        let cells: Vec<String> = line
            .trim_matches('|')
            .split('|')
            .map(|c| c.trim().trim_matches('`').to_owned())
            .collect();
        let mut it = cells.into_iter();
        let (Some(key), Some(formal), Some(plain), Some(voyage)) =
            (it.next(), it.next(), it.next(), it.next())
        else {
            return Err(format!("short catalogue row: {line}"));
        };
        if key == "Key" {
            continue;
        }
        let row = CatalogueRow {
            formal,
            plain,
            voyage,
        };
        if out.insert(key.clone(), row).is_some() {
            return Err(format!("catalogue key {key} occurs twice"));
        }
    }
    Ok(out)
}

/// A definition of the section 5.3 shape, generated from the domain side.
///
/// It feeds the reference's own teeth, so they run without a shipped file.
/// Node kinds are a placeholder reading: `stage` for a non-terminal state
/// and `outcome` for a terminal one. Policy references are left empty.
pub fn generated_definition(states: &[StateTag], table: &[TransitionRule]) -> Value {
    let nodes: Vec<Value> = states
        .iter()
        .map(|s| {
            let kind = if s.is_terminal() { "outcome" } else { "stage" };
            object(vec![
                ("id", Value::from(s.spec_name())),
                ("kind", Value::from(kind)),
                ("terminal", Value::from(s.is_terminal())),
                ("label_key", Value::from(node_label_key(*s))),
                ("help_key", Value::from(node_help_key(*s))),
                ("policy_refs", Value::from(Vec::<Value>::new())),
            ])
        })
        .collect();
    let mut edges = Vec::new();
    let mut any_rules = Vec::new();
    for rule in table {
        if rule.row == Row::Withdraw {
            any_rules.push(object(vec![
                ("id", Value::from(any_rule_id(rule.to))),
                ("to", Value::from(rule.to.spec_name())),
                ("actor_role", Value::from(actor_string(rule.actor))),
            ]));
            continue;
        }
        for from in rule.from {
            edges.push(object(vec![
                ("id", Value::from(edge_id(*from, rule.to))),
                ("from", Value::from(from.spec_name())),
                ("to", Value::from(rule.to.spec_name())),
                ("actor_role", Value::from(actor_string(rule.actor))),
                ("label_key", Value::from(edge_label_key(*from, rule.to))),
            ]));
        }
    }
    let side_tracks: Vec<Value> = SIDE_TRACKS.iter().map(|t| Value::from(*t)).collect();
    object(vec![
        ("journey_def_version", Value::from(JOURNEY_DEF_VERSION)),
        ("graph", Value::from(PROPOSAL_GRAPH)),
        ("nodes", Value::from(nodes)),
        ("edges", Value::from(edges)),
        (ANY_RULE_MEMBER, Value::from(any_rules)),
        ("side_tracks", Value::from(side_tracks)),
    ])
}

// ---------------------------------------------------------------------------
// Teeth: one-sided changes
// ---------------------------------------------------------------------------

/// A change to one side of the drift test.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DefinitionMutation {
    /// Removes the edge with this id.
    RemoveEdge(&'static str),
    /// Adds an edge with these id, endpoints and actor role.
    AddEdge {
        /// The new edge id.
        id: &'static str,
        /// The state it leaves.
        from: &'static str,
        /// The state it reaches.
        to: &'static str,
        /// The actor role key.
        actor_role: &'static str,
    },
    /// Renames an edge id and keeps its endpoints.
    RenameEdge {
        /// The current id.
        id: &'static str,
        /// The new id.
        to_id: &'static str,
    },
    /// Points an edge at another state and keeps its id.
    RetargetEdge {
        /// The edge id.
        id: &'static str,
        /// The new target state.
        to: &'static str,
    },
    /// Changes an edge's actor role.
    ChangeEdgeActor {
        /// The edge id.
        id: &'static str,
        /// The new actor role key.
        actor_role: &'static str,
    },
    /// Removes a node and every edge that names it.
    RemoveNode(&'static str),
    /// Adds a node as a copy of `like` under a new id.
    AddNode {
        /// The new node id.
        id: &'static str,
        /// The node to copy.
        like: &'static str,
    },
    /// Renames a node everywhere it is named. Edge ids stay.
    RenameNode {
        /// The current id.
        id: &'static str,
        /// The new id.
        to_id: &'static str,
    },
    /// Flips a node's terminal flag.
    FlipTerminal(&'static str),
    /// Removes the withdrawal rule with this id.
    RemoveAnyRule(&'static str),
    /// Renames the withdrawal rule's id.
    RenameAnyRule {
        /// The current id.
        id: &'static str,
        /// The new id.
        to_id: &'static str,
    },
    /// Points the withdrawal rule at another state and keeps its id.
    RetargetAnyRule {
        /// The rule id.
        id: &'static str,
        /// The new target state.
        to: &'static str,
    },
    /// Changes the withdrawal rule's actor role.
    ChangeAnyRuleActor {
        /// The rule id.
        id: &'static str,
        /// The new actor role key.
        actor_role: &'static str,
    },
    /// Adds a second rule with these id, target and actor.
    AddAnyRule {
        /// The new rule id.
        id: &'static str,
        /// The target state.
        to: &'static str,
        /// The actor role key.
        actor_role: &'static str,
    },
}

/// A named definition-side change and the id the drift check must name.
#[derive(Clone, Debug)]
pub struct DefinitionCase {
    /// What the change does, for failure messages.
    pub name: &'static str,
    /// The change.
    pub mutation: DefinitionMutation,
    /// The id the drift report must name.
    pub names: &'static str,
    /// True when the change introduces a node id that is no domain state.
    /// A parser that checks node ids against the domain may refuse such a
    /// definition instead of reporting drift.
    pub unknown_state: bool,
}

/// The definition-side teeth: each case changes the definition only.
pub fn definition_mutations() -> Vec<DefinitionCase> {
    use DefinitionMutation as M;
    let case = |name, mutation, names, unknown_state| DefinitionCase {
        name,
        mutation,
        names,
        unknown_state,
    };
    vec![
        case(
            "an edge removed",
            M::RemoveEdge("T-STAGE2-RANKED"),
            "T-STAGE2-RANKED",
            false,
        ),
        case(
            "an edge added",
            M::AddEdge {
                id: "T-RANKED-DEFERRED",
                from: "RANKED",
                to: "DEFERRED",
                actor_role: "committee",
            },
            "T-RANKED-DEFERRED",
            false,
        ),
        case(
            "an edge added after GRANTED to WITHDRAWN",
            M::AddEdge {
                id: "T-GRANTED-WITHDRAWN",
                from: "GRANTED",
                to: "WITHDRAWN",
                actor_role: "applicant",
            },
            "T-GRANTED-WITHDRAWN",
            false,
        ),
        case(
            "an edge renamed",
            M::RenameEdge {
                id: "T-STAGE2-DEFERRED",
                to_id: "T-STAGE2-WAITING",
            },
            "T-STAGE2-DEFERRED",
            false,
        ),
        case(
            "an edge retargeted",
            M::RetargetEdge {
                id: "T-RANKED-IRC_REVIEW",
                to: "NEGOTIATION",
            },
            "T-RANKED-IRC_REVIEW",
            false,
        ),
        case(
            "an edge actor changed",
            M::ChangeEdgeActor {
                id: "T-STAGE2-DEFERRED",
                actor_role: "fstp_coordinator",
            },
            "T-STAGE2-DEFERRED",
            false,
        ),
        case(
            "a node removed with its edges",
            M::RemoveNode("DEFERRED"),
            "DEFERRED",
            false,
        ),
        case(
            "a node added",
            M::AddNode {
                id: "STAGE3",
                like: "STAGE2",
            },
            "STAGE3",
            true,
        ),
        case(
            "a node renamed",
            M::RenameNode {
                id: "RANKED",
                to_id: "RANKED_LIST",
            },
            "RANKED",
            true,
        ),
        case(
            "a node terminal flag flipped",
            M::FlipTerminal("DEFERRED"),
            "DEFERRED",
            false,
        ),
        case(
            "the WITHDRAWN rule removed",
            M::RemoveAnyRule("T-ANY-WITHDRAWN"),
            "T-ANY-WITHDRAWN",
            false,
        ),
        case(
            "the WITHDRAWN rule renamed",
            M::RenameAnyRule {
                id: "T-ANY-WITHDRAWN",
                to_id: "T-ANY-LEAVE",
            },
            "T-ANY-WITHDRAWN",
            false,
        ),
        case(
            "the WITHDRAWN rule retargeted",
            M::RetargetAnyRule {
                id: "T-ANY-WITHDRAWN",
                to: "DECLINED",
            },
            "T-ANY-WITHDRAWN",
            false,
        ),
        case(
            "the WITHDRAWN rule actor changed",
            M::ChangeAnyRuleActor {
                id: "T-ANY-WITHDRAWN",
                actor_role: "programme_manager",
            },
            "T-ANY-WITHDRAWN",
            false,
        ),
        case(
            "a second any-state rule added",
            M::AddAnyRule {
                id: "T-ANY-DECLINED",
                to: "DECLINED",
                actor_role: "system",
            },
            "T-ANY-DECLINED",
            false,
        ),
        case(
            "the WITHDRAWN source set changed by an edge from GRANTED back to DEFERRED",
            M::AddEdge {
                id: "T-GRANTED-DEFERRED",
                from: "GRANTED",
                to: "DEFERRED",
                actor_role: "system",
            },
            "T-ANY-WITHDRAWN",
            false,
        ),
    ]
}

/// Applies a definition-side change to a copy of `def`.
pub fn mutate(def: &Value, mutation: &DefinitionMutation) -> Result<Value, String> {
    use DefinitionMutation as M;
    let mut out = def.clone();
    match mutation {
        M::RemoveEdge(id) => remove_by_id(&mut out, "edges", id)?,
        M::AddEdge {
            id,
            from,
            to,
            actor_role,
        } => {
            let label = format!(
                "journey.edge.{}_{}",
                from.to_ascii_lowercase(),
                to.to_ascii_lowercase()
            );
            array_mut(&mut out, "edges")?.push(object(vec![
                ("id", Value::from(*id)),
                ("from", Value::from(*from)),
                ("to", Value::from(*to)),
                ("actor_role", Value::from(*actor_role)),
                ("label_key", Value::from(label)),
            ]));
        }
        M::RenameEdge { id, to_id } => set_member(&mut out, "edges", id, "id", to_id)?,
        M::RetargetEdge { id, to } => set_member(&mut out, "edges", id, "to", to)?,
        M::ChangeEdgeActor { id, actor_role } => {
            set_member(&mut out, "edges", id, "actor_role", actor_role)?;
        }
        M::RemoveNode(id) => {
            remove_by_id(&mut out, "nodes", id)?;
            array_mut(&mut out, "edges")?.retain(|e| {
                e.get("from").and_then(Value::as_str) != Some(*id)
                    && e.get("to").and_then(Value::as_str) != Some(*id)
            });
        }
        M::AddNode { id, like } => {
            let nodes = array_mut(&mut out, "nodes")?;
            let mut copy = nodes
                .iter()
                .find(|n| n.get("id").and_then(Value::as_str) == Some(*like))
                .cloned()
                .ok_or_else(|| format!("no node {like} to copy"))?;
            let lower = id.to_ascii_lowercase();
            let obj = copy
                .as_object_mut()
                .ok_or_else(|| format!("node {like} is not an object"))?;
            obj.insert("id", Value::from(*id));
            obj.insert("label_key", Value::from(format!("journey.node.{lower}")));
            obj.insert("help_key", Value::from(format!("journey.help.{lower}")));
            nodes.push(copy);
        }
        M::RenameNode { id, to_id } => {
            set_member(&mut out, "nodes", id, "id", to_id)?;
            for member in ["from", "to"] {
                for e in array_mut(&mut out, "edges")?.iter_mut() {
                    if e.get(member).and_then(Value::as_str) == Some(*id)
                        && let Some(obj) = e.as_object_mut()
                    {
                        obj.insert(member, Value::from(*to_id));
                    }
                }
            }
            for r in array_mut(&mut out, ANY_RULE_MEMBER)?.iter_mut() {
                if r.get("to").and_then(Value::as_str) == Some(*id)
                    && let Some(obj) = r.as_object_mut()
                {
                    obj.insert("to", Value::from(*to_id));
                }
            }
        }
        M::FlipTerminal(id) => {
            let node = find_mut(&mut out, "nodes", id)?;
            let flag = node
                .get("terminal")
                .and_then(Value::as_bool)
                .ok_or_else(|| format!("node {id} has no terminal flag"))?;
            if let Some(obj) = node.as_object_mut() {
                obj.insert("terminal", Value::from(!flag));
            }
        }
        M::RemoveAnyRule(id) => remove_by_id(&mut out, ANY_RULE_MEMBER, id)?,
        M::RenameAnyRule { id, to_id } => set_member(&mut out, ANY_RULE_MEMBER, id, "id", to_id)?,
        M::RetargetAnyRule { id, to } => set_member(&mut out, ANY_RULE_MEMBER, id, "to", to)?,
        M::ChangeAnyRuleActor { id, actor_role } => {
            set_member(&mut out, ANY_RULE_MEMBER, id, "actor_role", actor_role)?;
        }
        M::AddAnyRule { id, to, actor_role } => {
            array_mut(&mut out, ANY_RULE_MEMBER)?.push(object(vec![
                ("id", Value::from(*id)),
                ("to", Value::from(*to)),
                ("actor_role", Value::from(*actor_role)),
            ]));
        }
    }
    Ok(out)
}

/// A named domain-side change: a state list and a transition table that
/// differ from `StateTag::ALL` and `TRANSITIONS` in one way.
#[derive(Clone, Debug)]
pub struct DomainCase {
    /// What the change does, for failure messages.
    pub name: &'static str,
    /// The changed state list.
    pub states: Vec<StateTag>,
    /// The changed table.
    pub table: Vec<TransitionRule>,
    /// The id the drift report must name.
    pub names: String,
}

/// The withdrawal sources with GRANTED added, which NOTE 10 forbids.
const WITHDRAW_FROM_GRANTED: [StateTag; 9] = [
    StateTag::Draft,
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Deferred,
    StateTag::Negotiation,
    StateTag::Granted,
];

/// The withdrawal sources without DEFERRED.
const WITHDRAW_WITHOUT_DEFERRED: [StateTag; 7] = [
    StateTag::Draft,
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::Negotiation,
];

/// The domain-side teeth, each a one-sided change of `states` and `table`.
pub fn domain_mutations(states: &[StateTag], table: &[TransitionRule]) -> Vec<DomainCase> {
    let base: Vec<TransitionRule> = table.to_vec();
    let mut cases = Vec::new();
    let mut push = |name, states: Vec<StateTag>, table: Vec<TransitionRule>, names: String| {
        cases.push(DomainCase {
            name,
            states,
            table,
            names,
        });
    };
    let all = states.to_vec();

    let mut t = base.clone();
    t.retain(|r| r.row != Row::Stage2ToRanked);
    push(
        "a row removed",
        all.clone(),
        t,
        edge_id(StateTag::Stage2, StateTag::Ranked),
    );

    let mut t = base.clone();
    if let Some(r) = base.iter().find(|r| r.row == Row::RankedToNotSelected) {
        t.push(TransitionRule {
            to: StateTag::Deferred,
            ..*r
        });
    }
    push(
        "a row added",
        all.clone(),
        t,
        edge_id(StateTag::Ranked, StateTag::Deferred),
    );

    let t = base
        .iter()
        .map(|r| {
            if r.row == Row::RankedToIrcReview {
                TransitionRule {
                    to: StateTag::Negotiation,
                    ..*r
                }
            } else {
                *r
            }
        })
        .collect();
    push(
        "a row retargeted",
        all.clone(),
        t,
        edge_id(StateTag::Ranked, StateTag::IrcReview),
    );

    let t = base
        .iter()
        .map(|r| {
            if r.row == Row::Stage2ToDeferred {
                TransitionRule {
                    actor: ActorRule::Holder(Role::FstpCoordinator),
                    ..*r
                }
            } else {
                *r
            }
        })
        .collect();
    push(
        "a row actor changed",
        all.clone(),
        t,
        edge_id(StateTag::Stage2, StateTag::Deferred),
    );

    let with_withdraw = |f: &dyn Fn(TransitionRule) -> TransitionRule| -> Vec<TransitionRule> {
        base.iter()
            .map(|r| if r.row == Row::Withdraw { f(*r) } else { *r })
            .collect()
    };
    let withdrawn = any_rule_id(StateTag::Withdrawn);
    push(
        "the WITHDRAWN row opened in GRANTED",
        all.clone(),
        with_withdraw(&|r| TransitionRule {
            from: &WITHDRAW_FROM_GRANTED,
            ..r
        }),
        withdrawn.clone(),
    );
    push(
        "the WITHDRAWN row closed in DEFERRED",
        all.clone(),
        with_withdraw(&|r| TransitionRule {
            from: &WITHDRAW_WITHOUT_DEFERRED,
            ..r
        }),
        withdrawn.clone(),
    );
    push(
        "the WITHDRAWN row actor changed",
        all.clone(),
        with_withdraw(&|r| TransitionRule {
            actor: ActorRule::Holder(Role::ProgrammeManager),
            ..r
        }),
        withdrawn.clone(),
    );
    push(
        "the WITHDRAWN row retargeted",
        all.clone(),
        with_withdraw(&|r| TransitionRule {
            to: StateTag::Declined,
            ..r
        }),
        withdrawn.clone(),
    );

    let mut t = base.clone();
    t.retain(|r| r.row != Row::Withdraw);
    push("the WITHDRAWN row removed", all.clone(), t, withdrawn);

    let fewer: Vec<StateTag> = all
        .iter()
        .copied()
        .filter(|s| *s != StateTag::Deferred)
        .collect();
    // The rows into and out of DEFERRED go, and the withdrawal row keeps
    // every other source state.
    let t = base
        .iter()
        .filter(|r| r.to != StateTag::Deferred && r.from != [StateTag::Deferred])
        .map(|r| {
            if r.row == Row::Withdraw {
                TransitionRule {
                    from: &WITHDRAW_WITHOUT_DEFERRED,
                    ..*r
                }
            } else {
                *r
            }
        })
        .collect();
    push(
        "a state removed with its rows",
        fewer,
        t,
        StateTag::Deferred.spec_name().to_owned(),
    );

    cases
}

// ---------------------------------------------------------------------------
// Value helpers. They never panic.
// ---------------------------------------------------------------------------

fn object(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        o.insert(k, v);
    }
    Value::from(o)
}

fn array<'a>(v: &'a Value, member: &str) -> Result<&'a Array, String> {
    v.get(member)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("member {member} is missing or not an array"))
}

fn array_mut<'a>(v: &'a mut Value, member: &str) -> Result<&'a mut Array, String> {
    v.as_object_mut()
        .and_then(|o| o.get_mut(member))
        .and_then(Value::as_array_mut)
        .ok_or_else(|| format!("member {member} is missing or not an array"))
}

fn string(v: &Value, member: &str, at: &str) -> Result<String, String> {
    v.get(member)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("{at}.{member} is missing or not a string"))
}

fn boolean(v: &Value, member: &str, at: &str) -> Result<bool, String> {
    v.get(member)
        .and_then(Value::as_bool)
        .ok_or_else(|| format!("{at}.{member} is missing or not a boolean"))
}

fn find_mut<'a>(v: &'a mut Value, list: &str, id: &str) -> Result<&'a mut Value, String> {
    array_mut(v, list)?
        .iter_mut()
        .find(|x| x.get("id").and_then(Value::as_str) == Some(id))
        .ok_or_else(|| format!("{list} has no id {id}"))
}

fn remove_by_id(v: &mut Value, list: &str, id: &str) -> Result<(), String> {
    let items = array_mut(v, list)?;
    let before = items.len();
    items.retain(|x| x.get("id").and_then(Value::as_str) != Some(id));
    if items.len() == before {
        return Err(format!("{list} has no id {id}"));
    }
    Ok(())
}

fn set_member(v: &mut Value, list: &str, id: &str, member: &str, to: &str) -> Result<(), String> {
    find_mut(v, list, id)?
        .as_object_mut()
        .ok_or_else(|| format!("{list} entry {id} is not an object"))?
        .insert(member, Value::from(to));
    Ok(())
}
