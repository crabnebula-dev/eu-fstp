//! The journey definition parser (`SPEC/12-journey-ui.md` section 5.3, ADR-015).
//!
//! A definition is one I-JSON object with exactly these members, all
//! required:
//!
//! | Member | Type |
//! | --- | --- |
//! | `journey_def_version` | the integer 1 |
//! | `graph` | string |
//! | `nodes` | array of node objects |
//! | `edges` | array of edge objects |
//! | `any_nonterminal_before_granted` | array of rule objects |
//! | `side_tracks` | array of side track names |
//!
//! A node has `id`, `kind`, `terminal`, `label_key`, `help_key` and
//! `policy_refs`. An edge has `id`, `from`, `to`, `actor_role` and
//! `label_key`. A rule has `id`, `to` and `actor_role`. No other member is
//! allowed at any level.
//!
//! The parser checks the shape only. It never compares the graph with the
//! domain core: [`crate::drift`] does that. So a definition with a node
//! that is no domain state parses, and the drift check reports it.
//!
//! Readings taken here, pending Daniel:
//!
//! - A node `kind` is `stage` for a non-terminal state and `outcome` for a
//!   terminal one. Section 5.3 shows only `stage`.
//! - Ids, node references, actor roles and keys are tokens of 1 to 128
//!   ASCII letters, digits, `_`, `-` or `.`.
//! - Edge and rule ids share one namespace, so an edge cannot take the
//!   rule's id. Node ids have their own.
//! - Each policy reference names a parameter of the domain catalogue, once
//!   per node. Side tracks are the five names of section 5.3, each at most
//!   once.

use std::collections::BTreeSet;

use fstp_domain::rules::ParamId;
use fstp_json::{Array, Object, Value};

/// The definition format version this parser reads.
pub const FORMAT_VERSION: u64 = 1;

/// The longest token the parser accepts, in bytes.
pub const MAX_TOKEN: usize = 128;

/// The member that holds the "any non-terminal state before GRANTED" rules.
pub const ANY_RULE_MEMBER: &str = "any_nonterminal_before_granted";

const TOP_MEMBERS: [&str; 6] = [
    "journey_def_version",
    "graph",
    "nodes",
    "edges",
    ANY_RULE_MEMBER,
    "side_tracks",
];
const NODE_MEMBERS: [&str; 6] = [
    "id",
    "kind",
    "terminal",
    "label_key",
    "help_key",
    "policy_refs",
];
const EDGE_MEMBERS: [&str; 5] = ["id", "from", "to", "actor_role", "label_key"];
const RULE_MEMBERS: [&str; 3] = ["id", "to", "actor_role"];

/// Why a definition was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DefinitionErrorKind {
    /// The bytes are not one I-JSON text (`fstp-json` refused them).
    Json,
    /// A value has the wrong JSON type.
    WrongType,
    /// A required member is absent.
    MissingMember,
    /// A member outside the section 5.3 shape is present.
    UnknownMember,
    /// `journey_def_version` is not the integer 1.
    UnsupportedVersion,
    /// A string is not a valid token, node kind, policy reference or side track.
    InvalidValue,
    /// An id, policy reference or side track occurs more than once.
    DuplicateId,
    /// An edge or rule names a node the definition lacks.
    UnknownNode,
}

impl DefinitionErrorKind {
    fn describe(self) -> &'static str {
        match self {
            DefinitionErrorKind::Json => "not an I-JSON text",
            DefinitionErrorKind::WrongType => "wrong JSON type",
            DefinitionErrorKind::MissingMember => "missing member",
            DefinitionErrorKind::UnknownMember => "unknown member",
            DefinitionErrorKind::UnsupportedVersion => "unsupported journey_def_version",
            DefinitionErrorKind::InvalidValue => "invalid value",
            DefinitionErrorKind::DuplicateId => "repeated entry",
            DefinitionErrorKind::UnknownNode => "names no node of the definition",
        }
    }
}

/// A refused definition: the kind and where in the definition it was found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DefinitionError {
    kind: DefinitionErrorKind,
    at: String,
}

impl DefinitionError {
    fn new(kind: DefinitionErrorKind, at: impl Into<String>) -> DefinitionError {
        DefinitionError {
            kind,
            at: at.into(),
        }
    }

    /// Why the definition was refused.
    pub fn kind(&self) -> DefinitionErrorKind {
        self.kind
    }

    /// Where it was refused, such as `edges[3].to`. Empty for the whole text.
    pub fn at(&self) -> &str {
        &self.at
    }
}

impl core::fmt::Display for DefinitionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.at.is_empty() {
            write!(f, "journey definition: {}", self.kind.describe())
        } else {
            write!(
                f,
                "journey definition: {}: {}",
                self.at,
                self.kind.describe()
            )
        }
    }
}

impl std::error::Error for DefinitionError {}

/// The kind of a node (interim reading: `stage` or `outcome`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NodeKind {
    /// A non-terminal state: `stage`.
    Stage,
    /// A terminal state: `outcome`.
    Outcome,
}

impl NodeKind {
    /// Every kind.
    pub const ALL: [NodeKind; 2] = [NodeKind::Stage, NodeKind::Outcome];

    /// The kind as the definition spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            NodeKind::Stage => "stage",
            NodeKind::Outcome => "outcome",
        }
    }
}

/// A side track of `SPEC/12-journey-ui.md` section 9, as section 5.3 spells it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SideTrack {
    /// `amendment`.
    Amendment,
    /// `payment_request`.
    PaymentRequest,
    /// `complaint`.
    Complaint,
    /// `support`.
    Support,
    /// `event_notice`.
    EventNotice,
}

impl SideTrack {
    /// Every side track, in section 5.3 order.
    pub const ALL: [SideTrack; 5] = [
        SideTrack::Amendment,
        SideTrack::PaymentRequest,
        SideTrack::Complaint,
        SideTrack::Support,
        SideTrack::EventNotice,
    ];

    /// The side track as the definition spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            SideTrack::Amendment => "amendment",
            SideTrack::PaymentRequest => "payment_request",
            SideTrack::Complaint => "complaint",
            SideTrack::Support => "support",
            SideTrack::EventNotice => "event_notice",
        }
    }
}

/// A node of the journey graph: one proposal state.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Node {
    /// The formal state name, such as `IRC_REVIEW`.
    pub id: String,
    /// The node kind.
    pub kind: NodeKind,
    /// Whether the state is terminal.
    pub terminal: bool,
    /// The message catalogue key of the node label.
    pub label_key: String,
    /// The message catalogue key of the node help text.
    pub help_key: String,
    /// The policy parameters the node's overlay and guards name.
    pub policy_refs: Vec<ParamId>,
}

/// An edge of the journey graph: one row of the transition table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Edge {
    /// The stable edge id, such as `T-STAGE2-RANKED`.
    pub id: String,
    /// The node id it leaves.
    pub from: String,
    /// The node id it reaches.
    pub to: String,
    /// The actor role key, such as `assigned_reviewer`.
    pub actor_role: String,
    /// The message catalogue key of the edge label.
    pub label_key: String,
}

/// An "any non-terminal state before GRANTED" rule, such as withdrawal.
///
/// It names no source states. They follow from the graph: every
/// non-terminal node that GRANTED cannot reach through the edges.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AnyRule {
    /// The stable rule id, such as `T-ANY-WITHDRAWN`.
    pub id: String,
    /// The node id it reaches.
    pub to: String,
    /// The actor role key.
    pub actor_role: String,
}

/// A parsed journey definition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Definition {
    version: u64,
    graph: String,
    nodes: Vec<Node>,
    edges: Vec<Edge>,
    any_rules: Vec<AnyRule>,
    side_tracks: Vec<SideTrack>,
    checksum: [u8; 32],
}

impl Definition {
    /// `journey_def_version`.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// The graph name, such as `proposal`.
    pub fn graph(&self) -> &str {
        &self.graph
    }

    /// The nodes, in file order.
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The edges, in file order.
    pub fn edges(&self) -> &[Edge] {
        &self.edges
    }

    /// The "any non-terminal state before GRANTED" rules, in file order.
    pub fn any_nonterminal_before_granted(&self) -> &[AnyRule] {
        &self.any_rules
    }

    /// The side tracks, in file order.
    pub fn side_tracks(&self) -> &[SideTrack] {
        &self.side_tracks
    }

    /// The SHA-256 of the definition's bytes, as for a migration.
    pub fn checksum(&self) -> &[u8; 32] {
        &self.checksum
    }

    /// The node with this id.
    pub fn node(&self, id: &str) -> Option<&Node> {
        self.nodes.iter().find(|n| n.id == id)
    }
}

/// Parses a journey definition from its file bytes.
///
/// The bytes go through `fstp_json::parse` with its default limits, so
/// only one I-JSON text is accepted.
pub fn parse(bytes: &[u8]) -> Result<Definition, DefinitionError> {
    use DefinitionErrorKind as K;
    let checksum = fstp_crypto::sha256(bytes);
    let value = fstp_json::parse(bytes).map_err(|_| DefinitionError::new(K::Json, ""))?;
    let top = object(&value, "")?;
    only(top, &TOP_MEMBERS, "")?;

    let version = match member(top, "journey_def_version", "")? {
        Value::Number(n) => match n.as_u64() {
            Some(FORMAT_VERSION) => FORMAT_VERSION,
            _ => {
                return Err(DefinitionError::new(
                    K::UnsupportedVersion,
                    "journey_def_version",
                ));
            }
        },
        _ => return Err(DefinitionError::new(K::WrongType, "journey_def_version")),
    };
    let graph = token(top, "graph", "")?;

    let mut node_ids = BTreeSet::new();
    let mut nodes = Vec::new();
    for (i, v) in array(top, "nodes", "")?.iter().enumerate() {
        let at = format!("nodes[{i}]");
        let node = parse_node(v, &at)?;
        if !node_ids.insert(node.id.clone()) {
            return Err(DefinitionError::new(K::DuplicateId, format!("{at}.id")));
        }
        nodes.push(node);
    }

    let mut transition_ids = BTreeSet::new();
    let mut edges = Vec::new();
    for (i, v) in array(top, "edges", "")?.iter().enumerate() {
        let at = format!("edges[{i}]");
        let edge = parse_edge(v, &at)?;
        known_node(&node_ids, &edge.from, &at, "from")?;
        known_node(&node_ids, &edge.to, &at, "to")?;
        if !transition_ids.insert(edge.id.clone()) {
            return Err(DefinitionError::new(K::DuplicateId, format!("{at}.id")));
        }
        edges.push(edge);
    }

    let mut any_rules = Vec::new();
    for (i, v) in array(top, ANY_RULE_MEMBER, "")?.iter().enumerate() {
        let at = format!("{ANY_RULE_MEMBER}[{i}]");
        let rule = parse_rule(v, &at)?;
        known_node(&node_ids, &rule.to, &at, "to")?;
        if !transition_ids.insert(rule.id.clone()) {
            return Err(DefinitionError::new(K::DuplicateId, format!("{at}.id")));
        }
        any_rules.push(rule);
    }

    let mut side_tracks = Vec::new();
    for (i, v) in array(top, "side_tracks", "")?.iter().enumerate() {
        let at = format!("side_tracks[{i}]");
        let name = v
            .as_str()
            .ok_or_else(|| DefinitionError::new(K::WrongType, at.as_str()))?;
        let track = SideTrack::ALL
            .into_iter()
            .find(|t| t.as_str() == name)
            .ok_or_else(|| DefinitionError::new(K::InvalidValue, at.as_str()))?;
        if side_tracks.contains(&track) {
            return Err(DefinitionError::new(K::DuplicateId, at));
        }
        side_tracks.push(track);
    }

    Ok(Definition {
        version,
        graph,
        nodes,
        edges,
        any_rules,
        side_tracks,
        checksum,
    })
}

fn parse_node(v: &Value, at: &str) -> Result<Node, DefinitionError> {
    use DefinitionErrorKind as K;
    let obj = object(v, at)?;
    only(obj, &NODE_MEMBERS, at)?;
    let id = token(obj, "id", at)?;
    let kind_at = format!("{at}.kind");
    let kind_name = member(obj, "kind", at)?
        .as_str()
        .ok_or_else(|| DefinitionError::new(K::WrongType, kind_at.as_str()))?;
    let kind = NodeKind::ALL
        .into_iter()
        .find(|k| k.as_str() == kind_name)
        .ok_or_else(|| DefinitionError::new(K::InvalidValue, kind_at.as_str()))?;
    let terminal = member(obj, "terminal", at)?
        .as_bool()
        .ok_or_else(|| DefinitionError::new(K::WrongType, format!("{at}.terminal")))?;
    let label_key = token(obj, "label_key", at)?;
    let help_key = token(obj, "help_key", at)?;
    let mut policy_refs = Vec::new();
    for (i, r) in array(obj, "policy_refs", at)?.iter().enumerate() {
        let ref_at = format!("{at}.policy_refs[{i}]");
        let name = r
            .as_str()
            .ok_or_else(|| DefinitionError::new(K::WrongType, ref_at.as_str()))?;
        let param = ParamId::ALL
            .into_iter()
            .find(|p| p.spec_id() == name)
            .ok_or_else(|| DefinitionError::new(K::InvalidValue, ref_at.as_str()))?;
        if policy_refs.contains(&param) {
            return Err(DefinitionError::new(K::DuplicateId, ref_at));
        }
        policy_refs.push(param);
    }
    Ok(Node {
        id,
        kind,
        terminal,
        label_key,
        help_key,
        policy_refs,
    })
}

fn parse_edge(v: &Value, at: &str) -> Result<Edge, DefinitionError> {
    let obj = object(v, at)?;
    only(obj, &EDGE_MEMBERS, at)?;
    Ok(Edge {
        id: token(obj, "id", at)?,
        from: token(obj, "from", at)?,
        to: token(obj, "to", at)?,
        actor_role: token(obj, "actor_role", at)?,
        label_key: token(obj, "label_key", at)?,
    })
}

fn parse_rule(v: &Value, at: &str) -> Result<AnyRule, DefinitionError> {
    let obj = object(v, at)?;
    only(obj, &RULE_MEMBERS, at)?;
    Ok(AnyRule {
        id: token(obj, "id", at)?,
        to: token(obj, "to", at)?,
        actor_role: token(obj, "actor_role", at)?,
    })
}

// ---------------------------------------------------------------------------
// Member helpers. They never panic.
// ---------------------------------------------------------------------------

/// `parent.name`, or `name` at the top level.
fn path(parent: &str, name: &str) -> String {
    if parent.is_empty() {
        name.to_owned()
    } else {
        format!("{parent}.{name}")
    }
}

fn object<'a>(v: &'a Value, at: &str) -> Result<&'a Object, DefinitionError> {
    v.as_object()
        .ok_or_else(|| DefinitionError::new(DefinitionErrorKind::WrongType, at))
}

/// Refuses any member outside `allowed`.
fn only(obj: &Object, allowed: &[&str], at: &str) -> Result<(), DefinitionError> {
    for key in obj.keys() {
        if !allowed.contains(&key) {
            // The name comes from the input, so it is quoted and shortened.
            let shown: String = key.chars().take(MAX_TOKEN).collect();
            return Err(DefinitionError::new(
                DefinitionErrorKind::UnknownMember,
                path(at, &format!("{shown:?}")),
            ));
        }
    }
    Ok(())
}

fn member<'a>(obj: &'a Object, name: &str, at: &str) -> Result<&'a Value, DefinitionError> {
    obj.get(name)
        .ok_or_else(|| DefinitionError::new(DefinitionErrorKind::MissingMember, path(at, name)))
}

fn array<'a>(obj: &'a Object, name: &str, at: &str) -> Result<&'a Array, DefinitionError> {
    member(obj, name, at)?
        .as_array()
        .ok_or_else(|| DefinitionError::new(DefinitionErrorKind::WrongType, path(at, name)))
}

/// A string member that is a token: 1 to [`MAX_TOKEN`] bytes of ASCII
/// letters, digits, `_`, `-` or `.`.
fn token(obj: &Object, name: &str, at: &str) -> Result<String, DefinitionError> {
    let s = member(obj, name, at)?
        .as_str()
        .ok_or_else(|| DefinitionError::new(DefinitionErrorKind::WrongType, path(at, name)))?;
    let valid = !s.is_empty()
        && s.len() <= MAX_TOKEN
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'));
    if !valid {
        return Err(DefinitionError::new(
            DefinitionErrorKind::InvalidValue,
            path(at, name),
        ));
    }
    Ok(s.to_owned())
}

fn known_node(
    nodes: &BTreeSet<String>,
    id: &str,
    at: &str,
    name: &str,
) -> Result<(), DefinitionError> {
    if nodes.contains(id) {
        Ok(())
    } else {
        Err(DefinitionError::new(
            DefinitionErrorKind::UnknownNode,
            path(at, name),
        ))
    }
}
