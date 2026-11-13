//! The control plane: registry, placement, provisioning, routing, operator
//! tickets, metering, the isolation auditor and the cell role plan (M3
//! design section 9, ADR-011).
//!
//! The control plane cannot decode tenant data (I-19, I-20). It reaches no
//! crate that defines tenant records, account types or vault data
//! (layering rule 4).
//!
//! What this crate holds:
//!
//! - [`pg::cell_role_plan`], the one owner of a cell's roles, CONNECT
//!   grants, `pg_hba` lines, revocations and grant rows (I-82), and
//!   [`pg::render_hba`], the `pg_hba.conf` generator;
//! - [`placement::Placement`], which never mixes cluster kinds (I-83);
//! - [`pgagent`], the typed provisioning jobs, their decoder and the DDL
//!   they render from the closed identifier grammar (ADR-011);
//! - [`provision`], the ordered jobs of design section 9.2 and the mode
//!   rule;
//! - [`isolation_audit`], the privilege graph and its catalogue reader
//!   (design section 9.3);
//! - [`install`], the self-hosted install configuration (design section
//!   9.5);
//! - [`api`], the closed operator API request;
//! - [`CATALOGUE`], the `cp` column map of design section 4.4, whose
//!   tables the `migrations/cp` set creates.
//!
//! - [`config`], the closed JSON process configurations of `fstp-control`
//!   and `fstp-pgagent`;
//! - [`exchange`], the one-exchange-per-connection framing over mutual
//!   TLS that the `CellToCp` link and the agent link share;
//! - [`agent`], the `fstp-pgagent` executor, listener and run loop;
//! - [`operator`], the staff passkey login and step-up;
//! - [`approval`], the two-operator check of destructive jobs (ADR-011);
//! - [`erase`], the `erase-cell` job and its confirmation (R-SW-02);
//! - [`service`], the `CellToCp` listener and the `fstp-control` run loop.
//!
//! [`service::run`] and [`agent::run`] serve until SIGTERM. A destructive
//! request runs only through the two-operator check of [`approval`].
//! A destructive `fstp-pgagent` job runs only after the agent checked
//! both approvals again itself, against the staff passkeys pinned in its
//! configuration ([`approval::AgentApprovals`]). [`install::run`] stays a
//! refusal under B-06.

pub mod agent;
pub mod api;
pub mod approval;
pub mod catalogue;
pub mod config;
pub mod erase;
pub mod exchange;
pub mod install;
pub mod isolation_audit;
pub mod operator;
pub mod pg;
pub mod pgagent;
pub mod placement;
pub mod provision;
pub mod service;

pub use catalogue::CATALOGUE;

/// The configuration of the control plane service, as
/// [`config::decode_control_config`] reads it.
///
/// No field may hold a payment account type or a debtor account (I-16,
/// design section 14.4 `i16_config_types_hold_no_debtor_account`). No
/// field holds a credential: the TLS keys sit in files under
/// `credentials_dir`, readable only by the service's OS user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ControlConfig {
    /// The registered database clusters.
    pub clusters: Vec<placement::Cluster>,
    /// The control-private address the `CellToCp` listener binds.
    pub cell_listen: std::net::SocketAddr,
    /// The directory of the TLS files ([`config::CONTROL_FILES`]).
    pub credentials_dir: String,
    /// The control-plane host, the relying party id of staff passkeys
    /// (ADR-008 "Control plane").
    pub operator_host: String,
    /// The pinned staff passkeys (ADR-011 "Two-operator approval").
    pub staff: Vec<operator::StaffCredential>,
}

/// Why a control plane operation failed. No variant carries input bytes
/// (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ControlError {
    /// The operation is not built yet. It names the operation.
    NotImplemented(&'static str),
    /// A name is outside the DDL identifier grammar of ADR-011.
    Identifier,
    /// A role does not belong to the database it is named for (ADR-011
    /// role sets).
    RoleOutsideDatabase,
    /// A `fstp-pgagent` job did not decode. It names the rule broken.
    Job(&'static str),
    /// A destructive job needs two operators' approvals (ADR-011
    /// "Two-operator approval"), and they are not all there.
    ApprovalRequired,
    /// An operator API request did not decode. It names the rule broken.
    Request(&'static str),
    /// A configuration did not decode. It names the rule broken.
    Config(&'static str),
    /// A placement was refused (I-83).
    Placement(placement::PlacementError),
    /// The provisioning mode rule refused the clusters (design section
    /// 9.2).
    Mode(provision::ModeError),
    /// A `pg_hba` subnet is malformed.
    Subnet,
    /// A catalogue read failed. It names the query.
    Catalogue(&'static str),
    /// A file or socket operation failed.
    Io(std::io::ErrorKind),
    /// A TLS configuration did not build. It names the configuration.
    Tls(&'static str),
    /// Termination signals could not be set up.
    Signal,
    /// A database session or statement of the agent failed. It names the
    /// step.
    Database(&'static str),
    /// The operator login or authorisation refused (ADR-008, ADR-011).
    Operator(operator::OperatorRefusal),
    /// Custody refused a call of a control-plane job (ADR-004).
    Custody(fstp_custody::CustodyError),
}

impl std::fmt::Display for ControlError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ControlError::NotImplemented(op) => write!(f, "{op} is not implemented yet"),
            ControlError::Identifier => f.write_str("identifier outside the DDL grammar"),
            ControlError::RoleOutsideDatabase => {
                f.write_str("role does not belong to the named database")
            }
            ControlError::Job(rule) => write!(f, "pgagent job refused: {rule}"),
            ControlError::ApprovalRequired => {
                f.write_str("destructive job needs two operators' approvals")
            }
            ControlError::Request(rule) => write!(f, "API request refused: {rule}"),
            ControlError::Config(rule) => write!(f, "configuration refused: {rule}"),
            ControlError::Placement(e) => write!(f, "placement refused: {e:?}"),
            ControlError::Mode(e) => write!(f, "provisioning mode refused: {e:?}"),
            ControlError::Subnet => f.write_str("malformed pg_hba subnet"),
            ControlError::Catalogue(query) => write!(f, "catalogue read failed: {query}"),
            ControlError::Io(kind) => write!(f, "i/o failed: {kind:?}"),
            ControlError::Tls(what) => write!(f, "TLS configuration refused: {what}"),
            ControlError::Signal => f.write_str("termination signals could not be set up"),
            ControlError::Database(step) => write!(f, "database step failed: {step}"),
            ControlError::Operator(r) => write!(f, "operator refused: {r:?}"),
            ControlError::Custody(e) => write!(f, "custody refused: {e}"),
        }
    }
}

impl std::error::Error for ControlError {}
