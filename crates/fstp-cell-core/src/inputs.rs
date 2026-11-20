//! What a command's batch takes from its route or task beyond the ledger
//! and the vault answers (design sections 4.2, 5.1, 8.3 to 8.5).
//!
//! [`crate::RouteInput`] names each kind of input, and
//! [`crate::route_inputs`] lists what each auth command needs. A
//! [`RouteInputs`] carries them into `decide`:
//!
//! - [`SessionRows`]: the live rows of `auth.session` and the side table
//!   of which credential logged each passkey session in. They are
//!   operational rows, so no ledger record holds them (design section
//!   4.2). A batch that ends sessions names them from these rows. A route
//!   reads them for its own command, and the timeline for
//!   `EndSessionsAtBindingEnd`.
//! - The deployment mode, which picks the recovery path of a sole tenant
//!   admin (design section 8.5).
//! - A verified new passkey. Only the gate sets it, after it verified the
//!   registration itself ([`crate::gate::admit_add_passkey`]). The
//!   recovery completion verifies one too, but admits nothing yet
//!   ([`crate::gate::ROUTE_ADMISSION_SEAM`]). So no session and no
//!   caller of `decide` with a plain [`RouteInputs`] registers a key that
//!   `fstp_webauthn` did not verify through the gate.
//! - A verified operator ticket for the `OperatorProcess` recovery path.
//!   Only `fstp_auth::recovery::verify_ticket_as` builds one, after the
//!   composite signature verified under the pinned control-plane key.
//!
//! Session rows are data, not proof. A row can only make a batch end a
//! session, which is the restrictive direction. `decide` uses only the
//! rows of the account its rule names, and never a session the ledger
//! ended already, so a batch never ends one session twice and the
//! `auth_log.session_end` primary key holds (design section 5.3 step 6).

use fstp_auth::recovery::{Deployment, VerifiedTicket};
use fstp_auth::session::SessionLogin;
use fstp_auth::{NewCredential, SessionView};
use fstp_domain::id::AccountId;

/// The live session rows a route or a task read from `auth.session`, and
/// the credential each passkey session logged in with.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SessionRows {
    live: Vec<SessionView>,
    logins: Vec<SessionLogin>,
}

impl SessionRows {
    /// The rows `live`, with the logins side table `logins`. A row the
    /// ledger ended already is ignored by `decide`.
    pub fn new(live: Vec<SessionView>, logins: Vec<SessionLogin>) -> SessionRows {
        SessionRows { live, logins }
    }

    /// The live rows.
    pub fn live(&self) -> &[SessionView] {
        &self.live
    }

    /// Which credential logged each passkey session in.
    pub fn logins(&self) -> &[SessionLogin] {
        &self.logins
    }

    /// The live rows of `account` that the state has not ended, each id
    /// once, in row order.
    pub(crate) fn of(&self, s: &crate::CellState, account: AccountId) -> Vec<SessionView> {
        let mut seen = std::collections::BTreeSet::new();
        self.live
            .iter()
            .filter(|r| r.account == account && !s.auth().session_ended(r.id))
            .filter(|r| seen.insert(r.id))
            .cloned()
            .collect()
    }
}

/// The inputs of one command beyond the ledger and the vault answers.
/// [`RouteInputs::default`] carries none.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RouteInputs {
    sessions: Option<SessionRows>,
    mode: Option<Deployment>,
    credential: Option<NewCredential>,
    ticket: Option<VerifiedTicket>,
    outbox: Option<Vec<crate::timeline::MessageBody>>,
    creator: Option<crate::creator::CreatorFacts>,
    agent: bool,
    api: Option<ApiEffects>,
    dry: bool,
}

impl RouteInputs {
    /// No inputs.
    pub fn none() -> RouteInputs {
        RouteInputs::default()
    }

    /// The same inputs with the session rows `rows`.
    #[must_use]
    pub fn with_sessions(mut self, rows: SessionRows) -> RouteInputs {
        self.sessions = Some(rows);
        self
    }

    /// The same inputs with the deployment mode `mode`.
    #[must_use]
    pub fn with_mode(mut self, mode: Deployment) -> RouteInputs {
        self.mode = Some(mode);
        self
    }

    /// The same inputs with the operator ticket `ticket`, which
    /// `fstp_auth::recovery::verify_ticket_as` verified.
    #[must_use]
    pub fn with_ticket(mut self, ticket: VerifiedTicket) -> RouteInputs {
        self.ticket = Some(ticket);
        self
    }

    /// The same inputs with the new passkey `credential`. Only the gate
    /// calls it, after it verified the registration (module docs).
    #[must_use]
    pub(crate) fn with_credential(mut self, credential: NewCredential) -> RouteInputs {
        self.credential = Some(credential);
        self
    }

    /// The session rows, if given.
    pub fn sessions(&self) -> Option<&SessionRows> {
        self.sessions.as_ref()
    }

    /// The deployment mode, if given.
    pub fn mode(&self) -> Option<Deployment> {
        self.mode
    }

    /// The verified new passkey, if the gate set one.
    pub fn credential(&self) -> Option<&NewCredential> {
        self.credential.as_ref()
    }

    /// The verified operator ticket, if given.
    pub fn ticket(&self) -> Option<&VerifiedTicket> {
        self.ticket.as_ref()
    }

    /// The same inputs with the message bodies of a timeline firing, in
    /// message order (M6 design section 4 step 2). Bodies are data: the
    /// decider checks they name exactly the fired messages.
    #[must_use]
    pub fn with_outbox(mut self, bodies: Vec<crate::timeline::MessageBody>) -> RouteInputs {
        self.outbox = Some(bodies);
        self
    }

    /// The message bodies, if given.
    pub fn outbox(&self) -> Option<&[crate::timeline::MessageBody]> {
        self.outbox.as_deref()
    }

    /// The same inputs with the creator shell facts `facts`, which the
    /// route read from the cell's shell (`crate::creator`). Facts are
    /// data: they change no check of the gate, and the creator decides
    /// over them.
    #[must_use]
    pub fn with_creator(mut self, facts: crate::creator::CreatorFacts) -> RouteInputs {
        self.creator = Some(facts);
        self
    }

    /// The creator shell facts, if given.
    pub fn creator(&self) -> Option<&crate::creator::CreatorFacts> {
        self.creator.as_ref()
    }

    /// The same inputs for a command an agent sent through MCP, under
    /// its grant (ADR-026 "Channel in the decision"). Only the agent
    /// admission sets it ([`crate::gate::admit_agent_command`]). The
    /// decision then runs with `Via::Mcp`, which can only add refusals.
    #[must_use]
    pub(crate) fn with_agent(mut self) -> RouteInputs {
        self.agent = true;
        self
    }

    /// The channel the command came through: `Via::Mcp` for an agent's
    /// command, `Via::Web` otherwise.
    pub fn via(&self) -> fstp_domain::Via {
        if self.agent {
            fstp_domain::Via::Mcp
        } else {
            fstp_domain::Via::Web
        }
    }

    /// The same inputs with the API core's side effects `effects`
    /// (ADR-026, ADR-010 amendment of 2026-11-20): the pending action
    /// the command confirms and the call's audit events. They are data:
    /// they change no check of the gate and no decision, and the store
    /// writes them in the command's append transaction.
    #[must_use]
    pub fn with_api(mut self, effects: ApiEffects) -> RouteInputs {
        self.api = Some(effects);
        self
    }

    /// The same inputs for a dry run only (ADR-026 "Dry run"). Only the
    /// gate's dry-run admission sets it, and the engine executes no
    /// admission that carries it.
    #[must_use]
    pub(crate) fn with_dry(mut self) -> RouteInputs {
        self.dry = true;
        self
    }

    /// Whether the admission is for a dry run only.
    pub fn dry_run(&self) -> bool {
        self.dry
    }

    /// The API core's side effects, if given.
    pub fn api(&self) -> Option<&ApiEffects> {
        self.api.as_ref()
    }
}

/// The side effects of an `ApiCore` call that join its command's append
/// (ADR-026 "Pending actions", ADR-010 amendment of 2026-11-20).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ApiEffects {
    /// The pending action the command confirms (I-85). The store inserts
    /// its one `api.pending_confirmed` row, and a second confirmation
    /// aborts the append.
    pub pending: Option<[u8; 16]>,
    /// The canonical bodies of the call's audit events, in order. The
    /// store seals each into one kind 2 row of the App chain (I-24).
    pub events: Vec<Vec<u8>>,
}
