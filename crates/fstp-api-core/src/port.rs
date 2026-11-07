//! The ports M4 needs from M3 (M4 design section 6.1).
//!
//! M4 is built against these traits. `fstp-api-testkit` holds a fake for
//! each, so M4 lanes start before M3 lands. If the M3 design names them
//! differently, only `crates/fstp-cell/src/routes/m4.rs` changes. Only
//! this file may name [`CellPorts`], [`AsyncEngine`] or a port trait in a
//! public item (layering rule A2). Adapters never name this module (rule
//! A2b).
//!
//! Ownership: lane W0 wrote this file, and the lead holds it after W0
//! (design section 13). The value types follow section 6.1. Where the
//! design leaves a type open, it is a W0 placeholder, and a lane that
//! needs it asks the lead.
//!
//! Every answer a vault port gives, dry runs and previews included, is
//! recorded through [`VaultAudit`] (`overview.md` NOTE 5).

use std::collections::BTreeSet;
use std::future::Future;
use std::sync::Arc;

use fstp_domain::id::{AccountId, OrganisationId, ProgrammeId, ProposalId, VaultEpoch};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain::refusal::Refusal;
use fstp_domain::time::Timestamp;
use fstp_domain::{Ctx, Via};
use fstp_engine::EngineState;
use fstp_ledger::Seq;

use crate::{ActionDigest, ApiCore, Credential, DispatchFuture, Op, RequestHead};

macro_rules! port_id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

port_id!(
    /// An M3 session.
    SessionId,
    /// An OAuth client of an agent.
    AgentClientId,
    /// A pending action (I-85).
    PendingId,
    /// An account recovery case.
    RecoveryId,
    /// A break-glass request (SoD-08).
    BreakGlassId,
    /// A second tenant admin approval (SoD-07).
    ApprovalId,
    /// A tenant, in the control plane.
    TenantId,
    /// A pre-check run (M7 design section 4).
    PrecheckRunId,
);

/// A port that could not answer. Every caller fails closed on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortError {
    /// The port is unavailable.
    Unavailable,
    /// The port refused the request.
    Refused,
}

/// A login method (`authentication.md`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LoginMethod {
    /// A passkey.
    Passkey,
    /// A magic link.
    MagicLink,
    /// OPAQUE.
    Opaque,
    /// The EUDI Wallet.
    EudiWallet,
}

/// What an M3 session attests.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionPrincipal {
    /// The account.
    pub account: AccountId,
    /// The session.
    pub session: SessionId,
    /// How the session logged in.
    pub method: LoginMethod,
    /// Whether the method is phishing-resistant (I-77).
    pub phishing_resistant: bool,
    /// Whether the attested tenant admin set holds the account.
    pub tenant_admin: bool,
}

/// A step-up challenge bound to one action digest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StepUpChallenge {
    /// The digest the challenge is bound to.
    pub action: ActionDigest,
    /// The WebAuthn challenge bytes.
    pub challenge: Vec<u8>,
}

/// A reference to a finished step-up, recorded with the action.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StepUpRef(pub u128);

/// A fresh step-up proof for one digest and session. Consumed on use.
#[derive(Debug, PartialEq, Eq)]
pub struct StepUpProof {
    /// The step-up this proof comes from.
    pub step_up: StepUpRef,
    /// The digest it authorises.
    pub action: ActionDigest,
}

/// No fresh step-up proof exists for the digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StepUpRequired;

/// What an invitation is for.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InviteKind {
    _w0: (),
}

/// An invitation link.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationLink(pub String);

/// A pseudonymous display handle. Never an email.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayHandle(pub String);

/// A fact that only the vault may receive. It has no `Debug`, `Display`,
/// `ToJson` or `Clone`, and no accessor here. Only the M3 vault client
/// consumes it, through the W6 adapter.
pub struct VaultBound<T>(T);

impl<T> VaultBound<T> {
    /// Wraps a fact for the vault.
    pub fn new(fact: T) -> VaultBound<T> {
        VaultBound(fact)
    }
}

/// A vault receipt for one intake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Receipt(pub u128);

/// An ISO 3166-1 alpha-2 country code.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CountryCode(pub [u8; 2]);

/// Declared affiliations of one account.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
pub struct Affiliations {
    _w0: (),
}

/// Why a verification runs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum VerificationPurpose {
    /// Applicant identity.
    Applicant,
    /// Tenant admin identity, for the I-67 Sybil check (design section 6.1, item 13).
    AdminIdentity,
}

/// Where the browser goes to verify.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationRedirect(pub String);

/// The P-13 exclusion classes of a programme.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExclusionClasses(pub BTreeSet<fstp_domain::id::ClassId>);

/// The operation name recorded in audit entries.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct OpName(pub &'static str);

/// What an execution carries besides the command.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecMeta {
    /// The channel.
    pub via: Via,
    /// The session, if any.
    pub session: Option<SessionId>,
    /// The agent client, for MCP calls.
    pub agent: Option<AgentClientId>,
    /// The operation.
    pub op: OpName,
    /// The request digest.
    pub request: ActionDigest,
    /// The step-up, for high-risk operations.
    pub step_up: Option<StepUpRef>,
    /// The pending action this execution confirms.
    pub pending: Option<PendingId>,
    /// The second tenant admin of a recorded approval (SoD-07).
    pub second_tenant_admin: Option<AccountId>,
}

/// Why an execution failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExecError {
    /// The domain refused the command.
    Refused(Refusal),
    /// A port failed. Nothing was appended.
    Port(PortError),
}

/// An open database transaction of the cell.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
pub struct Tx {
    _w0: (),
}

/// The outcome an audit entry records.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The call succeeded.
    Accepted,
    /// The call was refused, with the rule text.
    Refused(&'static str),
}

/// One audit entry per call, accepted or refused (I-24).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The account, if any.
    pub actor: Option<AccountId>,
    /// The channel.
    pub via: Via,
    /// The agent client, for MCP calls.
    pub agent: Option<AgentClientId>,
    /// The operation.
    pub op: OpName,
    /// The outcome.
    pub outcome: Outcome,
    /// The request digest.
    pub request: ActionDigest,
    /// The step-up, for high-risk operations.
    pub step_up: Option<StepUpRef>,
}

/// The class of a stored text, which picks its data key (ADR-004, ADR-007).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextClass {
    /// Proposal and review text.
    Confidential,
    /// Text approved for public pages.
    Public,
}

/// Who owns a stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextOwner {
    /// A proposal.
    Proposal(ProposalId),
    /// A programme.
    Programme(ProgrammeId),
    /// The tenant, for its onboarding texts such as the data protection
    /// contact (Q22, lane m4tenant).
    Tenant,
}

/// A reference to a stored text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TextRef(pub u128);

/// A reference to a stored public text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicTextRef(pub u128);

/// The clearance a read obtained, which a store checks before it releases
/// text.
///
/// W0 placeholder with no fields. Lane W3a writes it in `fstp-access`.
pub struct ReadClearance {
    _w0: (),
}

/// Who owns a stored blob, such as an uploaded import document (R-PG-02).
///
/// W0 placeholder. The lead writes it with the M3 seam.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BlobOwner {
    /// A programme, for its import documents.
    Programme(ProgrammeId),
}

/// A content address of a stored blob: the SHA-256 of its bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BlobRef(pub [u8; 32]);

/// Who owns sealed bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SealOwner {
    /// The workspace of a proposal.
    Workspace(ProposalId),
}

/// Sealed bytes under a hybrid-wrapped data key (ADR-001, ADR-004).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sealed(pub Vec<u8>);

/// SHA-256 of one vault query, recorded with its answer bit.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryDigest(pub [u8; 32]);

/// One session of an account (R-LG-04).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SessionInfo {
    /// The session.
    pub session: SessionId,
    /// How it logged in.
    pub method: LoginMethod,
    /// When it started.
    pub started: Timestamp,
}

/// The tenant settings the cell holds.
///
/// Interim (W3b seam proposal for the lead): the three values dispatch
/// reads. Lane W2d writes the full settings in `fstp-tenant`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TenantSettings {
    /// P-74: whether the MCP server is enabled, and for which roles.
    pub mcp: fstp_access::McpSettings,
    /// The tenant's inference record (design section 3.5). `None` before
    /// onboarding records one, so a publication is refused (R-LA-05).
    pub inference: Option<InferenceRecord>,
    /// The tenant, bound into every action digest.
    pub tenant: Option<TenantId>,
}

/// The tenant's inference configuration record: the `LlmConfigId` and
/// the primary model a publication names (design section 3.5).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceRecord {
    /// The configuration.
    pub config: fstp_domain::id::LlmConfigId,
    /// The primary model, which must equal the programme's P-21 primary.
    pub model: fstp_domain::policy::ModelRef,
    /// The endpoint and decoding inputs of the `config_id` derivation (M7
    /// design section 2, reading 2). `None` before onboarding records
    /// them, and then no assessment or pre-check runs.
    pub endpoint: Option<InferenceEndpoint>,
}

/// The wire protocol of an inference endpoint (ADR-019). Daniel decided
/// on 2026-11-06 that the Anthropic Messages API is the default and the
/// chat-completions shape the secondary path.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InferenceProvider {
    /// The in-memory synthetic model of the demo cell. Its findings say
    /// "Synthetic assessor (demo)", and it is never an LLM result.
    Synthetic,
    /// The Anthropic Messages API, non-streaming. The default for a
    /// hosted model. The tenant picks the model (P-21).
    Anthropic,
    /// One endpoint speaking the chat-completions JSON shape, non-streaming,
    /// for an open-weight EU-hosted or local model.
    ChatCompletions,
}

/// The endpoint part of a tenant's inference record (M7 design sections
/// 2 and 9, R-LA-04). With the prompt set digest, the rubric digest and
/// the call's P-01, it is the input of the `config_id` derivation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferenceEndpoint {
    /// The wire protocol.
    pub provider: InferenceProvider,
    /// The endpoint URL. `None` for [`InferenceProvider::Synthetic`].
    pub url: Option<String>,
    /// The most tokens of a reply.
    pub max_tokens: u32,
    /// The temperature in thousandths, 0 to 2000. No floats.
    pub temperature_milli: u16,
    /// The sampling seed.
    pub seed: u32,
    /// The P-21 fallback models in order. Each gets its own `config_id`
    /// at publication (M7 design section 2, reading 3).
    pub fallbacks: Vec<fstp_domain::policy::ModelRef>,
    /// Pinned trust anchors (PEM) for the endpoint's TLS certificate.
    /// Interim, pending Daniel (Q2): no allowlisted crate holds a public
    /// root store, so a hosted endpoint is reachable only through these.
    pub trust_anchors_pem: Vec<u8>,
}

/// A recorded second tenant admin approval (SoD-07).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SecondAdminApproval {
    /// The approval.
    pub approval: ApprovalId,
    /// The approving admin.
    pub approver: AccountId,
}

/// One page of a listing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    /// The first item.
    pub offset: u32,
    /// The item count.
    pub limit: u32,
}

/// One page of in-app notices.
///
/// W0 placeholder with no fields. The lead writes it with the M3 seam.
/// Interim (W3b seam proposal): `Default` builds the empty page.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NoticePage {
    _w0: (),
}

/// What a probe checks (Q5).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeKind {
    /// An enabled channel of P-32.
    Channel,
    /// SPF, DKIM and DMARC of the sending domain.
    SendingDomain,
    /// The inference configuration (P-21).
    Inference,
}

/// The result of one probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeOutcome {
    /// The probe passed.
    Pass,
    /// The probe failed, or no prober exists (Q5).
    Fail,
}

/// Sessions and principals (`authentication.md`).
pub trait Sessions: Send + Sync {
    /// The principal of the request's session.
    fn principal(
        &self,
        head: &RequestHead,
        cred: &Credential,
        now: Timestamp,
    ) -> impl Future<Output = Result<SessionPrincipal, PortError>> + Send;
}

/// Step-up (I-78), bound to one action digest and consumed on use.
pub trait StepUp: Send + Sync {
    /// Starts a step-up for one digest.
    fn begin(
        &self,
        s: SessionId,
        action: ActionDigest,
    ) -> impl Future<Output = Result<StepUpChallenge, PortError>> + Send;
    /// Finishes a step-up with the authenticator response.
    fn finish(
        &self,
        s: SessionId,
        response: &[u8],
    ) -> impl Future<Output = Result<StepUpRef, PortError>> + Send;
    /// A proof for exactly this digest and session, younger than P-71 at
    /// `now`. Consumed.
    fn take(
        &self,
        s: SessionId,
        action: ActionDigest,
        now: Timestamp,
    ) -> impl Future<Output = Result<StepUpProof, StepUpRequired>> + Send;
}

/// Accounts: invitations, enrolment and pseudonymous display handles only.
pub trait Accounts: Send + Sync {
    /// Creates an invitation.
    fn invite(
        &self,
        kind: InviteKind,
    ) -> impl Future<Output = Result<InvitationLink, PortError>> + Send;
    /// The display handle of an account. Never an email.
    fn display_handle(
        &self,
        a: AccountId,
    ) -> impl Future<Output = Result<DisplayHandle, PortError>> + Send;
}

/// The M2 oracle answers, asynchronously.
pub trait AsyncIdentityOracle: Send + Sync {
    /// Answers one query.
    fn answer(&self, q: &Query) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
}

/// The vault: the oracle, write-only intake and two proposed one-bit
/// queries (Q35, blocking).
pub trait Vault: AsyncIdentityOracle {
    /// States the applicant's country, to the vault only (R-NG-01).
    fn state_country(
        &self,
        a: AccountId,
        p: ProposalId,
        c: VaultBound<CountryCode>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// Declares affiliations, to the vault only.
    fn declare_affiliations(
        &self,
        a: AccountId,
        p: ProposalId,
        d: VaultBound<Affiliations>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// Declares whether the lead is under 18 at the deadline, to the vault only.
    fn declare_minor(
        &self,
        a: AccountId,
        p: ProposalId,
        under_18_at_deadline: VaultBound<bool>,
    ) -> impl Future<Output = Result<Receipt, OracleDown>> + Send;
    /// Starts a verification.
    fn begin_verification(
        &self,
        purpose: VerificationPurpose,
        a: AccountId,
    ) -> impl Future<Output = Result<VerificationRedirect, OracleDown>> + Send;
    /// Whether the vault knows every P-13 class (Q35).
    fn classes_defined(
        &self,
        programme: ProgrammeId,
        classes: &ExclusionClasses,
    ) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
    /// Whether every partner organisation declared a P-38 list (Q35).
    fn proximity_lists_declared(
        &self,
        programme: ProgrammeId,
        orgs: &BTreeSet<OrganisationId>,
    ) -> impl Future<Output = Result<Answer, OracleDown>> + Send;
}

/// The asynchronous driver over the M2 pure functions, with a dry run.
pub trait AsyncEngine: Send + Sync {
    /// Queries, vault answers, decide, then one transaction: the ledger
    /// batch, the audit entry and the pending status.
    fn execute(
        &self,
        cmd: fstp_engine::Command,
        ctx: Ctx,
        meta: ExecMeta,
    ) -> impl Future<Output = Result<Seq, ExecError>> + Send;
    /// The same with no append and no audit entry for a commit.
    fn dry_run(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = Result<(), Refusal>> + Send;
    /// A dry run that also returns every vault answer it obtained, in
    /// order, whether it was refused or not, so dispatch records each one
    /// (`overview.md` NOTE 5). Interim (W3b seam proposal for the lead).
    fn dry_run_answers(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = (Result<(), Refusal>, Vec<Answer>)> + Send;
    /// The current engine state.
    fn snapshot(&self) -> Arc<EngineState>;
    /// The cell's ledger from genesis, in sequence order, which the
    /// journey reads fold into journey rows (ADR-015 "Read model only",
    /// I-92). The API core reads it and writes nothing.
    ///
    /// Interim (lane j2 seam proposal for the lead): the cell's projector
    /// writes the rows into the `journey` schema, and this port will serve
    /// those rows with the entries the diary sentences read. The default
    /// answers `None`, so the journey reads fail closed as unavailable.
    fn ledger(&self) -> Option<Vec<fstp_ledger::Entry<fstp_engine::Record>>> {
        None
    }
    /// The shell's creator facts for `cmd` by `ctx` (design section 3.2,
    /// `CreatorInputs`): the facts the engine port's
    /// `fstp_engine::CreatorEnvironment` answers for the same command. The
    /// API core reads them for the validation report, the invitations and
    /// the approval inbox, so a read shows what a decision would see.
    ///
    /// The engine replaces the parts it owns before it decides: the count
    /// of unresolved imports and the vault answers of the builders. The
    /// API core does the same for its reads.
    ///
    /// Interim (lane m4wire seam proposal for the lead). The default
    /// supplies no shell fact, as `fstp_engine::NoEnvironment` does, so
    /// every check that needs one fails closed.
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &fstp_creator::CreatorCommand,
        ctx: &Ctx,
    ) -> fstp_creator::CreatorInputs {
        fstp_engine::CreatorEnvironment::creator_inputs(
            &fstp_engine::NoEnvironment,
            state,
            cmd,
            ctx,
        )
    }
}

/// MCP bearer tokens (design sections 3.7 step 0 and 3.8). Interim (W3b
/// seam proposal for the lead): ADR-013 is a draft, so the token store of
/// `fstp-oauth` is not built. This port resolves a token to its grant.
pub trait Tokens: Send + Sync {
    /// The grant of a valid token at `now`.
    fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> impl Future<Output = Result<fstp_access::GrantFacts, PortError>> + Send;
    /// Revokes every token of `client` for `account` at once (R-MC-03).
    fn revoke(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Audit (I-24): one entry per call, in the same transaction as any append.
pub trait AuditSink: Send + Sync {
    /// Records one entry.
    fn record(&self, tx: &mut Tx, e: AuditEntry) -> Result<(), PortError>;
}

/// Free text, each under its own data key (ADR-004, ADR-007).
pub trait TextStore: Send + Sync {
    /// Stores a text.
    fn put(
        &self,
        class: TextClass,
        owner: TextOwner,
        bytes: &[u8],
    ) -> impl Future<Output = Result<TextRef, PortError>> + Send;
    /// Reads a text against a clearance.
    fn get(
        &self,
        r: TextRef,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
    /// Reads a public text.
    fn get_public(
        &self,
        r: PublicTextRef,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
}

/// Blobs, such as uploaded import documents (R-PG-02): content-addressed,
/// size-limited and each under its own data key (ADR-004, ADR-007).
///
/// W0 placeholder methods. The lead writes the size limit and the key
/// handling with the M3 seam.
pub trait BlobStore: Send + Sync {
    /// Stores a blob and returns its content address.
    fn put(
        &self,
        owner: BlobOwner,
        bytes: &[u8],
    ) -> impl Future<Output = Result<BlobRef, PortError>> + Send;
    /// Reads a blob against a clearance.
    fn get(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
}

/// One section of a pre-check snapshot (M7 design section 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PrecheckSection {
    /// The title.
    Title,
    /// The neutral summary.
    Summary,
    /// The narrative.
    Narrative,
}

/// The draft a pre-check run reads: the workspace as it stood when the
/// applicant asked. Every text is untrusted data. The port passes it to
/// a model only as a data part (`fstp-infer`, TH-01).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckSnapshot {
    /// The title.
    pub title: fstp_findings::UntrustedText,
    /// The neutral summary.
    pub summary: fstp_findings::UntrustedText,
    /// The narrative.
    pub narrative: fstp_findings::UntrustedText,
}

/// A quote that supports a pre-check finding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckEvidence {
    /// The section it quotes.
    pub section: PrecheckSection,
    /// The quoted text, as data.
    pub quote: fstp_findings::UntrustedText,
}

/// One pre-check finding. It carries no confidence and no number, so no
/// score or band is derivable from it (R-LA-06, TH-02, T-LLM-ORACLE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckFinding {
    /// Completeness, quality, accuracy or integrity.
    pub kind: fstp_findings::FindingKind,
    /// The P-01 criterion, where one applies.
    pub criterion: Option<fstp_domain::id::CriterionId>,
    /// Info, minor or major.
    pub severity: fstp_findings::Severity,
    /// The observation, as data.
    pub statement: fstp_findings::UntrustedText,
    /// Quotes from the snapshot.
    pub evidence: Vec<PrecheckEvidence>,
}

/// Where a pre-check run stands.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckRunState {
    /// The run is queued or running.
    Pending,
    /// The run finished with findings, possibly none.
    Done,
    /// The provider was unavailable. The run still counts (P-23).
    Unavailable,
}

/// One pre-check run, stored in the applicant workspace beside the draft
/// and never in the `FindingStore` (I-21).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrecheckRun {
    /// The run.
    pub run: PrecheckRunId,
    /// When it was requested, which is when it was counted (P-23).
    pub requested: Timestamp,
    /// The call's pinned configuration (I-11).
    pub config: fstp_domain::id::LlmConfigId,
    /// Where it stands.
    pub state: PrecheckRunState,
    /// Its findings, empty until it is done.
    pub findings: Vec<PrecheckFinding>,
}

/// The remaining P-23 checks of one applicant on one draft. These counts
/// are the only numbers a pre-check reply shows (M7 design section 2,
/// reading 4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PrecheckQuota {
    /// Runs left today on this proposal.
    pub proposal_today: u32,
    /// Runs left in this call on this proposal.
    pub proposal_call: u32,
    /// Runs left for this account across its drafts in this call (TH-29).
    pub account_call: u32,
    /// When the next run becomes available, if none is left now.
    pub next: Option<Timestamp>,
}

/// Why a pre-check request was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PrecheckRefusal {
    /// The port failed or is not built yet. Fails closed.
    Port(PortError),
    /// A P-23 limit is reached.
    QuotaExhausted(PrecheckQuota),
    /// The draft's call is not published, so it has no pinned config.
    CallNotPublished,
}

/// The pre-check provider (M7 design section 4, R-LA-06, I-21). M4
/// production cells have none, so `PrecheckUnavailable` fails validation
/// there (Q38). The e2e cell supplies a fake.
///
/// L-SEAM stub: every method has a default that fails closed with
/// [`PortError::Unavailable`], so the ops answer "unavailable" until lane
/// L-PRE implements the port over `fstp-infer`.
pub trait Precheck: Send + Sync {
    /// Requests one run on `snapshot` for `account`, counted at once
    /// against every P-23 limit (TH-29).
    fn request(
        &self,
        proposal: ProposalId,
        account: AccountId,
        snapshot: PrecheckSnapshot,
    ) -> impl Future<Output = Result<PrecheckRunId, PrecheckRefusal>> + Send {
        let _ = (proposal, account);
        drop(snapshot);
        std::future::ready(Err(PrecheckRefusal::Port(PortError::Unavailable)))
    }
    /// The runs of a proposal, newest first. Only its team reads them.
    fn runs(
        &self,
        proposal: ProposalId,
    ) -> impl Future<Output = Result<Vec<PrecheckRun>, PortError>> + Send {
        let _ = proposal;
        std::future::ready(Err(PortError::Unavailable))
    }
    /// The remaining checks of `account` on `proposal`.
    fn quota(
        &self,
        proposal: ProposalId,
        account: AccountId,
    ) -> impl Future<Output = Result<PrecheckQuota, PortError>> + Send {
        let _ = (proposal, account);
        std::future::ready(Err(PortError::Unavailable))
    }
}

/// Sealing under ADR-004 level 3 keys, hybrid-wrapped in M3 (ADR-001).
pub trait Sealer: Send + Sync {
    /// Seals bytes for an owner.
    fn seal(
        &self,
        owner: SealOwner,
        plaintext: &[u8],
    ) -> impl Future<Output = Result<Sealed, PortError>> + Send;
    /// Opens sealed bytes against a clearance.
    fn open(
        &self,
        owner: SealOwner,
        sealed: &Sealed,
        clearance: &ReadClearance,
    ) -> impl Future<Output = Result<Vec<u8>, PortError>> + Send;
}

/// Records vault answers that commit no command, as a query digest and the
/// answer bit (`overview.md` NOTE 5).
pub trait VaultAudit: Send + Sync {
    /// Records one answer.
    fn record(
        &self,
        q: QueryDigest,
        answer: bool,
        epoch: VaultEpoch,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Sessions and devices (R-LG-04).
pub trait SessionsAdmin: Send + Sync {
    /// The sessions of an account.
    fn list(
        &self,
        a: AccountId,
    ) -> impl Future<Output = Result<Vec<SessionInfo>, PortError>> + Send;
    /// Ends one session of an account.
    fn end(&self, a: AccountId, s: SessionId)
    -> impl Future<Output = Result<(), PortError>> + Send;
}

/// The M3 recovery approval flow (Q41).
pub trait Recovery: Send + Sync {
    /// Approves a recovery case.
    fn approve(
        &self,
        approver: AccountId,
        r: RecoveryId,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// The M3 break-glass approval flow (SoD-08, Q41).
pub trait BreakGlass: Send + Sync {
    /// Approves or refuses a break-glass request.
    fn decide(
        &self,
        approver: AccountId,
        b: BreakGlassId,
        approve: bool,
        proof: StepUpProof,
    ) -> impl Future<Output = Result<(), PortError>> + Send;
}

/// Tenant configuration: the attested admin set and second-admin approvals.
pub trait TenantConfig: Send + Sync {
    /// The current tenant settings.
    fn settings(&self) -> Arc<TenantSettings>;
    /// Whether the attested tenant admin set holds the account.
    fn is_tenant_admin(&self, a: AccountId) -> bool;
    /// A recorded second-admin approval.
    fn approval(
        &self,
        id: ApprovalId,
    ) -> impl Future<Output = Result<SecondAdminApproval, PortError>> + Send;
}

/// The in-app notice list, read from outbox records.
pub trait Outbox: Send + Sync {
    /// One page of an account's notices.
    fn notices(&self, a: AccountId, page: Page) -> NoticePage;
}

/// Probes for channels, the sending domain and inference (Q5).
pub trait Prober: Send + Sync {
    /// Runs one probe.
    fn probe(&self, p: ProbeKind) -> impl Future<Output = ProbeOutcome> + Send;
}

/// The cell clock.
pub trait Clock: Send + Sync {
    /// The current instant.
    fn now(&self) -> Timestamp;
}

/// Fresh ids, drawn with `fstp_crypto::random_array`.
pub trait Ids: Send + Sync {
    /// A fresh 128-bit id value.
    fn fresh(&self) -> Result<u128, PortError>;
}

/// Every port of one cell. Only `fstp-cell` implements it, and only
/// [`api_core`] takes it.
pub trait CellPorts: Send + Sync + 'static {
    /// The sessions port.
    type Sessions: Sessions;
    /// The step-up port.
    type StepUp: StepUp;
    /// The accounts port.
    type Accounts: Accounts;
    /// The vault port.
    type Vault: Vault;
    /// The engine port.
    type Engine: AsyncEngine;
    /// The audit port.
    type Audit: AuditSink;
    /// The text store.
    type Texts: TextStore;
    /// The blob store.
    type Blobs: BlobStore;
    /// The pre-check provider, absent in M4 production cells (Q38).
    type Precheck: Precheck;
    /// The sealer.
    type Sealer: Sealer;
    /// The vault answer recorder.
    type VaultAudit: VaultAudit;
    /// The sessions admin port.
    type SessionsAdmin: SessionsAdmin;
    /// The recovery port.
    type Recovery: Recovery;
    /// The break-glass port.
    type BreakGlass: BreakGlass;
    /// The tenant configuration.
    type Tenant: TenantConfig;
    /// The outbox.
    type Outbox: Outbox;
    /// The prober.
    type Prober: Prober;
    /// The clock.
    type Clock: Clock;
    /// The id source.
    type Ids: Ids;
    /// The MCP token grants.
    type Tokens: Tokens;

    /// The sessions port.
    fn sessions(&self) -> &Self::Sessions;
    /// The step-up port.
    fn step_up(&self) -> &Self::StepUp;
    /// The accounts port.
    fn accounts(&self) -> &Self::Accounts;
    /// The vault port.
    fn vault(&self) -> &Self::Vault;
    /// The engine port.
    fn engine(&self) -> &Self::Engine;
    /// The audit port.
    fn audit(&self) -> &Self::Audit;
    /// The text store.
    fn texts(&self) -> &Self::Texts;
    /// The blob store.
    fn blobs(&self) -> &Self::Blobs;
    /// The pre-check provider. `None` in every M4 production cell, so
    /// `PrecheckUnavailable` fails validation there (Q38).
    fn precheck(&self) -> Option<&Self::Precheck>;
    /// The sealer.
    fn sealer(&self) -> &Self::Sealer;
    /// The vault answer recorder.
    fn vault_audit(&self) -> &Self::VaultAudit;
    /// The sessions admin port.
    fn sessions_admin(&self) -> &Self::SessionsAdmin;
    /// The recovery port.
    fn recovery(&self) -> &Self::Recovery;
    /// The break-glass port.
    fn break_glass(&self) -> &Self::BreakGlass;
    /// The tenant configuration.
    fn tenant(&self) -> &Self::Tenant;
    /// The outbox.
    fn outbox(&self) -> &Self::Outbox;
    /// The prober.
    fn prober(&self) -> &Self::Prober;
    /// The clock.
    fn clock(&self) -> &Self::Clock;
    /// The id source.
    fn ids(&self) -> &Self::Ids;
    /// The MCP token grants.
    fn tokens(&self) -> &Self::Tokens;
}

/// The object-safe dispatch behind [`ApiCore`]. Private to this crate.
pub(crate) trait Dispatch: Send + Sync {
    /// Runs one call.
    fn dispatch<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        op: Op,
    ) -> DispatchFuture<'a>;
}

/// The ports of one cell inside an [`ApiCore`], with the dispatch state
/// beside them: pending actions and rate-limit counters, in memory.
struct Core<P> {
    ports: P,
    state: crate::dispatch::State,
}

impl<P: CellPorts> Dispatch for Core<P> {
    fn dispatch<'a>(
        &'a self,
        cred: Credential,
        head: &'a RequestHead,
        op: Op,
    ) -> DispatchFuture<'a> {
        Box::pin(crate::dispatch::run(
            &self.ports,
            &self.state,
            cred,
            head,
            op,
        ))
    }
}

/// The dispatch seams over the ports (W3b seam proposal for the lead).
impl<P: CellPorts> crate::dispatch::Seams for P {
    fn grant(
        &self,
        token: &[u8],
        now: Timestamp,
    ) -> impl Future<Output = Result<fstp_access::GrantFacts, PortError>> + Send {
        self.tokens().grant(token, now)
    }

    fn revoke_agent(
        &self,
        account: AccountId,
        client: AgentClientId,
    ) -> impl Future<Output = Result<(), PortError>> + Send {
        self.tokens().revoke(account, client)
    }

    fn dry_run_answers(
        &self,
        cmd: &fstp_engine::Command,
        ctx: Ctx,
    ) -> impl Future<Output = (Result<(), Refusal>, Vec<Answer>)> + Send {
        self.engine().dry_run_answers(cmd, ctx)
    }

    fn mcp_settings(&self) -> fstp_access::McpSettings {
        self.tenant().settings().mcp.clone()
    }

    fn inference(&self) -> Option<(fstp_domain::id::LlmConfigId, fstp_domain::policy::ModelRef)> {
        let s = self.tenant().settings();
        s.inference.as_ref().map(|i| (i.config, i.model.clone()))
    }

    fn tenant_id(&self) -> Option<u128> {
        self.tenant().settings().tenant.map(TenantId::raw)
    }

    fn record_audit(&self, e: AuditEntry) -> Result<(), PortError> {
        self.audit().record(&mut Tx { _w0: () }, e)
    }

    fn call_ids(&self, state: &EngineState) -> Vec<fstp_domain::id::CallId> {
        state.core.calls().iter().map(|(id, _)| id).collect()
    }
}

/// Builds the opaque [`ApiCore`] from a cell's ports. Only `fstp-cell`
/// calls it (rule A2b).
pub fn api_core<P: CellPorts>(ports: P) -> ApiCore {
    ApiCore {
        inner: Box::new(Core {
            ports,
            state: crate::dispatch::State::default(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use fstp_rt::future::block_on;

    struct Stub;
    impl Precheck for Stub {}

    /// R-LA-06, Q38: a pre-check port whose methods are not built yet
    /// fails closed on every method.
    #[test]
    fn r_la_06_precheck_stub_fails_closed() {
        let p = ProposalId::from_raw(1);
        let a = AccountId::from_raw(2);
        let empty = || fstp_findings::UntrustedText::new(String::new());
        let snapshot = PrecheckSnapshot {
            title: empty(),
            summary: empty(),
            narrative: empty(),
        };
        assert_eq!(
            block_on(Stub.request(p, a, snapshot)),
            Err(PrecheckRefusal::Port(PortError::Unavailable))
        );
        assert_eq!(block_on(Stub.runs(p)), Err(PortError::Unavailable));
        assert_eq!(block_on(Stub.quota(p, a)), Err(PortError::Unavailable));
    }
}
