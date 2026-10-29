//! The checks every route shares, in order, and the replies (design
//! sections 5.4 and 8.2, ADR-008).
//!
//! The front has matched the route already: an unlisted path got 404 and
//! another method 405. Then, before any handler:
//!
//! 1. A POST or DELETE carries exactly one `Origin` field, equal to the
//!    cell origin byte for byte (403). The vault origin `id.<host>` is
//!    same-site with the cell, so `SameSite=Strict` does not stop its
//!    requests. Only this check does.
//! 2. A POST carries exactly one `Content-Type` field, `application/json`
//!    (415). A plain HTML form or a no-preflight `fetch` cannot send it.
//! 3. The body is within the route's limit (413). A GET or DELETE takes
//!    no body.
//! 4. A route whose class needs a session reads the `__Host-fstp` cookie.
//!    A missing, doubled, malformed or foreign cookie, and a token with no
//!    live session row, get 401 (TH-05, B11).
//! 5. The handler decodes its body (400) and asks the gate (403 for a
//!    refusal, 401 for an ended session). Every session route reaches the
//!    gate before it reads or changes anything (TH-05).

use std::sync::Arc;

use fstp_auth::{EnabledMethods, SessionView};
use fstp_cell_core::CellState;
use fstp_cell_core::driver::ExecError;
use fstp_cell_core::gate::{self, Action, Admitted, Deny, LoginPolicy, ReadAction, StepUpView};
use fstp_cell_core::tenant::P71_DEFAULT_US;
use fstp_cell_core::{CellCommand, CellRefusal};
use fstp_http::{HeaderName, HeaderValue, Request, Response, StatusCode};
use fstp_json::{Object, Value};
use fstp_webauthn::RelyingParty;

use crate::http::body::{BodyRefusal, hex};
use crate::http::cookie::{CookieRefusal, read_session_cookie};
use crate::routes::{Access, Backend, BackendFault, Endpoint, Route, SessionRow};

/// The rule a refusal is logged under (R-NF-02: a rule reference, never
/// text).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Rule {
    /// ADR-007: the audit and erasure logs are for Auditors and tenant
    /// admins (G30).
    Adr007,
    /// ADR-008: `Origin`, JSON bodies, cookies.
    Adr008,
    /// I-18: a `minor` member in a request.
    I18,
    /// I-19 and B11: another cell's cookie, or another host.
    I19,
    /// I-77: a weak session of a management holder.
    I77,
    /// I-78: a high-risk action without a valid step-up.
    I78,
    /// TH-05: no session, or the gate refused the action.
    Th05,
    /// TH-26: a body over its limit or malformed.
    Th26,
    /// The spec rule of a domain refusal.
    Spec(&'static str),
}

impl Rule {
    /// The rule reference.
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Rule::Adr007 => "ADR-007",
            Rule::Adr008 => "ADR-008",
            Rule::I18 => "I-18",
            Rule::I19 => "I-19",
            Rule::I77 => "I-77",
            Rule::I78 => "I-78",
            Rule::Th05 => "TH-05",
            Rule::Th26 => "TH-26",
            Rule::Spec(s) => s,
        }
    }
}

/// How a route answered, for its log event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Outcome {
    /// The rule of a refusal, if the route refused under one.
    pub(crate) rule: Option<Rule>,
}

/// The cell configuration the routes read.
#[derive(Debug)]
pub(crate) struct CellCfg {
    /// The cell id.
    pub(crate) cell: [u8; 16],
    /// The cell origin, `https://<host>`.
    pub(crate) origin: String,
    /// The relying party: the exact cell host (I-20).
    pub(crate) rp: RelyingParty,
    /// The login methods the tenant enables (P-70).
    pub(crate) enabled: EnabledMethods,
}

/// What a handler runs against.
pub(crate) struct Ctx<B> {
    /// The cell runtime.
    pub(crate) backend: Arc<B>,
    /// The configuration.
    pub(crate) cfg: CellCfg,
}

/// The caller of a session route: its session row and gate view.
#[derive(Clone, Debug)]
pub(crate) struct Caller {
    /// The session row.
    pub(crate) row: SessionRow,
    /// The session as the gate sees it.
    pub(crate) view: SessionView,
}

/// A handler's answer.
#[derive(Debug)]
pub(crate) struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: &'static str,
    cookie: Option<HeaderValue>,
    rule: Option<Rule>,
}

/// The media type of every JSON reply.
const JSON: &str = "application/json";

impl Reply {
    /// A JSON reply.
    pub(crate) fn json(status: StatusCode, value: &Value) -> Reply {
        Reply {
            status,
            body: value.to_compact().into_bytes(),
            content_type: JSON,
            cookie: None,
            rule: None,
        }
    }

    /// A reply with a fixed body of `content_type`.
    pub(crate) fn fixed(status: StatusCode, content_type: &'static str, body: &[u8]) -> Reply {
        Reply {
            status,
            body: body.to_vec(),
            content_type,
            cookie: None,
            rule: None,
        }
    }

    /// A refusal: `{"error":"<code>"}` under `rule`.
    pub(crate) fn refuse(status: StatusCode, rule: Option<Rule>, code: &'static str) -> Reply {
        let mut o = Object::with_capacity(1);
        o.insert("error", Value::String(code.to_owned()));
        Reply {
            rule,
            ..Reply::json(status, &Value::Object(o))
        }
    }

    /// A route step that needs an API the sources do not offer yet. It
    /// fails closed with 501 and names no internals.
    pub(crate) fn not_built() -> Reply {
        Reply::refuse(StatusCode::NOT_IMPLEMENTED, None, "not_implemented")
    }

    /// The reply with a `Set-Cookie` field.
    pub(crate) fn with_cookie(mut self, cookie: HeaderValue) -> Reply {
        self.cookie = Some(cookie);
        self
    }

    fn into_response(self) -> (Response, Outcome) {
        let mut resp = Response::with_body(self.status, self.content_type, self.body);
        if let Some(c) = self.cookie
            && let Ok(name) = HeaderName::new("set-cookie")
        {
            resp.headers.append(name, c);
        }
        (resp, Outcome { rule: self.rule })
    }
}

/// The reply of a backend fault: 503, nothing decided.
pub(crate) fn unavailable(_: BackendFault) -> Reply {
    Reply::refuse(StatusCode::SERVICE_UNAVAILABLE, None, "unavailable")
}

/// The reply of a body refusal: 400, or 413 for a body over its limit.
pub(crate) fn bad_body(r: BodyRefusal) -> Reply {
    match r {
        BodyRefusal::TooLarge => {
            Reply::refuse(StatusCode::CONTENT_TOO_LARGE, Some(Rule::Th26), "too_large")
        }
        BodyRefusal::MinorMember => Reply::refuse(StatusCode::BAD_REQUEST, Some(Rule::I18), "body"),
        _ => Reply::refuse(StatusCode::BAD_REQUEST, Some(Rule::Th26), "body"),
    }
}

/// The reply of a session refusal: 401.
fn no_session(rule: Rule) -> Reply {
    Reply::refuse(StatusCode::UNAUTHORIZED, Some(rule), "session")
}

/// The reply of a gate refusal.
pub(crate) fn denied(d: Deny) -> Reply {
    use Deny as D;
    match d {
        D::NoSession | D::SessionEnded => no_session(Rule::Th05),
        D::WeakSessionForRole => no_session(Rule::I77),
        D::StepUpRequired(_)
        | D::StepUpStale
        | D::StepUpMismatch
        | D::StepUpFromWeakMethod
        | D::MagicLinkSessionHighRisk => {
            Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::I78), "stepup")
        }
        D::EnrolPasskeyFirst => Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::I77), "passkey"),
        D::NotPermitted => Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::Th05), "forbidden"),
        D::NotImplemented(_) => Reply::not_built(),
    }
}

/// The reply of a command the engine did not finish.
pub(crate) fn exec_failed(e: &ExecError) -> Reply {
    use fstp_domain::refusal::{RefusalReason, RuleRef};
    match e {
        ExecError::Refused(CellRefusal::Domain(r)) => {
            let status = match (r.rule, r.reason) {
                (RuleRef::OracleDown, _) | (_, RefusalReason::OracleUnavailable) => {
                    StatusCode::SERVICE_UNAVAILABLE
                }
                (RuleRef::StaleFacts, _) | (_, RefusalReason::IdReused) => StatusCode::CONFLICT,
                _ => StatusCode::FORBIDDEN,
            };
            let mut o = Object::with_capacity(2);
            o.insert("error", Value::String("refused".to_owned()));
            o.insert("reason", Value::String(format!("{:?}", r.reason)));
            if let Some(id) = r.rule.spec_id() {
                o.insert("rule", Value::String(id.to_owned()));
            }
            Reply {
                rule: r.rule.spec_id().map(Rule::Spec),
                ..Reply::json(status, &Value::Object(o))
            }
        }
        ExecError::VaultFault => Reply::refuse(StatusCode::SERVICE_UNAVAILABLE, None, "vault"),
        ExecError::Contended => Reply::refuse(StatusCode::CONFLICT, None, "contended"),
        ExecError::ReservedCommandId
        | ExecError::NotASystemCommandId
        | ExecError::CommandIdMismatch
        | ExecError::CommandIdTaken { .. } => {
            Reply::refuse(StatusCode::BAD_REQUEST, Some(Rule::Th26), "command_id")
        }
        ExecError::Refused(CellRefusal::NotImplemented(_)) | ExecError::NotImplemented(_) => {
            Reply::not_built()
        }
        ExecError::NoCommandId
        | ExecError::NotACommand
        | ExecError::Store(_)
        | ExecError::Fold(_)
        | ExecError::Unfoldable(_)
        | ExecError::Protocol => Reply::refuse(StatusCode::INTERNAL_SERVER_ERROR, None, "internal"),
    }
}

/// Whether the request carries exactly one field `name` equal to `want`.
fn single_field_is(req: &Request, name: &str, want: &[u8]) -> bool {
    let mut values = req.headers.get_all(name);
    matches!((values.next(), values.next()), (Some(v), None) if v.as_bytes() == want)
}

/// Serves one matched route: the shared checks of the module
/// documentation, then its handler.
pub(crate) async fn serve_route<B: Backend>(
    ctx: &Ctx<B>,
    route: &'static Route,
    req: Request,
) -> (Response, Outcome) {
    shared_checks(ctx, route, req).await.into_response()
}

async fn shared_checks<B: Backend>(ctx: &Ctx<B>, route: &'static Route, req: Request) -> Reply {
    let (method, _, _) = route.parts();
    if matches!(route.access(), Access::Unserved | Access::Loopback) {
        return Reply::refuse(StatusCode::NOT_FOUND, None, "route");
    }
    if matches!(method, "POST" | "DELETE")
        && !single_field_is(&req, "origin", ctx.cfg.origin.as_bytes())
    {
        return Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::Adr008), "origin");
    }
    if method == "POST" && !single_field_is(&req, "content-type", JSON.as_bytes()) {
        return Reply::refuse(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            Some(Rule::Adr008),
            "content_type",
        );
    }
    if req.body.len() > route.body_limit() {
        return Reply::refuse(StatusCode::CONTENT_TOO_LARGE, Some(Rule::Th26), "too_large");
    }
    let caller = if route.access().needs_session() {
        match caller(ctx, &req).await {
            Ok(c) => Some(c),
            Err(reply) => return reply,
        }
    } else {
        None
    };
    dispatch(ctx, route, &req, caller).await
}

/// Looks up the caller's session (step 4 of the module documentation).
async fn caller<B: Backend>(ctx: &Ctx<B>, req: &Request) -> Result<Caller, Reply> {
    let cookie = match read_session_cookie(ctx.cfg.cell, &req.headers) {
        Ok(Some(c)) => c,
        Ok(None) => return Err(no_session(Rule::Th05)),
        Err(CookieRefusal::OtherCell) => return Err(no_session(Rule::I19)),
        Err(CookieRefusal::Ambiguous | CookieRefusal::Malformed) => {
            return Err(no_session(Rule::Adr008));
        }
    };
    let digest = fstp_crypto::sha256(&cookie.token().0);
    let row = ctx
        .backend
        .session(digest)
        .await
        .map_err(unavailable)?
        .ok_or_else(|| no_session(Rule::Th05))?;
    let view = SessionView {
        id: row.id,
        account: row.account,
        method: row.method,
        started: row.started,
        last_used: row.last_used,
    };
    Ok(Caller { row, view })
}

async fn dispatch<B: Backend>(
    ctx: &Ctx<B>,
    route: &'static Route,
    req: &Request,
    caller: Option<Caller>,
) -> Reply {
    use crate::routes::{api, auth};
    match (route.endpoint(), caller) {
        (Endpoint::PasskeyLoginOptions, _) => auth::login_options(ctx, req).await,
        (Endpoint::PasskeyLogin, _) => auth::login(ctx, req).await,
        (Endpoint::MagicRequest, _) => auth::magic_request(ctx, req).await,
        (Endpoint::MagicConfirm, _) => auth::magic_confirm(),
        (Endpoint::MagicConsume, _) => auth::magic_consume(ctx, req).await,
        (
            Endpoint::InvitationOptions
            | Endpoint::InvitationRegister
            | Endpoint::SignupOptions
            | Endpoint::Signup
            | Endpoint::RecoveryRequest
            | Endpoint::RecoveryEmail
            | Endpoint::RecoveryComplete,
            _,
        ) => auth::not_built_ceremony(req),
        (Endpoint::StepUpOptions, Some(c)) => auth::stepup_options(ctx, req, &c).await,
        (Endpoint::StepUp, Some(c)) => auth::stepup(ctx, req, &c).await,
        (Endpoint::PasskeyOptions | Endpoint::PasskeyAdd, Some(c)) => {
            auth::add_passkey(ctx, req, &c).await
        }
        (Endpoint::Sessions, Some(c)) => auth::sessions(ctx, &c).await,
        (Endpoint::EndSession, Some(c)) => auth::end_session(ctx, req, &c).await,
        (Endpoint::Devices, Some(c)) => auth::devices(ctx, &c).await,
        (Endpoint::RemoveDevice, Some(c)) => auth::remove_device(ctx, req, &c).await,
        (Endpoint::RecoveryApprove, Some(c)) => auth::approve_recovery(ctx, req, &c).await,
        (Endpoint::Commands, Some(c)) => api::commands(ctx, req, &c).await,
        (Endpoint::VaultTickets, Some(c)) => api::vault_tickets(ctx, req, &c).await,
        (Endpoint::Verifications, Some(c)) => api::verifications(ctx, req, &c).await,
        (Endpoint::AuditAnchors, Some(c)) => api::anchors(ctx, &c).await,
        (Endpoint::Erasures, Some(c)) => api::erasures(ctx, &c).await,
        // A session route without a caller, the health route on the
        // tunnel, or an unserved route: never served.
        _ => Reply::refuse(StatusCode::NOT_FOUND, None, "route"),
    }
}

/// The state and an admitted action for the caller, through the gate
/// (design section 5.4). The step-up the request names is read from the
/// ledger's `StepUpGranted` record and its instant. A step-up the ledger
/// does not know is passed as none, so a high-risk action is refused.
/// On admission the session's last use is recorded.
pub(crate) async fn admit<B: Backend>(
    ctx: &Ctx<B>,
    caller: &Caller,
    action: Action,
    command_id: Option<[u8; 16]>,
    stepup: Option<[u8; 16]>,
) -> Result<(Arc<CellState>, Admitted), Reply> {
    let s = ctx.backend.state().await.map_err(unavailable)?;
    let now = ctx.backend.now();
    let view = match stepup.and_then(|id| s.auth().stepup_grant(id).map(|g| (id, g))) {
        None => None,
        Some((id, grant)) => {
            let asserted_at = ctx
                .backend
                .stepup_asserted_at(id)
                .await
                .map_err(unavailable)?
                .ok_or_else(|| unavailable(BackendFault::Unavailable))?;
            Some(StepUpView {
                id,
                session: grant.session,
                action_digest: grant.action_digest,
                asserted_at,
                // The ledger grants a step-up only after a passkey
                // assertion with user verification (design section 8.4).
                strong: true,
                consumed: s.auth().consumed(id),
            })
        }
    };
    let policy = LoginPolicy {
        stepup_freshness_us: P71_DEFAULT_US,
    };
    // The gate refuses a log read to anyone but an Auditor or a tenant
    // admin with `NotPermitted`. That refusal is logged under ADR-007.
    let log_read = matches!(
        action,
        Action::Read(ReadAction::ReadAudit | ReadAction::ReadErasureLog)
    );
    let admitted = match command_id {
        Some(id) => gate::admit_command(&s, &caller.view, action, id, view.as_ref(), now, &policy),
        None => gate::admit(&s, &caller.view, action, view.as_ref(), now, &policy),
    }
    .map_err(|d| match d {
        Deny::NotPermitted if log_read => {
            Reply::refuse(StatusCode::FORBIDDEN, Some(Rule::Adr007), "forbidden")
        }
        other => denied(other),
    })?;
    ctx.backend
        .touch_session(caller.row.id, now)
        .await
        .map_err(unavailable)?;
    Ok((s, admitted))
}

/// A fresh random array from the cell's random source.
pub(crate) fn random<const N: usize>() -> Result<[u8; N], Reply> {
    fstp_crypto::random_array::<N>().map_err(|_| unavailable(BackendFault::Unavailable))
}

/// A JSON string of lowercase hexadecimal.
pub(crate) fn hex_value(b: &[u8]) -> Value {
    Value::String(hex(b))
}

/// A JSON string of a decimal integer.
pub(crate) fn decimal(n: impl std::fmt::Display) -> Value {
    Value::String(n.to_string())
}

/// Runs an admitted command and answers with the new head.
pub(crate) async fn run<B: Backend>(ctx: &Ctx<B>, admitted: Admitted) -> Reply {
    match ctx.backend.execute(admitted).await {
        Err(f) => unavailable(f),
        Ok(Err(e)) => exec_failed(&e),
        Ok(Ok(done)) => {
            let mut o = Object::with_capacity(2);
            o.insert("duplicate", Value::Bool(done.duplicate.is_some()));
            o.insert("head", decimal(done.head.raw()));
            Reply::json(StatusCode::OK, &Value::Object(o))
        }
    }
}

/// Whether the batch of `c` needs an input that only a route holds and
/// that `fstp_cell_core::decide` cannot take yet (`RouteInput`). Such a
/// command fails closed with 501 before it reaches the engine.
pub(crate) fn needs_route_input(c: &CellCommand) -> bool {
    match c {
        CellCommand::Auth(a) => !fstp_cell_core::route_inputs(a).is_empty(),
        _ => false,
    }
}
