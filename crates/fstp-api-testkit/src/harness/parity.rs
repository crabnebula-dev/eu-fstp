//! The runner of M-PARITY (I-84, M4 design section 8.5). Lane m4/parity.
//!
//! [`ParityRunner::run`] runs one MCP cell and its web twin on clean
//! worlds of the matrix harness, as the MCP channel runs them:
//!
//! - the web twin through the HTTP routes of `fstp-web`, with a fresh
//!   step-up where the twin asks for one;
//! - the MCP cell through the `tools/call` handler of
//!   `fstp_mcp::McpServer`, with the cell's bearer token.
//!
//! When the MCP call stores a pending action, the same world confirms it
//! through the web. The account reads the new action's id and digest from
//! `pending.list`, and posts the confirmation with that digest through the
//! HTTP routes in a passkey session. A step-up challenge is answered in
//! that session, and the confirmation is sent again.
//!
//! The runner reads no `fstp-access` rule and no reference rule. The model
//! decides which property applies to a pair.

use super::*;

/// What one MCP cell and its web twin gave.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PairRun {
    /// The web twin, on a clean world.
    pub web: Observed,
    /// The MCP cell, on a clean world.
    pub mcp: Observed,
    /// The web confirmation of the pending action the MCP cell stored, on
    /// the MCP cell's world. `None` when the MCP cell stored none.
    pub confirmed: Option<Observed>,
}

/// The world cache of M-PARITY: one runner of the MCP transport, so a
/// web cell goes through the HTTP routes and an MCP cell through the MCP
/// server.
pub struct ParityRunner {
    runner: Runner,
}

impl std::fmt::Debug for ParityRunner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("ParityRunner")
    }
}

impl Default for ParityRunner {
    fn default() -> ParityRunner {
        ParityRunner::new()
    }
}

impl ParityRunner {
    /// A runner with an empty world cache.
    pub fn new() -> ParityRunner {
        ParityRunner {
            runner: Runner::new(Transport::Mcp),
        }
    }

    /// Runs `web`, then `mcp`, each on a clean world, and confirms the
    /// pending action `mcp` stored, if any. `web` must be a web cell and
    /// `mcp` an MCP cell of the same world.
    pub fn run(&mut self, mcp: &Cell, web: &Cell) -> Result<PairRun, ChannelFault> {
        if !matches!(mcp.session.channel, Via2::Mcp { .. })
            || web.session.channel != Via2::Web
            || WorldKey::of(mcp) != WorldKey::of(web)
        {
            return Err(ChannelFault::Setup(format!(
                "not an MCP cell and its web twin: {mcp:?}, {web:?}"
            )));
        }
        let web = observe_with(&mut self.runner, web)?;
        let (mcp, confirmed) = self.mcp(mcp)?;
        Ok(PairRun {
            web,
            mcp,
            confirmed,
        })
    }

    /// Runs the MCP cell, again on a rebuilt world once if a rate limit
    /// refused it, as [`observe_with`] does.
    fn mcp(&mut self, cell: &Cell) -> Result<(Observed, Option<Observed>), ChannelFault> {
        let first = self.mcp_once(cell);
        let limited = matches!(
            &first,
            Ok((Observed::Refused(Some(r)), _)) if r == "rate" || r == "H-07"
        );
        if !limited {
            return first;
        }
        if let Some(Ok(w)) = self.runner.worlds.get_mut(&WorldKey::of(cell)) {
            w.dirty = true;
        }
        self.mcp_once(cell)
    }

    /// Runs the MCP cell once on a clean world, and confirms the pending
    /// action it stored through the web on the same world.
    fn mcp_once(&mut self, cell: &Cell) -> Result<(Observed, Option<Observed>), ChannelFault> {
        let key = WorldKey::of(cell);
        let w = self
            .runner
            .world(key)
            .map_err(|e| ChannelFault::Setup(format!("world {key:?}: {e}")))?;
        let account = account_of(cell.who);
        let before = match account {
            Some(a) => pending_of(w, a)?,
            None => BTreeMap::new(),
        };
        let result = run_on(w, cell, Transport::Mcp);
        let changed = w.ports.engine.head() != w.head
            || match &result {
                Ok(Observed::Completed) if port_confined(cell.op) => false,
                Ok(Observed::Completed | Observed::Pending) => !is_read(cell.op),
                _ => false,
            };
        if changed {
            w.dirty = true;
        }
        let observed = result?;
        if observed != Observed::Pending {
            return Ok((observed, None));
        }
        w.dirty = true;
        let a = account.ok_or_else(|| {
            ChannelFault::Setup(format!("a pending action without an account: {cell:?}"))
        })?;
        let fresh: Vec<(String, String)> = pending_of(w, a)?
            .into_iter()
            .filter(|(id, _)| !before.contains_key(id))
            .collect();
        let [(id, digest)] = fresh.as_slice() else {
            return Err(ChannelFault::Setup(format!(
                "{} new pending actions after {cell:?}, one wanted",
                fresh.len()
            )));
        };
        let confirmed = confirm(w, a, id, digest)?;
        Ok((Observed::Pending, Some(confirmed)))
    }
}

/// The pending actions `account` sees through `pending.list`, as id and
/// digest, both as the wire spells them.
fn pending_of(w: &mut Built, account: AccountId) -> Result<BTreeMap<String, String>, ChannelFault> {
    let fault = |e: String| ChannelFault::Setup(format!("pending.list: {e}"));
    let login = w.ports.sessions.login(account, LoginMethod::Passkey);
    let r = decode_route(ApiMethod::Get, "/me/pending-actions", &[]).and_then(|op| {
        block_on(w.core.dispatch(
            Credential::SessionCookie(login.cookie),
            &RequestHead::new(),
            op,
        ))
    });
    let body = match r {
        Ok(OpResult::Done { body, .. }) => body.to_json(),
        other => return Err(fault(format!("{other:?}"))),
    };
    let rows = body
        .as_array()
        .ok_or_else(|| fault(format!("not a list: {}", body.to_compact())))?;
    let mut out = BTreeMap::new();
    for row in rows {
        match (str_member(row, "id"), str_member(row, "digest")) {
            (Some(id), Some(digest)) => {
                out.insert(id, digest);
            }
            _ => {
                return Err(fault(format!(
                    "a row without id or digest: {}",
                    row.to_compact()
                )));
            }
        }
    }
    Ok(out)
}

/// Confirms the pending action `id` of `account` through the HTTP routes
/// with the digest it was shown, in a passkey session, answering a step-up
/// challenge in that session (I-78, I-85).
fn confirm(
    w: &mut Built,
    account: AccountId,
    id: &str,
    digest: &str,
) -> Result<Observed, ChannelFault> {
    let login = w.ports.sessions.login(account, LoginMethod::Passkey);
    let cred = Credential::SessionCookie(login.cookie.clone());
    let mut body = Object::new();
    let _ = body.insert("shown", s(digest));
    let req = Request {
        op: "pending.confirm",
        method: ApiMethod::Post,
        path: format!("/pending-actions/{id}/confirmation"),
        body,
        params: Object::new(),
    };
    let mut reply = http_call(w, &req, &cred)?;
    if let Some(challenge) = reply.challenge() {
        w.ports
            .step_up
            .approve(login.session, challenge)
            .map_err(|e| ChannelFault::Setup(format!("step-up: {e:?}")))?;
        reply = http_call(w, &req, &cred)?;
    }
    match reply {
        Reply::Http(status, body) => observed_of_http(status, &body),
        Reply::Direct(r) => observed_of_result(&r),
        Reply::Mcp(..) => Err(ChannelFault::Setup(
            "the confirmation went through MCP".to_owned(),
        )),
    }
}
