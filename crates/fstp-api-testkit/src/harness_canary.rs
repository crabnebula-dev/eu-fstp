//! The I-86 canary crawl over the matrix worlds (M4 design section 8.4).
//! Built by lane m4/i86.
//!
//! A [`CrawlWorld`] is the matrix world of one state profile, every
//! proposal state included, with the canaries of a [`CanaryVault`] planted
//! over the whole cast. [`CrawlWorld::crawl`] calls every MCP tool for
//! every principal of the matrix through `fstp_mcp::McpServer`, with the
//! arguments the matrix sends for that cell, and keeps every answer as
//! text: the result or the JSON-RPC error. Anonymous calls go to
//! `/mcp/public`, and each principal's `tools/list` is kept too.
//!
//! A completed write changes the world, so later calls of the same crawl
//! see the changed world. The crawl judges leaks, not outcomes.

use super::*;
use crate::canary::CanaryVault;

/// One answer of the crawl.
#[derive(Clone, Debug)]
pub struct CrawlAnswer {
    /// Where it came from: principal, surface and tool.
    pub at: String,
    /// The answer as text: the compact JSON result, or the error.
    pub text: String,
    /// Whether the call completed without an error result.
    pub completed: bool,
}

/// The matrix world of one state profile with the canaries planted.
pub struct CrawlWorld {
    w: Built,
    state: StateProfile,
    vault: CanaryVault,
    /// The audit entries written before the crawl.
    audit_from: usize,
    /// Teeth only: whether the mutant read model is planted.
    mutant: bool,
}

impl std::fmt::Debug for CrawlWorld {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CrawlWorld").finish_non_exhaustive()
    }
}

/// The canary vault over the whole cast of the matrix worlds.
pub fn cast_vault() -> CanaryVault {
    CanaryVault::over(CAST)
}

impl CrawlWorld {
    /// The SUPERSAFE world of `state`, with `vault`'s canaries planted.
    pub fn new(state: StateProfile, vault: &CanaryVault) -> Result<CrawlWorld, String> {
        let w = build(WorldKey {
            state,
            policy: Policy::SUPERSAFE,
            variant: Variant::Main,
        })?;
        vault.plant(&w.ports.vault, &w.ports.accounts);
        let audit_from = w.ports.audit.entries().len();
        Ok(CrawlWorld {
            w,
            state,
            vault: vault.clone(),
            audit_from,
            mutant: false,
        })
    }

    /// Teeth only: plants a mutant read model. Every completed read adds
    /// a vault field to its data: the caller's vault identity number, as
    /// a read model that joined a vault row would. The mutant lives in this
    /// test crate only and changes no production code.
    pub fn plant_identity_field_mutant(&mut self) {
        self.mutant = true;
    }

    /// The MCP server over this world's core.
    fn server(&mut self) -> Result<(), String> {
        if self.w.mcp.is_none() {
            let server = fstp_mcp::McpServer::new(
                Arc::clone(&self.w.core),
                fstp_mcp::McpConfig {
                    tenant_origins: vec![ORIGIN.to_owned()],
                    verified_domain: "tenant.fstp.test".to_owned(),
                    resource_metadata_url: format!(
                        "{ORIGIN}{}",
                        fstp_oauth::RESOURCE_METADATA_PATH
                    ),
                },
            )
            .map_err(|e| format!("MCP server: {e}"))?;
            self.w.mcp = Some(server);
        }
        Ok(())
    }

    /// Calls every tool for every principal of the matrix, and lists the
    /// tools for each, in this world.
    pub fn crawl(&mut self) -> Result<Vec<CrawlAnswer>, String> {
        self.server()?;
        let mut out = Vec::new();
        let tools: Vec<&'static fstp_access::OpSpec> = fstp_access::OPS
            .iter()
            .filter(|o| o.tool.is_some())
            .collect();
        for who in Who::ALL {
            let account = account_of(who);
            let (surface, list_cred) = match account {
                None => (fstp_mcp::Surface::Public, Credential::None),
                Some(a) => (fstp_mcp::Surface::Mcp, self.bearer(a)),
            };
            let server = self.w.mcp.as_ref().ok_or("no MCP server")?;
            let l = block_on(server.list_tools(surface, list_cred));
            out.push(answer(format!("{who:?} tools/list"), &l));
            for op in &tools {
                let Some(tool) = op.tool else { continue };
                let now = Timestamp::from_micros(self.w.now);
                self.w.ports.clock.set(now);
                let cell = Cell {
                    op: op.name,
                    who,
                    state: self.state,
                    policy: Policy::SUPERSAFE,
                    session: crate::reference::authz::Session {
                        login: account.map(|_| Login::Passkey),
                        step_up: StepUp::Absent,
                        channel: Via2::Mcp { scope: true },
                    },
                };
                let args = match request_of(&cell, &self.w, None) {
                    Ok(req) => req.tool_args(),
                    // A cell the world gives no target to: the tool is
                    // still called, with no arguments.
                    Err(_) => b"{}".to_vec(),
                };
                let cred = match account {
                    None => Credential::None,
                    Some(a) => self.bearer(a),
                };
                let server = self.w.mcp.as_ref().ok_or("no MCP server")?;
                let mut r = block_on(server.call_tool(surface, cred, tool.name, &args));
                if self.mutant
                    && is_read(op.name)
                    && let (Ok(v), Some(t)) = (&mut r, account.and_then(|a| self.vault.tag(a)))
                {
                    add_vault_field(v, t.raw());
                }
                out.push(answer(format!("{who:?} {surface:?} {}", tool.name), &r));
            }
        }
        Ok(out)
    }

    /// A fresh bearer token of `a` with every scope, consented in a passkey
    /// session. The caller's other agent client holds a token too, so a
    /// revocation never touches this one (as `run_on` does).
    fn bearer(&self, a: AccountId) -> Credential {
        let _ = self
            .w
            .ports
            .tokens
            .issue(a, other_agent_of(a), Vec::new(), LoginMethod::Passkey);
        Credential::Bearer(self.w.ports.tokens.issue(
            a,
            agent_of(a),
            Scope::ALL,
            LoginMethod::Passkey,
        ))
    }

    /// The logs the cell wrote since the canaries were planted, one line
    /// each: the audit entries, which record every MCP call and refusal,
    /// and the ledger records the calls appended.
    pub fn logs(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for (i, e) in self
            .w
            .ports
            .audit
            .entries()
            .iter()
            .enumerate()
            .skip(self.audit_from)
        {
            out.push((format!("audit entry {i}"), format!("{e:?}")));
        }
        let store = self.w.ports.engine.store_copy();
        let mut entries = Vec::new();
        let from = fstp_ledger::Seq::from_raw(self.w.head.raw().saturating_add(1));
        if store.read(from, usize::MAX, &mut entries).is_ok() {
            for e in entries {
                out.push((
                    format!("ledger record {:?}", e.seq),
                    format!("{:?}", e.record),
                ));
            }
        }
        out
    }

    /// The canary vault of the world.
    pub fn vault(&self) -> &CanaryVault {
        &self.vault
    }
}

/// One crawl answer of `r`.
fn answer(at: String, r: &Result<Value, fstp_mcp::RpcError>) -> CrawlAnswer {
    match r {
        Ok(v) => {
            let error = v
                .as_object()
                .and_then(|o| o.get("isError"))
                .and_then(Value::as_bool)
                .unwrap_or(false);
            CrawlAnswer {
                at,
                text: v.to_compact(),
                completed: !error,
            }
        }
        Err(e) => CrawlAnswer {
            at,
            text: format!("{}: {}", e.code, e.message),
            completed: false,
        },
    }
}

/// The mutant read model of the teeth test: the `data` of a completed
/// read gains the member `identity` with the vault identity number `n`.
/// In an array of rows, the first row gains it.
fn add_vault_field(v: &mut Value, n: u64) {
    let Some(sc) = v.as_object_mut() else { return };
    if sc.get("isError").and_then(Value::as_bool) == Some(true) {
        return;
    }
    let Some(data) = sc
        .get_mut("structuredContent")
        .and_then(Value::as_object_mut)
        .and_then(|s| s.get_mut("data"))
    else {
        return;
    };
    let row = match data {
        Value::Object(o) => Some(o),
        Value::Array(a) => a.iter_mut().find_map(Value::as_object_mut),
        _ => None,
    };
    if let Some(o) = row {
        let _ = o.insert("identity", Value::String(n.to_string()));
    }
}
