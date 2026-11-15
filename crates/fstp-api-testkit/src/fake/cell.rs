//! A cell of fake ports behind one `ApiCore`, the way `fstp-cell` builds
//! one from its real ports, with helpers that drive dispatch.

use fstp_api_core::meta::Scope;
use fstp_api_core::port::{AgentClientId, LoginMethod, api_core};
use fstp_api_core::{
    ApiCore, ApiError, Credential, ErrorCode, Op, OpResult, PendingView, ReadModel, RequestHead,
};
use fstp_domain::id::AccountId;
use fstp_rt::future::block_on;

use super::fixture::{self, World};
use super::requests;
use super::{FakePorts, WebLogin, port_seams};
use crate::NotImplemented;

/// What one call gave, as the I-85 tests compare it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Class {
    /// `OpResult::Done`.
    Done,
    /// `OpResult::Pending`.
    Pending,
    /// `OpResult::StepUpRequired`.
    StepUpRequired,
    /// `OpResult::StrongMethodRequired`.
    StrongMethodRequired,
    /// `ApiError::Refused` with this code.
    Refused(ErrorCode),
    /// `ApiError::NotImplemented`: a stub answered.
    Stub,
}

impl Class {
    /// Whether the call completed.
    pub const fn completed(self) -> bool {
        matches!(self, Class::Done)
    }

    /// Whether the call was refused.
    pub const fn refused(self) -> bool {
        matches!(self, Class::Refused(_))
    }
}

/// The class of `r`.
pub fn class(r: &Result<OpResult, ApiError>) -> Class {
    match r {
        Ok(OpResult::Done { .. }) => Class::Done,
        Ok(OpResult::Pending(_)) => Class::Pending,
        Ok(OpResult::StepUpRequired(_)) => Class::StepUpRequired,
        Ok(OpResult::StrongMethodRequired) => Class::StrongMethodRequired,
        Err(ApiError::Refused { code, .. }) => Class::Refused(*code),
        Err(ApiError::NotImplemented(_)) => Class::Stub,
    }
}

/// One cell: an `ApiCore` over [`FakePorts`], and the ports themselves.
pub struct FakeCell {
    core: ApiCore,
    /// The ports, shared with the `ApiCore`.
    pub ports: FakePorts,
}

impl std::fmt::Debug for FakeCell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FakeCell")
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

impl FakeCell {
    /// A cell over the I-85 world.
    ///
    /// It refuses until `port.rs` can build `TenantSettings` and
    /// `NoticePage` (see [`port_seams`]).
    pub fn new() -> Result<FakeCell, NotImplemented> {
        let world = fixture::pending_world().map_err(|_| {
            NotImplemented::new(
                "fstp_api_testkit::fake::FakeCell::new: the I-85 world did not build",
            )
        })?;
        FakeCell::from_world(&world)
    }

    /// A cell over `world`. It refuses as [`FakeCell::new`] does.
    pub fn from_world(world: &World) -> Result<FakeCell, NotImplemented> {
        let seams = port_seams()?;
        let ports = FakePorts::new(world, seams)?;
        Ok(FakeCell {
            core: api_core(ports.clone()),
            ports,
        })
    }

    /// The cell after a restart: a fresh engine replays a copy of this
    /// cell's ledger, over copies of its texts, blobs and sealed values,
    /// and a fresh API core holds nothing in memory. A held import value
    /// is gone, as the ledger keeps only its digest.
    pub fn restarted(&self) -> Result<FakeCell, NotImplemented> {
        let world = World {
            store: self.ports.engine.store_copy(),
            truth: self.ports.vault.truth(),
            start: self.ports.clock.read(),
            admins: self.ports.tenant.admins(),
        };
        let cell = FakeCell::from_world(&world)?;
        cell.ports.texts.copy_from(&self.ports.texts);
        cell.ports.blobs.copy_from(&self.ports.blobs);
        cell.ports.sealer.copy_from(&self.ports.sealer);
        cell.ports.workspaces.copy_from(&self.ports.workspaces);
        cell.ports.ids.continue_from(&self.ports.ids);
        Ok(cell)
    }

    /// The API core, for reads that need no credential (M9 lane B2).
    pub fn core(&self) -> &ApiCore {
        &self.core
    }

    /// Logs `account` in through the web with `method`.
    pub fn login(&self, account: AccountId, method: LoginMethod) -> WebLogin {
        self.ports.sessions.login(account, method)
    }

    /// Issues an MCP token for `client` of `account` with `scopes`,
    /// consented in a session that logged in with `method`.
    pub fn token(
        &self,
        account: AccountId,
        client: AgentClientId,
        scopes: impl IntoIterator<Item = Scope>,
        method: LoginMethod,
    ) -> Vec<u8> {
        self.ports.tokens.issue(account, client, scopes, method)
    }

    /// Dispatches `op` with `cred`. A decode error is returned as is.
    pub fn call(&self, cred: Credential, op: Result<Op, ApiError>) -> Result<OpResult, ApiError> {
        let op = op?;
        block_on(self.core.dispatch(cred, &RequestHead::new(), op))
    }

    /// Dispatches `op` through the web session of `login`.
    pub fn web(&self, login: &WebLogin, op: Result<Op, ApiError>) -> Result<OpResult, ApiError> {
        self.call(Credential::SessionCookie(login.cookie.clone()), op)
    }

    /// Founds the organisation of a cell whose ledger holds the tenant
    /// part, through real onboarding and activation (ADR-021, SoD-07,
    /// SoD-14, SoD-15, SoD-18): `first` grants both signatory roles to
    /// `signatory`, saves every step the cell requires with the synthetic
    /// values of [`crate::harness::onboarding_step_values`] and completes
    /// onboarding. Then `first` requests the activation and `second`
    /// approves it. Both must be verified tenant admins of the ledger.
    /// Every high-risk call completes its step-up in the same session.
    pub fn found(
        &self,
        first: AccountId,
        second: AccountId,
        signatory: AccountId,
    ) -> Result<(), String> {
        self.found_with_model(first, second, signatory, "placeholder-model")
    }

    /// [`FakeCell::found`], with `model` as the P-21 primary model of the
    /// Inference step, which a publication pins.
    pub fn found_with_model(
        &self,
        first: AccountId,
        second: AccountId,
        signatory: AccountId,
        model: &str,
    ) -> Result<(), String> {
        use fstp_api_core::decode::{Method, decode_route};
        use fstp_json::{ToJson, Value};
        let l1 = self.login(first, LoginMethod::Passkey);
        let l2 = self.login(second, LoginMethod::Passkey);
        let run = |l: &WebLogin, method: Method, path: &str, body: &str| -> Result<Value, String> {
            let send = || self.web(l, decode_route(method, path, body.as_bytes()));
            let r = match send() {
                Ok(OpResult::StepUpRequired(ch)) => {
                    self.ports
                        .step_up
                        .approve(l.session, ch.action)
                        .map_err(|e| format!("{path}: the step-up: {e:?}"))?;
                    send()
                }
                other => other,
            };
            match r {
                Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
                other => Err(format!("{method:?} {path}: {other:?}")),
            }
        };
        let member = |v: &Value, k: &str| -> Result<String, String> {
            v.as_object()
                .and_then(|o| o.get(k))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or_else(|| format!("no {k} in {}", v.to_compact()))
        };
        for role in ["financial_signatory", "legal_signatory"] {
            let body = format!(r#"{{"account":"{}","role":"{role}"}}"#, signatory.raw());
            run(&l1, Method::Post, "/admin/signatories", &body)?;
        }
        let admins = [first, second];
        for name in crate::harness::ONBOARDING_STEP_NAMES {
            let path = format!("/admin/onboarding/{name}");
            let view = run(&l1, Method::Get, &path, "")?;
            if member(&view, "status")? == "skipped" {
                continue;
            }
            if name == "payments" {
                run(
                    &l1,
                    Method::Put,
                    "/admin/settings/payment-mode",
                    r#"{"value":"record_only"}"#,
                )?;
            }
            let view = run(&l1, Method::Get, &path, "")?;
            let base = member(&view, "revision")?;
            let mut values = crate::harness::onboarding_step_values(name, first, &admins);
            if name == "inference"
                && let Value::Object(o) = &mut values
            {
                let _ = o.insert("primary", Value::from(model));
            }
            let body = format!(r#"{{"base":"{base}","values":{}}}"#, values.to_compact());
            let saved = run(&l1, Method::Put, &path, &body)?;
            if member(&saved, "outcome")? != "validated" {
                return Err(format!("onboarding step {name}: {}", saved.to_compact()));
            }
        }
        run(&l1, Method::Post, "/admin/onboarding/complete", "{}")?;
        run(&l1, Method::Post, "/admin/activation", "{}")?;
        let view = run(&l1, Method::Get, "/admin/activation", "")?;
        let request = member(&view, "request")?;
        run(
            &l2,
            Method::Post,
            "/admin/activation/approval",
            &format!(r#"{{"request":"{request}"}}"#),
        )?;
        Ok(())
    }

    /// Dispatches `op` through MCP with the bearer token `token`.
    pub fn mcp(&self, token: &[u8], op: Result<Op, ApiError>) -> Result<OpResult, ApiError> {
        self.call(Credential::Bearer(token.to_vec()), op)
    }

    /// The pending actions `login` sees through `pending.list`.
    pub fn pending(&self, login: &WebLogin) -> Result<Vec<PendingView>, String> {
        match self.web(login, requests::pending_list()) {
            Ok(OpResult::Done {
                body: ReadModel::PendingActions(list),
                ..
            }) => Ok(list),
            other => Err(format!("pending.list gave {other:?}")),
        }
    }
}
