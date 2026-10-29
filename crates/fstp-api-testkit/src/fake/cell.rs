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
