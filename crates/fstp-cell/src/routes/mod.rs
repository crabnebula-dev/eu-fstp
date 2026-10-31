//! The route table and the route handlers (design sections 5.4 and 8.7,
//! I-77, I-78, H-01).
//!
//! [`table`] lists every route of design section 8.7, each with its risk
//! class, its access class, its handler and its body limit. `Route::new`
//! takes a risk class with no default, so a route without one does not
//! compile (I-78). A route built with `Route::new` alone has no access
//! class and no handler, so the front never serves it. Only
//! [`Route::served`] builds a served route, and it takes every class.
//!
//! [`RiskClass`] keeps the two W0 variants. A route that design section
//! 8.7 marks high risk names its `HighRiskAction`. Every other route is
//! `Normal`, including `POST /api/v1/commands` and
//! `POST /api/v1/vault-tickets`, whose commands the gate classes one by
//! one through `HighRiskAction::of`. [`Access`] carries the other classes
//! of the section: public, ceremony, session, and the rest.
//!
//! The handlers reach the cell runtime only through [`Backend`].

mod api;
mod auth;
pub mod backend;
mod handle;
/// Test only: the in-memory backend and the local cell. Built only with
/// the `memory` feature, which no shipped build enables, so the
/// `fstp-cell` binary never contains a `LocalCell` (design section 14.3).
#[cfg(feature = "memory")]
pub mod memory;
/// The route backend of a serving cell over its engine and its application
/// database (lane int5).
pub mod pg;

pub use auth::{CHALLENGE_US, MAGIC_LINK_US};
pub use backend::{
    AnchorRow, Backend, BackendFault, ChallengePurpose, ChallengeRow, ErasureRow, SessionRow,
    TokenKind, TokenRow,
};
pub(crate) use handle::{CellCfg, Ctx, Outcome, Rule, serve_route};

use fstp_cell_core::gate::HighRiskAction;

/// The risk class of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RiskClass {
    /// A read or a low-risk command.
    Normal,
    /// A high-risk action that needs a step-up.
    HighRisk(fstp_cell_core::gate::HighRiskAction),
}

/// Who may reach a route, beside its risk class (design section 8.7).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    /// No session.
    Public,
    /// A first-passkey ceremony (design section 8.3). No session.
    Ceremony,
    /// A session.
    Session,
    /// A session. The gate classes each command through
    /// `HighRiskAction::of`.
    PerCommand,
    /// A session. A download scope is `IdentityDownload` (ADR-008).
    SessionOrIdentityDownload,
    /// A session of an Auditor or a tenant admin (ADR-007, G30).
    AuditorOrAdmin,
    /// A session of a tenant admin with a verified identity (ADR-008).
    VerificationTicket,
    /// The loopback health listener only (ADR-009).
    Loopback,
    /// No access class: a route built with `Route::new` alone. It is never
    /// served.
    Unserved,
}

impl Access {
    /// Whether the class needs a session.
    pub const fn needs_session(self) -> bool {
        !matches!(
            self,
            Access::Public | Access::Ceremony | Access::Loopback | Access::Unserved
        )
    }
}

/// The handler of a route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Endpoint {
    /// `POST /auth/invitations/{token}/register/options`.
    InvitationOptions,
    /// `POST /auth/invitations/{token}/register`.
    InvitationRegister,
    /// `POST /auth/signup/options`.
    SignupOptions,
    /// `POST /auth/signup`.
    Signup,
    /// `POST /auth/passkey/login/options`.
    PasskeyLoginOptions,
    /// `POST /auth/passkey/login`.
    PasskeyLogin,
    /// `POST /auth/magic/request`.
    MagicRequest,
    /// `GET /auth/magic`.
    MagicConfirm,
    /// `POST /auth/magic/consume`.
    MagicConsume,
    /// `POST /auth/stepup/options`.
    StepUpOptions,
    /// `POST /auth/stepup`.
    StepUp,
    /// `POST /auth/passkeys/options`.
    PasskeyOptions,
    /// `POST /auth/passkeys`.
    PasskeyAdd,
    /// `GET /auth/sessions`.
    Sessions,
    /// `DELETE /auth/sessions/{id}`.
    EndSession,
    /// `GET /auth/devices`.
    Devices,
    /// `DELETE /auth/devices/{id}`.
    RemoveDevice,
    /// `POST /auth/recovery`.
    RecoveryRequest,
    /// `POST /auth/recovery/{case}/email`.
    RecoveryEmail,
    /// `POST /auth/recovery/{case}/approve`.
    RecoveryApprove,
    /// `POST /auth/recovery/{case}/complete`.
    RecoveryComplete,
    /// `POST /api/v1/commands`.
    Commands,
    /// `POST /api/v1/vault-tickets`.
    VaultTickets,
    /// `POST /api/v1/verifications`.
    Verifications,
    /// `GET /api/v1/audit/anchors`.
    AuditAnchors,
    /// `GET /api/v1/erasures`.
    Erasures,
    /// `GET /healthz`.
    Health,
    /// A page path of the compiled auth pages: the shell
    /// ([`page_table`]).
    PageShell,
    /// `GET /assets/auth/{file}`: a compiled module or a stylesheet
    /// ([`page_table`]).
    PageAsset,
    /// `GET /assets/auth/pages/{file}`: a compiled page module
    /// ([`page_table`]).
    PageModule,
    /// No handler: a route built with `Route::new` alone.
    Unserved,
}

/// One route.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Route {
    method: &'static str,
    path: &'static str,
    risk: RiskClass,
    access: Access,
    endpoint: Endpoint,
    body_limit: usize,
}

impl Route {
    /// A route with its risk class. It has no access class and no
    /// handler, so the front never serves it ([`Route::served`]).
    pub const fn new(method: &'static str, path: &'static str, risk: RiskClass) -> Route {
        Route {
            method,
            path,
            risk,
            access: Access::Unserved,
            endpoint: Endpoint::Unserved,
            body_limit: 0,
        }
    }

    /// A served route with its risk class, access class, handler and body
    /// limit in bytes.
    pub const fn served(
        method: &'static str,
        path: &'static str,
        risk: RiskClass,
        access: Access,
        endpoint: Endpoint,
        body_limit: usize,
    ) -> Route {
        Route {
            method,
            path,
            risk,
            access,
            endpoint,
            body_limit,
        }
    }

    /// The method, path and risk class.
    pub fn parts(&self) -> (&'static str, &'static str, RiskClass) {
        (self.method, self.path, self.risk)
    }

    /// The access class.
    pub const fn access(&self) -> Access {
        self.access
    }

    /// The handler.
    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    /// The body limit in bytes. A GET or DELETE route takes no body.
    pub const fn body_limit(&self) -> usize {
        self.body_limit
    }

    /// The step-up action the route always needs, if any.
    pub const fn high_risk(&self) -> Option<HighRiskAction> {
        match self.risk {
            RiskClass::HighRisk(a) => Some(a),
            RiskClass::Normal => None,
        }
    }
}

/// The body limit of an auth route that carries ids, a token or one
/// assertion.
pub const AUTH_BODY_LIMIT: usize = 16 * 1024;

/// The body limit of a ceremony that carries a registration: an
/// attestation object of at most 64 KiB of CBOR (ADR-008 "Constants") and
/// its client data, both as hexadecimal.
pub const CEREMONY_BODY_LIMIT: usize = 320 * 1024;

/// The body limit of the API routes that take a command.
pub const API_BODY_LIMIT: usize = crate::http::COMMAND_BODY_LIMIT;

use Access as A;
use Endpoint as E;
use HighRiskAction as H;
use RiskClass::{HighRisk, Normal};

/// Every route of design section 8.7.
static TABLE: [Route; 27] = [
    Route::served(
        "POST",
        "/auth/invitations/{token}/register/options",
        Normal,
        A::Ceremony,
        E::InvitationOptions,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/invitations/{token}/register",
        Normal,
        A::Ceremony,
        E::InvitationRegister,
        CEREMONY_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/signup/options",
        Normal,
        A::Ceremony,
        E::SignupOptions,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/signup",
        Normal,
        A::Ceremony,
        E::Signup,
        CEREMONY_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/passkey/login/options",
        Normal,
        A::Public,
        E::PasskeyLoginOptions,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/passkey/login",
        Normal,
        A::Public,
        E::PasskeyLogin,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/magic/request",
        Normal,
        A::Public,
        E::MagicRequest,
        AUTH_BODY_LIMIT,
    ),
    Route::served("GET", "/auth/magic", Normal, A::Public, E::MagicConfirm, 0),
    Route::served(
        "POST",
        "/auth/magic/consume",
        Normal,
        A::Public,
        E::MagicConsume,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/stepup/options",
        Normal,
        A::Session,
        E::StepUpOptions,
        API_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/stepup",
        Normal,
        A::Session,
        E::StepUp,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/passkeys/options",
        HighRisk(H::AddPasskey),
        A::Session,
        E::PasskeyOptions,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/passkeys",
        HighRisk(H::AddPasskey),
        A::Session,
        E::PasskeyAdd,
        CEREMONY_BODY_LIMIT,
    ),
    Route::served("GET", "/auth/sessions", Normal, A::Session, E::Sessions, 0),
    Route::served(
        "DELETE",
        "/auth/sessions/{id}",
        Normal,
        A::Session,
        E::EndSession,
        0,
    ),
    Route::served("GET", "/auth/devices", Normal, A::Session, E::Devices, 0),
    Route::served(
        "DELETE",
        "/auth/devices/{id}",
        HighRisk(H::ChangeLoginMethods),
        A::Session,
        E::RemoveDevice,
        0,
    ),
    Route::served(
        "POST",
        "/auth/recovery",
        Normal,
        A::Public,
        E::RecoveryRequest,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/recovery/{case}/email",
        Normal,
        A::Public,
        E::RecoveryEmail,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/recovery/{case}/approve",
        HighRisk(H::ApproveRecovery),
        A::Session,
        E::RecoveryApprove,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/auth/recovery/{case}/complete",
        Normal,
        A::Ceremony,
        E::RecoveryComplete,
        CEREMONY_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/api/v1/commands",
        Normal,
        A::PerCommand,
        E::Commands,
        API_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/api/v1/vault-tickets",
        Normal,
        A::SessionOrIdentityDownload,
        E::VaultTickets,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "POST",
        "/api/v1/verifications",
        Normal,
        A::VerificationTicket,
        E::Verifications,
        AUTH_BODY_LIMIT,
    ),
    Route::served(
        "GET",
        "/api/v1/audit/anchors",
        Normal,
        A::AuditorOrAdmin,
        E::AuditAnchors,
        0,
    ),
    Route::served(
        "GET",
        "/api/v1/erasures",
        Normal,
        A::AuditorOrAdmin,
        E::Erasures,
        0,
    ),
    Route::served("GET", "/healthz", Normal, A::Loopback, E::Health, 0),
];

/// Every route of the cell, with its classes (design section 8.7).
pub fn table() -> &'static [Route] {
    &TABLE
}

/// The routes of the compiled auth pages of design section 11.2
/// (`crate::http::pages`). Each is a `GET` with no body, no session and
/// no state change, so its risk class is `Normal` and its access class
/// `Public`. Like every route, each row names its risk class (I-78).
static PAGE_TABLE: [Route; 7] = [
    Route::served("GET", "/auth/login", Normal, A::Public, E::PageShell, 0),
    Route::served("GET", "/auth/signup", Normal, A::Public, E::PageShell, 0),
    Route::served("GET", "/auth/invite", Normal, A::Public, E::PageShell, 0),
    Route::served("GET", "/auth/recovery", Normal, A::Public, E::PageShell, 0),
    Route::served("GET", "/auth/account", Normal, A::Public, E::PageShell, 0),
    Route::served(
        "GET",
        "/assets/auth/{file}",
        Normal,
        A::Public,
        E::PageAsset,
        0,
    ),
    Route::served(
        "GET",
        "/assets/auth/pages/{file}",
        Normal,
        A::Public,
        E::PageModule,
        0,
    ),
];

/// The page routes, with their classes (design section 11.2).
///
/// They are not rows of [`table`]. Design section 8.7 lists
/// `GET /auth/magic` as the only page of the cell, while section 11.2
/// puts the auth pages on the cell origin. Until Daniel adds the page
/// rows to section 8.7, the strict reading holds: the production front
/// serves exactly [`table`], and only `crate::http::Front::with_pages`,
/// built with the test and dev-stack feature `dev-pages`, serves these
/// rows. It serves them through the same shared checks as every other
/// route.
pub fn page_table() -> &'static [Route] {
    &PAGE_TABLE
}

#[cfg(test)]
mod tests {
    use super::*;

    /// I-78, H-01: every route of the table is served, a high-risk route
    /// needs a session, and only the health route is on the loopback
    /// listener.
    #[test]
    fn i78_every_table_route_is_served_with_consistent_classes() {
        for r in table() {
            assert_ne!(r.access(), Access::Unserved, "{}", r.path);
            assert_ne!(r.endpoint(), Endpoint::Unserved, "{}", r.path);
            if r.high_risk().is_some() {
                assert!(r.access().needs_session(), "{}", r.path);
            }
            assert_eq!(
                r.access() == Access::Loopback,
                r.endpoint() == Endpoint::Health,
                "{}",
                r.path
            );
            if r.method != "POST" {
                assert_eq!(r.body_limit(), 0, "{}", r.path);
            }
            assert!(r.body_limit() <= 1 << 20, "{}", r.path);
        }
    }

    /// I-78, H-01, design section 11.2: the page routes are exactly the
    /// page paths and asset routes of `crate::http::pages`, each a public
    /// `GET` of risk class `Normal` with no body, and none is a row of
    /// [`table`]. A page endpoint appears in no other row.
    #[test]
    fn i78_page_routes_are_public_gets_outside_the_section_8_7_table() {
        use crate::http::pages::{ASSET_ROUTES, PAGE_PATHS};
        let want: Vec<&str> = PAGE_PATHS
            .iter()
            .chain(ASSET_ROUTES.iter())
            .copied()
            .collect();
        let got: Vec<&str> = page_table().iter().map(|r| r.path).collect();
        assert_eq!(got, want);
        for r in page_table() {
            assert_eq!(r.parts(), ("GET", r.path, RiskClass::Normal), "{}", r.path);
            assert_eq!(r.access(), Access::Public, "{}", r.path);
            assert_eq!(r.body_limit(), 0, "{}", r.path);
            assert!(
                matches!(
                    r.endpoint(),
                    Endpoint::PageShell | Endpoint::PageAsset | Endpoint::PageModule
                ),
                "{}",
                r.path
            );
            assert!(
                table()
                    .iter()
                    .all(|t| t.parts().1 != r.path || t.method != "GET"),
                "{} is also a row of the section 8.7 table",
                r.path
            );
        }
        assert!(table().iter().all(|t| !matches!(
            t.endpoint(),
            Endpoint::PageShell | Endpoint::PageAsset | Endpoint::PageModule
        )));
    }
}
