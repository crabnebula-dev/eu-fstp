//! The MCP endpoints and the OAuth metadata documents (M4 design section
//! 3.8, ADR-013 "Transport" and "Metadata", RFC 8414, RFC 9728).
//!
//! `/mcp` and `/mcp/public` go to `fstp_mcp::McpServer`, which reaches
//! only `ApiCore::dispatch`. The two `/.well-known` documents come from
//! `fstp_oauth::AuthorizationServer`, built once for the tenant origin.
//! `/oauth/**` keeps the typed ADR-013 refusal: the authorisation
//! endpoints wait for the lane that mounts the OAuth server with its
//! token store.
//!
//! Interim, pending Daniel: the metadata names the tenant origin as the
//! issuer and `{origin}/mcp` as the resource. The server built here holds
//! no client or token. The lifetimes it needs to build are those of
//! `fstp-oauth`'s own tests, and no metadata member names them.
//! `fstp-oauth` refuses an `http` issuer outside loopback. A test cell on
//! a `.localhost` origin, such as the e2e cell's `http://a.fstp.localhost`,
//! sets `WebConfig::test_cell` (test-only feature `test-cell`), so its
//! metadata names that origin. Any other refused origin still serves MCP
//! and the 401 challenge, and its metadata documents keep the ADR-013
//! refusal, so no document names an issuer the OAuth server refuses.

use std::sync::Arc;

use fstp_api_core::ApiCore;
use fstp_http::{Method, Request, Response, StatusCode};

use crate::{Origin, WebError, reply};

/// P-72 for the metadata server: 12 hours. No document names it.
const METADATA_P72_MICROS: i64 = 43_200_000_000;
/// P-71 for the metadata server: 5 minutes. No document names it.
const METADATA_P71_MICROS: i64 = 300_000_000;

/// The metadata server of `cfg`: a test cell's when `test_cell` is set
/// and the build has the test-only feature `test-cell`, else a
/// production one, which refuses a plain `http` issuer outside loopback.
fn oauth_server(
    cfg: fstp_oauth::Config,
    test_cell: bool,
) -> Result<fstp_oauth::AuthorizationServer, fstp_oauth::OauthError> {
    #[cfg(feature = "test-cell")]
    if test_cell {
        return fstp_oauth::AuthorizationServer::new_test_cell(cfg);
    }
    let _ = test_cell;
    fstp_oauth::AuthorizationServer::new(cfg)
}

/// The MCP server and the two metadata documents of one tenant origin.
pub(crate) struct Mcp {
    server: fstp_mcp::McpServer,
    /// The resource and the server metadata, when `fstp-oauth` admits
    /// the origin as an issuer.
    docs: Option<(Vec<u8>, Vec<u8>)>,
}

impl Mcp {
    /// The endpoints of `origin` over `core`.
    pub(crate) fn new(
        core: Arc<ApiCore>,
        origin: &Origin,
        test_cell: bool,
    ) -> Result<Mcp, WebError> {
        let issuer = origin.to_string();
        let resource = format!("{issuer}{}", fstp_mcp::Surface::Mcp.path());
        let cfg =
            fstp_oauth::Config::new(&issuer, &resource, METADATA_P72_MICROS, METADATA_P71_MICROS);
        let docs = oauth_server(cfg, test_cell)
            .ok()
            .map(|o| (o.resource_metadata().body, o.server_metadata().body));
        let resource_metadata_url = format!("{issuer}{}", fstp_oauth::RESOURCE_METADATA_PATH);
        let server = fstp_mcp::McpServer::new(
            core,
            fstp_mcp::McpConfig {
                tenant_origins: vec![issuer],
                verified_domain: origin.host().to_owned(),
                resource_metadata_url,
            },
        )
        .map_err(|_| WebError::Mcp("the MCP server refuses the tenant origin"))?;
        Ok(Mcp { server, docs })
    }

    /// Answers a request to `/mcp`, `/mcp/public`, `/oauth` or an OAuth
    /// metadata document.
    pub(crate) async fn answer(&self, req: Request) -> Response {
        let path = req.target.path();
        if let Some(surface) = fstp_mcp::Surface::of_path(path) {
            return self.server.serve(surface, req).await;
        }
        let doc = match (path, &self.docs) {
            (fstp_oauth::RESOURCE_METADATA_PATH, Some((d, _)))
            | (fstp_oauth::SERVER_METADATA_PATH, Some((_, d))) => d,
            _ if path.starts_with("/mcp/") => return reply::not_found(),
            _ => return reply::adr013(),
        };
        if req.method != Method::GET && req.method != Method::HEAD {
            return reply::get_only();
        }
        Response::with_body(StatusCode::OK, "application/json", doc.clone())
    }
}
