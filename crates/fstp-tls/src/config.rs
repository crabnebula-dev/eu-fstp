//! Client and server configuration from PEM input.

use std::fmt;
use std::sync::Arc;

use rustls::RootCertStore;
use rustls::client::{Resumption, Tls12Resumption};
use rustls::crypto::CryptoProvider;
use rustls::server::{NoServerSessionStorage, WebPkiClientVerifier};
use rustls_pki_types::pem::PemObject;
use rustls_pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::TlsError;
use crate::provider::crypto_provider;
use crate::resumption::{
    CLIENT_SERVERS, CLIENT_TICKETS_PER_SERVER, ClientSessions, SERVER_SESSIONS, ServerSessions,
};

/// Limits applied to PEM input before it is parsed.
///
/// PEM files are local configuration, but the limits keep a wrong path (for
/// example a log file) from being read into memory without bound.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PemLimits {
    /// Largest accepted PEM input, in bytes, per argument.
    pub max_input_bytes: usize,
    /// Largest number of certificates accepted in one PEM input.
    pub max_certificates: usize,
}

impl Default for PemLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 1024 * 1024,
            max_certificates: 256,
        }
    }
}

/// Longest ALPN protocol identifier, in bytes (RFC 7301).
pub const MAX_ALPN_LEN: usize = 255;

/// Largest number of ALPN protocols a configuration may offer.
pub const MAX_ALPN_PROTOCOLS: usize = 16;

fn check_size(pem: &[u8], what: &str, limits: &PemLimits) -> Result<(), TlsError> {
    if pem.len() > limits.max_input_bytes {
        return Err(TlsError::config(format!(
            "{what}: PEM input of {} bytes exceeds the limit of {} bytes",
            pem.len(),
            limits.max_input_bytes
        )));
    }
    Ok(())
}

fn parse_certs(
    pem: &[u8],
    what: &str,
    limits: &PemLimits,
) -> Result<Vec<CertificateDer<'static>>, TlsError> {
    check_size(pem, what, limits)?;
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem) {
        let cert = item.map_err(|e| TlsError::config(format!("{what}: invalid PEM: {e}")))?;
        if out.len() >= limits.max_certificates {
            return Err(TlsError::config(format!(
                "{what}: more than {} certificates",
                limits.max_certificates
            )));
        }
        out.push(cert);
    }
    if out.is_empty() {
        return Err(TlsError::config(format!("{what}: no certificate found")));
    }
    Ok(out)
}

fn parse_key(
    pem: &[u8],
    what: &str,
    limits: &PemLimits,
) -> Result<PrivateKeyDer<'static>, TlsError> {
    check_size(pem, what, limits)?;
    // The PEM error text can quote input lines, so it is not included here:
    // key material must never reach an error message or a log.
    PrivateKeyDer::from_pem_slice(pem)
        .map_err(|_| TlsError::config(format!("{what}: no valid private key found")))
}

fn parse_roots(pem: &[u8], what: &str, limits: &PemLimits) -> Result<RootCertStore, TlsError> {
    let mut roots = RootCertStore::empty();
    for cert in parse_certs(pem, what, limits)? {
        roots
            .add(cert)
            .map_err(|e| TlsError::config_from(what, e))?;
    }
    Ok(roots)
}

fn check_alpn(protocols: &[Vec<u8>]) -> Result<(), TlsError> {
    if protocols.len() > MAX_ALPN_PROTOCOLS {
        return Err(TlsError::config("too many ALPN protocols"));
    }
    if protocols
        .iter()
        .any(|p| p.is_empty() || p.len() > MAX_ALPN_LEN)
    {
        return Err(TlsError::config(
            "ALPN protocol identifiers must be 1 to 255 bytes long",
        ));
    }
    Ok(())
}

static TLS13_ONLY: &[&rustls::SupportedProtocolVersion] = &[&rustls::version::TLS13];

/// TLS client configuration: trusted roots and an optional client
/// certificate for mutual TLS (R-NF-09).
///
/// Cheap to clone. One configuration serves any number of connections.
///
/// Session resumption follows policy P2. The configuration keeps a bounded
/// cache of TLS 1.3 tickets, which its clones share. A connection offers a
/// ticket only while its session is younger than
/// [`MAX_RESUMPTION_AGE`](crate::MAX_RESUMPTION_AGE), counted from the full
/// handshake that validated the server certificate.
/// A chain of resumptions never extends that time, whatever ticket lifetime
/// the server announces. After it, a full handshake validates the server
/// certificate again.
///
/// The cache keeps up to 8 tickets for each of up to 256 server names.
/// Certificate validity and ticket age use the same clock.
#[derive(Clone)]
pub struct ClientConfig {
    /// The shared rustls configuration. Its own resumption is disabled.
    /// `connection_config` adds the session cache for each connection.
    pub(crate) inner: Arc<rustls::ClientConfig>,
    /// `None` only for plain rustls configurations that tests build.
    pub(crate) sessions: Option<Arc<ClientSessions>>,
}

impl fmt::Debug for ClientConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfig")
            .field("alpn", &self.inner.alpn_protocols)
            .field(
                "client_auth",
                &self.inner.client_auth_cert_resolver.has_certs(),
            )
            .field("resumption", &self.sessions.is_some())
            .finish_non_exhaustive()
    }
}

impl ClientConfig {
    /// Wraps a plain rustls configuration, for tests. Its resumption
    /// settings stay as rustls has them.
    #[cfg(test)]
    pub(crate) fn from_rustls(cfg: rustls::ClientConfig) -> Self {
        Self {
            inner: Arc::new(cfg),
            sessions: None,
        }
    }

    /// The rustls configuration for one new connection. It is the shared
    /// configuration with a session store that tracks the origin of this
    /// connection's tickets (see `resumption.rs`).
    pub(crate) fn connection_config(&self) -> Arc<rustls::ClientConfig> {
        let Some(sessions) = &self.sessions else {
            return self.inner.clone();
        };
        let mut cfg = (*self.inner).clone();
        let handle = sessions.handle(cfg.time_provider.clone());
        cfg.resumption =
            Resumption::store(Arc::new(handle)).tls12_resumption(Tls12Resumption::Disabled);
        Arc::new(cfg)
    }

    /// Starts a configuration that trusts the CA certificates in `roots_pem`.
    pub fn builder(roots_pem: &[u8]) -> ClientConfigBuilder<'_> {
        ClientConfigBuilder {
            roots_pem,
            client_auth: None,
            alpn: Vec::new(),
            limits: PemLimits::default(),
        }
    }

    /// A configuration that trusts `roots_pem` and presents no client
    /// certificate.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when the PEM input is invalid or exceeds the default [`PemLimits`].
    pub fn new(roots_pem: &[u8]) -> Result<Self, TlsError> {
        Self::builder(roots_pem).build()
    }

    /// A mutual TLS configuration: trusts `roots_pem` and presents the
    /// certificate chain `chain_pem` with private key `key_pem`.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when any PEM input is invalid or the key does not match the chain.
    pub fn mutual(roots_pem: &[u8], chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        Self::builder(roots_pem)
            .client_auth_pem(chain_pem, key_pem)
            .build()
    }
}

/// Builder for [`ClientConfig`]. PEM input is parsed in
/// [`ClientConfigBuilder::build`], after all limits are known.
pub struct ClientConfigBuilder<'a> {
    roots_pem: &'a [u8],
    client_auth: Option<(&'a [u8], &'a [u8])>,
    alpn: Vec<Vec<u8>>,
    limits: PemLimits,
}

impl fmt::Debug for ClientConfigBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClientConfigBuilder")
            .field("client_auth", &self.client_auth.is_some())
            .field("alpn", &self.alpn)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<'a> ClientConfigBuilder<'a> {
    /// Presents the certificate chain `chain_pem` (leaf first) with the
    /// private key `key_pem` when the server asks for client authentication.
    #[must_use]
    pub fn client_auth_pem(mut self, chain_pem: &'a [u8], key_pem: &'a [u8]) -> Self {
        self.client_auth = Some((chain_pem, key_pem));
        self
    }

    /// Offers these ALPN protocols, in order of preference.
    #[must_use]
    pub fn alpn_protocols(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Replaces the default [`PemLimits`].
    #[must_use]
    pub fn pem_limits(mut self, limits: PemLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Parses all input and builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when PEM input is invalid or over its limits, when the key does not
    /// match the chain, or when an ALPN value is out of range.
    pub fn build(self) -> Result<ClientConfig, TlsError> {
        check_alpn(&self.alpn)?;
        let roots = parse_roots(self.roots_pem, "client trust roots", &self.limits)?;
        let builder = rustls::ClientConfig::builder_with_provider(crypto_provider())
            .with_protocol_versions(TLS13_ONLY)
            .map_err(|e| TlsError::config_from("client protocol versions", e))?
            .with_root_certificates(roots);
        let mut cfg = match self.client_auth {
            Some((chain_pem, key_pem)) => {
                let chain = parse_certs(chain_pem, "client certificate chain", &self.limits)?;
                let key = parse_key(key_pem, "client private key", &self.limits)?;
                builder
                    .with_client_auth_cert(chain, key)
                    .map_err(|e| TlsError::config_from("client certificate", e))?
            }
            None => builder.with_no_client_auth(),
        };
        cfg.alpn_protocols = self.alpn;
        // The shared configuration never resumes on its own. Each
        // connection gets the bounded session cache through
        // `connection_config` (P2, R-NF-09).
        cfg.resumption = Resumption::disabled();
        Ok(ClientConfig {
            inner: Arc::new(cfg),
            sessions: Some(Arc::new(ClientSessions::new(
                CLIENT_SERVERS,
                CLIENT_TICKETS_PER_SERVER,
            ))),
        })
    }
}

/// TLS server configuration: a certificate chain and key, and optionally
/// required client authentication against trusted roots (R-NF-09).
///
/// Cheap to clone. One configuration serves any number of connections.
///
/// Session resumption follows policy P2. The server keeps its sessions in a
/// bounded in-memory store, which its clones share, and issues one TLS 1.3
/// ticket per handshake. Tickets are single use. A session can be resumed
/// only while it is younger than
/// [`MAX_RESUMPTION_AGE`](crate::MAX_RESUMPTION_AGE), counted from the full
/// handshake that authenticated it. A chain of resumptions never extends
/// that time. After it, a full handshake runs, and under mutual TLS
/// it validates the client certificate again, including its expiry.
///
/// Within that time, a resumed session carries the client certificate of
/// its full handshake without checking it again. The store keeps up to 1024
/// sessions and drops the oldest first. The server issues no stateless
/// tickets and accepts no early data. Each ticket announces a lifetime of
/// 24 hours, which rustls 0.23.46 fixes for stateful tickets. The store
/// still refuses a session once the hour has passed.
#[derive(Clone)]
pub struct ServerConfig {
    /// The shared rustls configuration. It has no session store of its
    /// own. `connection_config` adds it for each connection.
    pub(crate) inner: Arc<rustls::ServerConfig>,
    /// `None` only for plain rustls configurations that tests build.
    pub(crate) sessions: Option<Arc<ServerSessions>>,
}

impl fmt::Debug for ServerConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfig")
            .field("alpn", &self.inner.alpn_protocols)
            .field("resumption", &self.sessions.is_some())
            .finish_non_exhaustive()
    }
}

impl ServerConfig {
    /// Wraps a plain rustls configuration, for tests. Its resumption
    /// settings stay as rustls has them.
    #[cfg(test)]
    pub(crate) fn from_rustls(cfg: rustls::ServerConfig) -> Self {
        Self {
            inner: Arc::new(cfg),
            sessions: None,
        }
    }

    /// The rustls configuration for one new connection. It is the shared
    /// configuration with a session store that tracks the origin of this
    /// connection's tickets (see `resumption.rs`).
    pub(crate) fn connection_config(&self) -> Arc<rustls::ServerConfig> {
        let Some(sessions) = &self.sessions else {
            return self.inner.clone();
        };
        let mut cfg = (*self.inner).clone();
        cfg.session_storage = Arc::new(sessions.handle(cfg.time_provider.clone()));
        Arc::new(cfg)
    }

    /// Starts a configuration that presents `chain_pem` (leaf first) with the
    /// private key `key_pem`.
    pub fn builder<'a>(chain_pem: &'a [u8], key_pem: &'a [u8]) -> ServerConfigBuilder<'a> {
        ServerConfigBuilder {
            chain_pem,
            key_pem,
            client_roots_pem: None,
            alpn: Vec::new(),
            limits: PemLimits::default(),
        }
    }

    /// A configuration without client authentication.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when the PEM input is invalid or the key does not match the chain.
    pub fn new(chain_pem: &[u8], key_pem: &[u8]) -> Result<Self, TlsError> {
        Self::builder(chain_pem, key_pem).build()
    }

    /// A mutual TLS configuration that requires every client to present a
    /// certificate issued under `client_roots_pem`.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when any PEM input is invalid or the key does not match the chain.
    pub fn mutual(
        chain_pem: &[u8],
        key_pem: &[u8],
        client_roots_pem: &[u8],
    ) -> Result<Self, TlsError> {
        Self::builder(chain_pem, key_pem)
            .require_client_auth(client_roots_pem)
            .build()
    }
}

/// Builder for [`ServerConfig`]. PEM input is parsed in
/// [`ServerConfigBuilder::build`], after all limits are known.
pub struct ServerConfigBuilder<'a> {
    chain_pem: &'a [u8],
    key_pem: &'a [u8],
    client_roots_pem: Option<&'a [u8]>,
    alpn: Vec<Vec<u8>>,
    limits: PemLimits,
}

impl fmt::Debug for ServerConfigBuilder<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ServerConfigBuilder")
            .field("client_auth", &self.client_roots_pem.is_some())
            .field("alpn", &self.alpn)
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}

impl<'a> ServerConfigBuilder<'a> {
    /// Requires every client to present a certificate that chains to one of
    /// the CA certificates in `roots_pem`. Clients without one are rejected
    /// during the handshake.
    #[must_use]
    pub fn require_client_auth(mut self, roots_pem: &'a [u8]) -> Self {
        self.client_roots_pem = Some(roots_pem);
        self
    }

    /// Accepts these ALPN protocols, in order of preference.
    #[must_use]
    pub fn alpn_protocols(mut self, protocols: &[&[u8]]) -> Self {
        self.alpn = protocols.iter().map(|p| p.to_vec()).collect();
        self
    }

    /// Replaces the default [`PemLimits`].
    #[must_use]
    pub fn pem_limits(mut self, limits: PemLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Parses all input and builds the configuration.
    ///
    /// # Errors
    ///
    /// Returns a [`TlsErrorKind::Config`](crate::TlsErrorKind::Config) error
    /// when PEM input is invalid or over its limits, when the key does not
    /// match the chain, or when an ALPN value is out of range.
    pub fn build(self) -> Result<ServerConfig, TlsError> {
        check_alpn(&self.alpn)?;
        let provider: Arc<CryptoProvider> = crypto_provider();
        let chain = parse_certs(self.chain_pem, "server certificate chain", &self.limits)?;
        let key = parse_key(self.key_pem, "server private key", &self.limits)?;
        let builder = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(TLS13_ONLY)
            .map_err(|e| TlsError::config_from("server protocol versions", e))?;
        let builder = match self.client_roots_pem {
            Some(roots_pem) => {
                let roots = parse_roots(roots_pem, "client CA roots", &self.limits)?;
                let verifier =
                    WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider)
                        .build()
                        .map_err(|e| {
                            TlsError::config(format!("client certificate verifier: {e}"))
                        })?;
                builder.with_client_cert_verifier(verifier)
            }
            None => builder.with_no_client_auth(),
        };
        let mut cfg = builder
            .with_single_cert(chain, key)
            .map_err(|e| TlsError::config_from("server certificate", e))?;
        cfg.alpn_protocols = self.alpn;
        // A resumed session skips the client verifier, so its age is
        // bounded (P2, R-NF-09). The shared configuration stores nothing
        // and fails safe if used directly. Each connection gets the bounded
        // store through `connection_config`. The default ticketer issues no
        // stateless tickets, and early data stays off.
        //
        // One ticket per handshake: a resumption consumes one and receives
        // one, so sequential clients leave no unused entries in the store.
        // Client requests for more tickets (RFC 9149) are ignored.
        cfg.session_storage = Arc::new(NoServerSessionStorage {});
        cfg.send_tls13_tickets = 1;
        cfg.max_tls13_tickets = 0;
        cfg.max_early_data_size = 0;
        Ok(ServerConfig {
            inner: Arc::new(cfg),
            sessions: Some(Arc::new(ServerSessions::new(SERVER_SESSIONS))),
        })
    }
}
