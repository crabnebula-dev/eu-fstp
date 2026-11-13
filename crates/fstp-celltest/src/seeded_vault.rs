//! The seeded vault of a world cell (design section 6.9, lane F-CYCLE2):
//! the `fstp-vault` library with a [`SeedSource`]. Test only.
//!
//! [`SeededVault::start`] runs the vault of one cell as
//! `fstp_vault::service::serve` does, with the same library parts:
//!
//! 1. It connects to `v_<cell>` as `v_<cell>_vault` and runs the I-83
//!    start check (`fstp_vault::service::check_database`), with the same
//!    server check on the connection.
//! 2. It loads the vault from its rows (`fstp_vault::store::load`).
//! 3. Its internal listener takes the cell's `cell-app` certificate only,
//!    on the four internal routes, and answers through
//!    `fstp_vault::origin::Vault::internal_bytes`.
//! 4. Its origin listener takes the edge's tunnel, then the browser's TLS
//!    for `id.<cell host>`, through the cell's own tunnel listener
//!    (`fstp_cell::http::tunnel::TunnelListener`), and answers through
//!    `Vault::origin`.
//!
//! Every call runs on a copy of the vault. Its journal is persisted with
//! `fstp_vault::store::persist` before the vault answers, and the copy is
//! kept only once that commit succeeded.
//!
//! What differs from the shipped service, so claims built on it say so:
//!
//! - [`SeededVault::seed`] takes a fact write from a [`SeedSource`]
//!   through `Vault::take_fact_write`, the vault core's own write entry.
//!   The fact becomes effective only after the cell reacts to its epoch
//!   (NOTE 4), as a real write does. Every seeded write is logged.
//! - The shipped service refuses with 503 any call whose journal is not
//!   empty, since the vault chain writer is not built (lane F-VCHAIN,
//!   ADR-010 open point 5). The seeded vault persists that journal with
//!   no vault chain row. No I-24 claim covers the vault chain of a world.
//! - Its instants come from the cell's [`WorldClock`], so a ticket the
//!   cell issued at its test instant is checked at the same instant.

use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use fstp_rt::{Runtime, Shutdown};
use fstp_vault::origin::{INTERNAL_ROUTES, Vault};
use fstp_vault::store::Sealer;
use fstp_vault_core::{CoreError, FactWrite, VaultEvent};
use fstp_witness::lock::AsyncMutex;

use crate::vault_seed::{SeedError, SeedLog, SeedSource, SeededWrite};
use crate::world::WorldClock;

/// The runtime of the world.
type Rt = fstp_rt::tokio::TokioRuntime;

/// What a seeded vault starts from: the parts of
/// `fstp_vault::service::VaultParts`, with the cell's tunnel listener
/// configuration and the cell's test clock.
pub struct SeededParts {
    /// The cell.
    pub cell: [u8; 16],
    /// The `v_<cell>_vault` login.
    pub db: fstp_pgwire::Config,
    /// The control plane's registration of cluster server keys.
    pub registered_servers: Vec<fstp_vault::service::RegisteredSpki>,
    /// Seals and opens the stored values.
    pub sealer: Arc<dyn Sealer>,
    /// The cell's ticket public keys.
    pub ticket_keys: Vec<[u8; 32]>,
    /// The internal listener's configuration, with client authentication
    /// against the cell CA.
    pub internal_tls: fstp_tls::ServerConfig,
    /// The tunnel and origin configurations of `id.<cell host>`.
    pub tunnel_tls: fstp_cell::http::tunnel::TunnelTls,
    /// The vault origin host.
    pub origin_host: String,
    /// The cell's test clock.
    pub clock: WorldClock,
}

/// One call's answer.
struct Answer {
    status: u16,
    headers: Vec<(&'static str, String)>,
    body: Vec<u8>,
}

/// The vault and its database connection under one lock, so a call and
/// its commit are never interleaved with another.
#[derive(Default)]
struct Held {
    vault: Vault,
    db: Option<fstp_pgwire::Client<Rt>>,
}

struct Shared {
    held: AsyncMutex<Held>,
    sealer: Arc<dyn Sealer>,
    clock: WorldClock,
    log: Mutex<SeedLog>,
    /// The key of the identity match keys of seeded verifications.
    match_key: [u8; 32],
}

impl Shared {
    /// Runs `call` on a copy of the vault, persists the copy's journal,
    /// and keeps the copy only once the journal is committed.
    async fn run<T>(&self, call: impl FnOnce(&mut Vault, i64) -> T) -> Result<T, ()> {
        let mut held = self.held.lock().await;
        let mut next = held.vault.clone();
        let out = call(&mut next, self.clock.now());
        let journal = next.take_journal();
        if !journal.is_empty() {
            let db = held.db.as_mut().ok_or(())?;
            fstp_vault::store::persist(db, self.sealer.as_ref(), &journal)
                .await
                .map_err(|e| {
                    eprintln!("fstp_celltest::seeded_vault: the journal did not persist: {e:?}");
                })?;
        }
        held.vault = next;
        Ok(out)
    }

    fn log(&self) -> MutexGuard<'_, SeedLog> {
        self.log.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

fn unavailable() -> Answer {
    Answer {
        status: 503,
        headers: vec![("content-type", "text/plain; charset=utf-8".to_owned())],
        body: Vec::new(),
    }
}

fn response(a: Answer) -> fstp_http::Response {
    let status = fstp_http::StatusCode::from_u16(a.status)
        .unwrap_or(fstp_http::StatusCode::INTERNAL_SERVER_ERROR);
    let mut resp = fstp_http::Response::new(status);
    resp.body = a.body;
    for (name, value) in a.headers {
        let _ = resp.headers.try_insert(name, value);
    }
    resp
}

/// The internal listener's handler, as `fstp_vault::service` routes it.
struct Internal(Arc<Shared>);

impl fstp_http::Handler for Internal {
    async fn handle(&self, req: fstp_http::Request) -> fstp_http::Response {
        let path = req.target.path().to_owned();
        if !INTERNAL_ROUTES.iter().any(|r| r.path == path) {
            return fstp_http::Response::new(fstp_http::StatusCode::NOT_FOUND);
        }
        if req.method != fstp_http::Method::POST {
            return fstp_http::Response::new(fstp_http::StatusCode::METHOD_NOT_ALLOWED);
        }
        let cell_app = req
            .client_certificate_der()
            .and_then(|der| fstp_witness::peer::read_cert_names(der).ok())
            .and_then(|n| n.subject_ou)
            .is_some_and(|ou| ou == fstp_vault::service::CELL_APP_OU.as_bytes());
        if !cell_app {
            return fstp_http::Response::new(fstp_http::StatusCode::FORBIDDEN);
        }
        let body = req.body;
        let a = self
            .0
            .run(|v, now| Answer {
                status: 200,
                headers: vec![("content-type", "application/json".to_owned())],
                body: v.internal_bytes(&body, now),
            })
            .await
            .unwrap_or_else(|()| unavailable());
        response(a)
    }
}

/// The vault origin's handler.
struct Origin(Arc<Shared>);

impl fstp_http::Handler for Origin {
    async fn handle(&self, req: fstp_http::Request) -> fstp_http::Response {
        let method = req.method.as_str().to_owned();
        let path = req.target.path().to_owned();
        let body = req.body;
        let a = self
            .0
            .run(|v, now| {
                let r = v.origin(&method, &path, &body, now);
                Answer {
                    status: r.status,
                    headers: r.headers,
                    body: r.body,
                }
            })
            .await
            .unwrap_or_else(|()| unavailable());
        response(a)
    }
}

fn http_config(tls: Option<fstp_tls::ServerConfig>) -> fstp_http::ServerConfig {
    fstp_http::ServerConfig {
        tls,
        limits: fstp_http::Limits {
            max_body_bytes: fstp_vault::service::MAX_BODY,
            ..fstp_http::Limits::default()
        },
        ..fstp_http::ServerConfig::default()
    }
}

/// A running seeded vault (module documentation).
pub struct SeededVault {
    rt: Rt,
    shared: Arc<Shared>,
    internal: fstp_http::ServerHandle<Rt>,
    origin: fstp_http::ServerHandle<Rt>,
    tunnel: Shutdown,
}

impl std::fmt::Debug for SeededVault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SeededVault")
            .field("internal", &self.internal.local_addr())
            .field("origin", &self.origin.local_addr())
            .finish_non_exhaustive()
    }
}

impl SeededVault {
    /// Starts the seeded vault of `parts` on `rt` (module documentation).
    ///
    /// # Errors
    ///
    /// [`fstp_vault::VaultError`] as `fstp_vault::service::serve` fails:
    /// a database that cannot be reached or is not this vault's, rows that
    /// do not load, or a listener that cannot be bound.
    pub async fn start(rt: Rt, parts: SeededParts) -> Result<SeededVault, fstp_vault::VaultError> {
        use fstp_vault::VaultError;
        let SeededParts {
            cell,
            db,
            registered_servers,
            sealer,
            ticket_keys,
            internal_tls,
            tunnel_tls,
            origin_host,
            clock,
        } = parts;
        let db = db.server_check(fstp_vault::service::vault_server_check(&registered_servers));
        let mut client: fstp_pgwire::Client<Rt> =
            fstp_pgwire::Client::connect(&rt, &db).await.map_err(|e| {
                if e.kind() == fstp_pgwire::ErrorKind::ServerRefused {
                    VaultError::Malformed("not a vault database (I-83)")
                } else {
                    VaultError::Unavailable("the vault database")
                }
            })?;
        fstp_vault::service::check_database(&mut client, &registered_servers).await?;
        let vault =
            fstp_vault::store::load(&mut client, sealer.as_ref(), cell, &ticket_keys).await?;
        let shared = Arc::new(Shared {
            held: AsyncMutex::new(Held {
                vault,
                db: Some(client),
            }),
            sealer,
            clock,
            log: Mutex::new(SeedLog::default()),
            match_key: fstp_crypto::random_array::<32>()
                .map_err(|_| VaultError::Unavailable("randomness"))?,
        });
        let loopback = std::net::SocketAddr::from((std::net::Ipv4Addr::LOCALHOST, 0));
        let internal = fstp_http::Server::new(
            rt.clone(),
            http_config(Some(internal_tls)),
            Internal(Arc::clone(&shared)),
        )
        .bind(loopback)
        .await
        .map_err(|_| VaultError::Unavailable("the internal listener"))?;
        let tcp = rt
            .bind_tcp(loopback)
            .await
            .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
        let tunnel = Shutdown::new();
        let listener = fstp_cell::http::tunnel::TunnelListener::new(
            &rt,
            tcp,
            tunnel_tls,
            origin_host,
            tunnel.signal(),
        )
        .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
        let origin =
            fstp_http::Server::new(rt.clone(), http_config(None), Origin(Arc::clone(&shared)))
                .serve(listener)
                .map_err(|_| VaultError::Unavailable("the tunnel listener"))?;
        Ok(SeededVault {
            rt,
            shared,
            internal,
            origin,
            tunnel,
        })
    }

    /// Where the internal listener is bound.
    pub fn internal_addr(&self) -> std::net::SocketAddr {
        self.internal.local_addr()
    }

    /// Where the tunnel listener of the vault origin is bound.
    pub fn origin_addr(&self) -> std::net::SocketAddr {
        self.origin.local_addr()
    }

    /// Seeds the fact write `w` from `source` at the cell's clock
    /// instant, through `Vault::take_fact_write`, and logs it. The fact
    /// becomes effective after the cell's reaction (NOTE 4).
    ///
    /// # Errors
    ///
    /// The vault core's refusal, or [`SeedError::NotImplemented`] when the
    /// vault database refused the journal.
    pub async fn seed(
        &self,
        source: SeedSource,
        w: FactWrite,
    ) -> Result<Vec<VaultEvent>, SeedError> {
        let kind = w.kind;
        let (events, at) = self
            .shared
            .run(|v, now| (v.take_fact_write(w, now), now))
            .await
            .map_err(|()| {
                SeedError::NotImplemented(crate::NotImplemented::new(
                    "fstp_celltest::seeded_vault: the vault database refused the seeded journal",
                ))
            })?;
        let events = events.map_err(|e: CoreError| SeedError::from(e))?;
        self.shared
            .log()
            .writes
            .push(SeededWrite { source, kind, at });
        Ok(events)
    }

    /// Seeds a synthetic manual verification of `account` (design sections
    /// 6.7 and 6.9) at the cell's clock instant. Its identity comes from
    /// the vault's own match key resolution (`Vault::verification_fact`)
    /// over the synthetic attribute tuple `attributes`, so two accounts
    /// share an identity only when their tuples are equal. The recorder is
    /// a synthetic account id that no world account takes. The fact
    /// becomes effective after the cell's reaction (NOTE 4).
    ///
    /// # Errors
    ///
    /// As [`SeededVault::seed`].
    pub async fn seed_verification(
        &self,
        account: u128,
        attributes: &[u8],
    ) -> Result<Vec<VaultEvent>, SeedError> {
        use fstp_vault_core::fact::{Check, DocumentType, VerificationMethod, VerificationRecord};
        use fstp_vault_proto::WireAccount;
        let mk = fstp_vault::match_key(&self.shared.match_key, attributes);
        let (events, at) = self
            .shared
            .run(|v, now| {
                let record = VerificationRecord {
                    method: VerificationMethod::Manual,
                    document_type: DocumentType::Passport,
                    checks: [Check::DocumentAuthentic, Check::PhotoMatch]
                        .into_iter()
                        .collect(),
                    at: now,
                    verifier: WireAccount(u128::MAX),
                };
                let events = v
                    .verification_fact(WireAccount(u128::MAX), WireAccount(account), record, mk)
                    .map_err(|_| CoreError::Refused(fstp_vault_proto::VaultRefusal::Unavailable))
                    .and_then(|fact| v.take_fact(fact, now));
                (events, now)
            })
            .await
            .map_err(|()| {
                SeedError::NotImplemented(crate::NotImplemented::new(
                    "fstp_celltest::seeded_vault: the vault database refused the seeded journal",
                ))
            })?;
        let events = events.map_err(SeedError::from)?;
        self.shared.log().writes.push(SeededWrite {
            source: SeedSource::SyntheticVerification,
            kind: fstp_vault_core::fact::kind::VERIFICATION_RECORDED,
            at,
        });
        Ok(events)
    }

    /// Every seeded write so far.
    pub fn seed_log(&self) -> SeedLog {
        self.shared.log().clone()
    }

    /// Stops both listeners and waits up to `deadline` for them.
    ///
    /// # Errors
    ///
    /// [`fstp_vault::VaultError::Unavailable`] when a connection was still
    /// open at the deadline.
    pub async fn shutdown(&self, deadline: Duration) -> Result<(), fstp_vault::VaultError> {
        self.tunnel.trigger();
        let a = self.internal.shutdown(deadline).await;
        let b = self.origin.shutdown(deadline).await;
        let c = self.tunnel.shutdown(&self.rt, deadline).await;
        if a.is_err() || b.is_err() || c.is_err() {
            return Err(fstp_vault::VaultError::Unavailable("the drain"));
        }
        Ok(())
    }
}
