//! The guard link over mutual TLS (ADR-004 record of lane `m10/guard-key`,
//! "The guard link" and "Certificates", R-NF-09).
//!
//! One exchange per connection, as `fstp_control::exchange`: the client
//! writes one frame and closes its sending side, the server answers one
//! frame and closes. TLS 1.3 comes from `fstp-tls` (rustls with the
//! aws-lc-rs provider), on tokio through `fstp_rt::tokio` (ADR-002).
//!
//! - The custodian requires a client certificate under the pilot's cell
//!   CA, which the pairing file carries. After the handshake it serves a
//!   request only when the certificate names exactly one CN
//!   `keyd-guard-<entry>` and the request names that entry.
//! - The pilot verifies the custodian's certificate under the same CA and
//!   the configured host name, and requires its one CN `keyd-custodian`.
//!
//! The socket loop of `fstp-keyd` stays on std threads. The listener runs
//! on its own thread with its own runtime, and the client draws a
//! current-thread runtime for each exchange.

use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use zeroize::Zeroizing;

use fstp_crypto::hybrid_kem::{self, HybridPublicKey};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{IoExt as _, Listener as _, Runtime as _};

use super::copy::HEADER_LEN;
use super::store::{answer_fetch, answer_open, answer_public, answer_put, answer_rotate};
use super::wire::{
    GuardRequest, MAX_REQUEST_LEN, MAX_RESPONSE_LEN, MAX_SMALL_REQUEST_LEN, MAX_SMALL_RESPONSE_LEN,
};
use super::{
    CUSTODIAN_CN, DEFAULT_PORT, GuardClient, GuardEntry, GuardFault, GuardLink, Rotated, fresh_id,
};
use crate::KeydError;
use crate::server::Server;

/// How long the client waits for a connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
/// How long the client waits for a whole exchange.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the server waits for the handshake and the request.
pub const READ_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a `put` or a `fetch` may take on either side: a copy is up to
/// 160 MiB (ADR-004 "The custodian's copy").
pub const COPY_TIMEOUT: Duration = Duration::from_secs(300);
/// The most connections the custodian serves at once.
pub const MAX_CONNECTIONS: usize = 16;
/// How often the listener looks at its stop flag.
const POLL: Duration = Duration::from_millis(100);

/// The variable that names the custodian of a pilot entry: `host` or
/// `host:port`.
pub const ENV_GUARD: &str = "FSTP_KEYD_GUARD";
/// The variable that names the pilot entry.
pub const ENV_ENTRY: &str = "FSTP_KEYD_GUARD_ENTRY";
/// The variable that turns an entry into a custodian: the listen address.
pub const ENV_LISTEN: &str = "FSTP_KEYD_GUARD_LISTEN";
/// The credential of the pilot's cell CA, on both sides.
pub const CRED_CA: &str = "guard-ca.pem";
/// The credentials of a pilot entry's client certificate and key.
pub const CRED_CLIENT: [&str; 2] = ["guard-client.pem", "guard-client.key"];
/// The credentials of the custodian's server certificate and key.
pub const CRED_SERVER: [&str; 2] = ["guard-server.pem", "guard-server.key"];

/// The one CN a peer certificate names, if it names exactly one in UTF-8.
fn one_cn(cert_der: &[u8]) -> Option<String> {
    let names = fstp_pgwire::x509::subject_common_names(cert_der).ok()?;
    let [cn] = names.as_slice() else {
        return None;
    };
    std::str::from_utf8(cn).ok().map(str::to_owned)
}

/// The pilot entry a verified client certificate names, if any.
#[must_use]
pub fn peer_entry(cert_der: &[u8]) -> Option<GuardEntry> {
    one_cn(cert_der).and_then(|cn| GuardEntry::of_client_cn(&cn))
}

/// Splits `host` or `host:port`, with `[v6]:port` for an IPv6 address.
#[must_use]
pub fn parse_target(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if let Some(rest) = text.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = match tail {
            "" => DEFAULT_PORT,
            t => t.strip_prefix(':')?.parse().ok().filter(|p| *p > 0)?,
        };
        return Some((host.to_owned(), port));
    }
    match text.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => {
            let port = port.parse().ok().filter(|p: &u16| *p > 0)?;
            (!host.is_empty()).then(|| (host.to_owned(), port))
        }
        Some(_) => None,
        None => (!text.is_empty()).then(|| (text.to_owned(), DEFAULT_PORT)),
    }
}

/// A pilot entry's client of its custodian over TLS.
#[derive(Clone)]
pub struct TlsGuard {
    host: String,
    port: u16,
    tls: fstp_tls::ClientConfig,
}

impl std::fmt::Debug for TlsGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsGuard")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl TlsGuard {
    /// A client of the custodian at `host` and `port`, trusting `ca_pem`
    /// and presenting `cert_pem` with `key_pem`.
    ///
    /// # Errors
    ///
    /// [`KeydError::Malformed`] when the PEM input does not build a TLS
    /// configuration.
    pub fn new(
        host: &str,
        port: u16,
        ca_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<TlsGuard, KeydError> {
        let tls = fstp_tls::ClientConfig::mutual(ca_pem, cert_pem, key_pem)
            .map_err(|_| KeydError::Malformed("the guard client credentials"))?;
        Ok(TlsGuard {
            host: host.to_owned(),
            port,
            tls,
        })
    }

    fn exchange(&self, request: &[u8]) -> Result<Vec<u8>, GuardFault> {
        self.exchange_with(request, EXCHANGE_TIMEOUT, MAX_SMALL_RESPONSE_LEN)
    }

    fn exchange_with(
        &self,
        request: &[u8],
        limit: Duration,
        max_reply: usize,
    ) -> Result<Vec<u8>, GuardFault> {
        let rt = TokioRuntime::new_current_thread().map_err(|_| GuardFault::Unreachable)?;
        let run = async {
            let addrs = rt.resolve(&self.host, self.port).await?;
            let addr = *addrs
                .first()
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
            let tcp = fstp_rt::timeout(&rt, CONNECT_TIMEOUT, rt.connect_tcp(addr))
                .await
                .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
            let mut tls = fstp_tls::connect(&self.tls, &self.host, tcp).await?;
            let server_ok = tls
                .peer_end_entity_der()
                .and_then(one_cn)
                .is_some_and(|cn| cn == CUSTODIAN_CN);
            if !server_ok {
                return Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied));
            }
            tls.write_all(request).await?;
            tls.flush().await?;
            tls.shutdown().await?;
            let mut reply = Vec::new();
            tls.read_to_end(&mut reply, max_reply).await?;
            Ok::<Vec<u8>, std::io::Error>(reply)
        };
        match rt.block_on(fstp_rt::timeout(&rt, limit, run)) {
            Ok(Ok(reply)) => Ok(reply),
            _ => Err(GuardFault::Unreachable),
        }
    }
}

impl GuardClient for TlsGuard {
    fn public(&self, entry: GuardEntry) -> Result<(u32, HybridPublicKey), GuardFault> {
        let id = fresh_id()?;
        let reply = self.exchange(&GuardRequest::Public { id, entry }.encode())?;
        answer_public(id, &reply)
    }

    fn rotate(&self, entry: GuardEntry, event: [u8; 16]) -> Result<Rotated, GuardFault> {
        let id = fresh_id()?;
        let reply = self.exchange(&GuardRequest::Rotate { id, entry, event }.encode())?;
        answer_rotate(id, entry, &reply)
    }

    fn open(
        &self,
        entry: GuardEntry,
        generation: u32,
        header: &[u8; HEADER_LEN],
        ciphertext: &[u8; hybrid_kem::CIPHERTEXT_LEN],
    ) -> Result<Zeroizing<[u8; 32]>, GuardFault> {
        let id = fresh_id()?;
        let request = GuardRequest::Open {
            id,
            entry,
            generation,
            header: Box::new(*header),
            ciphertext: Box::new(*ciphertext),
        };
        let reply = self.exchange(&request.encode())?;
        answer_open(id, &reply)
    }

    fn put(&self, entry: GuardEntry, copy: &[u8]) -> Result<u32, GuardFault> {
        let id = fresh_id()?;
        let generation = super::copy::decode_guarded(copy)
            .map_err(|_| GuardFault::Refused(fstp_custody::Refusal::BadRequest))?
            .0
            .generation;
        let request = GuardRequest::Put {
            id,
            entry,
            generation,
            copy: copy.to_vec(),
        };
        let reply = self.exchange_with(&request.encode(), COPY_TIMEOUT, MAX_SMALL_RESPONSE_LEN)?;
        answer_put(id, &reply)
    }

    fn fetch(&self, entry: GuardEntry) -> Result<Vec<u8>, GuardFault> {
        let id = fresh_id()?;
        let request = GuardRequest::Fetch { id, entry }.encode();
        let reply = self.exchange_with(&request, COPY_TIMEOUT, MAX_RESPONSE_LEN)?;
        answer_fetch(id, entry, &reply)
    }
}

/// The custodian side of the link: an address and a TLS configuration
/// that requires a client certificate under the pilot's cell CA.
#[derive(Clone)]
pub struct GuardListener {
    addr: SocketAddr,
    tls: fstp_tls::ServerConfig,
}

impl std::fmt::Debug for GuardListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardListener")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl GuardListener {
    /// A listener on `addr` presenting `cert_pem` with `key_pem` and
    /// trusting client certificates under `ca_pem` only.
    ///
    /// # Errors
    ///
    /// [`KeydError::Malformed`] when the PEM input does not build a TLS
    /// configuration.
    pub fn new(
        addr: SocketAddr,
        ca_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<GuardListener, KeydError> {
        let tls = fstp_tls::ServerConfig::mutual(cert_pem, key_pem, ca_pem)
            .map_err(|_| KeydError::Malformed("the guard server credentials"))?;
        Ok(GuardListener { addr, tls })
    }
}

/// Gives back one connection place when a connection ends.
struct Place(Arc<AtomicUsize>);

impl Drop for Place {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Serves the guard link on `listener` until `flag` is set. Each
/// connection runs in its own task, at most [`MAX_CONNECTIONS`] at once.
/// The server lock is held only while a decoded request is served.
pub(crate) fn run_listener(
    listener: &GuardListener,
    server: &Arc<Mutex<Server>>,
    flag: &AtomicBool,
) -> Result<(), KeydError> {
    let rt =
        TokioRuntime::new_multi_thread(2).map_err(|_| KeydError::Io("start the guard runtime"))?;
    let task_rt = rt.clone();
    rt.block_on(async move {
        let rt = task_rt;
        let mut tcp = rt
            .bind_tcp(listener.addr)
            .await
            .map_err(|_| KeydError::Io("bind the guard listener"))?;
        let active = Arc::new(AtomicUsize::new(0));
        while !flag.load(Ordering::SeqCst) {
            let accepted = match fstp_rt::future::race(tcp.accept(), rt.sleep(POLL)).await {
                fstp_rt::future::Either::Left(a) => a,
                fstp_rt::future::Either::Right(()) => continue,
            };
            let Ok((conn, _)) = accepted else {
                rt.sleep(Duration::from_millis(50)).await;
                continue;
            };
            if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS {
                active.fetch_sub(1, Ordering::SeqCst);
                drop(conn);
                continue;
            }
            let place = Place(Arc::clone(&active));
            let tls = listener.tls.clone();
            let server = Arc::clone(server);
            let conn_rt = rt.clone();
            drop(rt.spawn(async move {
                let _place = place;
                let Ok(Ok(mut stream)) =
                    fstp_rt::timeout(&conn_rt, READ_TIMEOUT, fstp_tls::accept(&tls, conn)).await
                else {
                    return;
                };
                // Only a peer that names a pilot entry may send a copy: any
                // other gets 1183 bytes and 10 seconds (ADR-004 "The
                // custodian's copy", row "Size").
                let peer = stream.peer_end_entity_der().and_then(peer_entry);
                let (limit, max) = match peer {
                    Some(_) => (COPY_TIMEOUT, MAX_REQUEST_LEN),
                    None => (READ_TIMEOUT, MAX_SMALL_REQUEST_LEN),
                };
                let mut request = Zeroizing::new(Vec::new());
                let read = stream.read_to_end(&mut request, max);
                if !matches!(fstp_rt::timeout(&conn_rt, limit, read).await, Ok(Ok(_))) {
                    return;
                }
                let reply = {
                    let mut s = server.lock().unwrap_or_else(PoisonError::into_inner);
                    s.guard_serve(peer, &request)
                };
                let write = async {
                    stream.write_all(&reply).await?;
                    stream.flush().await?;
                    stream.shutdown().await
                };
                let _ = fstp_rt::timeout(&conn_rt, limit, write).await;
            }));
        }
        Ok(())
    })
}

/// What the environment makes of an entry: a pilot entry with a custodian,
/// a custodian, or neither.
pub enum GuardSetup {
    /// No guard is configured.
    None,
    /// A pilot entry, guarded by its custodian.
    Pilot(GuardLink),
    /// The second custodian, serving the guard link.
    Custodian(GuardListener),
}

impl std::fmt::Debug for GuardSetup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardSetup::None => f.write_str("None"),
            GuardSetup::Pilot(l) => write!(f, "Pilot({:?})", l.entry),
            GuardSetup::Custodian(l) => write!(f, "Custodian({:?})", l.addr),
        }
    }
}

fn credential(dir: &Path, name: &str) -> Result<Zeroizing<Vec<u8>>, KeydError> {
    let path = dir.join(name);
    match std::fs::metadata(&path) {
        Ok(m) if m.len() <= 64 * 1024 => {}
        _ => return Err(KeydError::Io("read a guard credential")),
    }
    std::fs::read(path)
        .map(Zeroizing::new)
        .map_err(|_| KeydError::Io("read a guard credential"))
}

/// Reads the guard setup from the environment: [`ENV_GUARD`] and
/// [`ENV_ENTRY`] for a pilot entry, or [`ENV_LISTEN`] for a custodian,
/// with the PEM files from `$CREDENTIALS_DIRECTORY` (ADR-028 record of lane
/// `m10/guard-key`). Both at once are refused.
///
/// # Errors
///
/// [`KeydError::Malformed`] for a bad address or entry, both kinds at
/// once, and credentials that do not build a TLS configuration, and
/// [`KeydError::Io`] for a missing credential.
pub fn setup_from_env() -> Result<GuardSetup, KeydError> {
    let var = |name: &str| std::env::var(name).ok().filter(|v| !v.trim().is_empty());
    let dir = || {
        std::env::var_os("CREDENTIALS_DIRECTORY")
            .map(std::path::PathBuf::from)
            .ok_or(KeydError::Io("no credentials directory for the guard"))
    };
    match (var(ENV_GUARD), var(ENV_LISTEN)) {
        (None, None) => Ok(GuardSetup::None),
        (Some(_), Some(_)) => Err(KeydError::Malformed(
            "an entry is either guarded or a custodian, not both",
        )),
        (Some(target), None) => {
            let (host, port) =
                parse_target(&target).ok_or(KeydError::Malformed("the custodian address"))?;
            let entry = var(ENV_ENTRY)
                .and_then(|e| GuardEntry::from_name(e.trim()))
                .ok_or(KeydError::Malformed("the guarded entry name"))?;
            let d = dir()?;
            let client = TlsGuard::new(
                &host,
                port,
                &credential(&d, CRED_CA)?,
                &credential(&d, CRED_CLIENT[0])?,
                &credential(&d, CRED_CLIENT[1])?,
            )?;
            Ok(GuardSetup::Pilot(GuardLink {
                entry,
                client: Box::new(client),
            }))
        }
        (None, Some(listen)) => {
            let addr: SocketAddr = listen
                .trim()
                .parse()
                .map_err(|_| KeydError::Malformed("the guard listen address"))?;
            let d = dir()?;
            Ok(GuardSetup::Custodian(GuardListener::new(
                addr,
                &credential(&d, CRED_CA)?,
                &credential(&d, CRED_SERVER[0])?,
                &credential(&d, CRED_SERVER[1])?,
            )?))
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// ADR-028 record of lane `m10/guard-key`: the custodian is named by a
    /// host, an address, or either with a port.
    #[test]
    fn adr028_guard_target_parses_host_and_port() {
        assert_eq!(
            parse_target("c.example.eu"),
            Some(("c.example.eu".into(), DEFAULT_PORT))
        );
        assert_eq!(
            parse_target("c.example.eu:9"),
            Some(("c.example.eu".into(), 9))
        );
        assert_eq!(
            parse_target("192.0.2.4:7460"),
            Some(("192.0.2.4".into(), 7460))
        );
        assert_eq!(
            parse_target("[2001:db8::1]:8"),
            Some(("2001:db8::1".into(), 8))
        );
        assert_eq!(
            parse_target("[2001:db8::1]"),
            Some(("2001:db8::1".into(), DEFAULT_PORT))
        );
        for bad in ["", ":7460", "h:0", "h:x", "2001:db8::1", "[x]y"] {
            assert_eq!(parse_target(bad), None, "{bad}");
        }
    }
}
