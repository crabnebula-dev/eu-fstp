//! The custody simulator as a custody process (lane m3/custody-decisions).
//!
//! Daniel decided on 2026-11-13 that the simulator wraps and unwraps
//! (m3-exit-audit section 7, item 2). A world in process mode can then
//! keep every cell's roots out of the process that runs the cell: each
//! cell gets a `fstp-custody-sim --serve` process, and the cell reaches it
//! through the production client [`fstp_custody::keyd::KeydCustody`] over
//! the `fstp-keyd` wire form of ADR-004 part 2. Root bytes never cross the
//! socket (I-80), only seal keys do, as with `fstp-keyd`.
//!
//! The server decodes each request with `fstp-keyd`'s own decoder
//! (`fstp_keyd::request::decode_request`, fuzzed) and answers with its
//! encoder, so this module adds no parser of the wire form. A root is
//! named by its chain and epoch, as `fstp-keyd` names it. A create of a
//! live chain and epoch finds that root, as in `fstp-keyd`. Signing is
//! refused with `NoSignKey`: a world keeps its CA keys apart.
//!
//! The simulator reports every root, wrapped seal key and destroy to the
//! file the test named ([`super::report`]), so the I-80 scans know what
//! to look for without asking the cell.

use std::collections::BTreeMap;
use std::io::{Read as _, Write as _};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fstp_custody::keyd::{
    FRAME_HEADER_LEN, Receipt, Request, Response, RootHandle, frame_body_len,
};
use fstp_custody::{
    Aad, Custody as _, CustodyError, Refusal, RootLabel, RootRef, SealKey, UsageCursor,
    WrappedSealKey,
};
use fstp_rt::future::block_on;

use super::CustodySim;
use crate::NotImplemented;

/// How long one connection may stay silent.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// A custody server over a [`CustodySim`].
pub struct Server {
    sim: CustodySim,
    /// The simulator's root of each chain and epoch, by the chain code.
    roots: BTreeMap<(u8, u64), RootRef>,
}

impl std::fmt::Debug for Server {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Server")
            .field("roots", &self.roots.len())
            .finish_non_exhaustive()
    }
}

fn refused(e: CustodyError) -> Response {
    match e {
        CustodyError::Refused(r) => Response::Refused(r),
        _ => Response::Refused(Refusal::Internal),
    }
}

impl Server {
    /// A server over `sim`.
    #[must_use]
    pub fn new(sim: CustodySim) -> Server {
        Server {
            sim,
            roots: BTreeMap::new(),
        }
    }

    fn root(&self, handle: RootHandle) -> Result<&RootRef, Response> {
        self.roots
            .get(&(handle.chain.code(), handle.epoch.0))
            .ok_or(Response::Refused(Refusal::UnknownRoot))
    }

    /// The answer to `request`. Every call is served under the request's
    /// own id, so the usage log names it (ADR-004 "Reconciliation").
    pub fn handle(&mut self, request: &Request) -> Response {
        match self.answer(request) {
            Ok(r) | Err(r) => r,
        }
    }

    fn answer(&mut self, request: &Request) -> Result<Response, Response> {
        let id = request.id();
        match request {
            Request::CreateRoot {
                cell, chain, epoch, ..
            } => {
                let handle = RootHandle {
                    chain: *chain,
                    epoch: *epoch,
                };
                if let Ok(root) = self.root(handle) {
                    return if self.sim.with_material(root, |_| ()).is_some() {
                        Ok(Response::Root(handle))
                    } else {
                        Err(Response::Refused(Refusal::Destroyed))
                    };
                }
                let root = self
                    .sim
                    .create_with_id(
                        id,
                        RootLabel {
                            cell: *cell,
                            chain: *chain,
                            epoch: *epoch,
                        },
                    )
                    .map_err(|_| Response::Refused(Refusal::Internal))?;
                self.roots.insert((chain.code(), epoch.0), root);
                Ok(Response::Root(handle))
            }
            Request::Wrap { root, aad, key, .. } => {
                let root = self.root(*root)?.clone();
                let key = SealKey::from_slice(&key[..])
                    .map_err(|_| Response::Refused(Refusal::BadRequest))?;
                self.sim
                    .wrap_with_id(id, &root, &key, &Aad(aad.clone()))
                    .map(|w| Response::Wrapped(w.0))
                    .map_err(refused)
            }
            Request::Unwrap {
                root, aad, wrapped, ..
            } => {
                let root = self.root(*root)?.clone();
                self.sim
                    .unwrap_with_id(
                        id,
                        &root,
                        &WrappedSealKey(wrapped.clone()),
                        &Aad(aad.clone()),
                    )
                    .and_then(|k| {
                        fstp_custody::key_box(k.expose())
                            .map_err(|_| CustodyError::Refused(Refusal::Internal))
                    })
                    .map(Response::Unwrapped)
                    .map_err(refused)
            }
            Request::Destroy { root: handle, .. } => {
                let root = self.root(*handle)?.clone();
                // A destroyed root gets its receipt again, as in fstp-keyd.
                if self.sim.with_material(&root, |_| ()).is_some() {
                    self.sim
                        .destroy_root_with_id(id, &root)
                        .map_err(|_| Response::Refused(Refusal::Internal))?;
                }
                Ok(Response::Destroyed(
                    Receipt::full(handle.chain, handle.epoch).encode(),
                ))
            }
            // The simulator holds no signing keys, as fstp-keyd holds none
            // yet (lane m3/erase-cell-2), so it can destroy none either.
            Request::Sign { .. } | Request::DestroySignKey { .. } => {
                Err(Response::Refused(Refusal::NoSignKey))
            }
            Request::UsageSince { root, cursor, .. } => {
                let root = self.root(*root)?.clone();
                let page = block_on(
                    self.sim
                        .usage_since(&root, UsageCursor(cursor.to_be_bytes().to_vec())),
                )
                .map_err(refused)?;
                let next = page
                    .next
                    .0
                    .as_slice()
                    .try_into()
                    .map(u64::from_be_bytes)
                    .map_err(|_| Response::Refused(Refusal::Internal))?;
                Ok(Response::Usage {
                    records: page.operations,
                    next,
                })
            }
        }
    }
}

/// Serves one connection: one request frame, one response frame.
///
/// # Errors
///
/// Fails when the stream fails or the frame does not decode. The client
/// then sees the connection close, as with `fstp-keyd`.
pub fn serve_connection(
    server: &Mutex<Server>,
    mut stream: UnixStream,
) -> Result<(), NotImplemented> {
    let io = |_| NotImplemented::new("fstp-custody-sim: a connection failed");
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(io)?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream.read_exact(&mut header).map_err(io)?;
    let len = frame_body_len(&header)
        .map_err(|_| NotImplemented::new("fstp-custody-sim: a frame header broke the format"))?;
    let mut frame = header.to_vec();
    frame.resize(FRAME_HEADER_LEN.saturating_add(len), 0);
    let body = frame
        .get_mut(FRAME_HEADER_LEN..)
        .ok_or(NotImplemented::new("fstp-custody-sim: a frame was cut"))?;
    stream.read_exact(body).map_err(io)?;
    let request = fstp_keyd::request::decode_request(&frame);
    // The frame may hold a seal key: overwrite it once decoded.
    frame.fill(0);
    let response = match request {
        Ok(r) => server
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .handle(&r),
        Err(_) => Response::Refused(Refusal::BadRequest),
    };
    let mut out = fstp_keyd::request::encode_response(&response)
        .map_err(|_| NotImplemented::new("fstp-custody-sim: a response did not encode"))?;
    let sent = stream.write_all(&out).and_then(|()| stream.flush());
    out.fill(0);
    sent.map_err(io)
}

/// Serves `sim` on the Unix socket `socket` until standard input closes,
/// then removes the socket. It prints `ready` on standard output once the
/// socket listens.
///
/// # Errors
///
/// Fails when the socket cannot be bound or `ready` cannot be printed.
pub fn serve(socket: &Path, sim: CustodySim) -> Result<(), NotImplemented> {
    let listener = UnixListener::bind(socket)
        .map_err(|_| NotImplemented::new("fstp-custody-sim: cannot bind the socket"))?;
    let server = Arc::new(Mutex::new(Server::new(sim)));
    let accept = Arc::clone(&server);
    std::thread::Builder::new()
        .name("fstp-custody-sim-accept".to_owned())
        .spawn(move || {
            for stream in listener.incoming().flatten() {
                // A failed connection ends only that connection.
                let _ = serve_connection(&accept, stream);
            }
        })
        .map_err(|_| NotImplemented::new("fstp-custody-sim: cannot start the accept thread"))?;
    let mut stdout = std::io::stdout();
    stdout
        .write_all(b"ready\n")
        .and_then(|()| stdout.flush())
        .map_err(|_| NotImplemented::new("fstp-custody-sim: cannot write to stdout"))?;
    let mut sink = [0u8; 256];
    let mut stdin = std::io::stdin();
    while matches!(stdin.read(&mut sink), Ok(n) if n > 0) {}
    let _ = std::fs::remove_file(socket);
    drop(server);
    Ok(())
}
