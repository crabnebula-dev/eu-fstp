//! The assessor's outbound destinations (ADR-009 amendment "assessor
//! egress", I-16, B4).
//!
//! [`AssessorDestination`] is closed. Every connection of the assessor
//! goes through a [`Fence`]: a [`Runtime`] that resolves only the host and
//! port of its one endpoint, connects only to the addresses that endpoint
//! resolved to, and never listens. The inference client and the
//! retrieval client each get their own fence, so neither reaches the
//! other's endpoint.

use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use fstp_http::{RequestTarget, Scheme};
use fstp_rt::{JoinHandle, Runtime};

/// Where the assessor may open a connection. Closed and exhaustive. No
/// variant reaches a payment service, a CrabNebula host, the vault or a
/// database (I-16, I-38). A new variant needs an amendment of ADR-009.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AssessorDestination {
    /// The tenant's P-21 endpoint from its inference record, POST only
    /// (ADR-019).
    Inference,
    /// The retrieval proxy. In M7 it reaches the fixture server only.
    Retrieval,
}

impl AssessorDestination {
    /// Every destination.
    pub const ALL: [AssessorDestination; 2] = [
        AssessorDestination::Inference,
        AssessorDestination::Retrieval,
    ];
}

/// Why an endpoint could not be fenced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EgressError {
    /// The URL is not an absolute `http` or `https` URL with a host.
    Url,
    /// The TLS configuration of an `https` endpoint failed.
    Tls,
}

fn refused() -> io::Error {
    io::Error::new(
        io::ErrorKind::PermissionDenied,
        "outside the assessor destination",
    )
}

#[derive(Debug)]
struct Endpoint {
    host: String,
    port: u16,
    resolved: Mutex<Vec<SocketAddr>>,
}

/// A runtime that reaches one destination only (B4).
#[derive(Debug)]
pub struct Fence<R> {
    rt: R,
    to: AssessorDestination,
    endpoint: Arc<Endpoint>,
}

impl<R: Clone> Clone for Fence<R> {
    fn clone(&self) -> Self {
        Fence {
            rt: self.rt.clone(),
            to: self.to,
            endpoint: self.endpoint.clone(),
        }
    }
}

/// The scheme, lowercase host and port of an absolute URL.
pub(crate) fn authority(url: &str) -> Result<(Scheme, String, u16), EgressError> {
    let target = RequestTarget::absolute(url).map_err(|_| EgressError::Url)?;
    let scheme = target.scheme().ok_or(EgressError::Url)?;
    let a = target.authority().ok_or(EgressError::Url)?;
    let host = a.host_for_connect().to_ascii_lowercase();
    if host.is_empty() {
        return Err(EgressError::Url);
    }
    Ok((scheme, host, a.port().unwrap_or(scheme.default_port())))
}

impl<R: Runtime> Fence<R> {
    /// A fence around `rt` that reaches only the host and port of `url`
    /// for `to`.
    ///
    /// # Errors
    ///
    /// [`EgressError::Url`] when `url` is not an absolute `http` or
    /// `https` URL.
    pub fn new(rt: R, to: AssessorDestination, url: &str) -> Result<Fence<R>, EgressError> {
        let (_, host, port) = authority(url)?;
        Ok(Fence {
            rt,
            to,
            endpoint: Arc::new(Endpoint {
                host,
                port,
                resolved: Mutex::new(Vec::new()),
            }),
        })
    }

    /// The destination this fence reaches.
    pub fn destination(&self) -> AssessorDestination {
        self.to
    }

    fn admits(&self, addr: SocketAddr) -> bool {
        self.endpoint
            .resolved
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .contains(&addr)
    }
}

impl<R: Runtime> Runtime for Fence<R> {
    type Tcp = R::Tcp;
    type TcpListener = R::TcpListener;

    fn spawn<F>(&self, f: F) -> JoinHandle<F::Output>
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
    {
        self.rt.spawn(f)
    }

    fn spawn_blocking<F, T>(&self, f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        self.rt.spawn_blocking(f)
    }

    fn sleep(&self, d: Duration) -> impl Future<Output = ()> + Send + 'static {
        self.rt.sleep(d)
    }

    fn connect_tcp(&self, addr: SocketAddr) -> impl Future<Output = io::Result<Self::Tcp>> + Send {
        let admitted = self.admits(addr);
        let rt = self.rt.clone();
        async move {
            if !admitted {
                return Err(refused());
            }
            rt.connect_tcp(addr).await
        }
    }

    fn bind_tcp(
        &self,
        _addr: SocketAddr,
    ) -> impl Future<Output = io::Result<Self::TcpListener>> + Send {
        std::future::ready(Err(refused()))
    }

    fn resolve(
        &self,
        host: &str,
        port: u16,
    ) -> impl Future<Output = io::Result<Vec<SocketAddr>>> + Send {
        let ours = port == self.endpoint.port && host.eq_ignore_ascii_case(&self.endpoint.host);
        let rt = self.rt.clone();
        let endpoint = self.endpoint.clone();
        async move {
            if !ours {
                return Err(refused());
            }
            let addrs = rt.resolve(&endpoint.host, endpoint.port).await?;
            let mut seen = endpoint
                .resolved
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            for a in &addrs {
                if !seen.contains(a) {
                    seen.push(*a);
                }
            }
            Ok(addrs)
        }
    }
}
