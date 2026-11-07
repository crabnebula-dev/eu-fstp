//! Transports, and the record and replay wrappers (M7 design section 6).

use core::fmt;
use std::future::Future;
use std::path::PathBuf;

use crate::encode::EncodedRequest;

/// Why a transport failed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TransportError {
    /// The endpoint could not be reached or did not answer in time.
    Unavailable,
    /// The endpoint answered with a status other than 200.
    Status(u16),
    /// No recording exists for the request digest.
    ReplayMiss([u8; 32]),
    /// A recording could not be read or written.
    Storage,
    /// The synthetic model refused a request it cannot read.
    Refused,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            TransportError::Unavailable => f.write_str("endpoint unavailable"),
            TransportError::Status(s) => write!(f, "endpoint answered {s}"),
            TransportError::ReplayMiss(d) => {
                write!(f, "no recording for {}", crate::encode::hex(d))
            }
            TransportError::Storage => f.write_str("recording storage failed"),
            TransportError::Refused => f.write_str("request refused"),
        }
    }
}

impl std::error::Error for TransportError {}

/// Carries one encoded request to a model and returns the response body.
pub trait Transport: Send + Sync {
    /// Exchanges one request for one response body.
    fn exchange(
        &self,
        req: &EncodedRequest,
    ) -> impl Future<Output = Result<Vec<u8>, TransportError>> + Send;
}

/// Saves each response of an inner transport as `<dir>/<digest>.json`.
#[derive(Debug)]
pub struct Record<T> {
    inner: T,
    dir: PathBuf,
}

impl<T: Transport> Record<T> {
    /// Records the exchanges of `inner` into `dir`.
    pub fn new(inner: T, dir: PathBuf) -> Record<T> {
        Record { inner, dir }
    }
}

impl<T: Transport> Transport for Record<T> {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        let response = self.inner.exchange(req).await?;
        let file = self.dir.join(format!("{}.json", req.digest_hex()));
        let tmp = self.dir.join(format!("{}.json.tmp", req.digest_hex()));
        std::fs::create_dir_all(&self.dir).map_err(|_| TransportError::Storage)?;
        std::fs::write(&tmp, &response).map_err(|_| TransportError::Storage)?;
        std::fs::rename(&tmp, &file).map_err(|_| TransportError::Storage)?;
        Ok(response)
    }
}

/// Answers each request from `<dir>/<digest>.json` only. A miss fails.
#[derive(Debug)]
pub struct Replay {
    dir: PathBuf,
}

impl Replay {
    /// Replays the recordings in `dir`.
    pub fn new(dir: PathBuf) -> Replay {
        Replay { dir }
    }
}

impl Transport for Replay {
    async fn exchange(&self, req: &EncodedRequest) -> Result<Vec<u8>, TransportError> {
        let file = self.dir.join(format!("{}.json", req.digest_hex()));
        match std::fs::read(&file) {
            Ok(bytes) => Ok(bytes),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Err(TransportError::ReplayMiss(req.digest()))
            }
            Err(_) => Err(TransportError::Storage),
        }
    }
}
