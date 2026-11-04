//! The cell's vault client over the vault's internal mutual TLS listener
//! (design sections 6.1 and 6.2, NOTE 2, NOTE 4). Lane int5.
//!
//! [`HttpVaultClient`] posts the `fstp-vault-proto` requests to
//! `/v1/epoch`, `/v1/ask` and `/v1/ack` with the cell's `cell-app`
//! certificate, and decodes the vault's canonical replies. Every fault
//! fails the command closed (NOTE 2).
//!
//! Reading of lane int5, reported to Daniel and the lead: ADR-010 open
//! point 5 leaves open which vault rows the vault chain records. The vault
//! service therefore refuses every call that would change its database,
//! the query log of an `ask` and the acknowledgement included, until its
//! chain records them (`fstp_vault::service`). So `ask` and `ack` here
//! refuse as well, before anything is sent, and only the epoch is read
//! from the vault. A command without vault questions runs. One with
//! questions fails closed with [`VaultFault::Unavailable`].

use std::future::Future;

use fstp_cell_core::driver::VaultFault;
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;
use fstp_rt::Runtime;
use fstp_vault_proto::{VaultRequest, VaultResponse, decode_response, encode_request};

use crate::engine::VaultClient;

/// The vault client of one cell (module documentation).
pub struct HttpVaultClient<R: Runtime> {
    client: fstp_http::Client<R>,
    base: String,
}

impl<R: Runtime> std::fmt::Debug for HttpVaultClient<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpVaultClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> HttpVaultClient<R> {
    /// A client of the vault at `base`, such as `https://127.0.0.1:4100`,
    /// with `tls`: the vault's internal CA as the only root and the cell's
    /// `cell-app` certificate.
    pub fn new(rt: R, base: String, tls: fstp_tls::ClientConfig) -> HttpVaultClient<R> {
        let config = fstp_http::ClientConfig {
            tls: Some(tls),
            ..fstp_http::ClientConfig::default()
        };
        HttpVaultClient {
            client: fstp_http::Client::new(rt, config),
            base,
        }
    }

    async fn call(&self, path: &str, req: &VaultRequest) -> Result<VaultResponse, VaultFault> {
        let body = encode_request(req).map_err(|_| VaultFault::Refused)?;
        let url = format!("{}{path}", self.base);
        let request = fstp_http::Request::post(&url, body)
            .and_then(|r| r.try_with_header("content-type", "application/json"))
            .map_err(|_| VaultFault::Refused)?;
        let resp = self
            .client
            .send(request)
            .await
            .map_err(|_| VaultFault::Unavailable)?;
        if resp.status.as_u16() != 200 {
            return Err(VaultFault::Unavailable);
        }
        decode_response(&resp.body).map_err(|_| VaultFault::Unavailable)
    }
}

impl<R: Runtime> VaultClient for HttpVaultClient<R> {
    async fn epoch(&self) -> Result<VaultEpoch, VaultFault> {
        match self.call("/v1/epoch", &VaultRequest::Epoch).await? {
            VaultResponse::Epoch(e) => Ok(VaultEpoch::from_raw(e)),
            VaultResponse::Refused(_) => Err(VaultFault::Refused),
            VaultResponse::Answers(_) | VaultResponse::Acked => Err(VaultFault::Unavailable),
        }
    }

    fn ask(
        &self,
        queries: &[Query],
        reaction_for: Option<VaultEpoch>,
        at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        // The vault records each answer in its query log, which waits on
        // its chain (module documentation).
        let _ = (queries, reaction_for, at);
        std::future::ready(Err(VaultFault::Unavailable))
    }

    fn ack(
        &self,
        epoch: VaultEpoch,
        seq: Seq,
        link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        // An acknowledgement changes the vault's epoch row (module
        // documentation).
        let _ = (epoch, seq, link);
        std::future::ready(Err(VaultFault::Unavailable))
    }
}
