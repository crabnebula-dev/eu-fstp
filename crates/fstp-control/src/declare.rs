//! `declare-restore`: the SaaS restore declaration at the witness (ADR-012
//! "Declared restores at the witness" and the record of lane
//! m10/saas-declare, ADR-011 `DeclareRestore`). Every format here is
//! interim, pending Daniel.
//!
//! A restore that will serve production is declared at the witness before
//! the restored cell or vault serves. Each chain is one destructive job,
//! [`DestructiveJob::DeclareRestore`], so it runs only as an
//! [`ApprovedJob`] of two operators ([`crate::approval`]). Both chains of
//! one restore share the job id, so each operator approves them once as a
//! batch ([`declare_restore_batch`]).
//!
//! [`declare_restore`] signs the job's [`RestoreStatement`] with the
//! restore declaration key and sends it through a [`RestoreWitness`].
//! [`TlsRestoreWitness`] speaks the witness wire over mutual TLS with a
//! `control-witness` certificate of the control-plane CA. The witness
//! answers with the recorded declaration, which `declare_restore` checks
//! against its statement and the pinned witness keys.
//!
//! # The restore declaration key
//!
//! A composite key, sealed in [`KEY_FILE`] as the route feed key is
//! ([`crate::route_feed`]): the private key under a seal key `S(e)`, and
//! `S(e)` wrapped by `fstp-keyd` under a ControlPlane root, which never
//! leaves custody (I-80). Only the magic differs ([`KEY_MAGIC`]).
//! [`create_declaration_key`] makes it and [`open_declaration_key`] opens
//! it. Its public keys reach the witness, and any verifier that pins them,
//! as [`PUBLIC_KEYS_FILE`]. The SaaS `fstp-control` has no `fstp-keyd`
//! entry in its configuration yet, so no command calls these.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use fstp_audit::witness::{Declaration, RestoreStatement, declaration_verifies, sign_statement};
use fstp_audit::{ChainId, Link};
use fstp_cp_proto::CellId;
use fstp_crypto::composite::CompositeSigningKey;
use fstp_custody::Custody;
use fstp_rt::{IoExt as _, Runtime};
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};

use crate::ControlError;
use crate::approval::{ApprovalBatch, ApprovedJob, DestructiveJob};
use crate::route_feed::{
    FeedKeyFile, create_sealed_key, decode_sealed_key_file, encode_sealed_key_file, open_sealed_key,
};

/// The magic that opens a restore declaration key file and labels its AAD.
pub const KEY_MAGIC: &[u8; 27] = b"fstp-restore-declare-key-v1";

/// The sealed restore declaration key in `fstp-control`'s credentials
/// directory.
pub const KEY_FILE: &str = "restore-declaration.key";

/// The public keys of the restore declaration key, current and next, one
/// lowercase hex line each, as a witness reads them
/// (`fstp_witness::config::DECLARATION_KEYS_FILE`).
pub const PUBLIC_KEYS_FILE: &str = "restore-declaration-keys";

/// How long one exchange with the witness may take.
pub const WITNESS_TIMEOUT: Duration = Duration::from_secs(20);

/// Encodes a restore declaration key file: the layout of
/// [`crate::route_feed::encode_feed_key_file`] under [`KEY_MAGIC`].
///
/// # Errors
///
/// [`ControlError::Config`] for an empty or overlong field, or a sealed
/// key of another length.
pub fn encode_declaration_key_file(f: &FeedKeyFile) -> Result<Vec<u8>, ControlError> {
    encode_sealed_key_file(KEY_MAGIC, f)
}

/// Decodes a restore declaration key file. Fuzzed
/// (`declaration_key_file_decode`).
///
/// # Errors
///
/// [`ControlError::Config`] for a wrong magic, a cut or overlong field, or
/// trailing bytes.
pub fn decode_declaration_key_file(bytes: &[u8]) -> Result<FeedKeyFile, ControlError> {
    decode_sealed_key_file(KEY_MAGIC, bytes)
}

/// Seals `key` under a fresh `S(e)`, has `custody` create the ControlPlane
/// root and wrap `S(e)` under it, and returns the key file.
///
/// # Errors
///
/// [`ControlError::Custody`] when custody refuses, and
/// [`ControlError::Job`] when the seal fails.
pub async fn create_declaration_key<C: Custody>(
    custody: &C,
    key: &CompositeSigningKey,
) -> Result<Vec<u8>, ControlError> {
    create_sealed_key(custody, KEY_MAGIC, key).await
}

/// Opens the restore declaration key of the key file `bytes` through
/// `custody`.
///
/// # Errors
///
/// [`ControlError::Config`] for a file that does not decode or open, and
/// [`ControlError::Custody`] when custody does not unwrap `S(e)`.
pub async fn open_declaration_key<C: Custody>(
    custody: &C,
    bytes: &[u8],
) -> Result<CompositeSigningKey, ControlError> {
    open_sealed_key(custody, KEY_MAGIC, bytes).await
}

/// The two jobs of one restore of `cell`, by the job id `job`: the App
/// chain to `app_head`, then the Vault chain to `vault_head`.
pub fn declare_restore_jobs(
    cell: CellId,
    job: [u8; 16],
    app_head: (u64, [u8; 32]),
    vault_head: (u64, [u8; 32]),
) -> [DestructiveJob; 2] {
    [
        DestructiveJob::DeclareRestore {
            cell,
            chain: ChainId::App,
            head: app_head,
            job,
        },
        DestructiveJob::DeclareRestore {
            cell,
            chain: ChainId::Vault,
            head: vault_head,
            job,
        },
    ]
}

/// The batch that each of the two operators approves once for one
/// restore: the digests of [`declare_restore_jobs`].
///
/// # Errors
///
/// The errors of [`ApprovalBatch::of`].
pub fn declare_restore_batch(
    cell: CellId,
    job: [u8; 16],
    app_head: (u64, [u8; 32]),
    vault_head: (u64, [u8; 32]),
) -> Result<ApprovalBatch, ControlError> {
    ApprovalBatch::of(&declare_restore_jobs(cell, job, app_head, vault_head))
}

/// The statement of a `declare-restore` job.
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] for a job of another kind.
pub fn statement_of(job: &DestructiveJob) -> Result<RestoreStatement, ControlError> {
    match job {
        DestructiveJob::DeclareRestore {
            cell,
            chain,
            head,
            job,
        } => Ok(RestoreStatement {
            cell: fstp_audit::CellId(cell.0),
            chain: *chain,
            head: (head.0, Link(head.1)),
            job: *job,
        }),
        DestructiveJob::EraseCell { .. } | DestructiveJob::Pgagent(_) => {
            Err(ControlError::ApprovalRequired)
        }
    }
}

/// The witness as `fstp-control` reaches it to declare a restore.
pub trait RestoreWitness {
    /// Sends `statement` with its `signature` and returns the declaration
    /// the witness recorded.
    fn declare(
        &self,
        statement: &RestoreStatement,
        signature: &[u8],
    ) -> impl Future<Output = Result<Declaration, ControlError>>;
}

/// Runs the approved `declare-restore` job: signs its statement with the
/// restore declaration key `signer`, sends it through `witness`, and
/// checks the answer. The recorded declaration must name the statement's
/// head and job, carry the statement signature, and verify under
/// `witness_keys` and the signer's public key (I-90).
///
/// # Errors
///
/// [`ControlError::ApprovalRequired`] when `approved` is not a
/// `declare-restore` job. [`ControlError::Job`] when the signature fails,
/// the witness refuses, or its answer does not check. The errors of
/// `witness`.
pub async fn declare_restore<W: RestoreWitness>(
    approved: &ApprovedJob,
    signer: &CompositeSigningKey,
    witness: &W,
    witness_keys: &[Vec<u8>],
) -> Result<Declaration, ControlError> {
    let statement = statement_of(approved.job())?;
    let signature =
        sign_statement(signer, &statement).map_err(|_| ControlError::Job("the statement"))?;
    let d = witness.declare(&statement, &signature).await?;
    let own = vec![signer.public_key().to_bytes().to_vec()];
    let named = RestoreStatement::of(statement.cell, statement.chain, &d.fields) == statement;
    let same = d.statement.as_deref() == Some(signature.as_slice());
    if !named
        || !same
        || !declaration_verifies(statement.cell, statement.chain, &d, witness_keys, &own)
    {
        return Err(ControlError::Job("the witness declaration"));
    }
    Ok(d)
}

/// The SaaS witness over mutual TLS, with a `control-witness` client
/// certificate of the control-plane CA (ADR-009 witness row). One
/// connection per declaration.
pub struct TlsRestoreWitness<R: Runtime> {
    rt: R,
    addr: SocketAddr,
    server_name: String,
    tls: Arc<fstp_tls::ClientConfig>,
}

impl<R: Runtime> std::fmt::Debug for TlsRestoreWitness<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsRestoreWitness")
            .field("addr", &self.addr)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> TlsRestoreWitness<R> {
    /// The witness at `addr`, whose server certificate names `server_name`
    /// under `roots_pem`, reached with the client chain `cert_pem` and key
    /// `key_pem`, on `rt`.
    ///
    /// # Errors
    ///
    /// [`ControlError::Tls`] when the TLS configuration does not build.
    pub fn new(
        rt: R,
        addr: SocketAddr,
        server_name: &str,
        roots_pem: &[u8],
        cert_pem: &[u8],
        key_pem: &[u8],
    ) -> Result<TlsRestoreWitness<R>, ControlError> {
        let tls = fstp_tls::ClientConfig::mutual(roots_pem, cert_pem, key_pem)
            .map_err(|_| ControlError::Tls("the witness client"))?;
        Ok(TlsRestoreWitness {
            rt,
            addr,
            server_name: server_name.to_owned(),
            tls: Arc::new(tls),
        })
    }

    async fn exchange(&self, req: &WireRequest) -> Result<WireReply, ControlError> {
        let bytes = encode_request(req).map_err(|_| ControlError::Job("the declaration"))?;
        let tcp = self
            .rt
            .connect_tcp(self.addr)
            .await
            .map_err(|e| ControlError::Io(e.kind()))?;
        let mut stream = fstp_tls::connect(&self.tls, &self.server_name, tcp)
            .await
            .map_err(|e| ControlError::Io(e.kind()))?;
        write_frame(&mut stream, &bytes)
            .await
            .map_err(|e| ControlError::Io(e.kind()))?;
        let frame = fstp_rt::timeout(&self.rt, WITNESS_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| ControlError::Io(std::io::ErrorKind::TimedOut))?
            .map_err(|e| ControlError::Io(e.kind()))?
            .ok_or(ControlError::Io(std::io::ErrorKind::UnexpectedEof))?;
        let _ = stream.shutdown().await;
        decode_reply(&frame).map_err(|_| ControlError::Job("the witness answer"))
    }
}

impl<R: Runtime> RestoreWitness for TlsRestoreWitness<R> {
    async fn declare(
        &self,
        statement: &RestoreStatement,
        signature: &[u8],
    ) -> Result<Declaration, ControlError> {
        let req = WireRequest::Declare {
            statement: *statement,
            signature: signature.to_vec(),
        };
        match self.exchange(&req).await? {
            WireReply::Declared(d) => Ok(d),
            WireReply::Refused => Err(ControlError::Job("the witness refused the declaration")),
            _ => Err(ControlError::Job("the witness answer")),
        }
    }
}
