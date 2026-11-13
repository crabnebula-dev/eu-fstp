//! The vault chain writer (I-24, ADR-010 "The vault chain is anchored by
//! the vault only", open point 5). Lane F-VCHAIN.
//!
//! Daniel decided on 2026-11-13 (m3-finish Q-C): each committed fact
//! batch and each identity release or read is a kind 1 row of
//! `vault_audit.chain`. A KeyOp stays an event only (kind 2).
//!
//! One vault call whose journal is not empty is one entry, and so one kind
//! 1 row. Its entry schema is [`ENTRY_FACTS`] when the call wrote or
//! changed a fact, epoch, negotiation, condition, identity or account,
//! [`ENTRY_RELEASE`] when it used a release ticket only, and
//! [`ENTRY_READ`] when it logged queries only. The vault has no ledger, so
//! the row carries its own entry (migration 7): `entry_seq`, a random
//! `entry_command`, `entry_schema`, and a sealed `body`. The body holds
//! the digest of every row the call wrote (`crate::store::persist_in`).
//! The row's stored hash is the ADR-010 kind 1 hash over that entry, so
//! `fstp_audit::verify` checks it like an application chain row.
//!
//! [`VaultChain::commit`] runs the strict tail D of ADR-010 with the
//! `fstp_audit` anchorer core, in one transaction: the journal's rows, the
//! chain row, the prepare at the witness, the anchor with its receipt,
//! then COMMIT. No row commits before the witness receipted its link.
//!
//! [`VaultChain::open`] runs at start-up, before the vault serves. It
//! resolves the witness's outstanding prepare, then verifies the whole
//! chain, its anchors and the witness log with `fstp_audit::verify`.
//!
//! Interim reading of this lane, pending Daniel: the vault has no alert
//! store for `PossibleDeletion`. A prepare whose row is missing after an
//! unknown COMMIT outcome is recorded at the witness as `InDoubtAbsent`,
//! and the vault then refuses to start. The refusal is the detection, and
//! it repeats until an operator resolves it. At run time an unknown
//! outcome stops writes until the next start.

use std::net::SocketAddr;
use std::time::Duration;

use fstp_audit::anchor::{Anchor, AnchorRow, Receipt, decode_receipt, encode_receipt, sign_anchor};
use fstp_audit::anchorer::{AfterCommit, Anchorer, CommitOutcome, Resolution, Step};
use fstp_audit::chain::{ChainRow, ChainWriter, RowKind, StoredEntry, StoredRow, genesis};
use fstp_audit::verify::{ChainView, verify};
use fstp_audit::witness::{Prepare, WitnessRecord};
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_pgwire::Client;
use fstp_rt::Runtime;
use fstp_witness::lock::AsyncMutex;
use fstp_witness::wire::{
    WireReply, WireRequest, decode_reply, encode_request, read_frame, write_frame,
};

use crate::VaultError;
use crate::origin::JournalEntry;
use crate::store::{Sealer, persist_in};

/// The entry schema of a fact batch.
pub const ENTRY_FACTS: i16 = 1;
/// The entry schema of an identity release.
pub const ENTRY_RELEASE: i16 = 2;
/// The entry schema of an identity read.
pub const ENTRY_READ: i16 = 3;

/// The kind code of a kind 1 row.
const KIND_ENTRY: i16 = 1;

/// How long one witness connection, handshake included, may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How long one witness exchange may take.
pub const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

/// Where and how the vault reaches its witness (ADR-010 "Witnesses").
#[derive(Clone, Debug)]
pub struct VaultWitness {
    /// The witness address.
    pub addr: SocketAddr,
    /// The name its server certificate carries.
    pub server_name: String,
    /// The client configuration: the witness CA as the only root, and the
    /// vault's `vault-witness` certificate from the cell CA.
    pub tls: fstp_tls::ClientConfig,
    /// The SHA-256 digest of the witness CA's SubjectPublicKeyInfo. The
    /// configuration trusts that CA alone, so a completed handshake was
    /// verified under it (R-NF-09).
    pub ca_digest: [u8; 32],
}

/// What the vault chain writer starts from.
pub struct VaultChainParts {
    /// The Vault chain's composite anchor key (ADR-004, purpose `Anchor`).
    pub anchor_key: CompositeSigningKey,
    /// The witness.
    pub witness: VaultWitness,
    /// The pinned witness receipt keys, encoded.
    pub witness_keys: Vec<Vec<u8>>,
}

impl std::fmt::Debug for VaultChainParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VaultChainParts")
            .field("witness", &self.witness.addr)
            .finish_non_exhaustive()
    }
}

/// The entry schema of a journal (module documentation).
#[must_use]
pub fn entry_schema(entries: &[JournalEntry]) -> i16 {
    let fact = entries.iter().any(|e| {
        !matches!(
            e,
            JournalEntry::TicketUsed { .. } | JournalEntry::Asked { .. }
        )
    });
    if fact {
        ENTRY_FACTS
    } else if entries
        .iter()
        .any(|e| matches!(e, JournalEntry::TicketUsed { .. }))
    {
        ENTRY_RELEASE
    } else {
        ENTRY_READ
    }
}

/// The body of an entry before sealing: `be32(count)` and each row
/// digest.
fn entry_plain(digests: &[[u8; 32]]) -> Vec<u8> {
    let count = u32::try_from(digests.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(digests.len().saturating_mul(32).saturating_add(4));
    out.extend_from_slice(&count.to_be_bytes());
    for d in digests {
        out.extend_from_slice(d);
    }
    out
}

/// The AAD of an entry body.
fn entry_aad(seq: u64) -> Vec<u8> {
    [&b"vault_audit.chain.body|"[..], &seq.to_be_bytes()].concat()
}

/// Why a witness exchange failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fault {
    /// No answer: the connection failed or the answer was lost.
    Unreachable,
    /// The witness refused the request.
    Refused,
}

struct Conn<R: Runtime> {
    stream: Option<fstp_tls::TlsStream<R::Tcp>>,
}

impl<R: Runtime> Default for Conn<R> {
    fn default() -> Self {
        Conn { stream: None }
    }
}

/// The vault's link to its witness: one connection over mutual TLS, one
/// framed exchange at a time. A failed exchange drops the connection.
struct WitnessLink<R: Runtime> {
    rt: R,
    endpoint: VaultWitness,
    conn: AsyncMutex<Conn<R>>,
}

impl<R: Runtime> WitnessLink<R> {
    async fn connect(&self) -> Result<fstp_tls::TlsStream<R::Tcp>, Fault> {
        let open = async {
            let tcp = self.rt.connect_tcp(self.endpoint.addr).await?;
            fstp_tls::connect(&self.endpoint.tls, &self.endpoint.server_name, tcp).await
        };
        match fstp_rt::timeout(&self.rt, CONNECT_TIMEOUT, open).await {
            Ok(Ok(stream)) => Ok(stream),
            _ => Err(Fault::Unreachable),
        }
    }

    async fn exchange(&self, req: &WireRequest) -> Result<WireReply, Fault> {
        let bytes = encode_request(req).map_err(|_| Fault::Refused)?;
        let mut conn = self.conn.lock().await;
        if conn.stream.is_none() {
            conn.stream = Some(self.connect().await?);
        }
        let Some(stream) = conn.stream.as_mut() else {
            return Err(Fault::Unreachable);
        };
        let run = async {
            write_frame(stream, &bytes).await?;
            read_frame(stream).await
        };
        match fstp_rt::timeout(&self.rt, EXCHANGE_TIMEOUT, run).await {
            Ok(Ok(Some(frame))) => decode_reply(&frame).map_err(|_| {
                conn.stream = None;
                Fault::Unreachable
            }),
            _ => {
                conn.stream = None;
                Err(Fault::Unreachable)
            }
        }
    }

    async fn message(&self, m: fstp_witness::WitnessMessage) -> Result<WireReply, Fault> {
        self.exchange(&WireRequest::Message(m)).await
    }

    async fn outstanding(&self, cell: CellId) -> Result<Option<(u64, Link)>, Fault> {
        let chain = ChainId::Vault;
        match self
            .exchange(&WireRequest::Outstanding { cell, chain })
            .await?
        {
            WireReply::Outstanding(o) => Ok(o),
            WireReply::Refused => Err(Fault::Refused),
            _ => Err(Fault::Unreachable),
        }
    }

    async fn log(&self, cell: CellId) -> Result<Vec<WitnessRecord>, Fault> {
        let chain = ChainId::Vault;
        let mut records: Vec<WitnessRecord> = Vec::new();
        loop {
            let req = match u64::try_from(records.len()) {
                Ok(0) => WireRequest::Log { cell, chain },
                Ok(after) => WireRequest::LogAfter { cell, chain, after },
                Err(_) => return Err(Fault::Unreachable),
            };
            match self.exchange(&req).await? {
                WireReply::Log(page) => {
                    let more = page.more && !page.records.is_empty();
                    records.extend(page.records);
                    if !more {
                        return Ok(records);
                    }
                }
                WireReply::Refused => return Err(Fault::Refused),
                _ => return Err(Fault::Unreachable),
            }
        }
    }
}

const DB: &str = "the vault chain";

fn db(_: fstp_pgwire::Error) -> VaultError {
    VaultError::Unavailable(DB)
}

fn int(n: u64) -> Result<i64, VaultError> {
    i64::try_from(n).map_err(|_| VaultError::Malformed("a chain number beyond the database range"))
}

fn uint(n: i64) -> Result<u64, VaultError> {
    u64::try_from(n).map_err(|_| VaultError::Malformed("a negative chain number"))
}

fn link32(v: &[u8]) -> Result<Link, VaultError> {
    <[u8; 32]>::try_from(v)
        .map(Link)
        .map_err(|_| VaultError::Malformed("a chain link"))
}

/// The refusal of a chain that does not verify or resolve (I-24).
const TAMPERED: VaultError = VaultError::Malformed("the vault chain does not verify (I-24)");

/// The refusal when no witness answers.
const NO_WITNESS: VaultError = VaultError::Unavailable("the witness");

/// The vault's chain: its head, the anchorer core and the witness link.
/// Public so the seeded vault of a test world writes its chain as
/// `crate::service` does (lane m3/login-m2http, Daniel's Q-C).
pub struct VaultChain<R: Runtime> {
    cell: CellId,
    key: CompositeSigningKey,
    witness_keys: Vec<Vec<u8>>,
    link: WitnessLink<R>,
    head: (u64, Link),
    next_seq: u64,
    anchorer: Anchorer,
    /// An unknown COMMIT outcome stops writes until the next start.
    stopped: bool,
}

impl<R: Runtime> std::fmt::Debug for VaultChain<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The anchor key never shows.
        f.debug_struct("VaultChain")
            .field("head", &self.head.0)
            .field("next_seq", &self.next_seq)
            .field("stopped", &self.stopped)
            .finish_non_exhaustive()
    }
}

/// The chain as the database holds it.
struct Stored {
    rows: Vec<StoredRow>,
    entries: Vec<StoredEntry>,
    anchors: Vec<AnchorRow>,
}

async fn read_chain<R: Runtime>(
    client: &mut Client<R>,
    cell: CellId,
) -> Result<Stored, VaultError> {
    let bad = |_| VaultError::Malformed("a vault chain row");
    let rows = client
        .query(
            "SELECT n, at, kind, stored_hash, link, body, entry_seq, entry_command, entry_schema \
             FROM vault_audit.chain ORDER BY n",
            &[],
        )
        .await
        .map_err(db)?;
    let mut out = Stored {
        rows: Vec::with_capacity(rows.len()),
        entries: Vec::new(),
        anchors: Vec::new(),
    };
    for r in &rows {
        let n = uint(r.get::<i64>(0).map_err(bad)?)?;
        let at: i64 = r.get(1).map_err(bad)?;
        let kind: i16 = r.get(2).map_err(bad)?;
        let stored_hash = link32(&r.get::<Vec<u8>>(3).map_err(bad)?)?.0;
        let link = link32(&r.get::<Vec<u8>>(4).map_err(bad)?)?;
        let body: Vec<u8> = r.get(5).map_err(bad)?;
        let kind = if kind == KIND_ENTRY {
            let seq = uint(r.get::<i64>(6).map_err(bad)?)?;
            let command: Vec<u8> = r.get(7).map_err(bad)?;
            let schema: i16 = r.get(8).map_err(bad)?;
            out.entries.push(StoredEntry {
                seq,
                at,
                command: <[u8; 16]>::try_from(command.as_slice())
                    .map_err(|_| VaultError::Malformed("an entry command"))?,
                schema: u16::try_from(schema)
                    .map_err(|_| VaultError::Malformed("an entry schema"))?,
                key_ix: 0,
                body,
            });
            RowKind::Ledger { seq }
        } else {
            RowKind::Event { body }
        };
        out.rows.push(StoredRow {
            row: ChainRow {
                n,
                at,
                kind,
                stored_hash,
            },
            link,
        });
    }
    let anchors = client
        .query(
            "SELECT n, link, at, signature, receipt FROM vault_audit.anchor ORDER BY n",
            &[],
        )
        .await
        .map_err(db)?;
    for r in &anchors {
        let bad = |_| VaultError::Malformed("a vault anchor row");
        let receipt: Vec<u8> = r.get(4).map_err(bad)?;
        out.anchors.push(AnchorRow {
            anchor: Anchor {
                cell,
                chain: ChainId::Vault,
                n: uint(r.get::<i64>(0).map_err(bad)?)?,
                link: link32(&r.get::<Vec<u8>>(1).map_err(bad)?)?,
                at: r.get(2).map_err(bad)?,
                signature: r.get(3).map_err(bad)?,
            },
            receipt: decode_receipt(&receipt)
                .map_err(|_| VaultError::Malformed("a vault anchor receipt"))?,
        });
    }
    Ok(out)
}

/// The link of row `n`, read in a transaction that first waits for any
/// transaction still finishing (the anchorer's `ReadChain`).
async fn link_at<R: Runtime>(client: &mut Client<R>, n: u64) -> Result<Option<Link>, VaultError> {
    let row = client
        .query_opt(
            "SELECT link FROM vault_audit.chain WHERE n = $1",
            &[&int(n)?],
        )
        .await
        .map_err(db)?;
    match row {
        Some(r) => Ok(Some(link32(
            &r.get::<Vec<u8>>(0)
                .map_err(|_| VaultError::Malformed("a chain link"))?,
        )?)),
        None => Ok(None),
    }
}

impl<R: Runtime> VaultChain<R> {
    /// Opens the chain of `cell` over `client` (module documentation):
    /// resolves the witness's outstanding prepare, then verifies the
    /// chain, its anchors and the witness log.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when the witness or the database does
    /// not answer, and [`VaultError::Malformed`] for a chain that does not
    /// verify or a possible deletion.
    pub async fn open(
        rt: R,
        cell: [u8; 16],
        parts: VaultChainParts,
        client: &mut Client<R>,
    ) -> Result<VaultChain<R>, VaultError> {
        let cell = CellId(cell);
        let link = WitnessLink {
            rt,
            endpoint: parts.witness,
            conn: AsyncMutex::new(Conn::default()),
        };
        let open = link.outstanding(cell).await.map_err(|_| NO_WITNESS)?;
        if let Some(head) = open {
            let mut a = Anchorer::in_doubt(head);
            let at_n = link_at(client, head.0).await?;
            match a.chain_read(at_n.as_ref()).map_err(|_| TAMPERED)? {
                Resolution::Committed => {}
                Resolution::AbsentRaisePossibleDeletion => {
                    // The refusal below is the alert (interim reading in the
                    // module documentation). The record comes first, so the
                    // witness log shows the in-doubt prepare.
                    a.possible_deletion_raised().map_err(|_| TAMPERED)?;
                    let reply = link
                        .message(fstp_witness::WitnessMessage::InDoubtAbsent {
                            cell,
                            chain: ChainId::Vault,
                            n: head.0,
                            link: head.1,
                        })
                        .await;
                    let _ = reply;
                    return Err(VaultError::Malformed(
                        "a possible deletion of a vault chain row (I-24)",
                    ));
                }
            }
        }
        let stored = read_chain(client, cell).await?;
        let witness = link.log(cell).await.map_err(|_| NO_WITNESS)?;
        let anchor_keys = vec![parts.anchor_key.public_key().to_bytes().to_vec()];
        let view = ChainView {
            cell,
            chain: ChainId::Vault,
            rows: &stored.rows,
            ledger: &stored.entries,
            anchors: &stored.anchors,
            witness: &witness,
            anchor_keys: &anchor_keys,
            witness_keys: &parts.witness_keys,
        };
        verify(&view).map_err(|_| TAMPERED)?;
        let head = stored
            .rows
            .last()
            .map_or((0, genesis(cell, ChainId::Vault)), |r| (r.row.n, r.link));
        let next_seq = stored
            .entries
            .last()
            .map_or(Ok(1), |e| e.seq.checked_add(1).ok_or(TAMPERED))?;
        Ok(VaultChain {
            cell,
            key: parts.anchor_key,
            witness_keys: parts.witness_keys,
            link,
            head,
            next_seq,
            anchorer: Anchorer::new(),
            stopped: false,
        })
    }

    /// Commits `entries` with their kind 1 row, anchored at the witness,
    /// in one transaction (module documentation). Nothing is committed
    /// unless this returns `Ok`.
    ///
    /// # Errors
    ///
    /// [`VaultError::Unavailable`] when the witness or the database fails,
    /// and [`VaultError::Conflict`] for a used ticket. The caller keeps
    /// the vault it held before the call.
    #[allow(
        clippy::too_many_lines,
        reason = "the strict tail D, step by step, as ADR-010 lists it"
    )]
    pub async fn commit(
        &mut self,
        client: &mut Client<R>,
        sealer: &dyn Sealer,
        entries: &[JournalEntry],
        now: i64,
    ) -> Result<(), VaultError> {
        if self.stopped {
            return Err(NO_WITNESS);
        }
        let mut a = Anchorer::new();
        a.begin(true).map_err(|_| NO_WITNESS)?;
        let mut tx = client.transaction().await.map_err(db)?;
        for step in [Step::Lock, Step::CommandCheck, Step::HeadCheck] {
            a.step_done(step).map_err(|_| NO_WITNESS)?;
        }
        let digests = persist_in(&mut tx, sealer, entries).await?;
        a.step_done(Step::SealLedger).map_err(|_| NO_WITNESS)?;
        let seq = self.next_seq;
        let body = sealer.seal(&entry_aad(seq), &entry_plain(&digests))?;
        let command =
            fstp_crypto::random_array::<16>().map_err(|_| VaultError::Unavailable("randomness"))?;
        let schema = entry_schema(entries);
        let entry = StoredEntry {
            seq,
            at: now,
            command,
            schema: u16::try_from(schema).map_err(|_| TAMPERED)?,
            key_ix: 0,
            body: body.bytes.clone(),
        };
        let mut writer = ChainWriter::resume(self.head.0, self.head.1);
        let row = writer
            .append(
                self.cell,
                ChainId::Vault,
                now,
                RowKind::Ledger { seq },
                Some(&entry),
            )
            .map_err(|_| VaultError::Malformed("a vault chain row"))?;
        let epoch = entries
            .iter()
            .filter_map(|e| match e {
                JournalEntry::Written { epoch, .. } => Some(*epoch),
                _ => None,
            })
            .max()
            .map(int)
            .transpose()?;
        tx.execute(
            "INSERT INTO vault_audit.chain (n, at, kind, epoch, stored_hash, body, link, entry_seq, entry_command, entry_schema) \
             VALUES ($1, $2, 1, $3, $4, $5, $6, $7, $8, $9)",
            &[
                &int(row.row.n)?,
                &now,
                &epoch,
                &row.row.stored_hash.to_vec(),
                &body.bytes,
                &row.link.0.to_vec(),
                &int(seq)?,
                &command.to_vec(),
                &schema,
            ],
        )
        .await
        .map_err(db)?;
        a.step_done(Step::InsertChain).map_err(|_| NO_WITNESS)?;
        a.step_done(Step::SideEffects).map_err(|_| NO_WITNESS)?;
        let head = (row.row.n, row.link);
        let anchor = sign_anchor(&self.key, self.cell, ChainId::Vault, head.0, &head.1, now)
            .map_err(|_| VaultError::Unavailable("the anchor signature"))?;
        let prepare = Prepare {
            prev: self.head,
            stored_hashes: vec![row.row.stored_hash],
            anchor: anchor.clone(),
        };
        a.prepared(head).map_err(|_| NO_WITNESS)?;
        let reply = self
            .link
            .message(fstp_witness::WitnessMessage::Prepare(prepare))
            .await;
        let receipt: Receipt = match reply {
            Ok(WireReply::Receipt(r)) => r,
            Ok(_) => {
                // The witness refused and holds nothing for this head.
                let _ = tx.rollback().await;
                let _ = a.prepare_refused();
                return Err(NO_WITNESS);
            }
            Err(_) => {
                // The witness may hold the prepare: abort it before the same
                // n is prepared again (ADR-010 "Abort").
                let _ = tx.rollback().await;
                self.abort(head).await;
                return Err(NO_WITNESS);
            }
        };
        if a.signed_receipt(self.cell, ChainId::Vault, &receipt, &self.witness_keys)
            .is_err()
        {
            let _ = tx.rollback().await;
            self.abort(head).await;
            return Err(NO_WITNESS);
        }
        let encoded =
            encode_receipt(&receipt).map_err(|_| VaultError::Malformed("a witness receipt"))?;
        let stored = tx
            .execute(
                "INSERT INTO vault_audit.anchor (n, link, at, signature, witness_seq, receipt) \
                 VALUES ($1, $2, $3, $4, $5, $6)",
                &[
                    &int(head.0)?,
                    &head.1.0.to_vec(),
                    &anchor.at,
                    &anchor.signature,
                    &int(receipt.fields.witness_seq)?,
                    &encoded,
                ],
            )
            .await;
        if stored.is_err() {
            let _ = tx.rollback().await;
            self.abort(head).await;
            return Err(VaultError::Unavailable(DB));
        }
        a.anchor_inserted().map_err(|_| NO_WITNESS)?;
        a.commit_sent().map_err(|_| NO_WITNESS)?;
        let outcome = match tx.commit().await {
            Ok(()) => CommitOutcome::Committed,
            Err(e) if e.kind() == fstp_pgwire::ErrorKind::Db => CommitOutcome::Failed,
            Err(_) => CommitOutcome::Unknown,
        };
        match a.outcome(outcome).map_err(|_| NO_WITNESS)? {
            AfterCommit::Done => {
                self.head = head;
                self.next_seq = seq.checked_add(1).ok_or(TAMPERED)?;
                self.anchorer = a;
                Ok(())
            }
            AfterCommit::SendAbort => {
                self.abort(head).await;
                Err(VaultError::Unavailable(DB))
            }
            AfterCommit::InDoubt => {
                // The next start reads the chain and resolves the prepare.
                self.stopped = true;
                Err(VaultError::Unavailable(DB))
            }
        }
    }

    /// Sends `Abort { n, link }` for `head`. Without an answer the chain
    /// stops writes until the next start, which resolves the prepare.
    async fn abort(&mut self, head: (u64, Link)) {
        let reply = self
            .link
            .message(fstp_witness::WitnessMessage::Abort {
                cell: self.cell,
                chain: ChainId::Vault,
                n: head.0,
                link: head.1,
            })
            .await;
        if !matches!(reply, Ok(WireReply::Recorded | WireReply::UnknownPrepare)) {
            self.stopped = true;
        }
    }
}
