//! The protocol of the file custody server `fstp-keyd` and its client
//! [`KeydCustody`] (ADR-004 part 2 "File custody", Q32 A).
//!
//! # Wire form
//!
//! No ADR fixed these bytes before this lane. Lane W2f writes them at
//! first use. Their record in ADR-004 is with the lead. Integers are
//! big-endian. Every decoder accepts exactly one spelling: exact lengths,
//! known codes, flags of 0 or 1, and no trailing byte.
//!
//! ```text
//! frame    = "FKD1" | kind u8 | len u32 | body (len bytes, at most 65 536)
//! root     = chain u8 | epoch u64                                  9 bytes
//! id       = request id, 16 random bytes (ADR-004 "Reconciliation")
//!
//! requests (client to server)
//! 0x01 create   = id | cell flag u8 | [cell 16 if flag is 1] | chain u8 | epoch u64
//! 0x02 wrap     = id | root | aad len u16 | aad | seal key 32
//! 0x03 unwrap   = id | root | aad len u16 | aad | wrapped len u16 | wrapped
//! 0x04 destroy  = id | root
//! 0x05 sign     = id | handle len u8 | handle | digest 32
//! 0x06 usage    = id | root | cursor u64
//! 0x07 destroy sign key = id | handle len u8 | handle
//!
//! responses (server to client)
//! 0x81 root      = root
//! 0x82 wrapped   = len u16 | wrapped
//! 0x83 unwrapped = seal key 32
//! 0x84 destroyed = len u16 | receipt (a sign key receipt after 0x07)
//! 0x85 signed    = len u16 | signature
//! 0x86 usage     = next u64 | count u16 | count times (len u16 | record)
//! 0xff refused   = code u8
//!
//! usage record   = a 41-byte record of the fstp-keyd usage log
//!                | damage marker = 0xf0 | log index u64            9 bytes
//! sign handle    = class u8 (0x01 cell CA, 0x02 local cluster CA) | name
//! ```
//!
//! A damage marker stands in a usage page for a record of the log that
//! failed its check, whatever root it named. The `fstp-cell` socket signs
//! with cell CA handles only, and the `fstp-pgagent` socket with local
//! cluster CA handles only.
//!
//! A seal key crosses the socket in clear, inside the host, between the
//! cell or vault process and `fstp-keyd`. Root bytes never cross it
//! (I-80). Each socket admits one client OS user and serves a fixed set
//! of chains (ADR-004 part 2 "Access to `fstp-keyd`"). A request for any
//! other chain is refused with [`Refusal::NotPermitted`]. Every frame body
//! lives in `Zeroizing` memory ([`KeydFrame`]).
//!
//! The request decoder lives in `fstp-keyd`, which receives requests.
//! The response decoder lives here, beside the client that receives
//! responses. Each side decodes with its own code, so the round trip
//! tests check two implementations against each other.

use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, PoisonError};
use std::task::{Context, Poll, Waker};

use zeroize::{ZeroizeOnDrop, Zeroizing};

use crate::{
    Aad, BackendId, CellId, Chain, Custody, CustodyError, CustodyHandle, DestroyReceipt,
    EcdsaSignature, Epoch, Refusal, RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor,
    UsagePage, WrappedSealKey,
};

/// The magic of a keyd frame.
pub const FRAME_MAGIC: [u8; 4] = *b"FKD1";
/// Length of a frame header: magic, kind and body length.
pub const FRAME_HEADER_LEN: usize = 9;
/// The longest frame body.
pub const MAX_FRAME_BODY: usize = 65_536;
/// The longest AAD a wrap or unwrap carries.
pub const MAX_AAD_LEN: usize = 1024;
/// The longest wrapped seal key an unwrap carries.
pub const MAX_WRAPPED_LEN: usize = 1024;
/// The longest signing key handle.
pub const MAX_HANDLE_LEN: usize = 64;
/// The most usage records one page carries.
pub const MAX_USAGE_RECORDS: usize = 512;
/// The longest usage record.
pub const MAX_USAGE_RECORD_LEN: usize = 64;
/// The first byte of a damage marker in a usage page. `fstp-keyd` puts
/// one in place of each record of its log that fails its check, so the
/// daily reconciliation sees the gap and can raise `CustodyAnomaly`
/// (ADR-004 part 2 "Reconciliation").
pub const USAGE_DAMAGED_TAG: u8 = 0xf0;
/// Length of a damage marker: the tag and the log index u64 of the
/// damaged record.
pub const USAGE_DAMAGED_LEN: usize = 9;
/// The class byte of a sign key handle for a cell CA key. The key sits
/// in the cell's App custody entry (ADR-004 part 2 "CA keys in
/// custody"), so the `fstp-cell` socket reaches it.
pub const SIGN_KEY_CELL_CA: u8 = 0x01;
/// The class byte of a sign key handle for a local cluster CA key. The
/// `fstp-pgagent` socket reaches it.
pub const SIGN_KEY_CLUSTER_CA: u8 = 0x02;

/// The log index of the damaged record that `record` reports, if
/// `record` is a damage marker of a usage page ([`USAGE_DAMAGED_TAG`]).
#[must_use]
pub fn usage_damaged_index(record: &[u8]) -> Option<u64> {
    let (tag, index) = record.split_first()?;
    let index: [u8; 8] = index.try_into().ok()?;
    (*tag == USAGE_DAMAGED_TAG).then_some(u64::from_be_bytes(index))
}
/// Length of a request id.
pub const REQUEST_ID_LEN: usize = 16;
/// Length of a root on the wire.
pub const ROOT_LEN: usize = 9;

/// Request kind: create a root.
pub const KIND_CREATE: u8 = 0x01;
/// Request kind: wrap a seal key.
pub const KIND_WRAP: u8 = 0x02;
/// Request kind: unwrap a seal key.
pub const KIND_UNWRAP: u8 = 0x03;
/// Request kind: destroy a root.
pub const KIND_DESTROY: u8 = 0x04;
/// Request kind: sign a digest.
pub const KIND_SIGN: u8 = 0x05;
/// Request kind: read the usage log.
pub const KIND_USAGE: u8 = 0x06;
/// Request kind: destroy a CA sign key (ADR-004 "CA keys in custody").
pub const KIND_DESTROY_SIGN_KEY: u8 = 0x07;
/// Response kind: a root.
pub const KIND_ROOT: u8 = 0x81;
/// Response kind: a wrapped seal key.
pub const KIND_WRAPPED: u8 = 0x82;
/// Response kind: an unwrapped seal key.
pub const KIND_UNWRAPPED: u8 = 0x83;
/// Response kind: a destroy receipt.
pub const KIND_DESTROYED: u8 = 0x84;
/// Response kind: a signature.
pub const KIND_SIGNED: u8 = 0x85;
/// Response kind: a usage page.
pub const KIND_USAGE_PAGE: u8 = 0x86;
/// Response kind: a refusal.
pub const KIND_REFUSED: u8 = 0xff;

/// The longest a client waits for `fstp-keyd`, in seconds.
pub const CLIENT_TIMEOUT_SECS: u64 = 30;

/// One frame of the keyd protocol.
///
/// The body of a wrap request or an unwrap response holds an epoch seal
/// key `S(e)`. So the body lives in `Zeroizing` memory and is wiped on
/// drop, and the `Debug` form shows the kind and the body length only
/// (ADR-004 part 2, design section 3.3).
#[derive(Clone, PartialEq, Eq)]
pub struct KeydFrame {
    /// The frame kind.
    pub kind: u8,
    /// The frame body.
    pub body: Zeroizing<Vec<u8>>,
}

impl ZeroizeOnDrop for KeydFrame {}

impl std::fmt::Debug for KeydFrame {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KeydFrame")
            .field("kind", &self.kind)
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Encodes `frame` in its one spelling.
///
/// # Errors
///
/// Refuses a body longer than [`MAX_FRAME_BODY`].
pub fn encode_frame(frame: &KeydFrame) -> Result<Vec<u8>, CustodyError> {
    if frame.body.len() > MAX_FRAME_BODY {
        return Err(CustodyError::Protocol("frame body too long"));
    }
    let len = u32::try_from(frame.body.len())
        .map_err(|_| CustodyError::Protocol("frame body too long"))?;
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(frame.body.len()));
    out.extend_from_slice(&FRAME_MAGIC);
    out.push(frame.kind);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(&frame.body);
    Ok(out)
}

/// The body length a frame header announces.
///
/// # Errors
///
/// Refuses a wrong magic and a length above [`MAX_FRAME_BODY`].
pub fn frame_body_len(header: &[u8; FRAME_HEADER_LEN]) -> Result<usize, CustodyError> {
    let mut r = Reader::new(header);
    if r.array::<4>()? != FRAME_MAGIC {
        return Err(CustodyError::Protocol("frame has the wrong magic"));
    }
    let _kind = r.u8()?;
    let len = usize::try_from(r.u32()?).map_err(|_| CustodyError::Protocol("frame too long"))?;
    if len > MAX_FRAME_BODY {
        return Err(CustodyError::Protocol("frame body too long"));
    }
    Ok(len)
}

/// Decodes one whole frame. Fuzzed (`keyd_frame_decode`).
///
/// # Errors
///
/// Refuses input shorter than a header, a wrong magic, a body above
/// [`MAX_FRAME_BODY`], and a body of another length than announced.
pub fn decode_frame(bytes: &[u8]) -> Result<KeydFrame, CustodyError> {
    let mut r = Reader::new(bytes);
    let header: [u8; FRAME_HEADER_LEN] = r.array()?;
    let len = frame_body_len(&header)?;
    let kind = header.get(4).copied().unwrap_or(0);
    let body = Zeroizing::new(r.take(len)?.to_vec());
    r.end()?;
    Ok(KeydFrame { kind, body })
}

/// The magic of a destroy receipt.
pub const RECEIPT_MAGIC: [u8; 4] = *b"FKR1";
/// The format version of a destroy receipt.
pub const RECEIPT_VERSION: u8 = 1;
/// Length of a receipt before its step codes.
const RECEIPT_HEAD_LEN: usize = 15;

/// One step of a file custody destroy, in the order ADR-004 part 2
/// lists: "Destroy overwrites `K(e)` in the key table in place, fsyncs,
/// unlinks the epoch file, fsyncs the directory and reads back."
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestroyStep {
    /// `K(e)` overwritten in the key table in place.
    OverwriteKey,
    /// The key table fsynced.
    FsyncTable,
    /// The epoch file unlinked.
    UnlinkEpochFile,
    /// The key directory fsynced.
    FsyncDirectory,
    /// The key table and the directory read back.
    ReadBack,
}

impl DestroyStep {
    /// The steps of every destroy, in order.
    pub const ALL: [DestroyStep; 5] = [
        DestroyStep::OverwriteKey,
        DestroyStep::FsyncTable,
        DestroyStep::UnlinkEpochFile,
        DestroyStep::FsyncDirectory,
        DestroyStep::ReadBack,
    ];

    /// The step code.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            DestroyStep::OverwriteKey => 1,
            DestroyStep::FsyncTable => 2,
            DestroyStep::UnlinkEpochFile => 3,
            DestroyStep::FsyncDirectory => 4,
            DestroyStep::ReadBack => 5,
        }
    }

    /// The step of a code, if known.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<DestroyStep> {
        match code {
            1 => Some(DestroyStep::OverwriteKey),
            2 => Some(DestroyStep::FsyncTable),
            3 => Some(DestroyStep::UnlinkEpochFile),
            4 => Some(DestroyStep::FsyncDirectory),
            5 => Some(DestroyStep::ReadBack),
            _ => None,
        }
    }
}

/// A decoded destroy receipt of `fstp-keyd`.
///
/// ```text
/// receipt = "FKR1" | version u8 = 1 | chain u8 | epoch u64 | count u8 | count step codes
/// ```
///
/// The receipt names only the epoch and the steps, so a second destroy
/// of a destroyed epoch, after its read back passes again, returns the
/// same bytes (the M-SHRED environment rule). A receipt confirms a
/// destroy only when it lists every step of [`DestroyStep::ALL`], once
/// each and in order, so the decoder refuses every other step list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Receipt {
    /// The chain of the destroyed epoch.
    pub chain: Chain,
    /// The destroyed epoch.
    pub epoch: Epoch,
    /// The steps the destroy took, in order.
    pub steps: Vec<DestroyStep>,
}

impl Receipt {
    /// The receipt of a full destroy of `chain` and `epoch`.
    #[must_use]
    pub fn full(chain: Chain, epoch: Epoch) -> Receipt {
        Receipt {
            chain,
            epoch,
            steps: DestroyStep::ALL.to_vec(),
        }
    }

    /// The receipt bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RECEIPT_HEAD_LEN.saturating_add(self.steps.len()));
        out.extend_from_slice(&RECEIPT_MAGIC);
        out.push(RECEIPT_VERSION);
        out.push(self.chain.code());
        out.extend_from_slice(&self.epoch.0.to_be_bytes());
        out.push(u8::try_from(self.steps.len()).unwrap_or(u8::MAX));
        out.extend(
            self.steps
                .iter()
                .take(usize::from(u8::MAX))
                .map(|s| s.code()),
        );
        out
    }
}

/// Decodes a destroy receipt of `fstp-keyd`.
///
/// # Errors
///
/// Refuses any input that is not one receipt in its one spelling, and a
/// receipt whose steps are not exactly [`DestroyStep::ALL`] in order.
pub fn decode_receipt(bytes: &[u8]) -> Result<Receipt, CustodyError> {
    let mut r = Reader::new(bytes);
    if r.array::<4>()? != RECEIPT_MAGIC || r.u8()? != RECEIPT_VERSION {
        return Err(CustodyError::Protocol(
            "a receipt has the wrong magic or version",
        ));
    }
    let chain = Chain::from_code(r.u8()?)
        .ok_or(CustodyError::Protocol("a receipt names an unknown chain"))?;
    let epoch = Epoch(r.u64()?);
    let count = usize::from(r.u8()?);
    let codes = r.take(count)?;
    r.end()?;
    let steps = codes
        .iter()
        .map(|c| {
            DestroyStep::from_code(*c).ok_or(CustodyError::Protocol("an unknown receipt step"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if steps != DestroyStep::ALL {
        return Err(CustodyError::Protocol(
            "a receipt does not list every destroy step once and in order",
        ));
    }
    Ok(Receipt {
        chain,
        epoch,
        steps,
    })
}

pub use crate::RequestId;

/// A root of `fstp-keyd`: one chain and epoch. It is also the custody
/// handle of the root.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RootHandle {
    /// The chain.
    pub chain: Chain,
    /// The epoch.
    pub epoch: Epoch,
}

impl RootHandle {
    /// The 9 wire bytes.
    #[must_use]
    pub fn encode(&self) -> [u8; ROOT_LEN] {
        let mut out = [0u8; ROOT_LEN];
        let (c, e) = out.split_at_mut(1);
        c.copy_from_slice(&[self.chain.code()]);
        e.copy_from_slice(&self.epoch.0.to_be_bytes());
        out
    }

    /// Decodes the 9 wire bytes.
    ///
    /// # Errors
    ///
    /// Refuses another length and an unknown chain code.
    pub fn decode(bytes: &[u8]) -> Result<RootHandle, CustodyError> {
        let mut r = Reader::new(bytes);
        let root = r.root()?;
        r.end()?;
        Ok(root)
    }
}

/// A request to `fstp-keyd`. Its `Debug` form never shows a seal key.
#[derive(Clone, PartialEq, Eq)]
pub enum Request {
    /// Create a root for a chain and epoch.
    CreateRoot {
        /// The request id.
        id: RequestId,
        /// The cell, or `None` for a shared chain.
        cell: Option<CellId>,
        /// The chain.
        chain: Chain,
        /// The epoch.
        epoch: Epoch,
    },
    /// Wrap a seal key under a root.
    Wrap {
        /// The request id.
        id: RequestId,
        /// The root.
        root: RootHandle,
        /// The AAD.
        aad: Vec<u8>,
        /// The seal key.
        key: Zeroizing<[u8; 32]>,
    },
    /// Unwrap a seal key under a root.
    Unwrap {
        /// The request id.
        id: RequestId,
        /// The root.
        root: RootHandle,
        /// The AAD.
        aad: Vec<u8>,
        /// The wrapped seal key.
        wrapped: Vec<u8>,
    },
    /// Destroy a root.
    Destroy {
        /// The request id.
        id: RequestId,
        /// The root.
        root: RootHandle,
    },
    /// Sign a SHA-256 digest with a CA key.
    Sign {
        /// The request id.
        id: RequestId,
        /// The signing key handle.
        key: Vec<u8>,
        /// The digest.
        digest: [u8; 32],
    },
    /// Read the usage log of a root from a cursor.
    UsageSince {
        /// The request id.
        id: RequestId,
        /// The root.
        root: RootHandle,
        /// The index of the first record to read.
        cursor: u64,
    },
    /// Destroy a CA sign key (ADR-004 "CA keys in custody"). Kept apart
    /// from the six operations of the `Custody` trait (I-80).
    DestroySignKey {
        /// The request id.
        id: RequestId,
        /// The signing key handle.
        key: Vec<u8>,
    },
}

impl std::fmt::Debug for Request {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Request::CreateRoot {
                id,
                cell,
                chain,
                epoch,
            } => f
                .debug_struct("CreateRoot")
                .field("id", id)
                .field("cell", cell)
                .field("chain", chain)
                .field("epoch", epoch)
                .finish(),
            Request::Wrap { id, root, aad, .. } => f
                .debug_struct("Wrap")
                .field("id", id)
                .field("root", root)
                .field("aad_len", &aad.len())
                .finish_non_exhaustive(),
            Request::Unwrap {
                id,
                root,
                aad,
                wrapped,
            } => f
                .debug_struct("Unwrap")
                .field("id", id)
                .field("root", root)
                .field("aad_len", &aad.len())
                .field("wrapped_len", &wrapped.len())
                .finish(),
            Request::Destroy { id, root } => f
                .debug_struct("Destroy")
                .field("id", id)
                .field("root", root)
                .finish(),
            Request::Sign { id, key, .. } => f
                .debug_struct("Sign")
                .field("id", id)
                .field("key_len", &key.len())
                .finish_non_exhaustive(),
            Request::UsageSince { id, root, cursor } => f
                .debug_struct("UsageSince")
                .field("id", id)
                .field("root", root)
                .field("cursor", cursor)
                .finish(),
            Request::DestroySignKey { id, key } => f
                .debug_struct("DestroySignKey")
                .field("id", id)
                .field("key_len", &key.len())
                .finish(),
        }
    }
}

impl Request {
    /// The request id.
    #[must_use]
    pub fn id(&self) -> RequestId {
        match self {
            Request::CreateRoot { id, .. }
            | Request::Wrap { id, .. }
            | Request::Unwrap { id, .. }
            | Request::Destroy { id, .. }
            | Request::Sign { id, .. }
            | Request::UsageSince { id, .. }
            | Request::DestroySignKey { id, .. } => *id,
        }
    }

    /// The frame kind of the request.
    #[must_use]
    pub fn kind(&self) -> u8 {
        match self {
            Request::CreateRoot { .. } => KIND_CREATE,
            Request::Wrap { .. } => KIND_WRAP,
            Request::Unwrap { .. } => KIND_UNWRAP,
            Request::Destroy { .. } => KIND_DESTROY,
            Request::Sign { .. } => KIND_SIGN,
            Request::UsageSince { .. } => KIND_USAGE,
            Request::DestroySignKey { .. } => KIND_DESTROY_SIGN_KEY,
        }
    }
}

/// Encodes `request` as the whole frame `KeydCustody` sends.
///
/// # Errors
///
/// Refuses an AAD, wrapped key or handle above its limit.
pub fn encode_request(request: &Request) -> Result<Vec<u8>, CustodyError> {
    let mut b = Zeroizing::new(Vec::new());
    b.extend_from_slice(&request.id().0);
    match request {
        Request::CreateRoot {
            cell, chain, epoch, ..
        } => {
            match cell {
                Some(c) => {
                    b.push(1);
                    b.extend_from_slice(&c.0);
                }
                None => b.push(0),
            }
            b.push(chain.code());
            b.extend_from_slice(&epoch.0.to_be_bytes());
        }
        Request::Wrap { root, aad, key, .. } => {
            b.extend_from_slice(&root.encode());
            put_u16_bytes(&mut b, aad, MAX_AAD_LEN)?;
            b.extend_from_slice(&key[..]);
        }
        Request::Unwrap {
            root, aad, wrapped, ..
        } => {
            b.extend_from_slice(&root.encode());
            put_u16_bytes(&mut b, aad, MAX_AAD_LEN)?;
            put_u16_bytes(&mut b, wrapped, MAX_WRAPPED_LEN)?;
        }
        Request::Destroy { root, .. } => b.extend_from_slice(&root.encode()),
        Request::Sign { key, digest, .. } => {
            put_handle(&mut b, key)?;
            b.extend_from_slice(digest);
        }
        Request::DestroySignKey { key, .. } => put_handle(&mut b, key)?,
        Request::UsageSince { root, cursor, .. } => {
            b.extend_from_slice(&root.encode());
            b.extend_from_slice(&cursor.to_be_bytes());
        }
    }
    // The body may hold a seal key, so the frame wipes it on drop.
    let frame = KeydFrame {
        kind: request.kind(),
        body: b,
    };
    encode_frame(&frame)
}

/// A response of `fstp-keyd`. Its `Debug` form never shows a seal key.
#[derive(Clone, PartialEq, Eq)]
pub enum Response {
    /// The root a create made or found.
    Root(RootHandle),
    /// A wrapped seal key.
    Wrapped(Vec<u8>),
    /// An unwrapped seal key.
    Unwrapped(Zeroizing<[u8; 32]>),
    /// A destroy receipt.
    Destroyed(Vec<u8>),
    /// A DER signature.
    Signed(Vec<u8>),
    /// A page of usage records.
    Usage {
        /// The records.
        records: Vec<Vec<u8>>,
        /// The cursor after the page.
        next: u64,
    },
    /// A refusal.
    Refused(Refusal),
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Response::Root(r) => f.debug_tuple("Root").field(r).finish(),
            Response::Wrapped(w) => f.debug_struct("Wrapped").field("len", &w.len()).finish(),
            Response::Unwrapped(_) => f.debug_struct("Unwrapped").finish_non_exhaustive(),
            Response::Destroyed(r) => f.debug_struct("Destroyed").field("len", &r.len()).finish(),
            Response::Signed(s) => f.debug_struct("Signed").field("len", &s.len()).finish(),
            Response::Usage { records, next } => f
                .debug_struct("Usage")
                .field("records", &records.len())
                .field("next", next)
                .finish(),
            Response::Refused(r) => f.debug_tuple("Refused").field(r).finish(),
        }
    }
}

/// Decodes a whole response frame from `fstp-keyd`.
///
/// # Errors
///
/// Refuses any input that is not one response in its one spelling.
pub fn decode_response(bytes: &[u8]) -> Result<Response, CustodyError> {
    let frame = decode_frame(bytes)?;
    let mut r = Reader::new(&frame.body);
    let response = match frame.kind {
        KIND_ROOT => Response::Root(r.root()?),
        KIND_WRAPPED => Response::Wrapped(r.u16_bytes(MAX_WRAPPED_LEN)?.to_vec()),
        KIND_UNWRAPPED => Response::Unwrapped(Zeroizing::new(r.array()?)),
        KIND_DESTROYED => Response::Destroyed(r.u16_bytes(MAX_FRAME_BODY)?.to_vec()),
        KIND_SIGNED => Response::Signed(r.u16_bytes(MAX_FRAME_BODY)?.to_vec()),
        KIND_USAGE_PAGE => {
            let next = r.u64()?;
            let count = usize::from(r.u16()?);
            if count > MAX_USAGE_RECORDS {
                return Err(CustodyError::Protocol("too many usage records"));
            }
            let mut records = Vec::with_capacity(count);
            for _ in 0..count {
                records.push(r.u16_bytes(MAX_USAGE_RECORD_LEN)?.to_vec());
            }
            Response::Usage { records, next }
        }
        KIND_REFUSED => Response::Refused(
            Refusal::from_code(r.u8()?).ok_or(CustodyError::Protocol("unknown refusal code"))?,
        ),
        _ => return Err(CustodyError::Protocol("unknown response kind")),
    };
    r.end()?;
    Ok(response)
}

/// A signing key handle: a length octet and at most [`MAX_HANDLE_LEN`]
/// bytes.
fn put_handle(out: &mut Vec<u8>, key: &[u8]) -> Result<(), CustodyError> {
    if key.len() > MAX_HANDLE_LEN {
        return Err(CustodyError::Protocol("signing key handle too long"));
    }
    let n = u8::try_from(key.len())
        .map_err(|_| CustodyError::Protocol("signing key handle too long"))?;
    out.push(n);
    out.extend_from_slice(key);
    Ok(())
}

/// The magic of a sign key destroy receipt.
pub const SIGN_RECEIPT_MAGIC: [u8; 4] = *b"FKS1";

/// A decoded destroy receipt of a CA sign key (lane m3/erase-cell-2).
///
/// ```text
/// sign receipt = "FKS1" | version u8 = 1 | handle len u8 | handle | count u8 | count step codes
/// ```
///
/// Like a root's [`Receipt`], it confirms a destroy only when it lists
/// every step of [`DestroyStep::ALL`], once each and in order, and it
/// names only the handle, so a repeated destroy returns the same bytes.
/// Interim, pending Daniel: `fstp-keyd` holds no sign key yet, since no
/// request creates one, so it never issues this receipt yet.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignKeyReceipt {
    /// The handle of the destroyed key.
    pub handle: Vec<u8>,
    /// The steps the destroy took, in order.
    pub steps: Vec<DestroyStep>,
}

impl SignKeyReceipt {
    /// The receipt of a full destroy of the key `handle`.
    #[must_use]
    pub fn full(handle: &[u8]) -> SignKeyReceipt {
        SignKeyReceipt {
            handle: handle.to_vec(),
            steps: DestroyStep::ALL.to_vec(),
        }
    }

    /// The receipt bytes.
    ///
    /// # Errors
    ///
    /// Refuses a handle above [`MAX_HANDLE_LEN`].
    pub fn encode(&self) -> Result<Vec<u8>, CustodyError> {
        let mut out = SIGN_RECEIPT_MAGIC.to_vec();
        out.push(RECEIPT_VERSION);
        put_handle(&mut out, &self.handle)?;
        let n = u8::try_from(self.steps.len())
            .map_err(|_| CustodyError::Protocol("too many receipt steps"))?;
        out.push(n);
        out.extend(self.steps.iter().map(|s| s.code()));
        Ok(out)
    }
}

/// Decodes a sign key destroy receipt of `fstp-keyd`.
///
/// # Errors
///
/// Refuses any input that is not one receipt in its one spelling, and a
/// receipt whose steps are not exactly [`DestroyStep::ALL`] in order.
pub fn decode_sign_receipt(bytes: &[u8]) -> Result<SignKeyReceipt, CustodyError> {
    let mut r = Reader::new(bytes);
    if r.array::<4>()? != SIGN_RECEIPT_MAGIC || r.u8()? != RECEIPT_VERSION {
        return Err(CustodyError::Protocol(
            "a sign key receipt has the wrong magic or version",
        ));
    }
    let n = usize::from(r.u8()?);
    if n == 0 || n > MAX_HANDLE_LEN {
        return Err(CustodyError::Protocol("a sign key receipt handle length"));
    }
    let handle = r.take(n)?.to_vec();
    let count = usize::from(r.u8()?);
    let codes = r.take(count)?;
    r.end()?;
    let steps = codes
        .iter()
        .map(|c| {
            DestroyStep::from_code(*c).ok_or(CustodyError::Protocol("an unknown receipt step"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    if steps != DestroyStep::ALL {
        return Err(CustodyError::Protocol(
            "a receipt does not list every destroy step once and in order",
        ));
    }
    Ok(SignKeyReceipt { handle, steps })
}

fn put_u16_bytes(out: &mut Vec<u8>, bytes: &[u8], max: usize) -> Result<(), CustodyError> {
    if bytes.len() > max {
        return Err(CustodyError::Protocol("field too long"));
    }
    let n = u16::try_from(bytes.len()).map_err(|_| CustodyError::Protocol("field too long"))?;
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

/// A cursor over input bytes that never reads past the end. Its errors
/// carry static text only.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Reader { rest: bytes }
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], CustodyError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(CustodyError::Protocol("input is too short"))?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], CustodyError> {
        self.take(N)?
            .try_into()
            .map_err(|_| CustodyError::Protocol("input is too short"))
    }

    fn u8(&mut self) -> Result<u8, CustodyError> {
        Ok(u8::from_be_bytes(self.array()?))
    }

    fn u16(&mut self) -> Result<u16, CustodyError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, CustodyError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    fn u64(&mut self) -> Result<u64, CustodyError> {
        Ok(u64::from_be_bytes(self.array()?))
    }

    fn u16_bytes(&mut self, max: usize) -> Result<&'a [u8], CustodyError> {
        let n = usize::from(self.u16()?);
        if n > max {
            return Err(CustodyError::Protocol("field too long"));
        }
        self.take(n)
    }

    fn root(&mut self) -> Result<RootHandle, CustodyError> {
        let chain =
            Chain::from_code(self.u8()?).ok_or(CustodyError::Protocol("unknown chain code"))?;
        let epoch = Epoch(self.u64()?);
        Ok(RootHandle { chain, epoch })
    }

    fn end(&self) -> Result<(), CustodyError> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(CustodyError::Protocol("trailing bytes"))
        }
    }
}

// ---------------------------------------------------------------------------
// The client.

/// A custody client that talks to `fstp-keyd` over its Unix socket. It
/// connects once per call, so it can be built before the server binds.
///
/// Each call runs its blocking socket exchange on a thread of its own,
/// so a poll of a custody future never blocks the executor, even while
/// `fstp-keyd` stalls up to [`CLIENT_TIMEOUT_SECS`]. The future wakes
/// its task once the exchange ends. Custody calls are few (a handful per
/// root epoch), so one short-lived thread per call costs little, and the
/// client needs no runtime handle (ADR-002).
#[derive(Debug)]
pub struct KeydCustody {
    socket: PathBuf,
}

impl KeydCustody {
    /// A client for the server at `socket`.
    ///
    /// # Errors
    ///
    /// Refuses an empty path.
    pub fn new(socket: &Path) -> Result<KeydCustody, CustodyError> {
        if socket.as_os_str().is_empty() {
            return Err(CustodyError::InvalidConfig("the keyd socket path is empty"));
        }
        Ok(KeydCustody {
            socket: socket.to_path_buf(),
        })
    }

    /// The socket path.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Sends `request` and reads the one response, on a thread of its
    /// own. The encoded request, which may hold a seal key, and the
    /// answer both live in `Zeroizing` memory.
    fn call(&self, request: &Request) -> Exchange {
        let frame = encode_request(request).map(Zeroizing::new);
        let socket = self.socket.clone();
        Exchange::new(move || {
            let frame = frame?;
            let answer = Zeroizing::new(exchange(&socket, &frame)?);
            decode_response(&answer)
        })
    }

    /// Destroys the CA sign key `key` and returns the checked receipt
    /// ([`decode_sign_receipt`]). It is not one of the six `Custody`
    /// operations (I-80). `fstp-control` reaches it through its
    /// `SignKeyCustody` trait for cell erasure (R-SW-02). The call carries
    /// the caller's request id, as every custody call does.
    ///
    /// # Errors
    ///
    /// [`CustodyError::InvalidConfig`] for a key of another backend,
    /// [`CustodyError::Protocol`] for a handle above [`MAX_HANDLE_LEN`] or
    /// a receipt that names another key, and the refusal of the server,
    /// such as [`Refusal::NoSignKey`] or [`Refusal::NotPermitted`].
    pub async fn destroy_sign_key(&self, key: &SignKeyRef) -> Result<DestroyReceipt, CustodyError> {
        if key.backend != BackendId::Keyd {
            return Err(CustodyError::InvalidConfig("the key is not a keyd key"));
        }
        let request = Request::DestroySignKey {
            id: crate::request_or_fresh()?,
            key: key.handle.0.clone(),
        };
        match self.call(&request).await? {
            Response::Destroyed(r) => {
                if decode_sign_receipt(&r)?.handle != key.handle.0 {
                    return Err(CustodyError::Protocol(
                        "the destroy receipt names another sign key",
                    ));
                }
                Ok(DestroyReceipt(r))
            }
            other => Err(unexpected(other)),
        }
    }

    fn root_of(root: &RootRef) -> Result<RootHandle, CustodyError> {
        if root.backend != BackendId::Keyd {
            return Err(CustodyError::InvalidConfig("the root is not a keyd root"));
        }
        let handle = RootHandle::decode(&root.handle.0)?;
        if handle.chain != root.chain || handle.epoch != root.epoch {
            return Err(CustodyError::InvalidConfig(
                "the root handle names another chain or epoch",
            ));
        }
        Ok(handle)
    }
}

/// The error for a response of the wrong kind, or a refusal.
fn unexpected(response: Response) -> CustodyError {
    match response {
        Response::Refused(r) => CustodyError::Refused(r),
        _ => CustodyError::Protocol("response of the wrong kind"),
    }
}

/// The receipt of a destroy of `root`, checked: it must name the chain
/// and epoch of `root` and list every destroy step once and in order.
fn checked_receipt(root: RootHandle, bytes: Vec<u8>) -> Result<DestroyReceipt, CustodyError> {
    let receipt = decode_receipt(&bytes)?;
    if receipt.chain != root.chain || receipt.epoch != root.epoch {
        return Err(CustodyError::Protocol(
            "the destroy receipt names another chain or epoch",
        ));
    }
    Ok(DestroyReceipt(bytes))
}

/// What one exchange gives back.
type Answer = Result<Response, CustodyError>;

/// The shared state of one [`Exchange`]: its answer once the thread has
/// one, and the waker of the task that waits for it.
#[derive(Default)]
struct Slot {
    answer: Option<Answer>,
    waker: Option<Waker>,
}

/// A future that runs one blocking keyd exchange on a thread of its own.
/// The first poll starts the thread and returns `Pending`. The thread
/// stores the answer and wakes the task.
struct Exchange {
    slot: Arc<Mutex<Slot>>,
    job: Option<Box<dyn FnOnce() -> Answer + Send + 'static>>,
}

impl Exchange {
    fn new(job: impl FnOnce() -> Answer + Send + 'static) -> Exchange {
        Exchange {
            slot: Arc::new(Mutex::new(Slot::default())),
            job: Some(Box::new(job)),
        }
    }
}

fn lock(slot: &Mutex<Slot>) -> std::sync::MutexGuard<'_, Slot> {
    slot.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Future for Exchange {
    type Output = Answer;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Answer> {
        let this = self.get_mut();
        {
            let mut slot = lock(&this.slot);
            if let Some(answer) = slot.answer.take() {
                return Poll::Ready(answer);
            }
            slot.waker = Some(cx.waker().clone());
        }
        if let Some(job) = this.job.take() {
            let slot = Arc::clone(&this.slot);
            let spawned = std::thread::Builder::new()
                .name("fstp-keyd-client".to_owned())
                .spawn(move || {
                    let answer = job();
                    let waker = {
                        let mut s = lock(&slot);
                        s.answer = Some(answer);
                        s.waker.take()
                    };
                    if let Some(w) = waker {
                        w.wake();
                    }
                });
            if spawned.is_err() {
                return Poll::Ready(Err(CustodyError::Transport("start the exchange thread")));
            }
        }
        Poll::Pending
    }
}

/// Sends one frame and reads one frame back.
#[cfg(unix)]
fn exchange(socket: &Path, frame: &[u8]) -> Result<Vec<u8>, CustodyError> {
    use std::io::{Read as _, Write as _};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let mut stream = UnixStream::connect(socket).map_err(|_| CustodyError::Transport("connect"))?;
    let timeout = Some(Duration::from_secs(CLIENT_TIMEOUT_SECS));
    stream
        .set_read_timeout(timeout)
        .and_then(|()| stream.set_write_timeout(timeout))
        .map_err(|_| CustodyError::Transport("set timeouts"))?;
    stream
        .write_all(frame)
        .and_then(|()| stream.flush())
        .map_err(|_| CustodyError::Transport("send"))?;
    let mut header = [0u8; FRAME_HEADER_LEN];
    stream
        .read_exact(&mut header)
        .map_err(|_| CustodyError::Transport("receive"))?;
    let len = frame_body_len(&header)?;
    let mut out = Vec::with_capacity(FRAME_HEADER_LEN.saturating_add(len));
    out.extend_from_slice(&header);
    let mut body = Zeroizing::new(vec![0u8; len]);
    stream
        .read_exact(&mut body[..])
        .map_err(|_| CustodyError::Transport("receive"))?;
    out.extend_from_slice(&body);
    Ok(out)
}

/// Unix sockets exist only on Unix hosts, as does `fstp-keyd`.
#[cfg(not(unix))]
fn exchange(socket: &Path, frame: &[u8]) -> Result<Vec<u8>, CustodyError> {
    let _ = (socket, frame);
    Err(CustodyError::Transport("fstp-keyd needs a Unix host"))
}

impl Custody for KeydCustody {
    // Each call carries the caller's request id when it made the call
    // through `crate::with_request`, and a fresh one otherwise. `fstp-keyd`
    // logs it (ADR-004 "Reconciliation").

    async fn create_root(&self, label: RootLabel) -> Result<RootRef, CustodyError> {
        let request = Request::CreateRoot {
            id: crate::request_or_fresh()?,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
        };
        match self.call(&request).await? {
            Response::Root(h) if h.chain == label.chain && h.epoch == label.epoch => Ok(RootRef {
                backend: BackendId::Keyd,
                cell: label.cell,
                chain: h.chain,
                epoch: h.epoch,
                handle: CustodyHandle(h.encode().to_vec()),
            }),
            other => Err(unexpected(other)),
        }
    }

    async fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> Result<WrappedSealKey, CustodyError> {
        let request = Request::Wrap {
            id: crate::request_or_fresh()?,
            root: KeydCustody::root_of(root)?,
            aad: aad.0.clone(),
            key: Zeroizing::new(*key.expose()),
        };
        let exchange = self.call(&request);
        drop(request);
        match exchange.await? {
            Response::Wrapped(w) => Ok(WrappedSealKey(w)),
            other => Err(unexpected(other)),
        }
    }

    async fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> Result<SealKey, CustodyError> {
        let request = Request::Unwrap {
            id: crate::request_or_fresh()?,
            root: KeydCustody::root_of(root)?,
            aad: aad.0.clone(),
            wrapped: w.0.clone(),
        };
        match self.call(&request).await? {
            Response::Unwrapped(k) => Ok(SealKey::from_bytes(*k)),
            other => Err(unexpected(other)),
        }
    }

    async fn destroy(&self, root: &RootRef) -> Result<DestroyReceipt, CustodyError> {
        let handle = KeydCustody::root_of(root)?;
        let request = Request::Destroy {
            id: crate::request_or_fresh()?,
            root: handle,
        };
        match self.call(&request).await? {
            Response::Destroyed(r) => checked_receipt(handle, r),
            other => Err(unexpected(other)),
        }
    }

    async fn sign(
        &self,
        key: &SignKeyRef,
        digest: &[u8; 32],
    ) -> Result<EcdsaSignature, CustodyError> {
        if key.backend != BackendId::Keyd {
            return Err(CustodyError::InvalidConfig("the key is not a keyd key"));
        }
        let request = Request::Sign {
            id: crate::request_or_fresh()?,
            key: key.handle.0.clone(),
            digest: *digest,
        };
        match self.call(&request).await? {
            Response::Signed(s) => Ok(EcdsaSignature(s)),
            other => Err(unexpected(other)),
        }
    }

    async fn usage_since(
        &self,
        root: &RootRef,
        cursor: UsageCursor,
    ) -> Result<UsagePage, CustodyError> {
        let cursor = match cursor.0.as_slice() {
            [] => 0,
            bytes => u64::from_be_bytes(
                bytes
                    .try_into()
                    .map_err(|_| CustodyError::InvalidConfig("a keyd cursor is 8 bytes"))?,
            ),
        };
        let request = Request::UsageSince {
            id: crate::request_or_fresh()?,
            root: KeydCustody::root_of(root)?,
            cursor,
        };
        match self.call(&request).await? {
            Response::Usage { records, next } => Ok(UsagePage {
                operations: records,
                next: UsageCursor(next.to_be_bytes().to_vec()),
            }),
            other => Err(unexpected(other)),
        }
    }
}
