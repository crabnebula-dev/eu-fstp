//! The frames of the guard link (ADR-004 record of lane `m10/guard-key`,
//! "The guard link"). Integers are big-endian.
//!
//! ```text
//! request  = "FGL1" | version u8 = 1 | kind u8 | entry u8 | request id 16
//!   kind 1 public: nothing                                        23 bytes
//!   kind 2 rotate: event 16                                       39 bytes
//!   kind 3 open:   generation u32 | copy header 36 | ciphertext 1120
//!                                                                 1183 bytes
//! response = "FGL1" | version u8 = 1 | kind u8 | request id 16
//!   0x81 public:  generation u32 | public key 1216                1242 bytes
//!   0x82 rotated: destroyed u32 | generation u32 | public key 1216
//!                 | receipt len u16 | receipt (0 to 64)           1248 to 1312
//!   0x83 opened:  kek 32                                          54 bytes
//!   0xff refused: refusal code u8                                 23 bytes
//! ```
//!
//! Since 2026-11-24 (Q-F018-4), the custodian's copy:
//!
//! ```text
//!   kind 4 put:    generation u32 | len u32 | guarded copy        31 + len
//!   kind 5 fetch:  nothing                                        23 bytes
//!   0x84 stored:  generation u32                                  26 bytes
//!   0x85 copy:    generation u32 | len u32 | guarded copy         30 + len
//! ```
//!
//! A copy is 1 to [`MAX_GUARDED_LEN`] bytes.
//!
//! Each kind has one length, and every byte has one meaning, so each
//! decoder accepts exactly what its encoder writes. Fuzzed
//! (`guard_link_decode`).

use zeroize::Zeroizing;

use fstp_crypto::hybrid_kem::{CIPHERTEXT_LEN, PUBLIC_KEY_LEN};
use fstp_custody::Refusal;

use super::GuardEntry;
use super::copy::{HEADER_LEN, MAX_GUARDED_LEN};
use crate::KeydError;

/// The magic of every frame.
pub const LINK_MAGIC: [u8; 4] = *b"FGL1";
/// The one version of the link.
pub const LINK_VERSION: u8 = 1;
/// The longest request but a `put`: an `open`. The custodian reads no more
/// from a peer whose certificate names no pilot entry.
pub const MAX_SMALL_REQUEST_LEN: usize = REQUEST_HEAD_LEN + 4 + HEADER_LEN + CIPHERTEXT_LEN;
/// The longest request: a `put` of the longest copy.
pub const MAX_REQUEST_LEN: usize = REQUEST_HEAD_LEN + 8 + MAX_GUARDED_LEN;
/// The longest receipt a rotation carries.
pub const MAX_RECEIPT_LEN: usize = 64;
/// The longest response but a copy: a rotation with the longest receipt.
pub const MAX_SMALL_RESPONSE_LEN: usize =
    RESPONSE_HEAD_LEN + 4 + 4 + PUBLIC_KEY_LEN + 2 + MAX_RECEIPT_LEN;
/// The longest response: the longest copy.
pub const MAX_RESPONSE_LEN: usize = RESPONSE_HEAD_LEN + 8 + MAX_GUARDED_LEN;

const REQUEST_HEAD_LEN: usize = 23;
const RESPONSE_HEAD_LEN: usize = 22;

const KIND_PUBLIC: u8 = 1;
const KIND_ROTATE: u8 = 2;
const KIND_OPEN: u8 = 3;
const KIND_PUT: u8 = 4;
const KIND_FETCH: u8 = 5;
const KIND_STORED: u8 = 0x84;
const KIND_COPY: u8 = 0x85;
const KIND_PUBLIC_REPLY: u8 = 0x81;
const KIND_ROTATED: u8 = 0x82;
const KIND_OPENED: u8 = 0x83;
const KIND_REFUSED: u8 = 0xff;

/// A request of the guard link.
#[derive(Clone, PartialEq, Eq)]
pub enum GuardRequest {
    /// The current guard of `entry`, made at the first ask.
    Public {
        /// The request id.
        id: [u8; 16],
        /// The pilot entry.
        entry: GuardEntry,
    },
    /// Replace `entry`'s guard for `event`.
    Rotate {
        /// The request id.
        id: [u8; 16],
        /// The pilot entry.
        entry: GuardEntry,
        /// The owed event: the request id of the destroy that caused it.
        event: [u8; 16],
    },
    /// The key of the outer seal of a copy.
    Open {
        /// The request id.
        id: [u8; 16],
        /// The pilot entry.
        entry: GuardEntry,
        /// The guard generation the copy names.
        generation: u32,
        /// The copy's clear header.
        header: Box<[u8; HEADER_LEN]>,
        /// The hybrid ciphertext of the copy.
        ciphertext: Box<[u8; CIPHERTEXT_LEN]>,
    },
    /// Store `copy` as the entry's held copy (Q-F018-4).
    Put {
        /// The request id.
        id: [u8; 16],
        /// The pilot entry.
        entry: GuardEntry,
        /// The guard generation the copy is sealed to.
        generation: u32,
        /// The guarded copy.
        copy: Vec<u8>,
    },
    /// The entry's held copy.
    Fetch {
        /// The request id.
        id: [u8; 16],
        /// The pilot entry.
        entry: GuardEntry,
    },
}

impl std::fmt::Debug for GuardRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardRequest")
            .field("kind", &self.kind())
            .field("entry", &self.entry())
            .finish_non_exhaustive()
    }
}

impl GuardRequest {
    fn kind(&self) -> u8 {
        match self {
            GuardRequest::Public { .. } => KIND_PUBLIC,
            GuardRequest::Rotate { .. } => KIND_ROTATE,
            GuardRequest::Open { .. } => KIND_OPEN,
            GuardRequest::Put { .. } => KIND_PUT,
            GuardRequest::Fetch { .. } => KIND_FETCH,
        }
    }

    /// The pilot entry the request names.
    #[must_use]
    pub fn entry(&self) -> GuardEntry {
        match self {
            GuardRequest::Public { entry, .. }
            | GuardRequest::Rotate { entry, .. }
            | GuardRequest::Open { entry, .. }
            | GuardRequest::Put { entry, .. }
            | GuardRequest::Fetch { entry, .. } => *entry,
        }
    }

    /// The request id.
    #[must_use]
    pub fn id(&self) -> [u8; 16] {
        match self {
            GuardRequest::Public { id, .. }
            | GuardRequest::Rotate { id, .. }
            | GuardRequest::Open { id, .. }
            | GuardRequest::Put { id, .. }
            | GuardRequest::Fetch { id, .. } => *id,
        }
    }

    /// The request bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(MAX_SMALL_REQUEST_LEN);
        out.extend_from_slice(&LINK_MAGIC);
        out.extend_from_slice(&[LINK_VERSION, self.kind(), self.entry().code()]);
        out.extend_from_slice(&self.id());
        match self {
            GuardRequest::Public { .. } => {}
            GuardRequest::Rotate { event, .. } => out.extend_from_slice(event),
            GuardRequest::Open {
                generation,
                header,
                ciphertext,
                ..
            } => {
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&header[..]);
                out.extend_from_slice(&ciphertext[..]);
            }
            GuardRequest::Put {
                generation, copy, ..
            } => {
                out.extend_from_slice(&generation.to_be_bytes());
                let len = u32::try_from(copy.len()).unwrap_or(u32::MAX);
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(copy);
            }
            GuardRequest::Fetch { .. } => {}
        }
        out
    }
}

/// A response of the guard link.
#[derive(Clone, PartialEq, Eq)]
pub enum GuardResponse {
    /// The current guard.
    Public {
        /// The request id.
        id: [u8; 16],
        /// The current generation.
        generation: u32,
        /// Its public half.
        public: Box<[u8; PUBLIC_KEY_LEN]>,
    },
    /// The guard was replaced.
    Rotated {
        /// The request id.
        id: [u8; 16],
        /// The newest generation destroyed, or 0.
        destroyed: u32,
        /// The generation now current.
        generation: u32,
        /// Its public half.
        public: Box<[u8; PUBLIC_KEY_LEN]>,
        /// The destroy receipt, or empty.
        receipt: Vec<u8>,
    },
    /// The key of an outer seal.
    Opened {
        /// The request id.
        id: [u8; 16],
        /// The key.
        kek: Zeroizing<[u8; 32]>,
    },
    /// The custodian stored the copy.
    Stored {
        /// The request id.
        id: [u8; 16],
        /// The generation the copy is sealed to.
        generation: u32,
    },
    /// The entry's held copy.
    Copy {
        /// The request id.
        id: [u8; 16],
        /// The generation it is sealed to.
        generation: u32,
        /// The guarded copy.
        copy: Vec<u8>,
    },
    /// A refusal.
    Refused {
        /// The request id, or zeros when the request did not decode.
        id: [u8; 16],
        /// Why.
        refusal: Refusal,
    },
}

impl std::fmt::Debug for GuardResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GuardResponse::Public { generation, .. } => f
                .debug_struct("Public")
                .field("generation", generation)
                .finish_non_exhaustive(),
            GuardResponse::Rotated {
                destroyed,
                generation,
                ..
            } => f
                .debug_struct("Rotated")
                .field("destroyed", destroyed)
                .field("generation", generation)
                .finish_non_exhaustive(),
            GuardResponse::Opened { .. } => f.debug_struct("Opened").finish_non_exhaustive(),
            GuardResponse::Stored { generation, .. } | GuardResponse::Copy { generation, .. } => f
                .debug_struct("Copy")
                .field("generation", generation)
                .finish_non_exhaustive(),
            GuardResponse::Refused { refusal, .. } => f
                .debug_struct("Refused")
                .field("refusal", refusal)
                .finish_non_exhaustive(),
        }
    }
}

impl GuardResponse {
    /// The response bytes.
    ///
    /// # Errors
    ///
    /// Refuses a receipt above [`MAX_RECEIPT_LEN`].
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, KeydError> {
        let mut out = Zeroizing::new(Vec::with_capacity(MAX_SMALL_RESPONSE_LEN));
        out.extend_from_slice(&LINK_MAGIC);
        let (kind, id) = match self {
            GuardResponse::Public { id, .. } => (KIND_PUBLIC_REPLY, id),
            GuardResponse::Rotated { id, .. } => (KIND_ROTATED, id),
            GuardResponse::Opened { id, .. } => (KIND_OPENED, id),
            GuardResponse::Stored { id, .. } => (KIND_STORED, id),
            GuardResponse::Copy { id, .. } => (KIND_COPY, id),
            GuardResponse::Refused { id, .. } => (KIND_REFUSED, id),
        };
        out.extend_from_slice(&[LINK_VERSION, kind]);
        out.extend_from_slice(id);
        match self {
            GuardResponse::Public {
                generation, public, ..
            } => {
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&public[..]);
            }
            GuardResponse::Rotated {
                destroyed,
                generation,
                public,
                receipt,
                ..
            } => {
                if receipt.len() > MAX_RECEIPT_LEN {
                    return Err(bad("a guard receipt is too long"));
                }
                out.extend_from_slice(&destroyed.to_be_bytes());
                out.extend_from_slice(&generation.to_be_bytes());
                out.extend_from_slice(&public[..]);
                let len =
                    u16::try_from(receipt.len()).map_err(|_| bad("a guard receipt is too long"))?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(receipt);
            }
            GuardResponse::Opened { kek, .. } => out.extend_from_slice(&kek[..]),
            GuardResponse::Stored { generation, .. } => {
                out.extend_from_slice(&generation.to_be_bytes());
            }
            GuardResponse::Copy {
                generation, copy, ..
            } => {
                if copy.is_empty() || copy.len() > MAX_GUARDED_LEN {
                    return Err(bad("a held copy is out of bounds"));
                }
                out.extend_from_slice(&generation.to_be_bytes());
                let len = u32::try_from(copy.len()).map_err(|_| bad("a held copy is too long"))?;
                out.extend_from_slice(&len.to_be_bytes());
                out.extend_from_slice(copy);
            }
            GuardResponse::Refused { refusal, .. } => out.push(refusal.code()),
        }
        Ok(out)
    }
}

fn bad(rule: &'static str) -> KeydError {
    KeydError::Malformed(rule)
}

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], KeydError> {
        let (head, rest) = self
            .0
            .split_at_checked(n)
            .ok_or(bad("a guard frame is cut short"))?;
        self.0 = rest;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], KeydError> {
        self.take(N)?
            .try_into()
            .map_err(|_| bad("a guard frame is cut short"))
    }

    fn u32(&mut self) -> Result<u32, KeydError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// A copy: its length as `u32`, 1 to [`MAX_GUARDED_LEN`], then its
    /// bytes.
    fn copy(&mut self) -> Result<&'a [u8], KeydError> {
        let len = usize::try_from(self.u32()?).map_err(|_| bad("a held copy is too long"))?;
        if len == 0 || len > MAX_GUARDED_LEN {
            return Err(bad("a held copy is out of bounds"));
        }
        self.take(len)
    }

    fn end(&self) -> Result<(), KeydError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(bad("a guard frame has bytes after its end"))
        }
    }
}

fn head(r: &mut Reader<'_>) -> Result<u8, KeydError> {
    if r.array::<4>()? != LINK_MAGIC {
        return Err(bad("a guard frame has the wrong magic"));
    }
    let [version, kind] = r.array::<2>()?;
    if version != LINK_VERSION {
        return Err(bad("a guard frame has an unknown version"));
    }
    Ok(kind)
}

fn generation(g: u32) -> Result<u32, KeydError> {
    if g == 0 {
        Err(bad("a guard frame names generation 0"))
    } else {
        Ok(g)
    }
}

/// Decodes a request. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for a frame above [`MAX_REQUEST_LEN`], a wrong
/// magic, version, kind or entry, generation 0, and a wrong length.
pub fn decode_guard_request(bytes: &[u8]) -> Result<GuardRequest, KeydError> {
    if bytes.len() > MAX_REQUEST_LEN {
        return Err(bad("a guard request is too long"));
    }
    let mut r = Reader(bytes);
    let kind = head(&mut r)?;
    let [code] = r.array::<1>()?;
    let entry = GuardEntry::from_code(code).ok_or(bad("a guard request names an unknown entry"))?;
    let id = r.array::<16>()?;
    let request = match kind {
        KIND_PUBLIC => GuardRequest::Public { id, entry },
        KIND_ROTATE => GuardRequest::Rotate {
            id,
            entry,
            event: r.array()?,
        },
        KIND_OPEN => GuardRequest::Open {
            id,
            entry,
            generation: generation(r.u32()?)?,
            header: Box::new(r.array()?),
            ciphertext: Box::new(r.array()?),
        },
        KIND_PUT => {
            let generation = generation(r.u32()?)?;
            let copy = r.copy()?.to_vec();
            GuardRequest::Put {
                id,
                entry,
                generation,
                copy,
            }
        }
        KIND_FETCH => GuardRequest::Fetch { id, entry },
        _ => return Err(bad("a guard request has an unknown kind")),
    };
    r.end()?;
    Ok(request)
}

/// Decodes a response. Fuzzed (`guard_link_decode`).
///
/// # Errors
///
/// [`KeydError::Malformed`] for a frame above [`MAX_RESPONSE_LEN`], a
/// wrong magic, version or kind, an unknown refusal code, generation 0
/// where one is current, a receipt above [`MAX_RECEIPT_LEN`], and a wrong
/// length.
pub fn decode_guard_response(bytes: &[u8]) -> Result<GuardResponse, KeydError> {
    if bytes.len() > MAX_RESPONSE_LEN {
        return Err(bad("a guard response is too long"));
    }
    let mut r = Reader(bytes);
    let kind = head(&mut r)?;
    let id = r.array::<16>()?;
    let response = match kind {
        KIND_PUBLIC_REPLY => GuardResponse::Public {
            id,
            generation: generation(r.u32()?)?,
            public: Box::new(r.array()?),
        },
        KIND_ROTATED => {
            let destroyed = r.u32()?;
            let current = generation(r.u32()?)?;
            if destroyed >= current {
                return Err(bad("a guard rotation names no newer generation"));
            }
            let public = Box::new(r.array()?);
            let len = usize::from(u16::from_be_bytes(r.array()?));
            if len > MAX_RECEIPT_LEN {
                return Err(bad("a guard receipt is too long"));
            }
            GuardResponse::Rotated {
                id,
                destroyed,
                generation: current,
                public,
                receipt: r.take(len)?.to_vec(),
            }
        }
        KIND_OPENED => GuardResponse::Opened {
            id,
            kek: Zeroizing::new(r.array()?),
        },
        KIND_STORED => GuardResponse::Stored {
            id,
            generation: generation(r.u32()?)?,
        },
        KIND_COPY => {
            let generation = generation(r.u32()?)?;
            let copy = r.copy()?.to_vec();
            GuardResponse::Copy {
                id,
                generation,
                copy,
            }
        }
        KIND_REFUSED => {
            let [code] = r.array::<1>()?;
            GuardResponse::Refused {
                id,
                refusal: Refusal::from_code(code)
                    .ok_or(bad("a guard refusal has an unknown code"))?,
            }
        }
        _ => return Err(bad("a guard response has an unknown kind")),
    };
    r.end()?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    /// ADR-004 record of lane `m10/guard-key`: every request and response
    /// kind decodes back from its bytes, in one spelling, and a cut or
    /// longer frame is refused.
    #[test]
    fn adr004_guard_frames_round_trip_in_one_spelling() {
        let requests = [
            GuardRequest::Public {
                id: [1; 16],
                entry: GuardEntry::Cell,
            },
            GuardRequest::Rotate {
                id: [2; 16],
                entry: GuardEntry::Vault,
                event: [3; 16],
            },
            GuardRequest::Open {
                id: [4; 16],
                entry: GuardEntry::Witness,
                generation: 7,
                header: Box::new([5; HEADER_LEN]),
                ciphertext: Box::new([6; CIPHERTEXT_LEN]),
            },
        ];
        for q in &requests {
            let b = q.encode();
            assert_eq!(&decode_guard_request(&b).unwrap(), q);
            assert!(decode_guard_request(&b[..b.len() - 1]).is_err());
            let mut long = b.clone();
            long.push(0);
            assert!(decode_guard_request(&long).is_err());
        }
        assert_eq!(requests[2].encode().len(), MAX_SMALL_REQUEST_LEN);
        let responses = [
            GuardResponse::Public {
                id: [1; 16],
                generation: 1,
                public: Box::new([9; PUBLIC_KEY_LEN]),
            },
            GuardResponse::Rotated {
                id: [2; 16],
                destroyed: 1,
                generation: 2,
                public: Box::new([8; PUBLIC_KEY_LEN]),
                receipt: vec![7; MAX_RECEIPT_LEN],
            },
            GuardResponse::Opened {
                id: [3; 16],
                kek: Zeroizing::new([4; 32]),
            },
            GuardResponse::Refused {
                id: [5; 16],
                refusal: Refusal::Destroyed,
            },
        ];
        for s in &responses {
            let b = s.encode().unwrap();
            assert_eq!(&decode_guard_response(&b).unwrap(), s);
            assert!(decode_guard_response(&b[..b.len() - 1]).is_err());
        }
        assert_eq!(responses[1].encode().unwrap().len(), MAX_SMALL_RESPONSE_LEN);
    }

    /// ADR-004 "The custodian's copy" (Q-F018-4): the `put`, `fetch`,
    /// `stored` and `copy` frames decode back in one spelling, and an
    /// empty copy or a length that does not match is refused.
    #[test]
    fn adr004_guard_copy_frames_round_trip_in_one_spelling() {
        for q in [
            GuardRequest::Put {
                id: [1; 16],
                entry: GuardEntry::Vault,
                generation: 3,
                copy: vec![9; 70],
            },
            GuardRequest::Fetch {
                id: [2; 16],
                entry: GuardEntry::Cell,
            },
        ] {
            let b = q.encode();
            assert_eq!(decode_guard_request(&b).unwrap(), q);
            assert!(decode_guard_request(&b[..b.len() - 1]).is_err());
        }
        for s in [
            GuardResponse::Stored {
                id: [3; 16],
                generation: 4,
            },
            GuardResponse::Copy {
                id: [4; 16],
                generation: 4,
                copy: vec![8; 33],
            },
        ] {
            let b = s.encode().unwrap();
            assert_eq!(decode_guard_response(&b).unwrap(), s);
            assert!(decode_guard_response(&b[..b.len() - 1]).is_err());
        }
        let empty = GuardRequest::Put {
            id: [1; 16],
            entry: GuardEntry::Cell,
            generation: 1,
            copy: Vec::new(),
        };
        assert!(decode_guard_request(&empty.encode()).is_err());
    }
}
