//! The backup container decoder (ADR-012 "Container format", R-CR-01).
//!
//! The bytes are interim, pending Daniel, as ADR-012 marks them:
//!
//! ```text
//! header = "FBC1" | version u8 = 1 | aead u16 = 1 | kind u8 | chain u8 | owner 16
//!          | container 16 | part u32 | chunk_size u32 | sealed_key 1210   1259 bytes
//! chunk  = final u8 | len u32 | nonce 12 | ciphertext len | tag 16
//! ```
//!
//! The decoder admits one spelling only. `final` is 0 or 1. A non-final
//! chunk has `len` equal to `chunk_size`, and the final chunk at most
//! `chunk_size`. Exactly one chunk is final, and it is the last. Bytes
//! after it are refused, and a missing final chunk is truncation. An
//! empty final chunk is admitted only as chunk 0, the spelling of an
//! empty plaintext, as the reference reads ADR-012.
//!
//! The data key must be an `FSK1` key sealed through the hybrid KEM on
//! the container's own chain (ADR-004, R-CR-01). The sealed key bytes go
//! through `fstp_keys::envelope::decode_sealed_key`. Nothing here opens a
//! chunk: that needs the group secret.

use fstp_keys::Chain;
use fstp_keys::envelope::{
    AEAD_AES_256_GCM, FORMAT_VERSION, KEM_HYBRID, NONCE_LEN, SEALED_KEY_LEN, TAG_LEN,
    decode_sealed_key,
};

use crate::{BackupError, Chunk};

/// The magic of a backup container.
pub(crate) const CONTAINER_MAGIC: [u8; 4] = *b"FBC1";
/// The only chunk size version 1 accepts: 1 MiB.
pub(crate) const CHUNK_SIZE: u32 = 1_048_576;
/// The length of a container header.
pub(crate) const HEADER_LEN: usize = 49 + SEALED_KEY_LEN;

/// The fields of a container header that a reader needs.
pub(crate) struct Header<'a> {
    /// The kind code, 1 to 3.
    pub(crate) kind: u8,
    /// The owner.
    pub(crate) owner: [u8; 16],
    /// The container id.
    pub(crate) container: [u8; 16],
    /// The part number.
    pub(crate) part: u32,
    /// The sealed data key bytes.
    pub(crate) sealed_key: &'a [u8],
}

/// A cursor over input bytes that never reads past the end. Running out
/// of input is truncation.
struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], BackupError> {
        let (head, tail) = self
            .rest
            .split_at_checked(n)
            .ok_or(BackupError::Truncated)?;
        self.rest = tail;
        Ok(head)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], BackupError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    fn u8(&mut self) -> Result<u8, BackupError> {
        let [b] = self.array::<1>()?;
        Ok(b)
    }

    fn u16(&mut self) -> Result<u16, BackupError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    fn u32(&mut self) -> Result<u32, BackupError> {
        Ok(u32::from_be_bytes(self.array()?))
    }
}

/// Checks the container header (ADR-012) and its data key (R-CR-01).
fn header<'a>(r: &mut Reader<'a>) -> Result<Header<'a>, BackupError> {
    if r.array::<4>()? != CONTAINER_MAGIC {
        return Err(BackupError::Malformed("magic"));
    }
    if r.u8()? != FORMAT_VERSION {
        return Err(BackupError::Malformed("version"));
    }
    if r.u16()? != AEAD_AES_256_GCM {
        return Err(BackupError::Malformed("aead"));
    }
    let kind = r.u8()?;
    if !(1..=3).contains(&kind) {
        return Err(BackupError::Malformed("kind"));
    }
    let chain = match Chain::from_code(r.u8()?) {
        Some(c @ (Chain::CellBackup | Chain::ClusterBackup)) => c,
        _ => return Err(BackupError::Malformed("chain")),
    };
    let owner = r.array::<16>()?;
    let container = r.array::<16>()?;
    let part = r.u32()?;
    if r.u32()? != CHUNK_SIZE {
        return Err(BackupError::Malformed("chunk size"));
    }
    let sealed_key = r.take(SEALED_KEY_LEN)?;
    let key = decode_sealed_key(sealed_key)
        .map_err(|_| BackupError::KeyNotHybrid)?
        .header();
    if key.kem != KEM_HYBRID || key.chain != chain {
        return Err(BackupError::KeyNotHybrid);
    }
    Ok(Header {
        kind,
        owner,
        container,
        part,
        sealed_key,
    })
}

/// Decodes the header of a container alone (ADR-012).
///
/// # Errors
///
/// As [`decode`], for the header.
pub(crate) fn decode_header(bytes: &[u8]) -> Result<Header<'_>, BackupError> {
    header(&mut Reader { rest: bytes })
}

/// Decodes a backup container into its sealed chunks, in order (ADR-012).
///
/// # Errors
///
/// Returns [`BackupError::Truncated`] when the input ends before the
/// final chunk does, [`BackupError::KeyNotHybrid`] when the data key is
/// not a hybrid `FSK1` key of the container's chain, and
/// [`BackupError::Malformed`] for any other rule the input breaks.
pub(crate) fn decode(bytes: &[u8]) -> Result<Vec<Chunk>, BackupError> {
    let mut r = Reader { rest: bytes };
    header(&mut r)?;
    let mut chunks = Vec::new();
    let mut index: u64 = 0;
    loop {
        let last = match r.u8()? {
            0 => false,
            1 => true,
            _ => return Err(BackupError::Malformed("final flag")),
        };
        let len = r.u32()?;
        if len > CHUNK_SIZE || (!last && len != CHUNK_SIZE) {
            return Err(BackupError::Malformed("chunk length"));
        }
        if last && len == 0 && index != 0 {
            return Err(BackupError::Malformed(
                "empty final chunk after full chunks",
            ));
        }
        let body_len = usize::try_from(len)
            .ok()
            .and_then(|n| n.checked_add(NONCE_LEN))
            .and_then(|n| n.checked_add(TAG_LEN))
            .ok_or(BackupError::Malformed("chunk length"))?;
        let sealed = r.take(body_len)?.to_vec();
        chunks.push(Chunk {
            index,
            last,
            sealed,
        });
        if last {
            break;
        }
        index = index
            .checked_add(1)
            .ok_or(BackupError::Malformed("chunk index"))?;
    }
    if r.rest.is_empty() {
        Ok(chunks)
    } else {
        Err(BackupError::Malformed("bytes after the final chunk"))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]

    use super::*;
    use fstp_crypto::{aead, hybrid_kem};
    use fstp_keys::envelope::{self, DataKey, SealContext};
    use fstp_keys::{CellId, GroupId, ObjectId, Purpose};

    /// A container of `full` full chunks, then a final chunk of `tail`
    /// bytes. The chunks are sealed under a fresh data key.
    fn container(chain: Chain, full: usize, tail: usize) -> Vec<u8> {
        let sk = hybrid_kem::generate().unwrap();
        let ctx = SealContext {
            cell: CellId([1; 16]),
            chain,
            purpose: Purpose::Backup,
            group: GroupId([2; 16]),
            generation: 1,
            object: ObjectId([3; 16]),
        };
        let dek = DataKey::from_bytes(&[4; 32]).unwrap();
        let sealed = envelope::seal_key(sk.public(), &dek, &ctx).unwrap();
        let mut out = CONTAINER_MAGIC.to_vec();
        out.push(FORMAT_VERSION);
        out.extend_from_slice(&AEAD_AES_256_GCM.to_be_bytes());
        out.push(1);
        out.push(chain.code());
        out.extend_from_slice(&[1; 16]);
        out.extend_from_slice(&[3; 16]);
        out.extend_from_slice(&0u32.to_be_bytes());
        out.extend_from_slice(&CHUNK_SIZE.to_be_bytes());
        out.extend(envelope::encode_sealed_key(&sealed).unwrap());
        let key = aead::Key::from_bytes(&[4; 32]).unwrap();
        let size = CHUNK_SIZE as usize;
        let lens = std::iter::repeat_n(size, full).chain([tail]);
        for (i, len) in lens.enumerate() {
            let last = i == full;
            let s = aead::seal(&key, b"aad", &vec![0; len]).unwrap();
            out.push(u8::from(last));
            out.extend_from_slice(&u32::try_from(len).unwrap().to_be_bytes());
            out.extend_from_slice(&s.nonce);
            out.extend_from_slice(&s.body);
        }
        out
    }

    /// R-CR-01, ADR-012: a well-formed container decodes into its chunks
    /// in order, with the final flag on the last one only.
    #[test]
    fn r_cr_01_container_decodes_in_order() {
        let chunks = decode(&container(Chain::ClusterBackup, 1, 5)).unwrap();
        assert_eq!(chunks.len(), 2);
        assert_eq!((chunks[0].index, chunks[0].last), (0, false));
        assert_eq!((chunks[1].index, chunks[1].last), (1, true));
        assert_eq!(chunks[1].sealed.len(), NONCE_LEN + 5 + TAG_LEN);
        let empty = decode(&container(Chain::CellBackup, 0, 0)).unwrap();
        assert_eq!(empty.len(), 1);
    }

    /// ADR-012 "A missing final chunk is reported as truncation": every
    /// strict prefix of a container is refused as truncated.
    #[test]
    fn r_cr_01_missing_final_chunk_is_truncation() {
        let bytes = container(Chain::CellBackup, 0, 40);
        for cut in [0, 10, 1258, 1259, 1264, bytes.len() - 1] {
            assert_eq!(decode(&bytes[..cut]), Err(BackupError::Truncated), "{cut}");
        }
    }

    /// ADR-012 "one spelling only": full chunks then an empty final chunk
    /// are refused, and so is a key on another chain or an App chain
    /// container.
    #[test]
    fn r_cr_01_container_refuses_other_spellings_and_chains() {
        assert!(matches!(
            decode(&container(Chain::ClusterBackup, 1, 0)),
            Err(BackupError::Malformed(_))
        ));
        let mut moved = container(Chain::ClusterBackup, 0, 1);
        moved[8] = Chain::CellBackup.code();
        assert_eq!(decode(&moved), Err(BackupError::KeyNotHybrid));
        assert!(matches!(
            decode(&container(Chain::App, 0, 1)),
            Err(BackupError::Malformed("chain"))
        ));
    }
}
