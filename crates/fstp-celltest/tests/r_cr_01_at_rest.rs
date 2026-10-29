//! R-CR-01: data at rest that leaves the running system, such as backups
//! and exports, is protected by hybrid post-quantum key encapsulation
//! (ADR-001, T-CR-ATREST, design section 14.5). The sealed key format of
//! ADR-004 part 1 and the backup container of ADR-012.
//!
//! Lane W1d wrote these tests before the production code. The reference
//! self-checks run now. The production tests are red until
//! `fstp_keys::envelope` (lane W2f), `fstp_backup` (lane W2k) and the cell
//! runtime (lane W3a) land. The cross-implementation tests also need the
//! ADR-004 purpose code table, which is "Record at first use".

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::reference::hybrid::RefKeyPair;
use fstp_celltest::reference::keys::{
    self as rk, CHUNK_SIZE, KIND_BASE_BACKUP, KIND_KEYSTORE_SNAPSHOT, KIND_WAL_SEGMENT,
    RefContainerHeader, RefContext, SEALED_KEY_LEN, chain_code, purpose_code,
};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_crypto::hybrid_kem::{self, HybridPublicKey, HybridSecretKey};
use fstp_keys::envelope::{SealContext, decode_sealed_key, encode_sealed_key};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// Generators.

fn arr16(g: &mut Gen) -> [u8; 16] {
    let v = g.bytes(16..=16);
    let mut out = [0u8; 16];
    out.copy_from_slice(&v);
    out
}

fn ref_ctx(g: &mut Gen) -> RefContext {
    RefContext {
        owner: arr16(g),
        chain: g.u8_in(1..=5),
        purpose: g.u8(),
        group: arr16(g),
        generation: g.u32(),
        object: arr16(g),
    }
}

const CHAINS: [Chain; 5] = [
    Chain::App,
    Chain::Vault,
    Chain::CellBackup,
    Chain::ClusterBackup,
    Chain::ControlPlane,
];

const PURPOSES: [Purpose; 5] = [
    Purpose::Ledger,
    Purpose::Text,
    Purpose::AuditEvent,
    Purpose::Checkpoint,
    Purpose::Backup,
];

fn prod_ctx(g: &mut Gen) -> SealContext {
    SealContext {
        cell: CellId(arr16(g)),
        chain: *g.pick(&CHAINS),
        purpose: *g.pick(&PURPOSES),
        group: GroupId(arr16(g)),
        generation: g.u32(),
        object: ObjectId(arr16(g)),
    }
}

/// `ctx` with field `i` (0 to 5) changed.
fn moved_ref(ctx: &RefContext, i: usize) -> RefContext {
    let mut m = *ctx;
    match i {
        0 => m.owner[0] ^= 1,
        1 => m.chain = if m.chain == 5 { 1 } else { m.chain + 1 },
        2 => m.purpose ^= 1,
        3 => m.group[15] ^= 1,
        4 => m.generation ^= 1,
        _ => m.object[7] ^= 1,
    }
    m
}

/// `ctx` with field `i` (0 to 5) changed.
fn moved_prod(ctx: &SealContext, i: usize) -> SealContext {
    let mut m = *ctx;
    match i {
        0 => m.cell.0[0] ^= 1,
        1 => {
            m.chain = if m.chain == Chain::App {
                Chain::Vault
            } else {
                Chain::App
            }
        }
        2 => {
            m.purpose = if m.purpose == Purpose::Text {
                Purpose::Ledger
            } else {
                Purpose::Text
            }
        }
        3 => m.group.0[15] ^= 1,
        4 => m.generation ^= 1,
        _ => m.object.0[7] ^= 1,
    }
    m
}

/// The reference context of a production context.
fn as_ref_ctx(c: &SealContext) -> Result<RefContext, String> {
    let purpose = purpose_code(c.purpose).ok_or_else(|| {
        format!(
            "the ADR-004 purpose code table is not recorded, so {:?} has no code",
            c.purpose
        )
    })?;
    Ok(RefContext {
        owner: c.cell.0,
        chain: chain_code(c.chain),
        purpose,
        group: c.group.0,
        generation: c.generation,
        object: c.object.0,
    })
}

// ---------------------------------------------------------------------------
// Production seams.

/// The former seam of [`prod_seal_key`] and [`prod_open_key`]. Lane W2f
/// added `fstp_keys::envelope::seal_key` and `open_key` (design section
/// 3.2), which these helpers now call. A probe below still compares a
/// refusal with this text, so a helper that fell back to the seam fails.
const ENVELOPE_SEAM: &str =
    "fstp_keys::envelope has no seal_key or open_key yet (design section 3.2, lane W2f)";

fn prod_seal_key(
    pk: &HybridPublicKey,
    dek: &[u8; 32],
    ctx: &SealContext,
) -> Result<Vec<u8>, String> {
    let dek = fstp_keys::envelope::DataKey::from_bytes(dek).map_err(|e| format!("{e:?}"))?;
    let sealed = fstp_keys::envelope::seal_key(pk, &dek, ctx).map_err(|e| format!("{e:?}"))?;
    encode_sealed_key(&sealed).map_err(decode_err)
}

fn prod_open_key(
    sk: &HybridSecretKey,
    sealed: &[u8],
    ctx: &SealContext,
) -> Result<[u8; 32], String> {
    let sealed = decode_sealed_key(sealed).map_err(decode_err)?;
    fstp_keys::envelope::open_key(sk, &sealed, ctx)
        .map(|k| *k.expose())
        .map_err(|e| format!("{e:?}"))
}

fn decode_err(e: fstp_keys::envelope::DecodeError) -> String {
    format!("{e:?}")
}

// ---------------------------------------------------------------------------
// The sealed key format, reference self-checks.

/// R-CR-01, ADR-004 part 1: the reference seals a data key in exactly 1210
/// bytes, decodes and re-encodes them byte for byte, and opens them under
/// the same context.
#[test]
fn r_cr_01_reference_sealed_key_round_trips() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check("r_cr_01_reference_sealed_key_round_trips", |g: &mut Gen| {
        let ctx = ref_ctx(g);
        let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let sealed = rk::seal_key(kp.public_key(), &dek, &ctx).map_err(|e| e.0.to_owned())?;
        prop_assert_eq!(sealed.len(), SEALED_KEY_LEN);
        let decoded = rk::decode_sealed_key(&sealed).ok_or("decode")?;
        prop_assert_eq!(rk::encode_sealed_key(&decoded), sealed.clone());
        let opened = rk::open_key(&kp, &sealed, &ctx).map_err(|e| e.0.to_owned())?;
        prop_assert_eq!(opened, dek);
        Ok(())
    });
}

/// R-CR-01, ADR-004 test vector plan item 7, reference self-check: a
/// sealed key opened under a context with any one field changed fails.
#[test]
fn r_cr_01_reference_sealed_key_moved_context_fails_to_open() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_reference_sealed_key_moved_context_fails_to_open",
        |g: &mut Gen| {
            let ctx = ref_ctx(g);
            let field = g.usize_in(0..=5);
            let sealed =
                rk::seal_key(kp.public_key(), &[7; 32], &ctx).map_err(|e| e.0.to_owned())?;
            let moved = moved_ref(&ctx, field);
            prop_assert!(
                rk::open_key(&kp, &sealed, &moved).is_err(),
                "opened with field {field} changed"
            );
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// The sealed key format, production against the reference.

/// R-CR-01, ADR-004 part 1: production decodes every key the reference
/// seals and re-encodes it byte for byte.
#[test]
fn r_cr_01_sealed_key_decoder_accepts_the_reference_layout_and_re_encodes() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_sealed_key_decoder_accepts_the_reference_layout_and_re_encodes",
        |g: &mut Gen| {
            let ctx = ref_ctx(g);
            let sealed =
                rk::seal_key(kp.public_key(), &[3; 32], &ctx).map_err(|e| e.0.to_owned())?;
            let decoded = decode_sealed_key(&sealed).map_err(decode_err)?;
            let again = encode_sealed_key(&decoded).map_err(decode_err)?;
            prop_assert_eq!(again, sealed);
            Ok(())
        },
    );
}

/// A mutation of a valid sealed key: one byte of the header changed, a
/// byte added or a byte dropped.
fn mutate(g: &mut Gen, sealed: &[u8]) -> Vec<u8> {
    let mut m = sealed.to_vec();
    match g.usize_in(0..=2) {
        0 => {
            let at = g.usize_in(0..=rk::HEADER_LEN - 1);
            m[at] ^= g.u8_in(1..=255);
        }
        1 => m.push(g.u8()),
        _ => {
            m.pop();
        }
    }
    m
}

/// R-CR-01, ADR-004 part 1: "Any other input is refused." Production
/// refuses every mutation the reference refuses: a wrong length, magic,
/// version, KEM code, AEAD code or chain code.
#[test]
fn r_cr_01_sealed_key_decoder_refuses_what_the_reference_refuses() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_sealed_key_decoder_refuses_what_the_reference_refuses",
        |g: &mut Gen| {
            let ctx = ref_ctx(g);
            let sealed =
                rk::seal_key(kp.public_key(), &[5; 32], &ctx).map_err(|e| e.0.to_owned())?;
            let m = mutate(g, &sealed);
            let reference = rk::decode_sealed_key(&m);
            let got = decode_sealed_key(&m);
            if let Err(e @ fstp_keys::envelope::DecodeError::NotImplemented(_)) = got {
                return Err(decode_err(e));
            }
            prop_assert_eq!(got.is_ok(), reference.is_some(), "on {m:02x?}");
            if let Ok(k) = got {
                prop_assert_eq!(encode_sealed_key(&k).map_err(decode_err)?, m);
            }
            Ok(())
        },
    );
}

/// R-CR-01, ADR-004 test vector plan item 7 (`r_cr_01_sealed_key_moved_context_fails_to_open`):
/// a key production seals fails to open in production under a context
/// with any one field changed, and opens under its own.
#[test]
fn r_cr_01_sealed_key_moved_context_fails_to_open() {
    let sk = hybrid_kem::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_sealed_key_moved_context_fails_to_open",
        |g: &mut Gen| {
            let ctx = prod_ctx(g);
            let field = g.usize_in(0..=5);
            let sealed = prod_seal_key(sk.public(), &[9; 32], &ctx)?;
            prop_assert_eq!(prod_open_key(&sk, &sealed, &ctx)?, [9; 32]);
            prop_assert!(
                prod_open_key(&sk, &sealed, &moved_prod(&ctx, field)).is_err(),
                "opened with field {field} changed"
            );
            Ok(())
        },
    );
}

/// R-CR-01, ADR-004 test vector plan item 4 for sealed keys: production
/// opens every key the reference seals to a production public key.
#[test]
fn r_cr_01_production_opens_what_the_reference_seals() {
    let sk = hybrid_kem::generate().unwrap();
    let pk = sk.public().to_bytes();
    fstp_prop::check(
        "r_cr_01_production_opens_what_the_reference_seals",
        |g: &mut Gen| {
            let ctx = prod_ctx(g);
            let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let probe = prod_open_key(&sk, &[0; SEALED_KEY_LEN], &ctx);
            if let Err(e) = &probe
                && e == ENVELOPE_SEAM
            {
                return Err(e.clone());
            }
            let sealed = rk::seal_key(&pk, &dek, &as_ref_ctx(&ctx)?).map_err(|e| e.0.to_owned())?;
            prop_assert_eq!(prod_open_key(&sk, &sealed, &ctx)?, dek);
            Ok(())
        },
    );
}

/// R-CR-01, ADR-004 test vector plan item 4 for sealed keys: the
/// reference opens every key production seals to a reference public key.
#[test]
fn r_cr_01_reference_opens_what_production_seals() {
    let kp = RefKeyPair::generate().unwrap();
    let pk = HybridPublicKey::from_bytes(kp.public_key()).unwrap();
    fstp_prop::check(
        "r_cr_01_reference_opens_what_production_seals",
        |g: &mut Gen| {
            let ctx = prod_ctx(g);
            let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let sealed = prod_seal_key(&pk, &dek, &ctx)?;
            let opened =
                rk::open_key(&kp, &sealed, &as_ref_ctx(&ctx)?).map_err(|e| e.0.to_owned())?;
            prop_assert_eq!(opened, dek);
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// The backup container (ADR-012).

const KINDS: [(u8, u8); 3] = [
    (KIND_BASE_BACKUP, 4),
    (KIND_WAL_SEGMENT, 4),
    (KIND_KEYSTORE_SNAPSHOT, 3),
];

/// A container header whose data key `dek` is sealed to `kp` through the
/// reference.
fn header(g: &mut Gen, kp: &RefKeyPair, dek: &[u8; 32]) -> Result<RefContainerHeader, String> {
    let (kind, chain) = *g.pick(&KINDS);
    let owner = arr16(g);
    let container = arr16(g);
    let ctx = RefContext {
        owner,
        chain,
        purpose: g.u8(),
        group: arr16(g),
        generation: g.u32(),
        object: container,
    };
    let sealed_key = rk::seal_key(kp.public_key(), dek, &ctx).map_err(|e| e.0.to_owned())?;
    Ok(RefContainerHeader {
        version: 1,
        aead: 1,
        kind,
        chain,
        owner,
        container,
        part: 0,
        chunk_size: CHUNK_SIZE,
        sealed_key,
    })
}

/// Plaintext lengths around the chunk boundary.
fn body_len(g: &mut Gen) -> usize {
    let size = CHUNK_SIZE as usize;
    *g.pick(&[0, 1, 100, size - 1, size, size + 1])
}

/// R-CR-01, ADR-012, reference self-check: a container round-trips, its
/// header names a hybrid FSK1 key on its own chain, and its chunks have
/// one final chunk, the last.
#[test]
fn r_cr_01_reference_container_round_trips() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check("r_cr_01_reference_container_round_trips", |g: &mut Gen| {
        let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
        let h = header(g, &kp, &dek)?;
        let body = vec![0x5a; body_len(g)];
        let bytes = rk::seal_container(&h, &dek, &body).map_err(|e| e.0.to_owned())?;
        let (got, chunks) = rk::decode_container(&bytes).ok_or("decode")?;
        prop_assert_eq!(got.clone(), h);
        prop_assert!(got.key_is_hybrid());
        prop_assert_eq!(chunks.iter().filter(|c| c.last).count(), 1);
        prop_assert!(chunks.last().is_some_and(|c| c.last));
        prop_assert_eq!(rk::open_container(&bytes, &dek), Some(body));
        Ok(())
    });
}

/// R-CR-01 teeth for the reference decoder: a container whose data key
/// is not a hybrid FSK1 key of its chain never decodes.
#[test]
fn r_cr_01_reference_container_refuses_a_key_not_sealed_through_the_hybrid_kem() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_reference_container_refuses_a_key_not_sealed_through_the_hybrid_kem",
        |g: &mut Gen| {
            let dek = [1u8; 32];
            let mut h = header(g, &kp, &dek)?;
            match g.usize_in(0..=2) {
                // The KEM code: a classical or unknown KEM.
                0 => h.sealed_key[6] = g.u8_in(2..=255),
                // The chain code of the key: another chain.
                1 => h.sealed_key[9] = if h.chain == 3 { 4 } else { 3 },
                // No key at all.
                _ => h.sealed_key = vec![0; SEALED_KEY_LEN],
            }
            let bytes = rk::seal_container(&h, &dek, b"x").map_err(|e| e.0.to_owned())?;
            prop_assert!(rk::decode_container(&bytes).is_none());
            Ok(())
        },
    );
}

/// The bytes of one chunk of a container whose header bytes are `hb`,
/// sealed under `dek` with the AAD of ADR-012.
fn chunk_bytes(hb: &[u8], dek: &[u8; 32], index: u64, last: bool, part: &[u8]) -> Vec<u8> {
    let key = fstp_crypto::aead::Key::from_bytes(dek).unwrap();
    let sealed = fstp_crypto::aead::seal(&key, &rk::chunk_aad(hb, index, last), part).unwrap();
    let mut out = vec![u8::from(last)];
    out.extend_from_slice(&u32::try_from(part.len()).unwrap().to_be_bytes());
    out.extend_from_slice(&sealed.nonce);
    out.extend_from_slice(&sealed.body);
    out
}

/// R-CR-01, ADR-012 "Decoder: one spelling only", reference self-check:
/// a plaintext of a whole number of chunks has one spelling, with the
/// last full chunk final. The other spelling, full chunks then an empty
/// final chunk, is refused, although each of its chunks opens under the
/// data key. An empty plaintext is one empty final chunk 0, which
/// decodes.
#[test]
fn r_cr_01_reference_container_refuses_an_empty_final_chunk_after_full_chunks() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_reference_container_refuses_an_empty_final_chunk_after_full_chunks",
        |g: &mut Gen| {
            let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let h = header(g, &kp, &dek)?;
            let full = g.usize_in(1..=2);
            let body = vec![0xa5; full * CHUNK_SIZE as usize];
            let canonical = rk::seal_container(&h, &dek, &body).map_err(|e| e.0.to_owned())?;
            prop_assert_eq!(rk::open_container(&canonical, &dek), Some(body.clone()));
            let hb = h.encode();
            let mut other = hb.clone();
            for (i, part) in body.chunks(CHUNK_SIZE as usize).enumerate() {
                other.extend(chunk_bytes(&hb, &dek, i as u64, false, part));
            }
            other.extend(chunk_bytes(&hb, &dek, full as u64, true, &[]));
            prop_assert!(
                rk::decode_container(&other).is_none(),
                "the second spelling of {full} full chunks decodes"
            );
            let empty = rk::seal_container(&h, &dek, &[]).map_err(|e| e.0.to_owned())?;
            prop_assert_eq!(rk::open_container(&empty, &dek), Some(Vec::new()));
            Ok(())
        },
    );
}

fn backup_err(e: fstp_backup::BackupError) -> String {
    format!("{e}")
}

/// R-CR-01, ADR-012: production decodes every container the reference
/// seals, into the same chunks in order, with the final flag on the last
/// chunk only.
#[test]
fn r_cr_01_backup_container_decoder_matches_reference() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_backup_container_decoder_matches_reference",
        |g: &mut Gen| {
            let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
            let h = header(g, &kp, &dek)?;
            let bytes =
                rk::seal_container(&h, &dek, &vec![7; body_len(g)]).map_err(|e| e.0.to_owned())?;
            let (_, want) = rk::decode_container(&bytes).ok_or("reference decode")?;
            let got = fstp_backup::decode_container(&bytes).map_err(backup_err)?;
            prop_assert_eq!(got.len(), want.len());
            for (i, (c, w)) in got.iter().zip(&want).enumerate() {
                prop_assert_eq!(c.index, i as u64);
                prop_assert_eq!(c.last, w.last);
                prop_assert!(
                    c.sealed
                        .windows(w.body.len())
                        .any(|x| x == w.body.as_slice()),
                    "chunk {i} does not hold the reference ciphertext"
                );
            }
            Ok(())
        },
    );
}

/// The length of the final chunk of a container the reference decodes:
/// its flag, length, nonce and sealed body.
fn final_chunk_len(bytes: &[u8]) -> Result<usize, String> {
    let (_, chunks) = rk::decode_container(bytes).ok_or("reference decode")?;
    let c = chunks.last().ok_or("no chunk")?;
    Ok(1 + 4 + c.nonce.len() + c.body.len())
}

/// A container the decoder of ADR-012 must refuse, built from a valid
/// one, with the name of the mutation. The mutations are the second
/// spelling of a whole number of chunks, a dropped final chunk, a cut
/// inside the final chunk, appended bytes, and a final flag above 1.
fn refused_container(g: &mut Gen, kp: &RefKeyPair) -> Result<(&'static str, Vec<u8>), String> {
    let dek: [u8; 32] = g.bytes(32..=32).try_into().unwrap();
    let h = header(g, kp, &dek)?;
    let size = CHUNK_SIZE as usize;
    let which = g.usize_in(0..=4);
    if which == 0 {
        let full = g.usize_in(1..=2);
        let body = vec![0x3c; full * size];
        let hb = h.encode();
        let mut other = hb.clone();
        for (i, part) in body.chunks(size).enumerate() {
            other.extend(chunk_bytes(&hb, &dek, i as u64, false, part));
        }
        other.extend(chunk_bytes(&hb, &dek, full as u64, true, &[]));
        return Ok(("second spelling", other));
    }
    let body = vec![0x3c; body_len(g)];
    let mut bytes = rk::seal_container(&h, &dek, &body).map_err(|e| e.0.to_owned())?;
    let last = final_chunk_len(&bytes)?;
    let start = bytes.len() - last;
    match which {
        1 => {
            bytes.truncate(start);
            Ok(("dropped final chunk", bytes))
        }
        2 => {
            bytes.truncate(start + g.usize_in(1..=last - 1));
            Ok(("cut final chunk", bytes))
        }
        3 => {
            let extra = g.bytes(1..=16);
            bytes.extend(extra);
            Ok(("appended bytes", bytes))
        }
        _ => {
            bytes[start] = g.u8_in(2..=255);
            Ok(("final flag above 1", bytes))
        }
    }
}

/// R-CR-01, ADR-012 "Decoder: one spelling only ... Bytes after it are
/// refused. A missing final chunk is reported as truncation." Production
/// refuses each container the reference refuses: the second spelling of
/// a whole number of chunks, a dropped or cut final chunk, appended
/// bytes and a final flag above 1. `BackupError` names no truncation
/// yet, so the test checks the refusal and lane W2k adds the variant.
#[test]
fn r_cr_01_backup_container_decoder_refuses_what_the_reference_refuses() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_backup_container_decoder_refuses_what_the_reference_refuses",
        |g: &mut Gen| {
            let (what, bytes) = refused_container(g, &kp)?;
            prop_assert!(
                rk::decode_container(&bytes).is_none(),
                "the reference decoded a container with a {what}"
            );
            let got = fstp_backup::decode_container(&bytes);
            if let Err(e @ fstp_backup::BackupError::NotImplemented(_)) = got {
                return Err(backup_err(e));
            }
            prop_assert!(got.is_err(), "production decoded a container with a {what}");
            Ok(())
        },
    );
}

/// R-CR-01, ADR-012: production refuses a container whose data key is
/// not a hybrid FSK1 key of its chain.
#[test]
fn r_cr_01_backup_container_decoder_refuses_a_key_not_sealed_through_the_hybrid_kem() {
    let kp = RefKeyPair::generate().unwrap();
    fstp_prop::check(
        "r_cr_01_backup_container_decoder_refuses_a_key_not_sealed_through_the_hybrid_kem",
        |g: &mut Gen| {
            let dek = [2u8; 32];
            let mut h = header(g, &kp, &dek)?;
            h.sealed_key[6] = g.u8_in(2..=255);
            let bytes = rk::seal_container(&h, &dek, b"x").map_err(|e| e.0.to_owned())?;
            let got = fstp_backup::decode_container(&bytes);
            if let Err(e @ fstp_backup::BackupError::NotImplemented(_)) = got {
                return Err(backup_err(e));
            }
            prop_assert!(
                got.is_err(),
                "production decoded a container with a non-hybrid key"
            );
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// The real stack.

/// The seam of [`backup_objects`]: the world does not expose the objects
/// its backup agent and keystore snapshots upload. Lanes W2k and W3b add
/// the accessor.
const OBJECTS_SEAM: &str = "fstp_celltest::world::World does not expose the uploaded backup and snapshot objects (lanes W2k and W3b)";

fn backup_objects(world: &World) -> Result<Vec<(String, Vec<u8>)>, String> {
    let _ = world;
    Err(OBJECTS_SEAM.to_owned())
}

/// R-CR-01, T-CR-ATREST: after a base backup, a WAL archive and a
/// keystore snapshot, every object that left the running system is an
/// ADR-012 container whose data key is sealed through the hybrid KEM.
/// Base backups and WAL segments are on the ClusterBackup chain, and
/// keystore snapshots on the CellBackup chain. Each kind is present.
#[test]
fn r_cr_01_backups_and_snapshots_use_the_hybrid_kem() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("{e}"));
    let script = CycleScript {
        steps: [
            "call-cycle",
            "base-backup",
            "wal-archive",
            "keystore-snapshot",
        ]
        .iter()
        .map(|s| (*s).to_owned())
        .collect(),
    };
    if let Err(e) = world.run_cycle(0, &script).result {
        panic!("{e} (NotImplemented)");
    }
    let objects = backup_objects(&world).unwrap_or_else(|e| panic!("{e}"));
    let mut kinds = std::collections::BTreeSet::new();
    let mut bad = Vec::new();
    for (name, bytes) in &objects {
        match rk::decode_container(bytes) {
            Some((h, _)) if KINDS.contains(&(h.kind, h.chain)) && h.key_is_hybrid() => {
                kinds.insert(h.kind);
            }
            Some((h, _)) => bad.push(format!("{name}: kind {} on chain {}", h.kind, h.chain)),
            None => bad.push(format!(
                "{name}: not an ADR-012 container with a hybrid key"
            )),
        }
    }
    assert!(bad.is_empty(), "{bad:#?}");
    assert_eq!(kinds.len(), KINDS.len(), "kinds present: {kinds:?}");
}
