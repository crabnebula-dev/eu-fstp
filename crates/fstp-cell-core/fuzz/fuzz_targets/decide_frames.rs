//! The input format and the run of the fuzz target `cell_decide_sequence`
//! (M3 design section 15). The target and the crate's tests share this
//! file, so a seed is checked under the framing the target reads.
//!
//! The input is a sequence of frames. Each frame is a control byte, the
//! actor as a big-endian `u16`, the body length as a big-endian `u16`, and
//! that many bytes of a canonical cell command. A frame cut short ends the
//! input. The length prefix lets a frame carry any command, the long M2
//! setup commands included.
//!
//! The control byte moves the clock forward by its high nibble and gives
//! the answer bits for the command's vault queries.
//!
//! A frame whose body starts with [`ENTRY`] is a ledger entry instead of a
//! command: the rest of its body is a sequence of cell records, each a
//! big-endian `u16` length and that many bytes of a canonical record. The
//! leading entry frames form a stored ledger, and the run starts from its
//! replay. So a seed can start from a ledger the fold accepts, such as one
//! with an active programme, which since D2e no cell command reaches on
//! its own (M4 design section 15.0). A prefix that does not decode or
//! replay ends the input. An entry frame after the first command frame is
//! skipped, since no command decodes from it.

use fstp_cell_core::{
    CellCtx, CellRecord, CellState, apply, decide_with_id, decode_cell_command, decode_cell_record,
    encode_cell_record, queries_with_id, replay,
};
use fstp_domain::id::{AccountId, ContentDigest};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_ledger::{MemStore, RecordStore, Seq};

/// The most frames one input runs.
pub(crate) const MAX_FRAMES: usize = 64;

/// The time of the first frame: the corpus time `T0` of the M2 generators.
const START_AT: i64 = 1_000_000;

/// The first body byte of a ledger entry frame. A canonical command is a
/// JSON object, so no command body starts with it.
pub(crate) const ENTRY: u8 = 0;

/// One frame of the input.
pub(crate) struct Frame<'a> {
    /// The control byte.
    pub(crate) control: u8,
    /// The acting account.
    pub(crate) actor: u16,
    /// The command bytes.
    pub(crate) body: &'a [u8],
}

/// The frames of `data`, up to [`MAX_FRAMES`]. A frame cut short ends them.
pub(crate) fn frames(data: &[u8]) -> Vec<Frame<'_>> {
    let mut out = Vec::new();
    let mut rest = data;
    while out.len() < MAX_FRAMES {
        let Some((head, tail)) = rest.split_first_chunk::<5>() else {
            break;
        };
        let [control, a0, a1, l0, l1] = *head;
        let len = usize::from(u16::from_be_bytes([l0, l1]));
        let Some((body, after)) = tail.split_at_checked(len) else {
            break;
        };
        out.push(Frame {
            control,
            actor: u16::from_be_bytes([a0, a1]),
            body,
        });
        rest = after;
    }
    out
}

/// The records of the body of a ledger entry frame after [`ENTRY`], or
/// `None` if a record is cut short or does not decode.
pub(crate) fn entry_records(mut rest: &[u8]) -> Option<Vec<CellRecord>> {
    let mut out = Vec::new();
    while !rest.is_empty() {
        let (len, tail) = rest.split_first_chunk::<2>()?;
        let (body, after) = tail.split_at_checked(usize::from(u16::from_be_bytes(*len)))?;
        out.push(decode_cell_record(body).ok()?);
        rest = after;
    }
    Some(out)
}

/// The command id of the frame at index `n`.
fn frame_id(n: usize) -> [u8; 16] {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(&u64::try_from(n).unwrap_or(u64::MAX).to_be_bytes());
    id[8] = 0xCD;
    id
}

/// The number of leading ledger entry frames of `data`.
pub(crate) fn prefix_len(data: &[u8]) -> usize {
    frames(data)
        .iter()
        .take_while(|f| f.body.first() == Some(&ENTRY))
        .count()
}

/// The state, store and clock a run starts from.
pub(crate) struct Start {
    /// The replay of the ledger prefix.
    pub(crate) state: CellState,
    /// The ledger prefix.
    pub(crate) store: MemStore<CellRecord>,
    /// The time of the last prefix frame.
    pub(crate) at: i64,
}

/// Appends the leading ledger entry frames of `data` to a fresh store and
/// replays them, or says why it could not.
pub(crate) fn start(data: &[u8]) -> Result<Start, String> {
    let mut store = MemStore::new();
    let mut at = START_AT;
    for (n, frame) in frames(data).iter().enumerate().take(prefix_len(data)) {
        at = at.saturating_add(i64::from(frame.control >> 4));
        let batch = frame
            .body
            .get(1..)
            .and_then(entry_records)
            .ok_or("an entry frame does not decode")?;
        store
            .append(store.head(), at, frame_id(n), batch)
            .map_err(|e| format!("append: {e:?}"))?;
    }
    let mut prefix = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut prefix)
        .map_err(|e| format!("read: {e:?}"))?;
    let state = replay(&prefix).map_err(|e| format!("replay: {e:?}"))?;
    Ok(Start { state, store, at })
}

/// Runs the frames of `data`. The leading ledger entry frames are appended
/// first, and the run starts from their replay. Then each command that
/// decodes is asked, decided, appended and folded. It checks that
/// `queries`, `decide`, `apply` and `replay` never panic, that every
/// decided record reads back from its stored bytes, that every decided
/// batch folds, and that the replay of the whole ledger equals the state
/// folded entry by entry (I-23). It gives the number of command batches
/// decided and appended. The ledger entries of the prefix do not count.
pub(crate) fn run(data: &[u8]) -> usize {
    let all = frames(data);
    let lead = prefix_len(data);
    let Ok(Start {
        mut state,
        mut store,
        mut at,
    }) = start(data)
    else {
        return 0;
    };
    let mut decided = 0usize;
    for (n, frame) in all.into_iter().enumerate().skip(lead) {
        let Ok(cmd) = decode_cell_command(frame.body) else {
            continue;
        };
        at = at.saturating_add(i64::from(frame.control >> 4));
        let ctx = CellCtx {
            actor: AccountId::from_raw(u128::from(frame.actor)),
            at,
        };
        let id = frame_id(n);
        let asked = match queries_with_id(&state, &cmd, &ctx, id) {
            Ok(q) => q,
            Err(e) => {
                assert!(!format!("{e:?}").is_empty());
                continue;
            }
        };
        let epoch = state.engine().epoch();
        let mut answers = Answers::new();
        for (i, q) in asked.into_iter().enumerate() {
            let holds = (frame.control >> (i % 4)) & 1 == 1;
            let accounts = matches!(q, Query::ChangedSince { .. }).then(Default::default);
            answers.insert(
                q,
                Answer {
                    holds,
                    accounts,
                    epoch,
                    digest: ContentDigest::from_bytes([0; 32]),
                },
            );
        }
        let batch = match decide_with_id(&state, &cmd, &ctx, id, &answers) {
            Ok(b) => b,
            Err(e) => {
                assert!(!format!("{e:?}").is_empty());
                continue;
            }
        };
        // `PgRecordStore` keeps canonical text and decodes it on read
        // (design section 5.3), so every decided record must read back.
        for r in &batch {
            let back = decode_cell_record(&encode_cell_record(r));
            assert!(
                back.as_ref() == Ok(r),
                "a decided record does not read back: {:?}",
                back.err()
            );
        }
        let head = store.head();
        if store.append(head, at, id, batch).is_err() {
            continue;
        }
        let mut fresh = Vec::new();
        let from = Seq::from_raw(head.raw().saturating_add(1));
        if store.read(from, usize::MAX, &mut fresh).is_err() {
            return decided;
        }
        for e in &fresh {
            if let Err(err) = apply(&mut state, e) {
                panic!("a decided batch does not fold: {err:?}");
            }
        }
        decided = decided.saturating_add(1);
    }
    let mut all = Vec::new();
    if store.read(Seq::ZERO, usize::MAX, &mut all).is_err() {
        return decided;
    }
    match replay(&all) {
        Ok(whole) => assert_eq!(whole, state, "replay differs from the incremental fold"),
        Err(e) => panic!("replay refused a ledger the fold accepted: {e:?}"),
    }
    decided
}
