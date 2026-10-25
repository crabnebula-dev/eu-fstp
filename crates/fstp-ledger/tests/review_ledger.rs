//! Review reproducers for the W1b ledger lane (I-23, ADR-007).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_ledger::{AppendError, MemStore, RecordStore, Seq};

/// ADR-007: "A repeated command identifier is refused." A store may refuse
/// an empty batch, or accept it and record its command id. It must not
/// accept the empty batch and then accept the same command id again.
#[test]
fn review_adr007_empty_batch_does_not_free_its_command_id() {
    let mut store: MemStore<u8> = MemStore::new();
    let command = [7u8; 16];
    let first = store.append(Seq::ZERO, 0, command, Vec::new());
    if first.is_err() {
        // Refusing the empty batch keeps the command id unused, which is fine.
        return;
    }
    let head = store.head();
    let second = store.append(head, 0, command, vec![1, 2]);
    assert!(
        matches!(second, Err(AppendError::DuplicateCommand { .. })),
        "command id {command:?} was accepted twice: first {first:?}, then {second:?}"
    );
}
