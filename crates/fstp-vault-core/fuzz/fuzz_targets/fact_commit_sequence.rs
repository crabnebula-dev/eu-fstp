//! Fuzz target `fact_commit_sequence` of `fstp-vault-core` (TH-26, H-05,
//! M3 design sections 2.1 and 6.3).
//!
//! Design section 2.1 marks `fstp-vault-core` with a fuzz project, while
//! section 15 names no target for it. W0 takes the stricter reading and
//! adds this sequence target, pending Daniel's answer
//! (`docs/handoff/m3-base.md`). It drives the fact, epoch and commit
//! protocol of NOTE 4 with random step sequences: writes, acknowledgements,
//! queries and release checks.
//!
//! Checks: no step panics; the effective epoch never moves backwards.
//!
//! W0 skeleton. The code under test is a stub that refuses every step with
//! a typed `NotImplemented` error. Until lane W2d lands it, the target
//! checks only that no step panics, that a refusal formats, and that the
//! epoch stays monotonic.

#![no_main]

use fstp_vault_core::{FactWrite, ReleaseClaims, VaultState, ack, ask, release_allowed, write};
use libfuzzer_sys::fuzz_target;

/// Reads a little-endian integer of `N` bytes, or zero past the end.
fn take<const N: usize>(data: &[u8], at: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    for b in &mut out {
        *b = data.get(*at).copied().unwrap_or(0);
        *at = at.saturating_add(1);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let mut s = VaultState::default();
    let mut at = 0usize;
    let mut steps = 0usize;
    while at < data.len() && steps < 256 {
        steps = steps.saturating_add(1);
        let before = s.effective();
        let op = take::<1>(data, &mut at)[0];
        let shown = match op % 4 {
            0 => {
                let kind = u16::from_le_bytes(take::<2>(data, &mut at));
                let len = usize::from(take::<1>(data, &mut at)[0]);
                let end = at.saturating_add(len).min(data.len());
                let body = data.get(at..end).unwrap_or(&[]).to_vec();
                at = end;
                let now = i64::from_le_bytes(take::<8>(data, &mut at));
                format!("{:?}", write(&mut s, FactWrite { kind, body }, now))
            }
            1 => {
                let epoch = u64::from_le_bytes(take::<8>(data, &mut at));
                let seq = u64::from_le_bytes(take::<8>(data, &mut at));
                format!("{:?}", ack(&mut s, epoch, seq))
            }
            2 => format!("{:?}", ask(&s, &[])),
            _ => {
                let len = usize::from(take::<1>(data, &mut at)[0]);
                let end = at.saturating_add(len).min(data.len());
                let ticket = data.get(at..end).unwrap_or(&[]).to_vec();
                at = end;
                let now = i64::from_le_bytes(take::<8>(data, &mut at));
                format!("{:?}", release_allowed(&s, &ReleaseClaims { ticket }, now))
            }
        };
        assert!(!shown.is_empty());
        assert!(
            s.effective() >= before,
            "the effective epoch moved backwards"
        );
    }
});
