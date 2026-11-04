//! The step-up harness of the `fstp-cell` tests (I-78, design sections
//! 5.4 and 8.4).
//!
//! The gate admits a high-risk command only under a step-up the ledger
//! granted: a `StepUpGranted` record for the command's action digest in
//! the caller's own session, within P-71 of its entry instant. The route
//! `POST /auth/stepup` asks for that record after it verified a passkey
//! assertion with user verification. The gate has no admission yet for
//! that route-only command (`fstp_cell_core::gate::ROUTE_ADMISSION_SEAM`),
//! so the engine cannot run it.
//!
//! So a test records the grant into the store before the engine opens
//! it, as the seams1 harness of `fstp-celltest` does
//! (`mc::auth_model::ProdCell::grant_stepup`). The record comes from
//! production's `GrantStepUp` decision (`fstp_cell_core::decide_with_id`)
//! over the state the stored ledger folds to. The test never writes the
//! record itself, so the step-up id is the one production derives. The
//! engine then replays the grant like any other entry.

use fstp_auth::AuthCommand;
use fstp_cell_core::{CellCommand, CellCtx, CellRecord, action_digest};
use fstp_domain::id::AccountId;
use fstp_domain::oracle::Answers;
use fstp_ledger::{MemStore, RecordStore, Seq};

/// The command id of the step-up grant for the command `command_id`: a
/// SHA-256 over a fixed label and `command_id`, so it takes none of the
/// test's own ids.
pub(crate) fn grant_command_id(command_id: [u8; 16]) -> [u8; 16] {
    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-cell-test-stepup-grant-v1");
    h.update(&command_id);
    let d = h.finish();
    let mut out = [0u8; 16];
    out.copy_from_slice(&d[..16]);
    out
}

/// Records, at `at`, the step-up that `actor` asserted in `session` for
/// `cmd` under `command_id`, through production's `GrantStepUp` decision.
/// Returns the step-up id that production derived.
///
/// # Errors
///
/// The decision's refusal, a batch that is not one `StepUpGranted` for
/// this digest and session, or the store's refusal.
pub(crate) fn grant_stepup(
    store: &mut MemStore<CellRecord>,
    session: [u8; 16],
    actor: AccountId,
    cmd: &CellCommand,
    command_id: [u8; 16],
    at: i64,
) -> Result<[u8; 16], String> {
    let mut entries = Vec::new();
    store
        .read(Seq::ZERO, usize::MAX, &mut entries)
        .map_err(|e| format!("the store did not read: {e:?}"))?;
    let state = fstp_cell_core::replay(&entries)
        .map_err(|e| format!("the stored ledger does not fold: {e:?}"))?;
    let digest = action_digest(cmd, command_id);
    let grant = CellCommand::Auth(AuthCommand::GrantStepUp {
        session,
        action_digest: digest,
    });
    let id = grant_command_id(command_id);
    let x = CellCtx { actor, at };
    let batch = fstp_cell_core::decide_with_id(&state, &grant, &x, id, &Answers::new())
        .map_err(|e| format!("GrantStepUp was refused: {e:?}"))?;
    let stepup = match batch.as_slice() {
        [
            CellRecord::Auth(fstp_auth::AuthRecord::StepUpGranted {
                id,
                action_digest: d,
                session: s,
            }),
        ] if *d == digest && *s == session => *id,
        other => {
            return Err(format!(
                "GrantStepUp recorded {other:?}, not one StepUpGranted for its digest and session"
            ));
        }
    };
    let head = RecordStore::head(store);
    RecordStore::append(store, head, at, id, batch)
        .map_err(|e| format!("the grant did not append: {e:?}"))?;
    Ok(stepup)
}
