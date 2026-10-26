//! I-11, machine over the reference driver (design 6.2, test plan row I-11).
//!
//! The setup from genesis publishes call 1 with configuration 1 and call
//! 2 with configuration 2, leaves call 3 unpublished, and drafts PR1 in
//! call 1 and PR2 in call 2. Commands: `Record` findings with random
//! configuration ids, of proposals still in DRAFT (pre-check origin) and
//! submitted, in pinned, unpublished and unknown calls; `Regenerate` with
//! random models, configurations and sets (P-21 NOTE 10); and `Submit`.
//!
//! Each finding command is compared with the reference in both
//! directions, and appends only finding records (I-10). After every step
//! each call holds only findings under the configuration the ghost
//! expects, at most one configuration per call, production holds exactly
//! the reference's findings, and the ledger extends and replays to the
//! state (I-23).

use fstp_domain_testkit::mc::findings_model::PinMachine;
use fstp_prop::{Config, check_machine_with};

/// I-11, R-LA-05, P-21 NOTE 10: only the call's pinned config_id, or its
/// regenerated replacement, is ever stored for the call.
#[test]
fn i11_call_findings_share_pinned_config() {
    let machine = match PinMachine::new() {
        Ok(m) => m,
        Err(e) => panic!("setup from genesis: {e}"),
    };
    check_machine_with(
        "i11_call_findings_share_pinned_config",
        Config::default(),
        &machine,
    );
}
