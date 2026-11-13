//! The creator shell of a world cell (lane F-CYCLE2). Test only.
//!
//! A production cell activates no programme yet (`fstp_cell::shell`): no
//! prober runs, the vault has no Q35 query, and the shipped profiles carry
//! pending legal wording (Q6). A world cell passes [`WorldShell`] through
//! `fstp_cell::process::StartOptions` instead, so the call cycle can run.
//! Claims built on a world cycle say so. Its facts:
//!
//! - Every probe passes. The world runs no mail channel or sending domain
//!   a prober could reach.
//! - Both Q35 answers are yes. The synthetic programmes of the world name
//!   no exclusion class the seeded vault lacks.
//! - The cell has a pre-check provider and no score tools, as the M4 demo
//!   cell has.
//! - The funder profile is the shipped one with each legal marker line
//!   replaced by [`SYNTHETIC_WORDING`], so its wording counts as approved.
//!   Every section and placeholder of the shipped template stays. The
//!   wording is synthetic, never legal text.

use fstp_cell_core::CellState;
use fstp_cell_core::creator::CreatorFacts;
use fstp_creator::{CreatorCommand, PortPresence, ProbeSet};
use fstp_guide::{FunderProfile, ProfileError, ProfileFiles, ProfileSource, ShippedProfiles};

/// The wording a world profile puts where a shipped Guide holds a legal
/// marker. It is not legal text.
pub const SYNTHETIC_WORDING: &str =
    "Synthetic wording of the test world. Not legal text and never shown to a person.";

/// The creator shell of a world cell (module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct WorldShell;

/// One Guide text as a profile source.
struct OneGuide(String);

impl ProfileSource for OneGuide {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// The shipped profile `name` with synthetic wording in place of each
/// legal marker line (module documentation).
pub fn world_profile(name: &str) -> Option<FunderProfile> {
    let shipped = ShippedProfiles.files(name).ok()?;
    let mut out = String::new();
    for line in std::str::from_utf8(shipped.guide).ok()?.lines() {
        if line.starts_with(fstp_guide::LEGAL_MARKER) {
            out.push_str(SYNTHETIC_WORDING);
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    OneGuide(out).profile(name).ok()
}

impl fstp_cell::shell::CreatorShell for WorldShell {
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts {
        let profile = fstp_engine::compose::profile_ref(state.engine(), cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| world_profile(&name));
        CreatorFacts {
            probes: ProbeSet::passing(),
            exclusion_classes_known: Some(true),
            proximity_lists_declared: Some(true),
            ports: PortPresence {
                precheck: true,
                score_tools: false,
            },
            profile,
        }
    }
}
