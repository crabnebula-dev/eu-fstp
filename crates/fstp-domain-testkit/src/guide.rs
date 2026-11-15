//! Synthetic Guide facts for the generators' publications (I-52, R-GA-01,
//! D2e; Daniel's decision of 2026-11-15, "Generators supply a Guide").
//!
//! The engine fold refuses a `CallPublished` whose entry holds no
//! `GuidePublished`, and `execute` refuses a `PublishCall` whose shell
//! supplies no `GuideFacts`. So every publication of a setup or a model
//! step runs through [`crate::activation::run_core`], which decides it
//! with [`SyntheticGuides`].
//!
//! The facts are synthetic:
//!
//! - the template holds every required section and one placeholder,
//!   `programme.name`, so it binds over any generator policy;
//! - the artefacts come from the compiled SuperSAFE fixture. The Guide
//!   reads the frozen and live policy values from the ledger, never from
//!   the fixture;
//! - the addresses use the reserved `.example` names;
//! - the digest is [`synthetic_digest`], a fixed non-cryptographic mix.
//!   It is not SHA-256: an M2 crate never reaches `fstp-crypto`
//!   (`tools/deps-check`, rule 1). Nothing in the generators reads it.

use std::collections::BTreeMap;

use fstp_creator::{CreatorCommand, CreatorInputs};
use fstp_domain::command::Ctx;
use fstp_domain::id::CallId;
use fstp_engine::compose::GuideFacts;
use fstp_engine::{CreatorDecider, CreatorEnvironment, EngineState, NoEnvironment};

/// The synthetic platform address.
pub const SYNTHETIC_PLATFORM_URL: &str = "https://generators.fstp.example/";
/// The synthetic privacy statement address.
pub const SYNTHETIC_PRIVACY_URL: &str = "https://generators.fstp.example/privacy";
/// The synthetic data protection summary. It is not a privacy notice.
pub const SYNTHETIC_SUMMARY: &str =
    "Synthetic data protection summary of the test generators. It is not a privacy notice.";

/// The creator environment of the generators: no creator fact
/// ([`NoEnvironment`]) and the synthetic Guide facts of every
/// publication (module documentation).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SyntheticGuides;

impl CreatorEnvironment for SyntheticGuides {
    fn creator_inputs(
        &self,
        state: &EngineState,
        cmd: &CreatorCommand,
        ctx: &Ctx,
    ) -> CreatorInputs {
        NoEnvironment.creator_inputs(state, cmd, ctx)
    }

    fn guide_facts(&self, state: &EngineState, call: CallId) -> Option<GuideFacts> {
        let programme = fstp_domain::programme::call(&state.core, call)?.programme();
        let head = fstp_domain::policy::head(&state.core, programme)?;
        let fixture = fstp_programme::supersafe_fixture().ok()?;
        let compiled = fstp_programme::compile(
            &fixture.spec,
            &fstp_programme::FunderProfile::horizon_europe(),
            fstp_programme::CompileIds::new(programme, head.id, head.parent),
        )
        .ok()?;
        Some(GuideFacts {
            template: synthetic_template()?,
            compiled: Some(compiled),
            identifier: call.raw().to_string(),
            platform_url: SYNTHETIC_PLATFORM_URL.to_owned(),
            data_protection_summary: SYNTHETIC_SUMMARY.to_owned(),
            privacy_statement_url: SYNTHETIC_PRIVACY_URL.to_owned(),
            texts: BTreeMap::new(),
            digest: synthetic_digest,
            precheck_available: false,
        })
    }
}

/// The synthetic Guide template: a header, then one level 2 heading per
/// required section with one line of synthetic text (I-52).
pub fn synthetic_template() -> Option<fstp_guide::Template> {
    let mut text = String::from("# Synthetic Guide\n\n---\n");
    for s in fstp_guide::REQUIRED_SECTIONS {
        text.push_str("\n## ");
        text.push_str(s.heading);
        text.push_str("\n\nSynthetic text of the test generators.\n");
    }
    fstp_guide::parse_template(text.as_bytes()).ok()
}

/// A fixed 32-byte mix of `bytes`: four FNV-1a lanes with distinct
/// offsets. It is not a cryptographic digest (module documentation).
pub fn synthetic_digest(bytes: &[u8]) -> [u8; 32] {
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut lanes: [u64; 4] = [
        0xcbf2_9ce4_8422_2325,
        0x8422_2325_cbf2_9ce4,
        0x9ce4_8422_2325_cbf2,
        0x2325_cbf2_9ce4_8422,
    ];
    for (i, b) in bytes.iter().enumerate() {
        if let Some(lane) = lanes.get_mut(i & 3) {
            *lane ^= u64::from(*b);
            *lane = lane.wrapping_mul(PRIME);
        }
    }
    let mut out = [0u8; 32];
    for (chunk, lane) in out.chunks_exact_mut(8).zip(lanes) {
        chunk.copy_from_slice(&lane.to_be_bytes());
    }
    out
}

/// The production decider with the synthetic Guide facts: what a model
/// that decides core commands itself uses in place of
/// `fstp_engine::DomainDecider`, so its publications pair (I-52).
pub const GENERATOR_DECIDER: CreatorDecider<SyntheticGuides> = CreatorDecider(SyntheticGuides);
