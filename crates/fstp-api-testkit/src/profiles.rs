//! The synthetic legal-wording profile source (design sections 1.3 rule
//! A9b and 3.10).
//!
//! The shipped Horizon Europe Guide keeps its `TODO(legal)` markers until
//! Daniel supplies the approved wording, so `LegalWordingPending` fails
//! every report in production (Q6). The end-to-end cell and the fake
//! cell load this variant instead. It is the shipped template with each
//! marker line replaced by a line that reads "SYNTHETIC TEST WORDING. NOT
//! LEGAL TEXT." It holds no legal text.
//!
//! The files live in `profiles/synthetic-wording/` of this crate, never
//! in `fstp-guide` (rule A9b). They reach `fstp-guide` only through this
//! testkit implementation of `fstp_guide::ProfileSource`, and only the
//! test binary `fstp-e2e-cell` and the fakes use it (rule A9).
//!
//! Status: lane m4wire, in place of the W0 stub of lane W2c.

use fstp_guide::{FunderProfile, HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource};

use crate::NotImplemented;

/// The text every synthetic wording line starts with. A release check
/// scans the shipped profiles and the cell binary for it (rule A9b).
pub const SYNTHETIC_MARKER: &str = "SYNTHETIC TEST WORDING";

/// The synthetic Horizon Europe Guide template, version 1.
const HORIZON_EUROPE_GUIDE_V1: &[u8] =
    include_bytes!("../profiles/synthetic-wording/horizon-europe/guide.v1.md");

/// The testkit implementation of `fstp_guide::ProfileSource` over the
/// synthetic wording files.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct SyntheticProfiles {
    _private: (),
}

impl ProfileSource for SyntheticProfiles {
    fn files(&self, name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        match name {
            HORIZON_EUROPE => Ok(ProfileFiles {
                guide: HORIZON_EUROPE_GUIDE_V1,
            }),
            _ => Err(ProfileError::UnknownProfile),
        }
    }
}

/// Builds the `SyntheticProfiles`.
pub fn synthetic_profiles() -> Result<SyntheticProfiles, NotImplemented> {
    Ok(SyntheticProfiles::default())
}

/// The heading of the required section "Contact and FAQ" in the Horizon
/// Europe Guide template, which [`SectionGapProfiles`] renames.
pub const GAP_HEADING: &str = "## 15. Contact and FAQ";

/// The heading [`SectionGapProfiles`] writes in place of [`GAP_HEADING`].
/// A renamed heading leaves its section missing (`fstp_guide` sections).
pub const GAP_RENAMED: &str = "## 15. Contact";

/// A profile source whose Guide template lacks one required section, as
/// the test environment seeds `GuideSectionMissing` (I-52; Daniel,
/// 2026-11-15, the I-66 generator gaps: no command, a seeded template, as
/// theme faults are seeded). It holds a test-only template: it reaches
/// `fstp-guide` only through this testkit `ProfileSource` (rule A9b).
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct SectionGapProfiles {
    guide: Vec<u8>,
}

impl SectionGapProfiles {
    /// The template of `base` with [`GAP_HEADING`] renamed, or `None`
    /// when `base` has no such heading.
    pub fn from_profile(base: &FunderProfile) -> Option<SectionGapProfiles> {
        let text = base.guide_template();
        let from = format!("\n{GAP_HEADING}\n");
        if !text.contains(&from) {
            return None;
        }
        let guide = text.replacen(&from, &format!("\n{GAP_RENAMED}\n"), 1);
        Some(SectionGapProfiles {
            guide: guide.into_bytes(),
        })
    }
}

impl ProfileSource for SectionGapProfiles {
    fn files(&self, name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        match name {
            HORIZON_EUROPE => Ok(ProfileFiles { guide: &self.guide }),
            _ => Err(ProfileError::UnknownProfile),
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use fstp_guide::{LEGAL_MARKER, ShippedProfiles, WordingStatus};

    use super::*;

    /// Q6, R-GA-01: the synthetic profile supplies every legal section,
    /// so its wording is not pending, while the shipped one still is.
    #[test]
    fn q6_synthetic_wording_is_supplied_and_shipped_stays_pending() {
        let synthetic = synthetic_profiles()
            .unwrap()
            .profile(HORIZON_EUROPE)
            .unwrap();
        assert!(!synthetic.legal_wording_pending());
        assert!(
            synthetic
                .legal_sections()
                .iter()
                .all(|s| s.status == WordingStatus::Supplied)
        );
        let shipped = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
        assert!(shipped.legal_wording_pending());
    }

    /// A9b, Q6: the synthetic template is the shipped one with exactly the
    /// marker lines replaced, each by a line that carries the synthetic
    /// marker. Nothing else differs.
    #[test]
    fn a9b_synthetic_template_differs_only_at_the_marker_lines() {
        let shipped = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
        let synthetic = synthetic_profiles()
            .unwrap()
            .profile(HORIZON_EUROPE)
            .unwrap();
        let a: Vec<&str> = shipped.guide_template().lines().collect();
        let b: Vec<&str> = synthetic.guide_template().lines().collect();
        assert_eq!(a.len(), b.len());
        let mut replaced = 0;
        for (x, y) in a.iter().zip(&b) {
            if x == y {
                continue;
            }
            assert!(x.starts_with(LEGAL_MARKER), "{x}");
            assert!(y.starts_with(SYNTHETIC_MARKER), "{y}");
            replaced += 1;
        }
        assert_eq!(replaced, 2);
        assert!(!shipped.guide_template().contains(SYNTHETIC_MARKER));
    }

    /// I-52, I-66 (Daniel, 2026-11-15): the seeded template lacks exactly
    /// the section "Contact and FAQ", for the synthetic and the shipped
    /// profile alike.
    #[test]
    fn i52_section_gap_template_lacks_one_required_section() {
        let synthetic = synthetic_profiles()
            .unwrap()
            .profile(HORIZON_EUROPE)
            .unwrap();
        let shipped = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
        for base in [synthetic, shipped] {
            let full = fstp_guide::parse_template(base.guide_template().as_bytes()).unwrap();
            assert!(fstp_guide::missing_sections(&full).is_empty());
            let gap = SectionGapProfiles::from_profile(&base)
                .unwrap()
                .profile(HORIZON_EUROPE)
                .unwrap();
            let t = fstp_guide::parse_template(gap.guide_template().as_bytes()).unwrap();
            assert_eq!(fstp_guide::missing_sections(&t), vec!["Contact and FAQ"]);
        }
    }

    /// A9b: only the profiles `fstp-guide` names exist in the source.
    #[test]
    fn a9b_unknown_profiles_are_refused() {
        assert_eq!(
            synthetic_profiles().unwrap().profile("other"),
            Err(ProfileError::UnknownProfile)
        );
    }
}
