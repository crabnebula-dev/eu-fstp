//! Review reproducer for the legal wording status (Q6, I-66,
//! `guide-for-applicants.md` Rules: "The template marks each one with
//! `TODO(legal)` until then").
//!
//! Every `TODO(legal)` line marks wording still to be approved. The
//! profile reads markers only inside the two hard-coded sections 9 and
//! 11, so a marker anywhere else leaves `legal_wording_pending` false and
//! `LegalWordingPending` passes. The test fails until any marker line in
//! the template keeps the wording pending.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_guide::{HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource};

/// A source over one template text.
struct Over(&'static str);

impl ProfileSource for Over {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// Q6, I-66: a `TODO(legal)` line in section 10 (contract and payments, a
/// grant agreement obligation) keeps the profile's wording pending.
#[test]
fn review_q6_marker_outside_sections_9_and_11_stays_pending() {
    let text = "# Guide\n\n## 9. Financial support to third parties\n\nWorded.\n\n## 10. Contract and payments\n\nTODO(legal): insert the payment obligations of the grant agreement.\n\n## 11. Visibility and publication\n\nWorded.\n";
    let p = Over(text).profile(HORIZON_EUROPE).unwrap();
    assert!(
        p.legal_wording_pending(),
        "Q6: a TODO(legal) line outside sections 9 and 11 was treated as approved wording"
    );
}
