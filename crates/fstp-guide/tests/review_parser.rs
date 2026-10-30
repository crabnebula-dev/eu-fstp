//! Review reproducers for the parser-safety lens (TH-26, Q6), over the
//! combined m4creator and m4guide change.
//!
//! Each test fails against the code under review and passes once the
//! defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_guide::{HORIZON_EUROPE, ProfileError, ProfileFiles, ProfileSource};

/// TH-26, I-68: a GFM pipe table needs no leading or trailing bar. A
/// header row `a | b` followed by the delimiter row `:-- | ---` is a
/// table in GFM. The subset holds only `| cell |` tables, so it must
/// refuse this one. The parser reads it as a two-line paragraph instead,
/// so a construct outside the subset is passed through as text.
#[test]
fn review_parser_th26_pipeless_gfm_table_is_refused() {
    for doc in [
        "a | b\n:-- | ---\n",
        "Item | Value\n:---: | ---:\n",
        "a |\n:- |\n",
    ] {
        let parsed = fstp_guide::parse_markdown(doc.as_bytes());
        assert!(
            parsed.is_err(),
            "TH-26: the GFM table {doc:?} was accepted as {:?}",
            parsed.map(|d| d.to_markdown())
        );
    }
}

/// A test source over one template text.
struct Over(&'static str);

impl ProfileSource for Over {
    fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        Ok(ProfileFiles {
            guide: self.0.as_bytes(),
        })
    }
}

/// Q6, I-66: the code span exemption of `TODO(legal)` is meant for the
/// preamble that names the marker. The template header that is never
/// rendered ends at the first thematic break (`fstp_guide::Template`).
/// The exemption runs to the first numbered heading instead. So a
/// backticked marker in a rendered paragraph between `---` and
/// `## 1.` is exempt, and the profile reads as approved.
#[test]
fn review_parser_q6_backticked_marker_after_the_template_header_stays_pending() {
    const TEMPLATE: &str = "# Guide template\n\n\
Sections marked `TODO(legal)` need approved wording.\n\n\
---\n\n\
This rendered paragraph still holds `TODO(legal)` wording.\n\n\
## 1. About {{programme.name}}\n\n\
Text.\n\n\
## 9. Financial support to third parties\n\n\
Approved synthetic text.\n\n\
## 11. Visibility and publication\n\n\
Approved synthetic text.\n";
    // The paragraph with the marker is in the body, after the header.
    assert!(fstp_guide::parse_template(TEMPLATE.as_bytes()).is_ok());
    let p = Over(TEMPLATE).profile(HORIZON_EUROPE).unwrap();
    assert!(
        p.legal_wording_pending(),
        "Q6: a backticked TODO(legal) in rendered text was exempted: {:?}",
        p.legal_sections()
    );
}
