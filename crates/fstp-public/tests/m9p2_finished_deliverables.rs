//! The finished list shows the accepted deliverables a grantee includes,
//! each with its licence and evidence snapshot (`public-transparency.md`,
//! M9 lane P2; R-PB-01, R-PB-04).
//!
//! The finished page and the `finished` tool answer carry each deliverable
//! once. A grant with none carries no deliverable member, so the M4 tool
//! shapes are unchanged. Licence text is escaped like every other text.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod support;

use fstp_public::tools::select;
use fstp_public::{PublicDeliverable, PublicPage, PublicPart, PublicQuery, render_html};
use support::{chrome, sample_view, scriptless};

/// R-PB-01, R-PB-04: the finished page and tool show each included
/// deliverable's licence and snapshot, escaped, and nothing for a grant
/// with none.
#[test]
fn r_pb_01_finished_list_shows_included_deliverables() {
    let mut view = sample_view(true);
    let snapshot = "ab".repeat(32);
    view.finished[0].deliverables = vec![PublicDeliverable {
        licence: "Apache-2.0 <b>".to_owned(),
        snapshot: snapshot.clone(),
    }];
    let html = render_html(&view, &PublicPage::Finished, &chrome()).unwrap();
    let page = html.as_str();
    scriptless(page).unwrap();
    assert!(page.contains("Accepted deliverables"), "{page}");
    assert!(page.contains(&snapshot), "{page}");
    assert!(
        page.contains("Apache-2.0 &lt;b&gt;"),
        "the licence is escaped: {page}"
    );
    assert!(!page.contains("<b>"), "no markup from a licence: {page}");
    let tool = select(
        &view,
        &PublicQuery {
            part: PublicPart::Finished,
            search: None,
        },
    )
    .unwrap()
    .to_compact();
    assert!(tool.contains("\"deliverables\""), "{tool}");
    assert!(tool.contains(&snapshot), "{tool}");
    let funded = select(
        &view,
        &PublicQuery {
            part: PublicPart::Funded,
            search: None,
        },
    )
    .unwrap()
    .to_compact();
    assert!(!funded.contains("deliverables"), "{funded}");
}
