//! Independent review reproducers, lens "spec semantics and determinism"
//! (lane m4creator and m4guide, step m4cg; M4 design sections 3.1, 3.2
//! and 3.10). Each test fails against the code under review and passes
//! once the defect it names is fixed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[allow(dead_code)]
#[path = "creator_path/harness.rs"]
mod harness;

use fstp_creator::{CheckId, CheckSubject};
use fstp_programme::FieldId;

use harness::{M1, TB, decode, edit, valid_draft};

/// The P-01 value of the fixture with criterion 1 named by a stored text
/// (ADR-007) and criterion 2 named by empty inline text.
fn p01_stored_then_empty() -> fstp_programme::FieldValue {
    let hex: String = std::iter::repeat_n("ab".to_owned(), 32).collect();
    decode(
        FieldId::P01,
        &format!(
            "{{\"criteria\":[\
             {{\"id\":\"1\",\"name\":{{\"digest\":\"{hex}\",\"text\":\"901\"}},\"weight\":30}},\
             {{\"id\":\"2\",\"name\":\"\",\"weight\":40}},\
             {{\"id\":\"3\",\"name\":\"Value for money\",\"weight\":30}}],\
             \"scale_max\":5}}"
        ),
    )
}

/// I-51, I-66: a P-01 criterion with an empty name never resolves in the
/// Guide (`fstp_guide` refuses an empty text). The draft report must show
/// `GuideBindingUnresolved` for `P-01.table` whatever the other names
/// are.
///
/// Defect: the Guide resolver stops at the first criterion name that does
/// not resolve. When that first name is a stored text, the reason is
/// `TEXT_NOT_STORED`, which `fstp_creator::guide::guide_facts` drops as
/// "resolved at publication". The empty second name is never looked at,
/// so the report is clean and the draft activates with a Guide that
/// publication can never generate.
#[test]
fn review_semantics_text_not_stored_hides_an_empty_criterion_name() {
    let mut cell = valid_draft();
    cell.save(M1, vec![edit(p01_stored_then_empty(), 9)])
        .unwrap_or_else(|f| panic!("the P-01 save is refused: {f:?}"));
    let report = cell.report(Some(TB));
    let unresolved = report.failures().any(|r| {
        r.check == CheckId::GuideBindingUnresolved
            && r.subject == CheckSubject::Placeholder("P-01.table".to_owned())
    });
    assert!(
        unresolved,
        "the empty criterion name passes the report: {:?}",
        report.failures().collect::<Vec<_>>()
    );
}
