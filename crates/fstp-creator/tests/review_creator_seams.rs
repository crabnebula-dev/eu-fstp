//! Review reproducers (lane m4creator, step m4cg; M4 design sections 3.1,
//! 3.2 and 3.10). The lane scope asks for `OpenDraft`, `ApplyStart`,
//! `SaveFields`, `AcceptNarrative` and `SaveAsTenantTemplate` over the
//! draft spec, and for the content and profile checks over
//! `fstp_programme::compile` and the Guide API. Each test below is red
//! while the seam refuses and green once the seam is closed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[allow(dead_code)]
#[path = "creator_path/harness.rs"]
mod harness;

use fstp_creator::{
    CheckDetail, CheckId, CheckSubject, CreatorCommand, CreatorRefusal, TemplateId, decide_creator,
};
use fstp_domain::Command;
use fstp_programme::FieldId;

use harness::{Cell, M1, P, TA, adr006, decode, edit, forged, open_draft_command};

fn refusal(
    cell: &mut Cell,
    cmd: &CreatorCommand,
    actor: fstp_domain::id::AccountId,
) -> Option<CreatorRefusal> {
    let ctx = cell.ctx(actor);
    let inputs = cell.inputs(cmd, &ctx);
    decide_creator(&cell.core, &cell.creator, cmd, &ctx, &inputs).err()
}

/// R-PG-02, D1: `OpenDraft` by an attested tenant admin on an empty cell
/// composes one core `CreateProgramme`. Today it refuses with OPEN_SEAM,
/// so no draft can open on the demo path.
#[test]
fn review_r_pg_02_open_draft_is_not_a_seam() {
    let mut cell = Cell::genesis();
    let cmd = open_draft_command();
    let ctx = cell.ctx(TA);
    let inputs = cell.inputs(&cmd, &ctx);
    let d = decide_creator(&cell.core, &cell.creator, &cmd, &ctx, &inputs)
        .unwrap_or_else(|r| panic!("OpenDraft is refused: {r}"));
    assert!(
        d.core
            .iter()
            .any(|c| matches!(c, Command::CreateProgramme { .. })),
        "{:?}",
        d.core
    );
}

/// R-PG-01, I-50: a `SaveFields` of P-05 at or below P-58 by the
/// programme manager is decided, not refused with COMPILE_SEAM.
#[test]
fn review_r_pg_01_save_fields_is_not_a_seam() {
    let mut cell = forged();
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: cell.head(),
        fields: vec![
            edit(decode(FieldId::P05, &format!("\"{}\"", adr006(100_000))), 2),
            edit(decode(FieldId::P58, &format!("\"{}\"", adr006(200_000))), 2),
        ],
    };
    let got = refusal(&mut cell, &cmd, M1);
    assert!(
        !matches!(got, Some(CreatorRefusal::Unavailable(_))),
        "SaveFields still refuses with a seam: {got:?}"
    );
}

/// R-PG-01: an artefact-only save needs no core command, yet it is
/// refused with COMPILE_SEAM today.
#[test]
fn review_r_pg_01_artefact_save_is_not_a_seam() {
    let mut cell = forged();
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: cell.head(),
        fields: vec![edit(decode(FieldId::Faq, "\"Synthetic FAQ.\""), 3)],
    };
    let got = refusal(&mut cell, &cmd, M1);
    assert_eq!(got, None, "an artefact-only save is refused: {got:?}");
}

/// R-PG-05 (Q17): `SaveAsTenantTemplate` by the programme manager is
/// decided, not refused with TEMPLATE_SEAM.
#[test]
fn review_r_pg_05_save_as_template_is_not_a_seam() {
    let mut cell = forged();
    let cmd = CreatorCommand::SaveAsTenantTemplate {
        programme: P,
        template: TemplateId::from_raw(500),
    };
    let got = refusal(&mut cell, &cmd, M1);
    assert_eq!(got, None, "SaveAsTenantTemplate is refused: {got:?}");
}

/// Design 3.2 `LegalWordingPending` (Q6): the check is pure over the
/// profile's wording status, which `fstp_guide::FunderProfile` exposes as
/// `legal_wording_pending`. A profile with approved wording still raises
/// the failure with PROFILE_SEAM, so no draft can ever clear I-66.
#[test]
fn review_q6_approved_wording_raises_no_legal_wording_failure() {
    let cell = forged();
    let profile = cell.env.profile.clone().unwrap();
    assert!(!profile.legal_wording_pending());
    let report = cell.report(None);
    let row = report
        .results()
        .iter()
        .find(|r| r.check == CheckId::LegalWordingPending);
    assert!(row.is_none(), "approved wording still fails: {row:?}");
}

/// Design 3.2 `FieldUnset`: pure over `Compiled::unset`. The opened blank
/// draft leaves fields unset, so the report names each one as a field
/// subject. Today the content checks collapse into one `Unavailable` row
/// on the draft and never read the compiled spec.
#[test]
fn review_field_unset_names_each_unset_field_of_the_blank_draft() {
    let cell = forged();
    let report = cell.report(None);
    let content_unavailable: Vec<_> = report
        .results()
        .iter()
        .filter(|r| {
            matches!(
                r.check,
                CheckId::FieldUnset | CheckId::CallPackageIncomplete
            ) && matches!(r.detail, CheckDetail::Unavailable(_))
        })
        .collect();
    assert!(
        content_unavailable.is_empty(),
        "pure content checks do not run: {content_unavailable:?}"
    );
    assert!(
        report
            .failures()
            .any(|r| r.check == CheckId::FieldUnset && matches!(r.subject, CheckSubject::Field(_))),
        "FieldUnset names no field of the blank draft"
    );
}
