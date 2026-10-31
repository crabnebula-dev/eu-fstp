//! Starting points, held values, templates and the import save (M4 design
//! sections 3.1 to 3.3; R-PG-01, R-PG-02, R-PG-05, I-49, I-65 and
//! ADR-007).

use fstp_creator::{
    CheckDetail, CheckId, CheckSubject, CreatorCommand, CreatorRecord, CreatorRefusal,
    ImportFieldEdit, ImportProposalId, ImportResolution, Provenance, StartingPoint, TemplateId,
    decide_import_save,
};
use fstp_domain::Command;
use fstp_domain::id::{BindingId, ContentDigest, PolicyVersionId, ProgrammeId, TextId, TextRef};
use fstp_domain::roles::Role;
use fstp_programme::{FIELDS, FieldId, FieldKind, SUPERSAFE_TEMPLATE, supersafe_fixture};

use crate::harness::{
    Cell, Fail, M1, P, Rec, TA, V1, adr006, blank_policy, decode, digest, edit, forged, full_save,
    opened, synthetic_spec, value_of,
};

/// A second programme of the cell.
const Q: ProgrammeId = ProgrammeId::from_raw(8);

/// The template start of the shipped SuperSAFE template.
fn supersafe_start() -> StartingPoint {
    StartingPoint::Template {
        template: TemplateId::from_raw(SUPERSAFE_TEMPLATE.raw()),
        version: 1,
    }
}

/// The refusal of `cmd` by `actor`, if it is refused.
fn refusal(
    cell: &mut Cell,
    cmd: &CreatorCommand,
    actor: fstp_domain::id::AccountId,
) -> Option<Fail> {
    cell.run(cmd, actor).err()
}

/// I-65, R-PG-01: the bridge's save of a confirmed import takes the path
/// of a client save. A policy value records one `FieldsSaved` with import
/// provenance and composes one core `EditPolicy` that carries the value.
/// An artefact value composes no core command. Once appended, the value
/// is held, and the field table names the import. A tenant admin without
/// a programme manager binding is refused.
#[test]
fn i65_r_pg_01_import_save_takes_the_path_of_a_client_save() {
    let mut cell = forged();
    let base = cell.head();
    let value = decode(FieldId::P05, &format!("\"{}\"", adr006(30_000_000)));
    let import = ImportFieldEdit {
        field: FieldId::P05,
        value: value.clone(),
        digest: digest(FieldId::P05, 7),
        proposal: ImportProposalId::from_raw(9),
        resolution: ImportResolution::Confirmed,
    };
    let ctx = cell.ctx(TA);
    assert_eq!(
        decide_import_save(&cell.core, &cell.creator, P, base, &import, &ctx).err(),
        Some(CreatorRefusal::NotProgrammeManager)
    );
    let ctx = cell.ctx(M1);
    let d = decide_import_save(&cell.core, &cell.creator, P, base, &import, &ctx)
        .unwrap_or_else(|r| panic!("the import save is refused: {r}"));
    let provenance = Provenance::Import {
        proposal: ImportProposalId::from_raw(9),
        resolution: ImportResolution::Confirmed,
    };
    assert_eq!(
        d.records,
        vec![CreatorRecord::FieldsSaved {
            programme: P,
            revision: base,
            fields: vec![(FieldId::P05, digest(FieldId::P05, 7), provenance.clone())],
            by: M1,
        }]
    );
    let [Command::EditPolicy { base: on, version }] = d.core.as_slice() else {
        panic!("expected one EditPolicy: {:?}", d.core);
    };
    assert_eq!(*on, V1);
    assert_eq!(version.live.p05.amount().to_string(), adr006(30_000_000));
    let entry = cell.compose(&d, &ctx).unwrap_or_else(|f| panic!("{f:?}"));
    cell.append(&entry, ctx.now);
    assert!(cell.creator.hold_import(P, &import));
    assert_eq!(
        cell.policy().live.p05.amount().to_string(),
        adr006(30_000_000)
    );
    assert_eq!(
        cell.creator.draft(P).unwrap().fields().get(&FieldId::P05),
        Some(&(digest(FieldId::P05, 7), provenance))
    );
    let acronym = ImportFieldEdit {
        field: FieldId::ActionAcronym,
        value: decode(FieldId::ActionAcronym, "\"SYNTH\""),
        digest: digest(FieldId::ActionAcronym, 7),
        proposal: ImportProposalId::from_raw(10),
        resolution: ImportResolution::Edited,
    };
    let ctx = cell.ctx(M1);
    let d = decide_import_save(&cell.core, &cell.creator, P, cell.head(), &acronym, &ctx)
        .unwrap_or_else(|r| panic!("the artefact import save is refused: {r}"));
    assert!(d.core.is_empty(), "{:?}", d.core);
}

/// R-PG-02 (clone start), I-19: a clone of a programme of the cell writes
/// the source's head policy as the next version of the draft, under the
/// draft's ids. The clone sets the policy fields the source set and no
/// artefact field.
#[test]
fn r_pg_02_clone_start_copies_the_source_policy() {
    let mut cell = opened();
    let spec = synthetic_spec();
    cell.save(M1, full_save(&spec, None))
        .unwrap_or_else(|f| panic!("{f:?}"));
    let source = cell.policy().clone();
    let open_q = CreatorCommand::OpenDraft {
        programme: Q,
        version: PolicyVersionId::from_raw(80),
        profile: blank_policy().frozen.p53,
    };
    cell.run(&open_q, TA).unwrap_or_else(|f| panic!("{f:?}"));
    cell.run_core(TA, |ctx| Command::GrantRole {
        binding: BindingId::from_raw(2),
        account: M1,
        programme: Q,
        role: Role::ProgrammeManager,
        start: ctx.now,
        second_admin: None,
        confidentiality: Some(TextRef::new(
            TextId::from_raw(50_002),
            ContentDigest::from_bytes([4; 32]),
        )),
        organisation: None,
        end: None,
    })
    .unwrap_or_else(|f| panic!("{f:?}"));
    let cmd = CreatorCommand::ApplyStart {
        programme: Q,
        base: cell.creator.head(Q).unwrap(),
        start: StartingPoint::Clone { source: P },
    };
    let entry = cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(entry.iter().any(|r| matches!(
        r,
        Rec::Creator(CreatorRecord::StartApplied { programme, .. }) if *programme == Q
    )));
    let head = fstp_domain::policy::head(&cell.core, Q).unwrap();
    assert_eq!(head.programme, Q);
    assert_eq!(head.parent, Some(PolicyVersionId::from_raw(80)));
    assert_eq!(head.frozen, source.frozen);
    assert_eq!(head.live, source.live);
    let d = cell.creator.draft(Q).unwrap();
    for f in FIELDS {
        let set = d.set_fields().contains(&f.id);
        assert_eq!(set, f.kind == FieldKind::Policy, "{}", f.id.key());
    }
}

/// R-PG-02 (template start): template narrative waits for the programme
/// manager. After the start the narrative field is a gap. Its acceptance
/// sets it. A field the template leaves unset, a second acceptance and
/// the template's inline P-09 wording cannot be accepted, and none of
/// those refusals appends anything.
#[test]
fn r_pg_02_template_narrative_waits_for_acceptance() {
    let mut cell = forged();
    let start = CreatorCommand::ApplyStart {
        programme: P,
        base: cell.head(),
        start: supersafe_start(),
    };
    cell.run(&start, M1).unwrap_or_else(|f| panic!("{f:?}"));
    let unset = |cell: &Cell, f: FieldId| {
        cell.report(None)
            .failures()
            .any(|r| r.check == CheckId::FieldUnset && r.subject == CheckSubject::Field(f))
    };
    assert!(unset(&cell, FieldId::ProgrammeNarrative));
    assert!(!unset(&cell, FieldId::P01), "the template sets P-01");
    let accept = |cell: &Cell, field| CreatorCommand::AcceptNarrative {
        programme: P,
        base: cell.head(),
        field,
    };
    let entries = cell.entries.len();
    for field in [FieldId::Faq, FieldId::P09] {
        let cmd = accept(&cell, field);
        assert_eq!(
            refusal(&mut cell, &cmd, M1),
            Some(Fail::Creator(CreatorRefusal::NothingToSave)),
            "{}",
            field.key()
        );
    }
    assert_eq!(cell.entries.len(), entries);
    let cmd = accept(&cell, FieldId::ProgrammeNarrative);
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(!unset(&cell, FieldId::ProgrammeNarrative));
    let again = accept(&cell, FieldId::ProgrammeNarrative);
    assert_eq!(
        refusal(&mut cell, &again, M1),
        Some(Fail::Creator(CreatorRefusal::NothingToSave))
    );
}

/// ADR-007: P-09 wording that is still inline cannot reach a ledger body,
/// so a save of it is refused and appends nothing. The same wording
/// stored as a `TextRef` is saved.
#[test]
fn adr007_inline_p09_wording_is_refused() {
    let mut cell = forged();
    let inline = value_of(&supersafe_fixture().unwrap().spec, FieldId::P09);
    let entries = cell.entries.len();
    assert_eq!(
        cell.save(M1, vec![edit(inline, 4)]).err(),
        Some(Fail::Creator(CreatorRefusal::NothingToSave))
    );
    assert_eq!(cell.entries.len(), entries);
    let stored = value_of(&synthetic_spec(), FieldId::P09);
    cell.save(M1, vec![edit(stored, 4)])
        .unwrap_or_else(|f| panic!("{f:?}"));
}

/// R-PG-05 (Q17): a tenant-private template is recorded with a reference
/// to the draft revision it was saved at. It cannot take the id of a
/// shipped template. A start from it refuses with the named template
/// store seam, since the ledger keeps no template spec.
#[test]
fn r_pg_05_tenant_templates_keep_their_ids_and_name_the_store_seam() {
    let mut cell = forged();
    let shipped = CreatorCommand::SaveAsTenantTemplate {
        programme: P,
        template: TemplateId::from_raw(SUPERSAFE_TEMPLATE.raw()),
    };
    assert_eq!(
        refusal(&mut cell, &shipped, M1),
        Some(Fail::Creator(CreatorRefusal::TemplateExists))
    );
    let own = TemplateId::from_raw(500);
    let cmd = CreatorCommand::SaveAsTenantTemplate {
        programme: P,
        template: own,
    };
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    let start = CreatorCommand::ApplyStart {
        programme: P,
        base: cell.head(),
        start: StartingPoint::Template {
            template: own,
            version: 1,
        },
    };
    let got = refusal(&mut cell, &start, M1);
    assert!(
        matches!(got, Some(Fail::Creator(CreatorRefusal::Unavailable(why))) if why.contains("template spec store")),
        "{got:?}"
    );
}

/// I-49, I-66: a saved flow-down list that the shell has not held is
/// unknown, so `FlowDownMissing` fails closed and names the missing held
/// value. Once held, the complete list of the synthetic spec clears it.
#[test]
fn i49_i66_unheld_flow_down_list_fails_closed() {
    let mut cell = opened();
    let fields = full_save(&synthetic_spec(), None);
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base: cell.head(),
        fields: fields.clone(),
    };
    let ctx = cell.ctx(M1);
    let entry = cell.decide(&cmd, &ctx).unwrap_or_else(|f| panic!("{f:?}"));
    cell.append(&entry, ctx.now);
    let flow_down = |cell: &Cell| -> Vec<CheckDetail> {
        cell.report(None)
            .failures()
            .filter(|r| r.check == CheckId::FlowDownMissing)
            .map(|r| r.detail.clone())
            .collect()
    };
    let unheld = flow_down(&cell);
    assert!(
        matches!(unheld.as_slice(), [CheckDetail::Unavailable(why)] if why.contains("held")),
        "{unheld:?}"
    );
    assert!(cell.creator.hold_saved(P, &fields));
    assert_eq!(flow_down(&cell), Vec::new());
}
