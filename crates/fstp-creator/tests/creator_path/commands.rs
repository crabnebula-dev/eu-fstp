//! One test per creator command, in the order a builder runs them, from
//! `OpenDraft` to `ApproveActivation`, then `SaveAsTenantTemplate` (M4
//! design section 3.2; R-PG-01, R-PG-02, R-PG-03 and R-PG-05).

use std::collections::{BTreeMap, BTreeSet};

use fstp_creator::{
    CheckId, CheckSubject, CreatorCommand, CreatorRecord, InvitationId, Invitee, ProbeKind,
    Provenance, StartingPoint, TemplateId, WarningKey, decide_creator,
};
use fstp_domain::Command;
use fstp_domain::id::OrganisationId;
use fstp_domain::policy::PolicyVersion;
use fstp_domain::programme::ProgrammeStatus;
use fstp_domain::record::Record;
use fstp_domain::roles::Role;
use fstp_programme::{
    CompileIds, FieldId, INLINE_TEXT, SUPERSAFE_TEMPLATE, compile, shipped_templates,
};

use crate::harness::{
    Cell, Fail, M1, OUT, P, Rec, TA, TB, V1, adr006, blank_policy, decode, digest, edit,
    expected_open_entry, forged, he, open_draft_command, reference_builders, valid_draft,
};

/// The core `EditPolicy` commands of a creator decision.
fn edit_policies(core: &[Command]) -> Vec<(fstp_domain::id::PolicyVersionId, &PolicyVersion)> {
    core.iter()
        .filter_map(|c| match c {
            Command::EditPolicy { base, version } => Some((*base, version.as_ref())),
            _ => None,
        })
        .collect()
}

/// The decision of `cmd` by `actor` on `cell`, straight from
/// `decide_creator`, with the inputs the engine would pass.
fn decision(
    cell: &mut Cell,
    cmd: &CreatorCommand,
    actor: fstp_domain::id::AccountId,
) -> fstp_creator::CreatorDecision {
    let ctx = cell.ctx(actor);
    let inputs = cell.inputs(cmd, &ctx);
    decide_creator(&cell.core, &cell.creator, cmd, &ctx, &inputs)
        .unwrap_or_else(|r| panic!("{cmd:?} is refused: {r:?} ({r})"))
}

/// R-PG-02 (blank start), D1, I-67 (Q1): `OpenDraft` by a tenant admin
/// records `DraftOpened` and composes one core `CreateProgramme` with the
/// profile-default policy: the blank Horizon Europe spec compiled by
/// `fstp_programme::compile` with the ids the command names. The entry
/// opens a `Draft` programme at revision 1, and the opener is a builder.
#[test]
fn r_pg_02_d1_open_draft_composes_create_programme_with_the_profile_default() {
    let mut cell = Cell::genesis();
    let cmd = open_draft_command();
    let d = decision(&mut cell, &cmd, TA);
    assert_eq!(
        d.records,
        vec![CreatorRecord::DraftOpened {
            programme: P,
            profile: blank_policy().frozen.p53,
            by: TA,
        }]
    );
    assert_eq!(
        d.core,
        vec![Command::CreateProgramme {
            policy: Box::new(blank_policy()),
        }]
    );
    let ctx = cell.ctx(TA);
    let entry = cell.decide(&cmd, &ctx).unwrap_or_else(|f| panic!("{f:?}"));
    assert_eq!(entry, expected_open_entry(&ctx));
    cell.append(&entry, ctx.now);
    assert_eq!(cell.status(), Some(ProgrammeStatus::Draft));
    assert_eq!(cell.policy(), &blank_policy());
    let draft = cell.creator.draft(P).unwrap();
    assert_eq!(draft.head().seq(), 1);
    assert!(draft.builders().contains(&TA));
}

/// R-PG-02 (template start), ADR-007: `ApplyStart` from the shipped
/// SuperSAFE template by the programme manager records `StartApplied` at
/// the head and composes exactly one core `EditPolicy` on the head
/// version. The new version carries the template's policy values and no
/// inline wording, so it can go into a ledger body.
#[test]
fn r_pg_02_adr007_apply_start_from_the_supersafe_template_edits_policy_once() {
    let mut cell = forged();
    let base = cell.head();
    let start = StartingPoint::Template {
        template: TemplateId::from_raw(SUPERSAFE_TEMPLATE.raw()),
        version: 1,
    };
    let cmd = CreatorCommand::ApplyStart {
        programme: P,
        base,
        start: start.clone(),
    };
    let d = decision(&mut cell, &cmd, M1);
    let started: Vec<&CreatorRecord> = d
        .records
        .iter()
        .filter(|r| matches!(r, CreatorRecord::StartApplied { .. }))
        .collect();
    assert_eq!(
        started,
        vec![&CreatorRecord::StartApplied {
            programme: P,
            revision: base,
            start: start.clone(),
            by: M1,
        }]
    );
    let edits = edit_policies(&d.core);
    assert_eq!(edits.len(), 1, "one EditPolicy per start: {:?}", d.core);
    assert_eq!(d.core.len(), 1, "{:?}", d.core);
    let (edit_base, version) = edits[0];
    assert_eq!(edit_base, V1);
    assert_eq!(version.programme, P);
    assert_eq!(version.parent, Some(V1));
    assert_ne!(version.id, V1);
    let template = shipped_templates().unwrap().remove(0);
    let want = compile(
        &template.spec,
        &he(),
        CompileIds::new(P, version.id, Some(V1)),
    )
    .unwrap()
    .policy;
    assert_eq!(version.frozen.p01, want.frozen.p01);
    assert_eq!(version.frozen.p02, want.frozen.p02);
    assert_eq!(version.frozen.p03, want.frozen.p03);
    assert_eq!(version.frozen.p04, want.frozen.p04);
    assert_eq!(version.live.p05, want.live.p05);
    assert!(
        version.frozen.p09.0.iter().all(|k| k.text != INLINE_TEXT),
        "ADR-007: inline P-09 wording reached the ledger body"
    );
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert_eq!(cell.policy().live.p05, want.live.p05);
    let draft = cell.creator.draft(P).unwrap();
    assert_eq!(draft.start(), Some(&start));
    assert!(draft.builders().contains(&M1));
}

/// R-PG-02 (template start): template narrative is never applied
/// silently. `AcceptNarrative` of the programme narrative after a
/// template start records `NarrativeAccepted` at the head and composes no
/// core command, since the narrative is an artefact field.
#[test]
fn r_pg_02_accept_narrative_records_the_template_text_without_a_policy_edit() {
    let mut cell = forged();
    let start = CreatorCommand::ApplyStart {
        programme: P,
        base: cell.head(),
        start: StartingPoint::Template {
            template: TemplateId::from_raw(SUPERSAFE_TEMPLATE.raw()),
            version: 1,
        },
    };
    cell.run(&start, M1)
        .unwrap_or_else(|f| panic!("the template start is refused: {f:?}"));
    let base = cell.head();
    let cmd = CreatorCommand::AcceptNarrative {
        programme: P,
        base,
        field: FieldId::ProgrammeNarrative,
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::NarrativeAccepted {
            programme: P,
            revision: base,
            field: FieldId::ProgrammeNarrative,
            by: M1,
        }]
    );
    assert!(d.core.is_empty(), "{:?}", d.core);
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    let draft = cell.creator.draft(P).unwrap();
    assert!(draft.narratives().contains(&FieldId::ProgrammeNarrative));
}

/// R-PG-01, I-50, I-51: `SaveFields` of P-05, P-58 and the action acronym
/// by the programme manager records one `FieldsSaved` with each digest
/// and manual provenance, and composes exactly one core `EditPolicy` on
/// the head. The new head carries the saved P-05 and P-58, so a Guide
/// reading the policy binds the saved values.
#[test]
fn r_pg_01_i50_i51_save_fields_composes_one_edit_policy_with_the_saved_values() {
    let mut cell = forged();
    let base = cell.head();
    let fields = vec![
        edit(
            decode(FieldId::P05, &format!("\"{}\"", adr006(30_000_000))),
            2,
        ),
        edit(
            decode(FieldId::P58, &format!("\"{}\"", adr006(40_000_000))),
            2,
        ),
        edit(decode(FieldId::ActionAcronym, "\"SYNTH\""), 2),
    ];
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base,
        fields,
    };
    let d = decision(&mut cell, &cmd, M1);
    let [
        CreatorRecord::FieldsSaved {
            programme,
            revision,
            fields: saved,
            by,
        },
    ] = d.records.as_slice()
    else {
        panic!("expected one FieldsSaved, got {:?}", d.records);
    };
    assert_eq!((*programme, *revision, *by), (P, base, M1));
    let saved: BTreeMap<FieldId, _> = saved
        .iter()
        .map(|(f, dg, p)| (*f, (*dg, p.clone())))
        .collect();
    let want: BTreeMap<FieldId, _> = [FieldId::P05, FieldId::P58, FieldId::ActionAcronym]
        .into_iter()
        .map(|f| (f, (digest(f, 2), Provenance::Manual)))
        .collect();
    assert_eq!(saved, want);
    let edits = edit_policies(&d.core);
    assert_eq!(d.core.len(), 1, "{:?}", d.core);
    let (edit_base, version) = edits[0];
    assert_eq!(edit_base, V1);
    assert_eq!(version.parent, Some(V1));
    assert_eq!(version.live.p05.amount().to_string(), adr006(30_000_000));
    assert_eq!(
        version.live.p58.map(|a| a.amount().to_string()),
        Some(adr006(40_000_000))
    );
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert_eq!(
        cell.policy().live.p05.amount().to_string(),
        adr006(30_000_000)
    );
    let draft = cell.creator.draft(P).unwrap();
    for (f, v) in want {
        assert_eq!(draft.fields().get(&f), Some(&v), "{}", f.key());
    }
    assert!(draft.builders().contains(&M1));
}

/// R-PG-01: a save that touches only artefact fields records
/// `FieldsSaved` and composes no core command (design 3.2).
#[test]
fn r_pg_01_artefact_only_save_composes_no_policy_edit() {
    let mut cell = forged();
    let base = cell.head();
    let cmd = CreatorCommand::SaveFields {
        programme: P,
        base,
        fields: vec![edit(decode(FieldId::Faq, "\"Synthetic FAQ.\""), 3)],
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::FieldsSaved {
            programme: P,
            revision: base,
            fields: vec![(FieldId::Faq, digest(FieldId::Faq, 3), Provenance::Manual)],
            by: M1,
        }]
    );
    assert!(d.core.is_empty(), "{:?}", d.core);
}

/// R-PG-01 (creator step 9): `Invite` by the programme manager records
/// the invitation and composes no core command. The inviter is a builder
/// (Q1).
#[test]
fn r_pg_01_invite_records_the_invitation() {
    let mut cell = forged();
    let cmd = CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(1),
        role: Role::CommitteeMember,
        invitee: Invitee::Account(OUT),
        organisation: Some(OrganisationId::from_raw(1)),
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::InvitationRecorded {
            programme: P,
            invitation: InvitationId::from_raw(1),
            role: Role::CommitteeMember,
            invitee: Invitee::Account(OUT),
            organisation: Some(OrganisationId::from_raw(1)),
            by: M1,
        }]
    );
    assert!(d.core.is_empty());
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(
        cell.creator
            .draft(P)
            .unwrap()
            .invitations()
            .contains_key(&InvitationId::from_raw(1))
    );
}

/// R-PG-01 (creator step 9): `WithdrawInvitation` records the withdrawal,
/// and the withdrawn invitation is no longer live.
#[test]
fn r_pg_01_withdraw_invitation_records_the_withdrawal() {
    let mut cell = forged();
    let invite = CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(1),
        role: Role::CallDrafter,
        invitee: Invitee::Account(OUT),
        organisation: None,
    };
    cell.run(&invite, M1).unwrap_or_else(|f| panic!("{f:?}"));
    let cmd = CreatorCommand::WithdrawInvitation {
        programme: P,
        invitation: InvitationId::from_raw(1),
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::InvitationWithdrawn {
            programme: P,
            invitation: InvitationId::from_raw(1),
            by: M1,
        }]
    );
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert_eq!(cell.creator.draft(P).unwrap().live_invitations().count(), 0);
}

/// I-66 (reading R5): `AcknowledgeWarning` of a warning the report shows
/// records the acknowledgement at the head revision, and the
/// acknowledgement is live.
#[test]
fn i66_acknowledge_warning_binds_to_the_head_revision() {
    let mut cell = forged();
    let head = cell.head();
    let key = WarningKey {
        check: CheckId::RosterShort,
        subject: CheckSubject::Draft,
    };
    assert!(cell.report(None).results().iter().any(|r| r.key() == key));
    let cmd = CreatorCommand::AcknowledgeWarning {
        programme: P,
        revision: head,
        warning: key.clone(),
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::WarningAcknowledged {
            programme: P,
            revision: head,
            warning: key.clone(),
            by: M1,
        }]
    );
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(cell.creator.draft(P).unwrap().ack_live(&key));
}

/// I-66 (reading R6): `RequestActivation` records the request at the head
/// with the fingerprint of the report at that revision, and the request
/// is live.
#[test]
fn i66_request_activation_records_the_report_at_the_head() {
    let mut cell = forged();
    let head = cell.head();
    let report = cell.report(None).digest();
    let cmd = CreatorCommand::RequestActivation {
        programme: P,
        revision: head,
    };
    let d = decision(&mut cell, &cmd, M1);
    assert_eq!(
        d.records,
        vec![CreatorRecord::ActivationRequested {
            programme: P,
            revision: head,
            report,
            by: M1,
        }]
    );
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(cell.creator.draft(P).unwrap().request_live());
}

/// R-PG-03, I-66, I-67: the builder path of the demo. TA opens the draft,
/// M1 saves every field of the synthetic spec, acknowledges the roster
/// warning and requests activation, and TB, a tenant admin who built
/// nothing, approves.
///
/// The Guide checks run over the real Guide API and the approved-wording
/// profile, so the report is clean. The entry records every probe, the
/// approval and the core activation, and the programme is active with TA
/// and M1 as its builders.
#[test]
fn r_pg_03_i66_i67_second_admin_approves_the_valid_synthetic_draft() {
    let mut cell = valid_draft();
    cell.request(M1).unwrap_or_else(|f| panic!("{f:?}"));
    let entries = cell.entries.len();
    let failures: BTreeSet<CheckId> = cell.report(Some(TB)).failures().map(|r| r.check).collect();
    assert!(failures.is_empty(), "{failures:?}");
    let got = cell.approve(TB, 900);
    let entry = got.unwrap_or_else(|f| panic!("the clean approval is refused: {f:?}"));
    let probes: Vec<ProbeKind> = entry
        .iter()
        .filter_map(|r| match r {
            Rec::Creator(CreatorRecord::ProbeRecorded { probe, .. }) => Some(*probe),
            _ => None,
        })
        .collect();
    assert_eq!(probes, ProbeKind::ALL.to_vec());
    let approvals: Vec<_> = entry
        .iter()
        .filter_map(|r| match r {
            Rec::Creator(CreatorRecord::ActivationApproved(a)) => Some(a),
            _ => None,
        })
        .collect();
    let [a] = approvals.as_slice() else {
        panic!("expected one approval: {entry:?}");
    };
    assert_eq!(a.approver(), TB);
    let builders = reference_builders(&cell.entries[..entries]);
    assert_eq!(a.builders(), &builders);
    assert!(builders.contains(&TA) && builders.contains(&M1) && !builders.contains(&TB));
    let activated = entry.iter().any(|r| {
        matches!(r, Rec::Core(Record::ProgrammeActivated(pa))
            if pa.programme() == P && pa.approver() == TB && pa.revision() == a.revision().seq())
    });
    assert!(activated, "{entry:?}");
    assert_eq!(cell.status(), Some(ProgrammeStatus::Active));
}

/// R-PG-05 (tenant-private templates, Q17): `SaveAsTenantTemplate` by the
/// programme manager records one `TemplateSaved` for the draft and
/// composes no core command. The template id is then taken.
#[test]
fn r_pg_05_save_as_tenant_template_records_one_template() {
    let mut cell = forged();
    let template = TemplateId::from_raw(500);
    let cmd = CreatorCommand::SaveAsTenantTemplate {
        programme: P,
        template,
    };
    let d = decision(&mut cell, &cmd, M1);
    let [
        CreatorRecord::TemplateSaved {
            template: t,
            programme,
            by,
            ..
        },
    ] = d.records.as_slice()
    else {
        panic!("expected one TemplateSaved, got {:?}", d.records);
    };
    assert_eq!((*t, *programme, *by), (template, P, M1));
    assert!(d.core.is_empty(), "{:?}", d.core);
    cell.run(&cmd, M1).unwrap_or_else(|f| panic!("{f:?}"));
    assert!(cell.creator.template_taken(template));
    assert_eq!(
        cell.run(&cmd, M1).err(),
        Some(Fail::Creator(fstp_creator::CreatorRefusal::TemplateExists))
    );
}

/// R-PG-01, TH-49: `draft_view` reads the draft spec and the template
/// narratives that wait for `AcceptNarrative`. After a SuperSAFE template
/// start, the programme narrative is a gap in the spec and appears among
/// the pending narratives with the template text. Once accepted, it leaves
/// the pending narratives and the spec holds the text.
#[test]
fn r_pg_01_th49_draft_view_reads_the_spec_and_the_pending_narratives() {
    let mut cell = forged();
    let start = CreatorCommand::ApplyStart {
        programme: P,
        base: cell.head(),
        start: StartingPoint::Template {
            template: TemplateId::from_raw(SUPERSAFE_TEMPLATE.raw()),
            version: 1,
        },
    };
    cell.run(&start, M1)
        .unwrap_or_else(|f| panic!("the template start is refused: {f:?}"));
    let template = shipped_templates().unwrap().remove(0);
    let want = match template.spec.get(FieldId::ProgrammeNarrative).as_set() {
        Some(fstp_programme::FieldValue::ProgrammeNarrative(
            fstp_programme::Narrative::Inline(t),
        )) => t.clone(),
        other => panic!("the template narrative is {other:?}"),
    };
    let key = FieldId::ProgrammeNarrative.key();
    let spec_of = |cell: &Cell| {
        let view = fstp_creator::draft_view(&cell.core, &cell.creator, P)
            .unwrap_or_else(|| panic!("no view of the draft"));
        let text = view.spec.to_canonical().unwrap();
        (view, fstp_programme::decode_spec(text.as_bytes()).unwrap())
    };
    let (view, spec) = spec_of(&cell);
    assert_eq!(view.pending_narratives.get(&key), Some(&want));
    assert!(spec.get(FieldId::ProgrammeNarrative).as_set().is_none());
    let accept = CreatorCommand::AcceptNarrative {
        programme: P,
        base: cell.head(),
        field: FieldId::ProgrammeNarrative,
    };
    cell.run(&accept, M1).unwrap_or_else(|f| panic!("{f:?}"));
    let (view, spec) = spec_of(&cell);
    assert!(!view.pending_narratives.contains_key(&key));
    assert!(spec.get(FieldId::ProgrammeNarrative).as_set().is_some());
    let other = fstp_domain::id::ProgrammeId::from_raw(P.raw().wrapping_add(1));
    assert_eq!(
        fstp_creator::draft_view(&cell.core, &cell.creator, other),
        None
    );
}
