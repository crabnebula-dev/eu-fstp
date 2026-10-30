//! I-66: a programme cannot be activated while its validation report
//! shows any failure (M4 design sections 3.2 and 8.4).

use std::collections::BTreeSet;

use fstp_creator::{
    CheckDetail, CheckId, CreatorCommand, CreatorRefusal, InvitationId, Invitee, PreviewOutcome,
    ProbeKind, ProbeOutcome, Severity, Uncleared,
};
use fstp_domain::id::{ContentDigest, OrganisationId, TextId, TextRef};
use fstp_domain::programme::ProgrammeStatus;
use fstp_domain::refusal::RuleRef;
use fstp_domain::roles::Role;
use fstp_programme::{FIELDS, FieldId};
use fstp_prop::{check, prop_assert, prop_assert_eq};

use crate::harness::{
    Cell, Fail, GUIDE_CHECKS, M1, OUT, P, TB, decode, draft_with, edit, guide_works,
    shipped_profile, synthetic_spec, valid_draft,
};

/// I-66, I-51, I-52: on the valid synthetic draft, while the Guide API
/// refuses, the two Guide checks fail closed and name `fstp_guide` as the
/// missing source, and no other check fails. Once the Guide API works,
/// the report shows no failure at all.
#[test]
fn i66_i51_i52_guide_checks_fail_closed_while_the_guide_refuses() {
    let cell = valid_draft();
    let profile = cell.env.profile.clone().unwrap();
    let report = cell.report(Some(TB));
    let failures: Vec<_> = report.failures().collect();
    if guide_works(&profile) {
        assert!(failures.is_empty(), "{failures:?}");
        return;
    }
    let checks: BTreeSet<CheckId> = failures.iter().map(|r| r.check).collect();
    assert_eq!(checks, GUIDE_CHECKS.into_iter().collect(), "{failures:?}");
    for r in failures {
        assert!(
            matches!(r.detail, CheckDetail::Unavailable(why) if why.contains("fstp_guide")),
            "{} fails without naming the Guide API: {:?}",
            r.check.name(),
            r.detail
        );
    }
}

/// One seeded fault of the valid synthetic draft.
#[derive(Clone, Copy, Debug)]
enum Seed {
    /// A field left unset (`FieldUnset`, and `CallPackageIncomplete` for
    /// the I-48 fields).
    Omit(FieldId),
    /// P-57 with its start after its end.
    ActionDatesReversed,
    /// A flow-down list without one obligation (I-49).
    FlowDownShort,
    /// The shipped profile, whose legal wording is pending (Q6).
    WordingPending,
    /// An invited account whose SoD preview refuses.
    InviteeRefused,
    /// An invited account with no SoD preview.
    InviteeUnchecked,
    /// An invitation by contact address, not accepted yet (a warning).
    InviteeWithoutAccount,
    /// One attested tenant admin only (SoD-07).
    OneTenantAdmin,
    /// The vault does not verify M1, a builder (Q2).
    BuilderUnverified,
    /// The vault does not know a P-13 class, or gives no answer (Q35).
    ExclusionUnknown(bool),
    /// No answer on P-38 lists, or a missing list (a warning, Q35).
    ProximityMissing(bool),
    /// No pre-check port while P-23 is enabled (Q38).
    NoPrecheck,
    /// A probe fails or has no prober at approval (Q5).
    Probe(ProbeKind, ProbeOutcome),
    /// The theme lacks a mandatory element (I-69).
    ElementMissing,
    /// A theme pair with no contrast (I-70).
    WeakContrast,
    /// An import proposal still unresolved (Q30).
    ImportUnresolved,
    /// The P-04 maximum above P-05 (an M2 warning).
    P04AboveP05,
    /// P-39 above P-03 (an M2 warning).
    P39AboveP03,
    /// P-77 allowed while score tools exist (a warning).
    AiAct,
}

impl Seed {
    /// The check the seed must raise.
    fn check(self) -> CheckId {
        match self {
            Seed::Omit(_) => CheckId::FieldUnset,
            Seed::ActionDatesReversed => CheckId::ActionDatesInconsistent,
            Seed::FlowDownShort => CheckId::FlowDownMissing,
            Seed::WordingPending => CheckId::LegalWordingPending,
            Seed::InviteeRefused | Seed::InviteeUnchecked => CheckId::InviteeRefused,
            Seed::InviteeWithoutAccount => CheckId::InviteeWithoutAccount,
            Seed::OneTenantAdmin => CheckId::TooFewTenantAdmins,
            Seed::BuilderUnverified => CheckId::BuilderUnverified,
            Seed::ExclusionUnknown(_) => CheckId::ExclusionClassUnknown,
            Seed::ProximityMissing(_) => CheckId::ProximityListMissing,
            Seed::NoPrecheck => CheckId::PrecheckUnavailable,
            Seed::Probe(ProbeKind::Channel, _) => CheckId::ChannelUnreachable,
            Seed::Probe(ProbeKind::SendingDomain, _) => CheckId::SendingDomainUnverified,
            Seed::Probe(ProbeKind::Inference, _) => CheckId::InferenceUnreachable,
            Seed::ElementMissing => CheckId::MandatoryElementMissing,
            Seed::WeakContrast => CheckId::ContrastFailure,
            Seed::ImportUnresolved => CheckId::ImportUnresolved,
            Seed::P04AboveP05 => CheckId::P04MaxAboveP05,
            Seed::P39AboveP03 => CheckId::P39AboveP03,
            Seed::AiAct => CheckId::AiActReassessment,
        }
    }

    /// Every seed but [`Seed::Omit`], which takes a field.
    fn fixed() -> Vec<Seed> {
        let mut out = vec![
            Seed::ActionDatesReversed,
            Seed::FlowDownShort,
            Seed::WordingPending,
            Seed::InviteeRefused,
            Seed::InviteeUnchecked,
            Seed::InviteeWithoutAccount,
            Seed::OneTenantAdmin,
            Seed::BuilderUnverified,
            Seed::ExclusionUnknown(false),
            Seed::ExclusionUnknown(true),
            Seed::ProximityMissing(false),
            Seed::ProximityMissing(true),
            Seed::NoPrecheck,
            Seed::ElementMissing,
            Seed::WeakContrast,
            Seed::ImportUnresolved,
            Seed::P04AboveP05,
            Seed::P39AboveP03,
            Seed::AiAct,
        ];
        for probe in ProbeKind::ALL {
            out.push(Seed::Probe(probe, ProbeOutcome::Fail));
            out.push(Seed::Probe(probe, ProbeOutcome::Absent));
        }
        out
    }

    /// The draft with the seed's content fault, before the roster
    /// acknowledgement.
    fn build(self) -> Cell {
        let mut spec = synthetic_spec();
        let omit = match self {
            Seed::Omit(f) => Some(f),
            _ => None,
        };
        match self {
            Seed::ActionDatesReversed => spec.set(decode(
                FieldId::P57,
                r#"{"end":"2026-01-01","start":"2028-12-31"}"#,
            )),
            Seed::FlowDownShort => spec.set(decode(
                FieldId::FlowDown,
                r#"["conflict_of_interests","confidentiality_and_security","ethics_and_values","visibility_of_eu_funding","specific_rules_for_carrying_out_the_action","information_obligations","record_keeping"]"#,
            )),
            Seed::P04AboveP05 => spec.set(decode(
                FieldId::P04,
                r#"{"max":"500000.00","min":"5000.00"}"#,
            )),
            Seed::P39AboveP03 => spec.set(decode(FieldId::P39, "3")),
            Seed::AiAct => spec.set(decode(FieldId::P77, "\"allowed\"")),
            _ => {}
        }
        draft_with(&spec, omit, |cell| match self {
            Seed::InviteeRefused | Seed::InviteeUnchecked => invite(cell, Invitee::Account(OUT)),
            Seed::InviteeWithoutAccount => invite(
                cell,
                Invitee::Pending {
                    contact: TextRef::new(
                        TextId::from_raw(70_001),
                        ContentDigest::from_bytes([7; 32]),
                    ),
                },
            ),
            _ => {}
        })
    }

    /// The seed's shell or vault fault, applied after the build.
    fn apply_env(self, cell: &mut Cell) {
        match self {
            Seed::WordingPending => cell.env.profile = Some(shipped_profile()),
            Seed::InviteeRefused => {
                cell.env.sod.outcomes.insert(
                    InvitationId::from_raw(1),
                    PreviewOutcome::Refused(RuleRef::Sod06),
                );
            }
            Seed::OneTenantAdmin => cell.env.tenant_admins = [TB].into_iter().collect(),
            Seed::BuilderUnverified => {
                cell.vault.unverified.insert(M1);
            }
            Seed::ExclusionUnknown(none) => {
                cell.env.vault.exclusion_classes_known = if none { None } else { Some(false) }
            }
            Seed::ProximityMissing(none) => {
                cell.env.vault.proximity_lists_declared = if none { None } else { Some(false) }
            }
            Seed::NoPrecheck => cell.env.ports.precheck = false,
            Seed::Probe(probe, outcome) => {
                cell.env.probes = cell.env.probes.clone().with(probe, outcome);
            }
            Seed::ElementMissing => {
                let first = cell.env.theme.elements.iter().next().copied();
                if let Some(e) = first {
                    cell.env.theme.elements.remove(&e);
                }
            }
            Seed::WeakContrast => {
                if let Some(p) = cell.env.theme.pairs.first_mut() {
                    p.text = p.background;
                }
            }
            Seed::ImportUnresolved => cell.env.unresolved_imports = 1,
            Seed::AiAct => cell.env.ports.score_tools = true,
            _ => {}
        }
    }
}

/// Invites `invitee` as a committee member by M1.
fn invite(cell: &mut Cell, invitee: Invitee) {
    let cmd = CreatorCommand::Invite {
        programme: P,
        invitation: InvitationId::from_raw(1),
        role: Role::CommitteeMember,
        invitee,
        organisation: Some(OrganisationId::from_raw(1)),
    };
    cell.run(&cmd, M1)
        .unwrap_or_else(|f| panic!("the invitation is refused: {f:?}"));
}

/// I-66, design 8.4 `i66_seeded_failure_never_activates`: the valid
/// synthetic draft with one seeded fault, from every failure check a
/// draft or its shell can raise and from the warnings left
/// unacknowledged. The report shows the seeded check at its catalogue
/// severity. A requested approval by TB, who built nothing, is refused
/// and names a check the report shows, appends nothing, and the programme
/// stays a draft.
///
/// Not seeded here: `PolicyInvalid` and `CapAboveCeiling`, which the core
/// `EditPolicy` guard keeps out of a saved draft (see the I-50 test), and
/// the Guide checks, which the Guide test covers. `RosterShort` is the
/// acknowledged warning of every case.
#[test]
fn i66_seeded_failure_never_activates() {
    let omittable: Vec<FieldId> = FIELDS
        .iter()
        .map(|f| f.id)
        .filter(|f| *f != FieldId::P53)
        .collect();
    let fixed = Seed::fixed();
    check("i66_seeded_failure_never_activates", |g| {
        let seed = if g.bool() {
            Seed::Omit(*g.pick(&omittable))
        } else {
            *g.pick(&fixed)
        };
        g.note("seed", &seed);
        let mut cell = seed.build();
        seed.apply_env(&mut cell);
        let report = cell.report(Some(TB));
        let seeded = report.results().iter().find(|r| r.check == seed.check());
        prop_assert!(
            seeded.is_some_and(|r| r.severity == seed.check().severity()),
            "the report does not show {} at its severity: {:?}",
            seed.check().name(),
            report.results()
        );
        if let Seed::Omit(f) = seed {
            prop_assert!(
                report.failures().any(|r| r.check == CheckId::FieldUnset
                    && r.subject == fstp_creator::CheckSubject::Field(f)),
                "FieldUnset does not name {}",
                f.key()
            );
        }
        cell.request(M1)
            .map_err(|f| format!("the request is refused: {f:?}"))?;
        let entries = cell.entries.len();
        let got = cell.approve(TB, 902);
        let named = match got {
            Err(Fail::Creator(CreatorRefusal::Uncleared(Uncleared::Failure(c)))) => {
                report.failures().any(|r| r.check == c)
            }
            Err(Fail::Creator(CreatorRefusal::Uncleared(Uncleared::Unacknowledged(c)))) => {
                c.severity() == Severity::Warning && report.warnings().any(|r| r.check == c)
            }
            _ => false,
        };
        prop_assert!(
            named,
            "the approval is not refused naming a shown check: {:?}",
            got
        );
        prop_assert_eq!(cell.entries.len(), entries);
        prop_assert_eq!(cell.status(), Some(ProgrammeStatus::Draft));
        prop_assert!(cell.creator.draft(P).is_some_and(|d| d.active().is_none()));
        Ok(())
    });
}

/// I-66, design 3.2 "Fresh probes": a probe that passes at the request
/// and fails at the approval blocks activation, because the approval
/// reads the probes of its own request.
#[test]
fn i66_probes_run_at_approval() {
    let mut cell = valid_draft();
    cell.request(M1).unwrap_or_else(|f| panic!("{f:?}"));
    let entries = cell.entries.len();
    cell.env.probes = cell
        .env
        .probes
        .clone()
        .with(ProbeKind::Channel, ProbeOutcome::Fail);
    let got = cell.approve(TB, 903);
    assert!(
        matches!(
            got,
            Err(Fail::Creator(CreatorRefusal::Uncleared(
                Uncleared::Failure(_)
            )))
        ),
        "{got:?}"
    );
    assert!(
        cell.report(Some(TB))
            .failures()
            .any(|r| r.check == CheckId::ChannelUnreachable)
    );
    assert_eq!(cell.entries.len(), entries);
}

/// I-66, reading R1: a save after the request voids it, so the approval is
/// refused until the draft is requested again at the new head.
#[test]
fn i66_edit_after_request_voids_it() {
    let mut cell = valid_draft();
    cell.request(M1).unwrap_or_else(|f| panic!("{f:?}"));
    cell.save(
        M1,
        vec![edit(decode(FieldId::Faq, "\"Synthetic FAQ, edited.\""), 9)],
    )
    .unwrap_or_else(|f| panic!("{f:?}"));
    let entries = cell.entries.len();
    assert_eq!(
        cell.approve(TB, 904).err(),
        Some(Fail::Creator(CreatorRefusal::NoLiveRequest))
    );
    assert_eq!(cell.entries.len(), entries);
}
