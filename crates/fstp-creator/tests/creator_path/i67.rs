//! I-67: activating a programme needs approval by a second person who
//! did not build it (M4 design sections 3.2 and 8.4; Q1 and Q2, interim,
//! pending Daniel).
//!
//! The approver checks run before the report, so these tests hold
//! whatever the report shows. They open the draft with the entry a
//! correct `OpenDraft` appends.

use fstp_creator::{CheckId, CreatorCommand, CreatorRefusal, InvitationId, Invitee, Uncleared};
use fstp_domain::id::AccountId;
use fstp_domain::programme::ProgrammeStatus;
use fstp_domain::roles::Role;
use fstp_programme::FieldId;
use fstp_prop::{check, prop_assert, prop_assert_eq};

use crate::harness::{
    ADMINS, Cell, Fail, M1, M2, OUT, P, TA, TB, TC, decode, edit, forged, reference_builders,
};

/// The forged draft with the roster warning acknowledged and activation
/// requested by M1.
fn requested() -> Cell {
    let mut cell = forged();
    cell.acknowledge(M1, CheckId::RosterShort)
        .unwrap_or_else(|f| panic!("{f:?}"));
    cell.request(M1).unwrap_or_else(|f| panic!("{f:?}"));
    cell
}

/// Asserts that the approval by `by` is refused with `want` and appends
/// nothing.
fn refused(cell: &mut Cell, by: AccountId, want: CreatorRefusal) {
    let entries = cell.entries.len();
    assert_eq!(
        cell.approve(by, 950).err(),
        Some(Fail::Creator(want)),
        "approval by {by:?}"
    );
    assert_eq!(cell.entries.len(), entries);
    assert_eq!(cell.status(), Some(ProgrammeStatus::Draft));
}

/// I-67 (Q1): the opener, who also granted the programme manager role,
/// and an admin who acknowledged a warning are builders, so their
/// approvals are refused. The programme manager is no tenant admin. TB,
/// who built nothing, passes the approver checks: the approval is then
/// decided by the report alone.
#[test]
fn i67_approver_who_built_the_draft_is_refused() {
    let mut cell = requested();
    refused(&mut cell, TA, CreatorRefusal::ApproverIsBuilder);
    refused(&mut cell, M1, CreatorRefusal::NotTenantAdmin);
    cell.acknowledge(TC, CheckId::RosterShort)
        .unwrap_or_else(|f| panic!("{f:?}"));
    refused(&mut cell, TC, CreatorRefusal::ApproverIsBuilder);
    let got = cell.approve(TB, 951);
    assert!(
        matches!(
            got,
            Ok(_) | Err(Fail::Creator(CreatorRefusal::Uncleared(_)))
        ),
        "{got:?}"
    );
}

/// I-67 (Q2, T-SOD-SYBIL): TB shares one verified identity with M1, a
/// builder, so TB's approval is refused, though TB's account built
/// nothing.
#[test]
fn i67_sybil_builder_and_approver_refused() {
    let mut cell = requested();
    cell.vault.sybil.insert((TB, M1));
    refused(&mut cell, TB, CreatorRefusal::SameIdentity);
}

/// I-67 (Q2): an approver the vault does not verify is refused, and an
/// unverified builder gives the `BuilderUnverified` failure, which blocks
/// the approval.
#[test]
fn i67_unverified_builder_or_approver_refused() {
    let mut cell = requested();
    cell.vault.unverified.insert(TB);
    refused(&mut cell, TB, CreatorRefusal::ApproverUnverified);
    cell.vault.unverified.clear();
    cell.vault.unverified.insert(M1);
    assert!(
        cell.report(Some(TB))
            .failures()
            .any(|r| r.check == CheckId::BuilderUnverified)
    );
    let entries = cell.entries.len();
    let got = cell.approve(TB, 952);
    assert!(
        matches!(
            got,
            Err(Fail::Creator(
                CreatorRefusal::Uncleared(Uncleared::Failure(_))
                    | CreatorRefusal::BuilderUnverified
            ))
        ),
        "{got:?}"
    );
    assert_eq!(cell.entries.len(), entries);
}

/// One action of the I-67 machine.
#[derive(Clone, Copy, Debug)]
enum Action {
    /// Acknowledge the roster warning.
    Acknowledge(AccountId),
    /// Invite OUT as a call drafter, with this invitation id.
    Invite(AccountId, u128),
    /// Save the FAQ.
    SaveFaq(AccountId),
    /// Grant M2 the programme manager role.
    GrantM2(AccountId),
    /// Request activation.
    Request(AccountId),
}

/// I-67, design 8.4 `i67_approver_is_never_a_builder`: after random
/// creator, policy, grant and acknowledgement actions by the admins and
/// the programme managers, the draft's builder set equals the reference
/// set computed from the raw entries. An approval by an admin in the set
/// is refused as a builder's. An admin outside it is never refused as a
/// builder, and is refused as `SameIdentity` when the vault pairs it
/// with a builder.
#[test]
fn i67_approver_is_never_a_builder() {
    let actors = [TA, TB, TC, M1, M2];
    check("i67_approver_is_never_a_builder", |g| {
        let mut cell = forged();
        let n = g.usize_in(0..=8);
        let mut invitation = 0_u128;
        let mut binding = 10_u128;
        for _ in 0..n {
            let by = *g.pick(&actors);
            let action = match g.u8_in(0..=4) {
                0 => Action::Acknowledge(by),
                1 => {
                    invitation = invitation.saturating_add(1);
                    Action::Invite(by, invitation)
                }
                2 => Action::SaveFaq(by),
                3 => Action::GrantM2(by),
                _ => Action::Request(by),
            };
            g.note("action", &action);
            match action {
                Action::Acknowledge(by) => {
                    let _ = cell.acknowledge(by, CheckId::RosterShort);
                }
                Action::Invite(by, id) => {
                    let cmd = CreatorCommand::Invite {
                        programme: P,
                        invitation: InvitationId::from_raw(id),
                        role: Role::CallDrafter,
                        invitee: Invitee::Account(OUT),
                        organisation: None,
                    };
                    let _ = cell.run(&cmd, by);
                }
                Action::SaveFaq(by) => {
                    let _ = cell.save(by, vec![edit(decode(FieldId::Faq, "\"Synthetic.\""), 4)]);
                }
                Action::GrantM2(by) => {
                    binding = binding.saturating_add(1);
                    let _ = cell.try_grant(by, M2, Role::ProgrammeManager, binding);
                }
                Action::Request(by) => {
                    let _ = cell.request(by);
                }
            }
        }
        let builders = reference_builders(&cell.entries);
        let draft = cell.creator.draft(P).ok_or("the draft is gone")?;
        prop_assert_eq!(draft.builders(), &builders);
        let sybil = g.option(|g| *g.pick(&ADMINS));
        if let (Some(a), Some(b)) = (sybil, builders.iter().next().copied()) {
            cell.vault.sybil.insert((a, b));
        }
        g.note("sybil", &cell.vault.sybil);
        for a in ADMINS {
            let ctx = cell.ctx(a);
            let cmd = cell.approve_command(960);
            let got = cell.decide(&cmd, &ctx);
            let shares = cell.vault.sybil.iter().any(|(x, y)| {
                (*x == a && builders.contains(y)) || (*y == a && builders.contains(x))
            });
            if builders.contains(&a) {
                prop_assert_eq!(got, Err(Fail::Creator(CreatorRefusal::ApproverIsBuilder)));
            } else if shares {
                prop_assert_eq!(got, Err(Fail::Creator(CreatorRefusal::SameIdentity)));
            } else {
                prop_assert!(
                    !matches!(
                        got,
                        Err(Fail::Creator(
                            CreatorRefusal::ApproverIsBuilder | CreatorRefusal::SameIdentity
                        ))
                    ),
                    "{:?} built nothing and is refused as a builder: {:?}",
                    a,
                    got
                );
            }
        }
        Ok(())
    });
}
