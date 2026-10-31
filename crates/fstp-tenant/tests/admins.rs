//! The tenant admin set and the two-admin rule (SoD-07, Q31, R-LG-03,
//! I-85; M4 design sections 3.5, 3.6 and 13, lane W2d).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use fstp_domain::Via;
use fstp_domain::id::{LlmConfigId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_prop::{check, check_machine, prop_assert, prop_assert_eq};

use common::gens::{self, Focus, add_admin, test_env};
use common::machine::TenantMachine;
use common::prod::{self, Sut};
use common::reference::{Reference, setting_valid};
use common::setup;
use common::vocab::{Approval, Grant, Op, PaymentMode, Setting, Step, StepInput, Verdict, acct};

/// SoD-07, Q31 A (interim, pending Daniel): the admin set lives in the
/// cell ledger. Random invitations, acceptances and self-grant approvals,
/// with every other tenant operation, follow the reference. A fold of the
/// records alone gives the same admin set and approvals.
#[test]
fn sod07_q31_admin_set_follows_the_reference_and_replays() {
    check_machine(
        "sod07_q31_admin_set_follows_the_reference_and_replays",
        &TenantMachine {
            env: test_env(),
            focus: Focus::Admins,
            max: 32,
        },
    );
}

/// SoD-07, TH-05: "A tenant admin granting a role to their own account requires
/// approval by a second tenant admin." An approval is accepted only
/// in one case. A tenant admin approves the self-grant of a different
/// tenant admin (per account, NOTE 3). An accepted approval names its approver and
/// grant, and its id cannot be used again.
#[test]
fn sod07_self_grant_needs_second_admin_approval() {
    check("sod07_self_grant_needs_second_admin_approval", |g| {
        let env = test_env();
        let mut sut = setup(&env, &add_admin(acct(1), acct(2), 1))?;
        let pool = [acct(1), acct(2), acct(3)];
        let approver = *g.pick(&pool);
        let grant = Grant {
            grantee: *g.pick(&pool),
            programme: ProgrammeId::from_raw(1),
            role: *g.pick(&Role::ALL),
        };
        let op = Op::ApproveSelfGrant {
            actor: approver,
            via: Via::Web,
            approval: 7,
            grant,
        };
        let admins = [acct(1), acct(2)];
        let want = admins.contains(&approver)
            && admins.contains(&grant.grantee)
            && approver != grant.grantee;
        let o = sut.run(&op).map_err(|e| e.to_string())?;
        prop_assert_eq!(o.verdict == Verdict::Accepted, want);
        let seen = sut.observe().map_err(|e| e.to_string())?;
        if want {
            prop_assert_eq!(
                seen.approvals.get(&7).copied(),
                Some(Approval {
                    approver,
                    grant,
                    used: false,
                })
            );
            let again = sut.run(&op).map_err(|e| e.to_string())?;
            prop_assert_eq!(again.verdict, Verdict::Refused);
        } else {
            prop_assert!(o.records.is_empty());
            prop_assert!(seen.approvals.is_empty());
        }
        Ok(())
    });
}

/// SoD-07, Q31: an account outside the admin set issues no tenant command.
/// Each refusal appends nothing and leaves the projection unchanged.
#[test]
fn sod07_q31_non_admin_issues_no_tenant_command() {
    check("sod07_q31_non_admin_issues_no_tenant_command", |g| {
        let env = test_env();
        let mut sut = setup(&env, &add_admin(acct(1), acct(2), 1))?;
        let outsider = *g.pick(&[acct(3), acct(4), acct(5)]);
        let step = *g.pick(&Step::ALL);
        let op = match g.u8_in(0..=5) {
            0 => Op::SaveStep {
                actor: outsider,
                step,
                input: gens::step_input(g, step),
            },
            1 => Op::InviteAdmin {
                actor: outsider,
                via: Via::Web,
                invitation: 9,
                invitee: acct(4),
            },
            2 => Op::ApproveSelfGrant {
                actor: outsider,
                via: Via::Web,
                approval: 9,
                grant: Grant {
                    grantee: acct(1),
                    programme: ProgrammeId::from_raw(1),
                    role: Role::ProgrammeManager,
                },
            },
            3 => Op::SetSetting {
                actor: outsider,
                via: Via::Web,
                setting: Setting::P20(PaymentMode::RecordOnly),
            },
            4 => Op::RecordInference {
                actor: outsider,
                config: LlmConfigId::from_raw(9),
                primary: "model-a".to_string(),
                fallbacks: Vec::new(),
            },
            _ => Op::Complete { actor: outsider },
        };
        g.note("op", &op);
        let before = sut.observe().map_err(|e| e.to_string())?;
        let o = sut.run(&op).map_err(|e| e.to_string())?;
        prop_assert_eq!(o.verdict, Verdict::Refused);
        prop_assert!(o.records.is_empty());
        prop_assert_eq!(sut.observe().map_err(|e| e.to_string())?, before);
        Ok(())
    });
}

/// SoD-07, Q31: an admin invitation adds exactly one admin, its invitee.
/// It cannot be taken twice, an unknown invitation adds nobody, and a
/// current admin or another account cannot take it.
#[test]
fn sod07_q31_admin_invitation_is_taken_once() {
    let env = test_env();
    let run = || -> Result<Vec<Verdict>, String> {
        let mut sut = Sut::genesis(&env).map_err(|e| e.to_string())?;
        let accept = |account, invitation| Op::AcceptAdminInvitation {
            account,
            via: Via::Web,
            invitation,
        };
        let ops = [
            Op::InviteAdmin {
                actor: acct(1),
                via: Via::Web,
                invitation: 1,
                invitee: acct(2),
            },
            accept(acct(1), 1),
            accept(acct(3), 1),
            accept(acct(2), 2),
            accept(acct(2), 1),
            accept(acct(3), 1),
        ];
        let mut out = Vec::new();
        for op in &ops {
            out.push(sut.run(op).map_err(|e| e.to_string())?.verdict);
        }
        let admins = sut.observe().map_err(|e| e.to_string())?.admins;
        if admins != [acct(1), acct(2)].into_iter().collect() {
            return Err(format!("admin set {admins:?}"));
        }
        Ok(out)
    };
    use Verdict::{Accepted, Refused};
    assert_eq!(
        run(),
        Ok(vec![Accepted, Refused, Refused, Refused, Accepted, Refused])
    );
}

/// R-LG-03, I-78: inviting an admin grants tenant admin, and each tenant
/// setting change is its own high-risk operation (design 3.5, and
/// `STRICT_EXTRA_HIGH_RISK` beyond P-70). A SoD-07 approval is high-risk
/// too (M3 `STRICT_ADDITIONS`). So each needs a fresh step-up.
#[test]
fn r_lg_03_tenant_settings_need_step_up() {
    let mut ops = vec![
        Op::InviteAdmin {
            actor: acct(1),
            via: Via::Web,
            invitation: 1,
            invitee: acct(2),
        },
        Op::ApproveSelfGrant {
            actor: acct(2),
            via: Via::Web,
            approval: 1,
            grant: Grant {
                grantee: acct(1),
                programme: ProgrammeId::from_raw(1),
                role: Role::ProgrammeManager,
            },
        },
    ];
    for setting in sample_settings() {
        ops.push(Op::SetSetting {
            actor: acct(1),
            via: Via::Web,
            setting,
        });
    }
    for op in &ops {
        assert_eq!(prod::high_risk(op), Ok(true), "{op:?}");
    }
}

/// One valid value per settable parameter.
fn sample_settings() -> Vec<Setting> {
    let v = vec![
        Setting::P20(PaymentMode::RecordOnly),
        Setting::P69("CC0-1.0".to_string()),
        Setting::P70(
            [
                common::vocab::LoginMethod::Passkey,
                common::vocab::LoginMethod::MagicLink,
            ]
            .into_iter()
            .collect(),
        ),
        Setting::P71 { us: 60_000_000 },
        Setting::P72 {
            idle_us: 600_000_000,
            absolute_us: 3_600_000_000,
        },
        Setting::P74(common::vocab::McpSetting {
            enabled: false,
            roles: None,
            public_tools: true,
        }),
    ];
    assert!(v.iter().all(setting_valid));
    v
}

/// I-85, I-78 (interim, pending Daniel: defence in depth beside
/// `channel_policy`): a high-risk tenant command that arrives through MCP
/// is refused and appends nothing. So are the two web-only commands that
/// complete a grant: taking an admin invitation, whose `AdminAdded`
/// record grants tenant admin, and using a SoD-07 approval. The same
/// command through the web is accepted, so the channel alone causes the
/// refusal.
#[test]
fn i85_tenant_high_risk_commands_refused_via_mcp() {
    check("i85_tenant_high_risk_commands_refused_via_mcp", |g| {
        let env = test_env();
        let mut base = add_admin(acct(1), acct(2), 1).to_vec();
        let setting = valid_setting(g);
        let pick = g.u8_in(0..=4);
        let grant = Grant {
            grantee: acct(1),
            programme: ProgrammeId::from_raw(1),
            role: Role::CallDrafter,
        };
        match pick {
            3 => base.push(Op::InviteAdmin {
                actor: acct(1),
                via: Via::Web,
                invitation: 6,
                invitee: acct(3),
            }),
            4 => base.push(Op::ApproveSelfGrant {
                actor: acct(2),
                via: Via::Web,
                approval: 6,
                grant,
            }),
            _ => {}
        }
        let make = |via: Via| match pick {
            0 => Op::InviteAdmin {
                actor: acct(1),
                via,
                invitation: 5,
                invitee: acct(3),
            },
            1 => Op::ApproveSelfGrant {
                actor: acct(2),
                via,
                approval: 5,
                grant,
            },
            2 => Op::SetSetting {
                actor: acct(1),
                via,
                setting: setting.clone(),
            },
            3 => Op::AcceptAdminInvitation {
                account: acct(3),
                via,
                invitation: 6,
            },
            _ => Op::UseSelfGrantApproval {
                actor: acct(1),
                via,
                approval: 6,
                grant,
            },
        };
        g.note("op", &make(Via::Mcp));
        let mut sut = setup(&env, &base)?;
        let before = sut.observe().map_err(|e| e.to_string())?;
        let mcp = sut.run(&make(Via::Mcp)).map_err(|e| e.to_string())?;
        prop_assert_eq!(mcp.verdict, Verdict::Refused);
        prop_assert!(mcp.records.is_empty());
        prop_assert_eq!(sut.observe().map_err(|e| e.to_string())?, before);
        let web = sut.run(&make(Via::Web)).map_err(|e| e.to_string())?;
        prop_assert_eq!(web.verdict, Verdict::Accepted);
        Ok(())
    });
}

/// A generated setting that passes the reference's value rule.
fn valid_setting(g: &mut fstp_prop::Gen) -> Setting {
    let s = gens::setting(g);
    g.assume(setting_valid(&s));
    s
}

/// Q31: the Administrators step saved with fewer than two admins is not
/// validated, and saving it again after a second admin joins validates
/// it. The admin count is read from the ledger's own set.
#[test]
fn sod07_administrators_step_validates_with_two_admins() {
    let run = || -> Result<(), String> {
        let env = test_env();
        let mut ops = common::gens::walk(acct(1), &Step::ALL);
        let mut sut = setup(&env, &ops)?;
        let seen = sut.observe().map_err(|e| e.to_string())?;
        prop_assert!(!seen.validated.contains(&Step::Administrators));
        ops.clear();
        ops.extend(add_admin(acct(1), acct(2), 1));
        ops.push(Op::SaveStep {
            actor: acct(1),
            step: Step::Administrators,
            input: StepInput::Plain { valid: true },
        });
        for op in &ops {
            let o = sut.run(op).map_err(|e| e.to_string())?;
            prop_assert_eq!(o.verdict, Verdict::Accepted);
        }
        let seen = sut.observe().map_err(|e| e.to_string())?;
        prop_assert!(seen.validated.contains(&Step::Administrators));
        let mut model = Reference::new(&env);
        for op in common::gens::walk(acct(1), &Step::ALL)
            .iter()
            .chain(ops.iter())
        {
            model.apply(op);
        }
        prop_assert_eq!(seen, model.observed());
        Ok(())
    };
    assert_eq!(run(), Ok(()));
}
