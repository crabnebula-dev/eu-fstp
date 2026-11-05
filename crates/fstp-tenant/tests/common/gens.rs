//! Generators of the lane W2d tests.
//!
//! Accounts come from a pool of five: `acct(1)` is the first admin of
//! every fixed environment. Ids come from pools of four, so reuse is
//! common and the "used once" rules get exercised.

use std::collections::BTreeSet;

use fstp_domain::Via;
use fstp_domain::id::{AccountId, LlmConfigId, ProgrammeId};
use fstp_domain::roles::Role;
use fstp_prop::Gen;

use super::reference::Reference;
use super::vocab::{
    Env, Grant, INVALID_SPDX, InferenceDefault, LoginMethod, McpSetting, Op, P71_DEFAULT_US,
    P72_ABSOLUTE_DEFAULT_US, P72_IDLE_DEFAULT_US, PaymentMode, Probes, RpMode, Setting, Signatory,
    Step, StepInput, VALID_SPDX, VerifyMethod, acct,
};

/// The account the walks grant both signatory roles to: no tenant admin,
/// not verified (NOTE 5: none is needed) and holding no Receiving
/// binding.
pub const SIGNATORY: AccountId = acct(4);

/// The account pool.
pub const ACCOUNTS: [AccountId; 5] = [acct(1), acct(2), acct(3), acct(4), acct(5)];

/// The model names the generators draw from. The empty name is invalid.
pub const MODELS: [&str; 4] = ["model-a", "model-b", "model-c", ""];

/// The fixed test environment: `acct(1)` is the first admin, accounts 1
/// to 3 are verified, and every probe passes through a recording fake.
/// The control plane recorded the agreements, and `acct(5)` holds a
/// Receiving binding, so it never becomes a tenant admin (SoD-03).
pub fn test_env() -> Env {
    Env {
        first_admin: acct(1),
        verified: [acct(1), acct(2), acct(3)].into_iter().collect(),
        probes: Probes::Fake { pass: true },
        agreements_recorded: true,
        receiving: [acct(5)].into_iter().collect(),
    }
}

/// An account from the pool.
pub fn account(g: &mut Gen) -> AccountId {
    *g.pick(&ACCOUNTS)
}

/// A channel, mostly the web.
pub fn via(g: &mut Gen) -> Via {
    if g.weighted(&[4, 1]) == 0 {
        Via::Web
    } else {
        Via::Mcp
    }
}

/// An id from the pool 1 to 4.
pub fn small_id(g: &mut Gen) -> u128 {
    u128::from(g.u8_in(1..=4))
}

/// A model name from [`MODELS`].
pub fn model(g: &mut Gen) -> String {
    g.pick(&MODELS).to_string()
}

/// A fallback list, often with duplicates or the primary.
pub fn fallbacks(g: &mut Gen) -> Vec<String> {
    g.vec(0..=3, model)
}

/// A P-21 default, valid or not.
pub fn inference_default(g: &mut Gen) -> InferenceDefault {
    let provider = if g.weighted(&[5, 1]) == 0 {
        "synthetic-provider".to_string()
    } else {
        String::new()
    };
    InferenceDefault {
        provider,
        primary: model(g),
        fallbacks: fallbacks(g),
    }
}

/// A P-18 method set, sometimes empty.
pub fn p18(g: &mut Gen) -> BTreeSet<VerifyMethod> {
    let mut s = BTreeSet::new();
    if g.bool() {
        s.insert(VerifyMethod::EudiWallet);
    }
    if g.bool() {
        s.insert(VerifyMethod::DocumentUpload);
    }
    s
}

/// An input of the step's kind. `valid` steers plain steps only.
pub fn step_input(g: &mut Gen, step: Step) -> StepInput {
    match step {
        Step::Identity => StepInput::Identity {
            p18: p18(g),
            p45: *g.pick(&[RpMode::TenantRegistration, RpMode::CrabNebulaIntermediary]),
        },
        Step::Inference => StepInput::Inference(inference_default(g)),
        _ => StepInput::Plain {
            valid: g.weighted(&[5, 1]) == 0,
        },
    }
}

/// An input of the step's kind that passes the step's own checks.
pub fn valid_input(step: Step) -> StepInput {
    match step {
        Step::Identity => StepInput::Identity {
            p18: [VerifyMethod::EudiWallet].into_iter().collect(),
            p45: RpMode::TenantRegistration,
        },
        Step::Inference => StepInput::Inference(super::reference::sample_inference_default()),
        _ => StepInput::Plain { valid: true },
    }
}

/// A login method set, with or without passkeys.
pub fn login_methods(g: &mut Gen) -> BTreeSet<LoginMethod> {
    LoginMethod::ALL.into_iter().filter(|_| g.bool()).collect()
}

/// A microsecond value around `default`: both sides of the bounds, zero,
/// negatives and the extremes.
pub fn micros_around(g: &mut Gen, default: i64) -> i64 {
    match g.weighted(&[6, 1, 1, 1, 1, 1]) {
        0 => g.i64_in(1..=default),
        1 => default,
        2 => default.saturating_add(1),
        3 => 0,
        4 => g.i64_in(i64::MIN..=-1),
        _ => g.i64_in(default..=i64::MAX),
    }
}

/// A P-74 value.
pub fn mcp_setting(g: &mut Gen) -> McpSetting {
    let roles = g.option(|g| Role::ALL.into_iter().filter(|_| g.bool()).collect());
    McpSetting {
        enabled: g.bool(),
        roles,
        public_tools: g.bool(),
    }
}

/// A setting change of any settable parameter, valid or not.
pub fn setting(g: &mut Gen) -> Setting {
    match g.u8_in(0..=5) {
        0 => Setting::P20(*g.pick(&[PaymentMode::RecordOnly, PaymentMode::Execution])),
        1 => {
            if g.weighted(&[3, 1]) == 0 {
                Setting::P69(g.pick(&VALID_SPDX).to_string())
            } else {
                Setting::P69(g.pick(&INVALID_SPDX).to_string())
            }
        }
        2 => Setting::P70(login_methods(g)),
        3 => Setting::P71 {
            us: micros_around(g, P71_DEFAULT_US),
        },
        4 => Setting::P72 {
            idle_us: micros_around(g, P72_IDLE_DEFAULT_US),
            absolute_us: micros_around(g, P72_ABSOLUTE_DEFAULT_US),
        },
        _ => Setting::P74(mcp_setting(g)),
    }
}

/// A self-grant.
pub fn grant(g: &mut Gen) -> Grant {
    Grant {
        grantee: account(g),
        programme: ProgrammeId::from_raw(u128::from(g.u8_in(1..=2))),
        role: *g.pick(&Role::ALL),
    }
}

/// What a machine run concentrates on. Every focus still draws every
/// operation kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Focus {
    /// The onboarding steps and completion.
    Steps,
    /// The admin set and SoD-07 approvals.
    Admins,
    /// The tenant settings.
    Settings,
    /// The inference record and the tenant defaults.
    Inference,
}

impl Focus {
    /// Weights of save, invite, accept, approve, use approval, set,
    /// inference, complete, signatory grant and signatory end.
    fn weights(self) -> [u32; 10] {
        match self {
            Focus::Steps => [12, 2, 2, 1, 1, 1, 1, 2, 3, 1],
            Focus::Admins => [2, 5, 5, 6, 4, 1, 1, 1, 3, 2],
            Focus::Settings => [2, 1, 1, 1, 1, 10, 1, 1, 1, 1],
            Focus::Inference => [10, 1, 1, 1, 1, 1, 6, 1, 1, 1],
        }
    }
}

/// An actor, mostly a current admin of `model`.
pub fn actor(g: &mut Gen, model: &Reference) -> AccountId {
    let admins: Vec<AccountId> = model.admins().iter().copied().collect();
    if !admins.is_empty() && g.weighted(&[5, 1]) == 0 {
        *g.pick(&admins)
    } else {
        account(g)
    }
}

/// The next operation for a machine run in `model`.
pub fn op(g: &mut Gen, model: &Reference, focus: Focus) -> Op {
    let actor = actor(g, model);
    match g.weighted(&focus.weights()) {
        0 => {
            let step = match model.next_step() {
                Some(next) if g.weighted(&[3, 1]) == 0 => next,
                _ => *g.pick(&Step::ALL),
            };
            if step == Step::Payments && model.p20() != Some(PaymentMode::RecordOnly) && g.bool() {
                // The Payments step needs P-20 chosen (record-only in M4).
                return Op::SetSetting {
                    actor,
                    via: Via::Web,
                    setting: Setting::P20(PaymentMode::RecordOnly),
                };
            }
            Op::SaveStep {
                actor,
                step,
                input: step_input(g, step),
            }
        }
        1 => Op::InviteAdmin {
            actor,
            via: via(g),
            invitation: small_id(g),
            invitee: account(g),
        },
        2 => {
            let open = model.open_invitations();
            let (invitation, account) = if !open.is_empty() && g.weighted(&[4, 1]) == 0 {
                let (id, invitee) = *g.pick(&open);
                let taker = if g.weighted(&[4, 1]) == 0 {
                    invitee
                } else {
                    account(g)
                };
                (id, taker)
            } else {
                (small_id(g), account(g))
            };
            Op::AcceptAdminInvitation {
                account,
                via: via(g),
                invitation,
            }
        }
        3 => {
            let mut grant = grant(g);
            let admins: Vec<AccountId> = model.admins().iter().copied().collect();
            if !admins.is_empty() && g.bool() {
                grant.grantee = *g.pick(&admins);
            }
            Op::ApproveSelfGrant {
                actor,
                via: via(g),
                approval: small_id(g),
                grant,
            }
        }
        4 => {
            let open = model.open_approvals();
            if !open.is_empty() && g.weighted(&[4, 1]) == 0 {
                let (approval, a) = *g.pick(&open);
                let user = if g.weighted(&[4, 1]) == 0 {
                    a.grant.grantee
                } else {
                    actor
                };
                let grant = if g.weighted(&[5, 1]) == 0 {
                    a.grant
                } else {
                    grant(g)
                };
                Op::UseSelfGrantApproval {
                    actor: user,
                    via: via(g),
                    approval,
                    grant,
                }
            } else {
                Op::UseSelfGrantApproval {
                    actor,
                    via: via(g),
                    approval: small_id(g),
                    grant: grant(g),
                }
            }
        }
        5 => Op::SetSetting {
            actor,
            via: via(g),
            setting: setting(g),
        },
        6 => {
            let (primary, fallbacks) = match model.p21_default() {
                Some(d) if g.weighted(&[3, 1]) == 0 => (d.primary.clone(), d.fallbacks.clone()),
                _ => (model_name_weighted(g), fallbacks(g)),
            };
            Op::RecordInference {
                actor,
                config: LlmConfigId::from_raw(small_id(g)),
                primary,
                fallbacks,
            }
        }
        7 => Op::Complete { actor },
        8 => Op::GrantSignatory {
            actor,
            via: via(g),
            account: account(g),
            role: *g.pick(&Signatory::ALL),
        },
        _ => Op::EndSignatory {
            actor,
            via: via(g),
            account: account(g),
            role: *g.pick(&Signatory::ALL),
        },
    }
}

fn model_name_weighted(g: &mut Gen) -> String {
    if g.weighted(&[5, 1]) == 0 {
        g.pick(&MODELS[..3]).to_string()
    } else {
        String::new()
    }
}

/// The operations that walk every step in order with valid values, as
/// `actor`. Before the Payments step, `actor` chooses record-only P-20,
/// which the step needs. Before the Administrators step, `actor` grants
/// both signatory roles to [`SIGNATORY`], which it needs (SoD-14,
/// SoD-15).
pub fn walk(actor: AccountId, steps: &[Step]) -> Vec<Op> {
    let mut out = Vec::new();
    for s in steps {
        if *s == Step::Administrators {
            out.extend(Signatory::ALL.map(|role| Op::GrantSignatory {
                actor,
                via: Via::Web,
                account: SIGNATORY,
                role,
            }));
        }
        if *s == Step::Payments {
            out.push(Op::SetSetting {
                actor,
                via: Via::Web,
                setting: Setting::P20(PaymentMode::RecordOnly),
            });
        }
        out.push(Op::SaveStep {
            actor,
            step: *s,
            input: valid_input(*s),
        });
    }
    out
}

/// The operations by which `by` invites `account` and `account` takes the
/// invitation `invitation`.
pub fn add_admin(by: AccountId, account: AccountId, invitation: u128) -> [Op; 2] {
    [
        Op::InviteAdmin {
            actor: by,
            via: Via::Web,
            invitation,
            invitee: account,
        },
        Op::AcceptAdminInvitation {
            account,
            via: Via::Web,
            invitation,
        },
    ]
}
