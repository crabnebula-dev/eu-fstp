//! The coordinator unmask of ADR-023 on the matrix worlds (I-17 as amended
//! 2026-11-15, I-20, I-27, I-78, I-86, R-AU-01).
//!
//! - The FSTP coordinator of P unmasks each party kind of P: the lead,
//!   a team member, the guardian, a reviewer and an IRC member by their
//!   handles, a committee member by binding, and staff. Each unmask
//!   appends exactly one `PartyUnmasked` naming ids only, and opens the
//!   vault origin's release page for the subject.
//! - A purpose is required: missing, empty, blank and over-long are
//!   refused, and nothing is recorded.
//! - The step-up must be fresh (P-71). A stale proof records nothing.
//! - Every other Judging role stays masked, and so does every other
//!   principal. A coordinator acting on another programme is refused.
//! - MCP exposes neither the unmask nor the parties read (I-86), and no
//!   message is enqueued (I-27).
//! - The auditor and the tenant admins read the record through
//!   `audit.unmasks`, and nobody else does.
//! - Teeth: the properties catch a forged unmask by a committee member
//!   and a decide that admits one.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;
use fstp_domain::unmask::{PartyKind, UnmaskSubject};

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

/// A purpose of the synthetic corpus.
const PURPOSE: &str = "Synthetic purpose: check the declared affiliation of this party.";

fn world(state: StateTag) -> Built {
    build(WorldKey {
        state: StateProfile::Proposal(state),
        policy: Policy::SUPERSAFE,
        variant: Variant::Main,
    })
    .unwrap_or_else(|e| panic!("world {state:?}: {e}"))
}

fn seeder(w: &Built) -> Seeder {
    Seeder {
        ports: w.ports.clone(),
        core: w.core.clone(),
        now: w.now,
        command: 923_000,
        cookies: BTreeMap::new(),
        next_id: 92_300_000,
        admins: w.admins.iter().copied().collect(),
    }
}

/// The IRC_REVIEW world: X has its lead, team member and guardian, its
/// reviewer assignments and its IRC assignments, and P its staff.
fn irc_world() -> (Built, Seeder) {
    let w = world(StateTag::IrcReview);
    let seed = seeder(&w);
    (w, seed)
}

fn programme(w: &Built) -> ProgrammeId {
    w.targets.programme.expect("P")
}

fn proposal(w: &Built) -> ProposalId {
    w.targets.proposal.expect("X")
}

/// The binding of `account` in `programme` with `role`, held or ended.
fn binding_of(seed: &Seeder, programme: ProgrammeId, account: AccountId, role: Role) -> BindingId {
    let state = seed.ports.engine.state();
    let roster = state.core.roster();
    roster
        .bindings()
        .map(|(id, b)| (id, *b))
        .chain(roster.ended().map(|(id, e)| (id, e.binding)))
        .find(|(_, b)| b.account == account && b.programme == programme && b.role == role)
        .map(|(id, _)| id)
        .unwrap_or_else(|| panic!("no {role:?} binding of {}", account.raw()))
}

fn subject_json(s: UnmaskSubject) -> Value {
    match s {
        UnmaskSubject::Binding(b) => obj(vec![
            ("type", self::s("Binding")),
            ("binding", dec(b.raw())),
        ]),
        UnmaskSubject::Assignment(a) => obj(vec![
            ("type", self::s("Assignment")),
            ("assignment", dec(a.raw())),
        ]),
    }
}

fn body(subject: UnmaskSubject, purpose: Option<&str>) -> Value {
    let mut members = vec![("subject", subject_json(subject))];
    if let Some(p) = purpose {
        members.push(("purpose", s(p)));
    }
    obj(members)
}

fn unmask_path(p: ProgrammeId) -> String {
    format!("/programmes/{}/unmask", p.raw())
}

/// The unmask records of the core state, oldest first.
fn records(seed: &Seeder) -> Vec<fstp_domain::unmask::Unmask> {
    seed.ports.engine.state().core.unmasks().records().to_vec()
}

/// The unmask tickets the vault port was asked for, oldest first.
fn tickets(seed: &Seeder) -> Vec<(VerificationPurposeOf, AccountId)> {
    seed.ports
        .vault
        .verifications()
        .into_iter()
        .filter(|(p, _)| matches!(p, fstp_api_core::port::VerificationPurpose::Unmask { .. }))
        .collect()
}

type VerificationPurposeOf = fstp_api_core::port::VerificationPurpose;

/// The subjects of X and P the coordinator may unmask, with the party
/// kind and the account behind each.
fn every_party(w: &Built, seed: &Seeder) -> Vec<(UnmaskSubject, PartyKind, AccountId)> {
    let p = programme(w);
    let reviewer = *w
        .targets
        .assignments
        .get(&REVIEWER)
        .expect("REVIEWER's assignment");
    let irc = *w
        .targets
        .irc
        .get(&IRC_ASSIGNEE)
        .expect("IRC_ASSIGNEE's assignment");
    vec![
        (
            UnmaskSubject::Binding(binding_of(seed, p, LEAD, Role::Applicant)),
            PartyKind::Applicant,
            LEAD,
        ),
        (
            UnmaskSubject::Binding(binding_of(seed, p, TEAM, Role::ApplicantTeamMember)),
            PartyKind::TeamMember,
            TEAM,
        ),
        (
            UnmaskSubject::Binding(binding_of(seed, p, GUARDIAN, Role::Guardian)),
            PartyKind::Guardian,
            GUARDIAN,
        ),
        (
            UnmaskSubject::Assignment(reviewer),
            PartyKind::Reviewer,
            REVIEWER,
        ),
        (UnmaskSubject::Assignment(irc), PartyKind::Irc, IRC_ASSIGNEE),
        (
            UnmaskSubject::Binding(binding_of(seed, p, MEMBER, Role::CommitteeMember)),
            PartyKind::Reviewer,
            MEMBER,
        ),
        (
            UnmaskSubject::Binding(binding_of(seed, p, IRC_MEMBER, Role::IrcMember)),
            PartyKind::Irc,
            IRC_MEMBER,
        ),
        (
            UnmaskSubject::Binding(binding_of(seed, p, PM, Role::ProgrammeManager)),
            PartyKind::Staff,
            PM,
        ),
        (
            UnmaskSubject::Binding(binding_of(seed, p, FINANCE, Role::FinanceApprover)),
            PartyKind::Staff,
            FINANCE,
        ),
    ]
}

// ---------------------------------------------------------------------------
// The coordinator unmasks
// ---------------------------------------------------------------------------

/// I-17 (ADR-023), R-AU-01: the coordinator of P unmasks each party kind
/// with a purpose and a step-up. Each call appends exactly one
/// `PartyUnmasked` by the coordinator, naming the subject by its id and
/// the party kind the server derived. It asks the vault for an unmask
/// ticket for the subject's account, and the reply is the vault page.
#[test]
fn i17_adr023_coordinator_unmasks_each_party_kind_with_a_purpose_and_a_step_up() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    for (subject, kind, account) in every_party(&w, &seed) {
        let before = records(&seed).len();
        let asked = tickets(&seed).len();
        let reply = seed
            .api(COORD, POST, &unmask_path(p), &body(subject, Some(PURPOSE)))
            .unwrap_or_else(|e| panic!("I-17: {kind:?} {subject:?}: {e}"));
        let to = str_member(&reply, "redirect").unwrap_or_else(|| panic!("no redirect: {reply:?}"));
        assert!(
            to.contains("/r#") || to.starts_with("/fake-vault/"),
            "I-17: the reply opens the vault release page: {to}"
        );
        let after = records(&seed);
        assert_eq!(after.len(), before + 1, "I-17: one record per unmask");
        let r = after.last().expect("the record");
        assert_eq!(r.programme, p);
        assert_eq!(r.subject, subject);
        assert_eq!(r.party, kind, "I-17: the derived party kind of {subject:?}");
        assert_eq!(r.by, COORD);
        let t = tickets(&seed);
        assert_eq!(t.len(), asked + 1, "I-17: one vault ticket per unmask");
        let (purpose, by) = t.last().copied().expect("the ticket");
        assert_eq!(by, COORD);
        assert_eq!(
            purpose,
            fstp_api_core::port::VerificationPurpose::Unmask {
                programme: p,
                subject: account,
                party: kind,
            }
        );
    }
}

/// I-17 (ADR-023): the coordinator's parties read lists the parties of X
/// and the staff of P by id, party kind and role. It names no account and
/// no identity attribute, so the page shows ids and handles only.
#[test]
fn i17_adr023_parties_read_lists_parties_by_id_only() {
    let (w, mut seed) = irc_world();
    let x = proposal(&w);
    let v = seed
        .api(
            COORD,
            GET,
            &format!("/proposals/{}/parties", x.raw()),
            &Value::Null,
        )
        .unwrap_or_else(|e| panic!("identity.parties: {e}"));
    let text = v.to_compact();
    let parties = v
        .get("parties")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no parties: {text}"));
    for (subject, kind, _) in every_party(&w, &seed) {
        let (sk, id) = match subject {
            UnmaskSubject::Binding(b) => ("binding", b.raw()),
            UnmaskSubject::Assignment(a) => ("assignment", a.raw()),
        };
        let found = parties.iter().any(|row| {
            str_member(row, "subject_type").as_deref() == Some(sk)
                && str_member(row, "subject") == Some(id.to_string())
                && str_member(row, "party").as_deref() == Some(kind.wire())
        });
        assert!(found, "I-17: {kind:?} {subject:?} is not listed: {text}");
    }
    for leak in ["@", "email", "\"account\"", "name"] {
        assert!(
            !text.contains(leak),
            "I-17: the parties read names {leak}: {text}"
        );
    }
}

// ---------------------------------------------------------------------------
// Purpose and step-up
// ---------------------------------------------------------------------------

/// I-17 (ADR-023): an unmask without a purpose is refused. A missing, an
/// empty, a blank and an over-long purpose append nothing and ask the
/// vault for nothing. A purpose of exactly 500 characters is accepted.
#[test]
fn i17_adr023_unmask_without_a_purpose_is_refused() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let long = "a".repeat(501);
    for purpose in [None, Some(""), Some("   \n\t "), Some(long.as_str())] {
        let r = seed.api(COORD, POST, &unmask_path(p), &body(lead, purpose));
        assert!(r.is_err(), "I-17: purpose {purpose:?} was accepted: {r:?}");
        assert!(
            records(&seed).is_empty(),
            "I-17: purpose {purpose:?} recorded"
        );
        assert!(
            tickets(&seed).is_empty(),
            "I-17: purpose {purpose:?} asked the vault"
        );
    }
    let exact = "b".repeat(500);
    seed.api(COORD, POST, &unmask_path(p), &body(lead, Some(&exact)))
        .unwrap_or_else(|e| panic!("I-17: a purpose of 500 characters: {e}"));
    assert_eq!(records(&seed).len(), 1);
}

/// One web call as `account`, with no step-up answered.
fn raw(
    seed: &mut Seeder,
    account: AccountId,
    method: ApiMethod,
    path: &str,
    v: &Value,
) -> Result<OpResult, ApiError> {
    let l = seed.login(account);
    let bytes = match v {
        Value::Null => Vec::new(),
        v => v.to_compact().into_bytes(),
    };
    let op = decode_web(method, path, &bytes)?;
    block_on(seed.core.dispatch(
        Credential::SessionCookie(l.cookie.clone()),
        &RequestHead::new(),
        op,
    ))
}

/// I-78, I-17 (ADR-023): the unmask is high-risk. Without a proof it asks
/// for a step-up and records nothing. A proof older than P-71 does not
/// complete it: the call asks again or is refused, and records nothing.
/// A fresh proof completes it once.
#[test]
fn i78_adr023_unmask_with_a_stale_step_up_is_refused() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let b = body(lead, Some(PURPOSE));
    let ch = match raw(&mut seed, COORD, POST, &unmask_path(p), &b) {
        Ok(OpResult::StepUpRequired(ch)) => ch,
        other => panic!("I-78: an unmask without a proof: {other:?}"),
    };
    assert!(
        records(&seed).is_empty(),
        "I-78: recorded before the step-up"
    );
    // The proof is given one microsecond more than the world's P-71
    // before now, as the matrix harness makes a stale one.
    let l = seed.login(COORD);
    let now = seed.now;
    let stale = now.saturating_sub(w.targets.p71).saturating_sub(1);
    seed.ports.clock.set(Timestamp::from_micros(stale));
    seed.ports.step_up.approve(l.session, ch.action).unwrap();
    seed.ports.clock.set(Timestamp::from_micros(now));
    let r = raw(&mut seed, COORD, POST, &unmask_path(p), &b);
    assert!(
        !matches!(r, Ok(OpResult::Done { .. })),
        "I-78: a stale proof unmasked: {r:?}"
    );
    assert!(records(&seed).is_empty(), "I-78: a stale proof recorded");
    assert!(
        tickets(&seed).is_empty(),
        "I-78: a stale proof asked the vault"
    );
    seed.api(COORD, POST, &unmask_path(p), &b)
        .unwrap_or_else(|e| panic!("I-78: a fresh proof: {e}"));
    assert_eq!(records(&seed).len(), 1);
}

/// M10 F-058 (H01b-1), I-17 as amended, R-AU-01, ADR-023 reading 7: an
/// unmask that the vault port cannot open leaves no record. The
/// coordinator's call is refused before the append, with no step-up spent,
/// so `audit.unmasks` never lists an unmask that showed nothing. Once the
/// release page opens again, the same call records exactly one unmask.
#[test]
fn m10_f058_i17_unmask_leaves_no_record_when_the_vault_page_cannot_open() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let b = body(lead, Some(PURPOSE));
    seed.ports.vault.set_unmask_down(true);
    for _ in 0..2 {
        let r = seed.api(COORD, POST, &unmask_path(p), &b);
        assert!(r.is_err(), "F-058: the unmask answered: {r:?}");
        assert!(
            records(&seed).is_empty(),
            "F-058, I-17: an unmask that showed nothing was recorded"
        );
    }
    let r = raw(&mut seed, COORD, POST, &unmask_path(p), &b);
    assert!(
        !matches!(r, Ok(OpResult::StepUpRequired(_))),
        "F-058: a step-up was asked for an unmask that cannot open: {r:?}"
    );
    seed.ports.vault.set_unmask_down(false);
    seed.api(COORD, POST, &unmask_path(p), &b)
        .unwrap_or_else(|e| panic!("I-17: the page opens again: {e}"));
    assert_eq!(records(&seed).len(), 1, "I-17: one record per unmask");
    assert_eq!(tickets(&seed).len(), 1, "I-17: one ticket per unmask");
}

// ---------------------------------------------------------------------------
// Everyone else stays masked
// ---------------------------------------------------------------------------

/// Every principal of the world but the coordinators of P.
const NOT_COORDINATORS: [AccountId; 21] = [
    ADMIN_BUILDER,
    ADMIN_PLAIN,
    PM,
    PM_DRAFTER,
    PM_OTHER,
    DRAFTER,
    CHAIR,
    MEMBER,
    REVIEWER,
    REVIEWER_2,
    IRC_MEMBER,
    IRC_ASSIGNEE,
    LEAD,
    TEAM,
    GUARDIAN,
    LEAD_Y,
    FINANCE,
    RELEASER,
    SIGNATORY,
    AUDITOR,
    UNBOUND,
];

/// I-17: every Judging role other than the coordinator stays masked:
/// committee members, the chair, assigned reviewers and IRC members are
/// refused, with a step-up answered. So is every staff role, tenant admin,
/// auditor and Receiving role. Nothing is recorded, and the vault is
/// never asked. The parties read refuses them too.
#[test]
fn i17_judging_roles_other_than_the_coordinator_stay_masked() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let x = proposal(&w);
    let parties = every_party(&w, &seed);
    for who in NOT_COORDINATORS {
        for (subject, kind, _) in &parties {
            let r = seed.api(who, POST, &unmask_path(p), &body(*subject, Some(PURPOSE)));
            assert!(r.is_err(), "I-17: {} unmasked {kind:?}: {r:?}", who.raw());
        }
        let read = seed.api(
            who,
            GET,
            &format!("/proposals/{}/parties", x.raw()),
            &Value::Null,
        );
        assert!(
            read.is_err(),
            "I-17: {} read the parties: {read:?}",
            who.raw()
        );
    }
    assert!(records(&seed).is_empty(), "I-17: a refused unmask recorded");
    assert!(
        tickets(&seed).is_empty(),
        "I-17: a refused unmask asked the vault"
    );
}

/// I-17, I-20 (ADR-023 reading 1): a coordinator acts on their own
/// programme only. COORD naming P2, where COORD holds no binding, is
/// refused, even for a party of P. Naming P with a binding of P2 is
/// refused as unknown input. Nothing is recorded.
#[test]
fn i20_adr023_coordinator_of_another_programme_is_refused() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let p2 = other_programme_of(&seed, p);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let r = seed.api(COORD, POST, &unmask_path(p2), &body(lead, Some(PURPOSE)));
    assert!(r.is_err(), "I-20: COORD unmasked through P2: {r:?}");
    let pm2 = UnmaskSubject::Binding(binding_of(&seed, p2, PM_OTHER, Role::ProgrammeManager));
    let r = seed.api(COORD, POST, &unmask_path(p), &body(pm2, Some(PURPOSE)));
    assert!(r.is_err(), "I-20: COORD of P unmasked staff of P2: {r:?}");
    assert!(records(&seed).is_empty());
    assert!(tickets(&seed).is_empty());
}

/// The other programme of the tenant, P2.
fn other_programme_of(seed: &Seeder, p: ProgrammeId) -> ProgrammeId {
    let state = seed.ports.engine.state();
    state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b.programme)
        .find(|q| *q != p)
        .expect("P2")
}

// ---------------------------------------------------------------------------
// Production decide on a copy of the world (domain level)
// ---------------------------------------------------------------------------

fn ctx_of(actor: AccountId, now: Timestamp, admin: bool) -> Ctx {
    let mut id = [0u8; 16];
    id[..8].copy_from_slice(b"unmask23");
    id[8..].copy_from_slice(&actor.raw().to_be_bytes()[8..]);
    Ctx {
        now,
        actor: Actor::Account(actor),
        command: CommandId::from_bytes(id),
        via: Via::Web,
        tenant_admin: admin,
        second_tenant_admin: None,
        binds_tenant_admin: false,
    }
}

fn purpose_ref() -> fstp_domain::id::TextRef {
    fstp_domain::id::TextRef::new(
        fstp_domain::id::TextId::from_raw(923_001),
        fstp_domain::id::ContentDigest::from_bytes([7; 32]),
    )
}

type DecideFn<'a> = dyn Fn(&fstp_domain::State, &Core, &Ctx) -> Result<Vec<fstp_domain::Record>, fstp_domain::Refusal>
    + 'a;

fn production_decide(
    s: &fstp_domain::State,
    c: &Core,
    x: &Ctx,
) -> Result<Vec<fstp_domain::Record>, fstp_domain::Refusal> {
    fstp_domain::decide(s, c, x, &fstp_domain::Answers::new())
}

/// The I-17 property of ADR-023 over decide: for every account and every
/// party, `UnmaskParty` is admitted exactly when the account holds an
/// active FSTP coordinator binding of the named programme. An admitted
/// command yields one `PartyUnmasked` by the actor, naming the subject
/// and the purpose given, and nothing else.
fn i17_only_the_coordinator_unmasks(
    state: &fstp_domain::State,
    now: Timestamp,
    programme: ProgrammeId,
    parties: &[(UnmaskSubject, PartyKind, AccountId)],
    accounts: &[AccountId],
    admins: &BTreeSet<AccountId>,
    decide: &DecideFn<'_>,
) -> Result<(), String> {
    for a in accounts {
        let coordinator = state.roster().bindings().any(|(_, b)| {
            b.account == *a
                && b.programme == programme
                && b.role == Role::FstpCoordinator
                && b.active_at(now)
        });
        for (subject, kind, _) in parties {
            let cmd = Core::UnmaskParty {
                programme,
                subject: *subject,
                purpose: purpose_ref(),
            };
            let got = decide(state, &cmd, &ctx_of(*a, now, admins.contains(a)));
            match (coordinator, got) {
                (true, Ok(records)) => {
                    // ADR-023 decision 2: the record flags a conflict fact
                    // of the coordinator on the subject's proposal.
                    let x = match subject {
                        UnmaskSubject::Binding(b) => state
                            .roster()
                            .held_or_ended(*b)
                            .and_then(fstp_domain::roles::Binding::proposal),
                        UnmaskSubject::Assignment(id) => {
                            state.review().get(*id).map(|g| g.proposal)
                        }
                    };
                    let want = vec![fstp_domain::Record::PartyUnmasked {
                        programme,
                        party: *kind,
                        subject: *subject,
                        purpose: purpose_ref(),
                        by: *a,
                        conflict: x.is_some_and(|x| state.review().conflict_fact(*a, x)),
                    }];
                    if records != want {
                        return Err(format!(
                            "I-17: {} unmasking {subject:?} gave {records:?}",
                            a.raw()
                        ));
                    }
                }
                (true, Err(r)) => {
                    return Err(format!(
                        "I-17: the coordinator {} was refused {subject:?}: {r:?}",
                        a.raw()
                    ));
                }
                (false, Ok(records)) => {
                    return Err(format!(
                        "I-17: {} is no coordinator and unmasked {subject:?}: {records:?}",
                        a.raw()
                    ));
                }
                (false, Err(_)) => {}
            }
        }
    }
    Ok(())
}

fn every_account() -> Vec<AccountId> {
    let mut v = NOT_COORDINATORS.to_vec();
    v.extend([COORD, COORD_UNDECLARED, COORD_CONFLICTED]);
    v
}

/// I-17 (ADR-023): production decide admits exactly the active FSTP
/// coordinators of P, for every party kind. A tenant admin attested by
/// the shell is refused like everyone else.
#[test]
fn i17_adr023_decide_admits_only_the_programme_coordinator() {
    let (w, seed) = irc_world();
    let state = seed.ports.engine.state().core;
    let admins: BTreeSet<AccountId> = w.admins.iter().copied().collect();
    let now = Timestamp::from_micros(seed.now);
    i17_only_the_coordinator_unmasks(
        &state,
        now,
        programme(&w),
        &every_party(&w, &seed),
        &every_account(),
        &admins,
        &production_decide,
    )
    .unwrap_or_else(|e| panic!("{e}"));
}

/// I-17, I-20 (ADR-023): a coordinator of P2 is refused for every party of
/// P, and the coordinator of P naming P2 is refused. The coordinator
/// binding of P2 is folded into a copy of the state, since a draft
/// programme admits no coordinator grant.
#[test]
fn i20_adr023_decide_refuses_a_coordinator_of_another_programme() {
    let (w, seed) = irc_world();
    let p = programme(&w);
    let p2 = other_programme_of(&seed, p);
    let mut state = seed.ports.engine.state().core;
    let now = Timestamp::from_micros(seed.now);
    let grant = fstp_domain::record::BindingGranted {
        binding: BindingId::from_raw(923_777),
        account: UNBOUND,
        programme: p2,
        role: Role::FstpCoordinator,
        scope: fstp_domain::roles::BindingScope::Programme,
        start: now,
        granted_by: ADMIN_PLAIN,
        second_admin: None,
        confidentiality: None,
        organisation: None,
        verified_epoch: None,
    };
    fstp_domain::apply(
        &mut state,
        fstp_ledger::Seq::from_raw(9_230_000),
        now,
        &fstp_domain::Record::BindingGranted(grant),
    )
    .unwrap_or_else(|e| panic!("fold the P2 coordinator: {e}"));
    for (subject, kind, _) in every_party(&w, &seed) {
        for programme in [p, p2] {
            let cmd = Core::UnmaskParty {
                programme,
                subject,
                purpose: purpose_ref(),
            };
            let r = production_decide(&state, &cmd, &ctx_of(UNBOUND, now, false));
            assert!(
                r.is_err(),
                "I-20: P2's coordinator unmasked {kind:?} via {programme:?}: {r:?}"
            );
        }
        let cmd = Core::UnmaskParty {
            programme: p2,
            subject,
            purpose: purpose_ref(),
        };
        let r = production_decide(&state, &cmd, &ctx_of(COORD, now, false));
        assert!(
            r.is_err(),
            "I-20: COORD unmasked {kind:?} through P2: {r:?}"
        );
    }
}

/// I-17 teeth: a decide that admits a committee member's unmask is
/// caught by the property above.
#[test]
fn i17_teeth_committee_member_unmask_is_caught() {
    let (w, seed) = irc_world();
    let p = programme(&w);
    let state = seed.ports.engine.state().core;
    let now = Timestamp::from_micros(seed.now);
    let mutant = |s: &fstp_domain::State, c: &Core, x: &Ctx| match (c, x.actor) {
        (
            Core::UnmaskParty {
                programme,
                subject,
                purpose,
            },
            Actor::Account(a),
        ) if a == MEMBER => Ok(vec![fstp_domain::Record::PartyUnmasked {
            programme: *programme,
            party: PartyKind::Applicant,
            subject: *subject,
            purpose: *purpose,
            by: a,
            conflict: false,
        }]),
        _ => production_decide(s, c, x),
    };
    let e = i17_only_the_coordinator_unmasks(
        &state,
        now,
        p,
        &every_party(&w, &seed),
        &every_account(),
        &BTreeSet::new(),
        &mutant,
    )
    .expect_err("I-17 teeth: the mutant was not caught");
    assert!(e.contains("I-17"), "{e}");
}

/// The I-17 property of ADR-023 over the folded records: every
/// `PartyUnmasked` is by a holder of an FSTP coordinator binding of its
/// programme, and its subject resolves to the party kind it names.
fn i17_unmask_records_are_admitted(state: &fstp_domain::State) -> Result<(), String> {
    for r in state.unmasks().records() {
        let roster = state.roster();
        let coordinator = roster
            .bindings()
            .map(|(_, b)| *b)
            .chain(roster.ended().map(|(_, e)| e.binding))
            .any(|b| {
                b.account == r.by && b.programme == r.programme && b.role == Role::FstpCoordinator
            });
        if !coordinator {
            return Err(format!(
                "I-17: {} unmasked without a coordinator binding: {r:?}",
                r.by.raw()
            ));
        }
        match fstp_domain::unmask::party_of(state, r.programme, r.subject) {
            Some((kind, _)) if kind == r.party => {}
            other => return Err(format!("I-17: the subject resolves to {other:?}: {r:?}")),
        }
    }
    Ok(())
}

/// I-17: after the coordinator's unmasks the record property holds. A
/// forged `PartyUnmasked` by a committee member, folded through the
/// public `apply`, is caught.
#[test]
fn i17_teeth_forged_unmask_record_is_caught() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    seed.api(COORD, POST, &unmask_path(p), &body(lead, Some(PURPOSE)))
        .unwrap_or_else(|e| panic!("{e}"));
    let mut state = seed.ports.engine.state().core;
    i17_unmask_records_are_admitted(&state).unwrap_or_else(|e| panic!("production: {e}"));
    let now = Timestamp::from_micros(seed.now);
    fstp_domain::apply(
        &mut state,
        fstp_ledger::Seq::from_raw(9_230_001),
        now,
        &fstp_domain::Record::PartyUnmasked {
            programme: p,
            party: PartyKind::Applicant,
            subject: lead,
            purpose: purpose_ref(),
            by: MEMBER,
            conflict: false,
        },
    )
    .unwrap_or_else(|e| panic!("fold the forged record: {e}"));
    let e = i17_unmask_records_are_admitted(&state)
        .expect_err("I-17 teeth: the forged record was not caught");
    assert!(e.contains("I-17"), "{e}");
}

/// I-17, I-86 (ADR-023 reading 6): the record holds ids only. Its stored
/// JSON has exactly the members programme, party, subject, purpose, by
/// and the conflict flag of ADR-023 decision 2, and the purpose is a text
/// reference, never the text.
#[test]
fn i17_adr023_record_names_ids_only() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let before = seed.ports.engine.store_copy().head();
    seed.api(COORD, POST, &unmask_path(p), &body(lead, Some(PURPOSE)))
        .unwrap_or_else(|e| panic!("{e}"));
    let store = seed.ports.engine.store_copy();
    let mut entries = Vec::new();
    store
        .read(
            fstp_ledger::Seq::from_raw(before.raw() + 1),
            64,
            &mut entries,
        )
        .unwrap_or_else(|e| panic!("the new entries: {e:?}"));
    let records: Vec<String> = entries.iter().map(|e| format!("{:?}", e.record)).collect();
    let text = records.join("\n");
    assert_eq!(records.len(), 1, "I-17: one record: {text}");
    assert!(text.contains("PartyUnmasked"), "{text}");
    assert!(
        !text.contains(PURPOSE),
        "I-17: the purpose text is in the ledger: {text}"
    );
    assert!(
        !text.contains("OutboxEnqueued"),
        "I-27: the unmask enqueued a message: {text}"
    );
}

// ---------------------------------------------------------------------------
// Channels and messages
// ---------------------------------------------------------------------------

/// I-86, I-85 (ADR-023 reading 12): neither the unmask nor the parties
/// read has an MCP tool, and a bearer call of either is refused and
/// records nothing.
#[test]
fn i86_adr023_mcp_exposes_no_unmask() {
    for name in ["identity.unmask", "identity.parties"] {
        let spec = fstp_access::OPS
            .iter()
            .find(|o| o.name == name)
            .unwrap_or_else(|| panic!("no {name} in the registry"));
        assert!(spec.tool.is_none(), "I-86: {name} has a tool");
    }
    for t in fstp_api_core::meta::tools() {
        assert!(
            !t.name.contains("unmask") && !t.name.contains("parties"),
            "I-86: tool {}",
            t.name
        );
    }
    let (w, seed) = irc_world();
    let p = programme(&w);
    let x = proposal(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let token = seed.ports.tokens.issue(
        COORD,
        agent_of(COORD),
        [
            Scope::ReviewRead,
            Scope::ReviewDraft,
            Scope::AuditRead,
            Scope::ProposalsRead,
        ],
        LoginMethod::Passkey,
    );
    let b = body(lead, Some(PURPOSE)).to_compact().into_bytes();
    for (method, path, bytes) in [
        (POST, unmask_path(p), b),
        (GET, format!("/proposals/{}/parties", x.raw()), Vec::new()),
    ] {
        let op = decode_web(method, &path, &bytes).unwrap_or_else(|e| panic!("{path}: {e:?}"));
        let r = block_on(seed.core.dispatch(
            Credential::Bearer(token.clone()),
            &RequestHead::new(),
            op,
        ));
        assert!(
            !matches!(r, Ok(OpResult::Done { .. })),
            "I-86: {path} over a bearer token: {r:?}"
        );
    }
    assert!(records(&seed).is_empty());
    assert!(tickets(&seed).is_empty());
}

/// I-27 (ADR-023 open point 1, interim): an unmask sends no message. The
/// unmasked lead's mailbox reads the same before and after.
#[test]
fn i27_adr023_unmask_sends_no_message() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let before = seed
        .api(LEAD, GET, "/me/mailbox", &Value::Null)
        .unwrap_or_else(|e| panic!("mailbox: {e}"));
    seed.api(COORD, POST, &unmask_path(p), &body(lead, Some(PURPOSE)))
        .unwrap_or_else(|e| panic!("{e}"));
    let after = seed
        .api(LEAD, GET, "/me/mailbox", &Value::Null)
        .unwrap_or_else(|e| panic!("mailbox: {e}"));
    assert_eq!(
        before.to_compact(),
        after.to_compact(),
        "I-27: the lead's mailbox changed"
    );
}

// ---------------------------------------------------------------------------
// The audit read
// ---------------------------------------------------------------------------

/// R-AU-01, I-17 (ADR-023 reading 11): the auditor of P and every tenant
/// admin read the unmask through `audit.unmasks`: its party kind, subject
/// id, coordinator id, purpose and instant. The coordinator, the
/// subject and every other principal are refused.
#[test]
fn r_au_01_adr023_audit_read_shows_the_unmask_to_auditor_and_admins() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let lead_binding = binding_of(&seed, p, LEAD, Role::Applicant);
    seed.api(
        COORD,
        POST,
        &unmask_path(p),
        &body(UnmaskSubject::Binding(lead_binding), Some(PURPOSE)),
    )
    .unwrap_or_else(|e| panic!("{e}"));
    let path = format!("/programmes/{}/audit/unmasks", p.raw());
    for who in [AUDITOR, ADMIN_PLAIN, ADMIN_BUILDER] {
        let v = seed
            .api(who, GET, &path, &Value::Null)
            .unwrap_or_else(|e| panic!("R-AU-01: {} read: {e}", who.raw()));
        let rows = v
            .get("unmasks")
            .and_then(Value::as_array)
            .unwrap_or_else(|| panic!("no unmasks: {v:?}"));
        assert_eq!(rows.len(), 1, "{}", v.to_compact());
        let row = &rows[0];
        assert_eq!(str_member(row, "party").as_deref(), Some("applicant"));
        assert_eq!(str_member(row, "subject_type").as_deref(), Some("binding"));
        assert_eq!(
            str_member(row, "subject"),
            Some(lead_binding.raw().to_string())
        );
        assert_eq!(str_member(row, "by"), Some(COORD.raw().to_string()));
        assert_eq!(str_member(row, "purpose").as_deref(), Some(PURPOSE));
        assert!(str_member(row, "at").is_some());
    }
    for who in [COORD, MEMBER, PM, LEAD, FINANCE, UNBOUND] {
        let r = seed.api(who, GET, &path, &Value::Null);
        assert!(
            r.is_err(),
            "R-AU-01: {} read the unmask log: {r:?}",
            who.raw()
        );
    }
}

// ---------------------------------------------------------------------------
// Daniel's decisions of 2026-11-15 (evening)
// ---------------------------------------------------------------------------

/// The `conflict` member of each row of `audit.unmasks`, oldest first.
fn audit_conflicts(seed: &mut Seeder, p: ProgrammeId) -> Vec<Option<bool>> {
    let path = format!("/programmes/{}/audit/unmasks", p.raw());
    let v = seed
        .api(AUDITOR, GET, &path, &Value::Null)
        .unwrap_or_else(|e| panic!("audit.unmasks: {e}"));
    v.get("unmasks")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no unmasks: {v:?}"))
        .iter()
        .map(|row| row.get("conflict").and_then(Value::as_bool))
        .collect()
}

/// I-17, I-03, R-AU-01 (ADR-023 decision 2, Daniel, 2026-11-15): a
/// coordinator with a declared conflict on X may still unmask its lead.
/// `PartyUnmasked` records that the conflict existed, and `audit.unmasks`
/// shows it. The coordinator with no conflict, and the conflicted one
/// naming staff of P, which rests on no proposal, record none.
#[test]
fn i17_adr023_conflicted_coordinator_unmasks_and_the_record_flags_the_conflict() {
    let (w, mut seed) = irc_world();
    let p = programme(&w);
    let x = proposal(&w);
    assert!(
        seed.ports
            .engine
            .state()
            .core
            .review()
            .conflict_fact(COORD_CONFLICTED, x),
        "the world: COORD_CONFLICTED declared a conflict on X"
    );
    let lead = UnmaskSubject::Binding(binding_of(&seed, p, LEAD, Role::Applicant));
    let staff = UnmaskSubject::Binding(binding_of(&seed, p, PM, Role::ProgrammeManager));
    for (who, subject) in [
        (COORD_CONFLICTED, lead),
        (COORD, lead),
        (COORD_CONFLICTED, staff),
    ] {
        seed.api(who, POST, &unmask_path(p), &body(subject, Some(PURPOSE)))
            .unwrap_or_else(|e| {
                panic!(
                    "ADR-023 decision 2: {} unmasking {subject:?}: {e}",
                    who.raw()
                )
            });
    }
    let flags: Vec<(AccountId, bool)> = records(&seed).iter().map(|r| (r.by, r.conflict)).collect();
    assert_eq!(
        flags,
        vec![
            (COORD_CONFLICTED, true),
            (COORD, false),
            (COORD_CONFLICTED, false)
        ],
        "ADR-023 decision 2: the records' conflict flags"
    );
    assert_eq!(
        audit_conflicts(&mut seed, p),
        vec![Some(true), Some(false), Some(false)],
        "R-AU-01: audit.unmasks shows the conflict flag"
    );
}

/// I-17 (ADR-023 decision 4, Daniel, 2026-11-15, reading 3: any stage):
/// on a DRAFT proposal the coordinator of P reads its parties and
/// unmasks its lead. The read lists ids and roles only, as in every
/// other state.
#[test]
fn i17_adr023_parties_read_and_unmask_work_on_a_draft() {
    let w = world(StateTag::Draft);
    let mut seed = seeder(&w);
    let p = programme(&w);
    let x = proposal(&w);
    let lead = binding_of(&seed, p, LEAD, Role::Applicant);
    let v = seed
        .api(
            COORD,
            GET,
            &format!("/proposals/{}/parties", x.raw()),
            &Value::Null,
        )
        .unwrap_or_else(|e| panic!("ADR-023 decision 4: identity.parties on a DRAFT: {e}"));
    let text = v.to_compact();
    let listed = v
        .get("parties")
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no parties: {text}"))
        .iter()
        .any(|row| {
            str_member(row, "subject_type").as_deref() == Some("binding")
                && str_member(row, "subject") == Some(lead.raw().to_string())
                && str_member(row, "party").as_deref() == Some("applicant")
        });
    assert!(listed, "ADR-023 decision 4: the lead is not listed: {text}");
    seed.api(
        COORD,
        POST,
        &unmask_path(p),
        &body(UnmaskSubject::Binding(lead), Some(PURPOSE)),
    )
    .unwrap_or_else(|e| panic!("ADR-023 decision 4: the unmask on a DRAFT: {e}"));
    let r = records(&seed);
    assert_eq!(r.len(), 1, "one record");
    assert_eq!(r[0].subject, UnmaskSubject::Binding(lead));
    assert_eq!(r[0].party, PartyKind::Applicant);
}
