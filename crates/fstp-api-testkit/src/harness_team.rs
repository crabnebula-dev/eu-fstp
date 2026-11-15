//! The team and member pages and the display name on the matrix worlds
//! (SA-11, Daniel 2026-11-15 night; I-17, P-11, I-27, I-86, ADR-007).
//!
//! - An account sets, reads and clears its own display name. It is plain
//!   text of at most 100 characters. A replaced or cleared name is erased.
//! - The name is a confidential text the account owns, so an account
//!   erasure erases it.
//! - `team.list` lists the staff roles of P with display names and the
//!   login emails, and no applicant. The manager may invite only, a
//!   tenant admin may grant, end and reinstate too.
//! - `admin.members` lists each member account with its roles.
//! - Teeth for I-17, P-11 and I-27: with a canary display name on every
//!   account, no read an applicant or a Judging role may make, and no
//!   message, holds a canary. The team page of a tenant admin does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;
use fstp_api_core::port::TextOwner;

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

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
        command: 931_000,
        cookies: BTreeMap::new(),
        next_id: 93_100_000,
        admins: w.admins.iter().copied().collect(),
    }
}

fn programme(w: &Built) -> ProgrammeId {
    w.targets.programme.expect("P")
}

fn set_name(seed: &mut Seeder, a: AccountId, name: Value) -> Result<Value, String> {
    seed.api(
        a,
        POST,
        "/me/display-name",
        &obj(vec![("display_name", name)]),
    )
}

fn own_name(seed: &mut Seeder, a: AccountId) -> Value {
    let v = seed
        .api(a, GET, "/me/display-name", &Value::Null)
        .unwrap_or_else(|e| panic!("me.display_name: {e}"));
    v.get("display_name").cloned().expect("display_name")
}

fn team(seed: &mut Seeder, viewer: AccountId, p: ProgrammeId) -> Result<Value, String> {
    seed.api(
        viewer,
        GET,
        &format!("/programmes/{}/team", p.raw()),
        &Value::Null,
    )
}

fn rows(v: &Value) -> Vec<Value> {
    v.get("rows")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default()
}

fn actions(v: &Value) -> Vec<String> {
    v.get("actions")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

/// The rows of `account`.
fn rows_of(v: &Value, account: AccountId) -> Vec<Value> {
    rows(v)
        .into_iter()
        .filter(|r| str_member(r, "account") == Some(account.raw().to_string()))
        .collect()
}

/// SA-11: an account sets, reads and clears its own display name. Each
/// replaced or cleared name leaves the text store (ADR-007), and only
/// plain text of at most 100 characters is taken.
#[test]
fn sa11_account_sets_reads_and_clears_its_own_display_name() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    assert_eq!(own_name(&mut seed, PM), Value::Null);
    set_name(&mut seed, PM, s("Synthetic Programme Lead")).unwrap();
    assert_eq!(own_name(&mut seed, PM), s("Synthetic Programme Lead"));
    let first = seed.ports.texts.display_text(PM).expect("a text");
    set_name(&mut seed, PM, s("  Synthetic Renamed  ")).unwrap();
    assert_eq!(own_name(&mut seed, PM), s("Synthetic Renamed"));
    assert!(
        seed.ports.texts.peek(first).is_none(),
        "ADR-007: the replaced name stays stored"
    );
    for bad in [
        s(&"x".repeat(101)),
        s("<em>Synthetic</em>"),
        s("Two\nlines"),
        Value::Bool(true),
    ] {
        assert!(
            set_name(&mut seed, PM, bad.clone()).is_err(),
            "SA-11 took {bad:?}"
        );
    }
    assert_eq!(own_name(&mut seed, PM), s("Synthetic Renamed"));
    let second = seed.ports.texts.display_text(PM).expect("a text");
    set_name(&mut seed, PM, Value::Null).unwrap();
    assert_eq!(own_name(&mut seed, PM), Value::Null);
    assert!(seed.ports.texts.peek(second).is_none(), "ADR-007");
    assert!(seed.ports.texts.display_text(PM).is_none());
    // Another account never sees it: each reads its own.
    set_name(&mut seed, MEMBER, s("Synthetic Member")).unwrap();
    assert_eq!(own_name(&mut seed, PM), Value::Null);
}

/// SA-11, ADR-007: the display name is a confidential text the account
/// owns, so an account erasure erases it, and the team page then shows
/// no name.
#[test]
fn sa11_adr007_display_name_is_an_account_text_erased_with_the_account() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    let p = programme(&w);
    set_name(&mut seed, PM, s("Synthetic Programme Lead")).unwrap();
    let text = seed.ports.texts.display_text(PM).expect("a text");
    assert_eq!(seed.ports.texts.owner(text), Some(TextOwner::Account(PM)));
    let erased = seed
        .ports
        .texts
        .erase_account(PM, Timestamp::from_micros(seed.now));
    assert_eq!(erased, 1);
    assert_eq!(own_name(&mut seed, PM), Value::Null);
    let v = team(&mut seed, ADMIN_PLAIN, p).unwrap();
    for r in rows_of(&v, PM) {
        assert_eq!(r.get("display_name"), Some(&Value::Null), "{r:?}");
    }
}

/// The refusal of a taken display name, exactly: the rule and nothing
/// else, so it never names the account that holds the name (SA-11
/// amendment, R-CF-03 style).
const TAKEN: &str = "/me/display-name: {\"code\":\"refused\",\"rule\":\"SA-11-unique\"}";

/// SA-11 amendment: a display name is unique within the organisation. A
/// name another account holds is refused, also in another case or
/// spacing, under `SA-11-unique`, naming nobody. The own name again is
/// no conflict.
#[test]
fn sa11_unique_taken_name_is_refused_and_own_name_again_is_set() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    set_name(&mut seed, PM, s("Synthetic Anna Berg")).unwrap();
    for other in [
        "Synthetic Anna Berg",
        "synthetic anna berg",
        "  SYNTHETIC  Anna   berg ",
    ] {
        assert_eq!(
            set_name(&mut seed, MEMBER, s(other)),
            Err(TAKEN.to_owned()),
            "SA-11 amendment: {other:?}"
        );
    }
    assert_eq!(own_name(&mut seed, MEMBER), Value::Null);
    assert_eq!(own_name(&mut seed, PM), s("Synthetic Anna Berg"));
    set_name(&mut seed, PM, s("Synthetic Anna Berg")).unwrap();
    set_name(&mut seed, PM, s("synthetic ANNA berg")).unwrap();
    assert_eq!(own_name(&mut seed, PM), s("synthetic ANNA berg"));
    set_name(&mut seed, MEMBER, s("Synthetic Anna Bergh")).unwrap();
}

/// SA-11 amendment, ADR-007: a replace, a clear and an account erasure
/// each erase the fingerprint with the name, so another account may then
/// take it.
#[test]
fn sa11_unique_replace_clear_and_account_erasure_free_the_name() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    set_name(&mut seed, PM, s("Synthetic First")).unwrap();
    set_name(&mut seed, PM, s("Synthetic Second")).unwrap();
    set_name(&mut seed, MEMBER, s("synthetic first")).unwrap();
    assert_eq!(
        set_name(&mut seed, MEMBER, s("Synthetic Second")),
        Err(TAKEN.to_owned())
    );
    set_name(&mut seed, PM, Value::Null).unwrap();
    set_name(&mut seed, MEMBER, s("Synthetic Second")).unwrap();
    assert_eq!(
        set_name(&mut seed, PM, s("SYNTHETIC SECOND")),
        Err(TAKEN.to_owned())
    );
    seed.ports
        .texts
        .erase_account(MEMBER, Timestamp::from_micros(seed.now));
    assert!(seed.ports.texts.display_fingerprint(MEMBER).is_none());
    set_name(&mut seed, PM, s("SYNTHETIC SECOND")).unwrap();
    assert_eq!(seed.ports.texts.fingerprint_count(), 1);
}

/// SA-11 amendment, I-20: names are never compared across tenants. Two
/// tenant cells each give the same name to an account, and the stored
/// fingerprints differ, so none links the two accounts.
#[test]
fn sa11_unique_i20_two_tenants_may_use_the_same_name() {
    let one = world(StateTag::Stage1);
    let two = world(StateTag::Stage1);
    let mut a = seeder(&one);
    let mut b = seeder(&two);
    set_name(&mut a, PM, s("Synthetic Shared Name")).unwrap();
    set_name(&mut b, MEMBER, s("Synthetic Shared Name")).unwrap();
    let fa = a.ports.texts.display_fingerprint(PM).expect("one");
    let fb = b.ports.texts.display_fingerprint(MEMBER).expect("two");
    assert_ne!(fa, fb, "I-20: one fingerprint links two tenants");
}

/// SA-11: the team page lists every staff role of P with its display
/// name and its login email, and no Receiving binding. A tenant admin may
/// grant, end and reinstate. The manager may not.
#[test]
fn sa11_team_page_lists_staff_with_names_and_emails_and_no_applicant() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    let p = programme(&w);
    seed.ports
        .accounts
        .set_login_email(MEMBER, "member@example.invalid");
    set_name(&mut seed, MEMBER, s("Synthetic Committee Member")).unwrap();
    let v = team(&mut seed, ADMIN_PLAIN, p).unwrap_or_else(|e| panic!("team.list: {e}"));
    let text = v.to_compact();
    let member = rows_of(&v, MEMBER);
    assert!(!member.is_empty(), "SA-11: MEMBER is not listed: {text}");
    for r in &member {
        assert_eq!(
            str_member(r, "display_name").as_deref(),
            Some("Synthetic Committee Member")
        );
        assert_eq!(
            str_member(r, "email").as_deref(),
            Some("member@example.invalid")
        );
        assert_eq!(str_member(r, "role").as_deref(), Some("committee_member"));
    }
    assert!(!rows_of(&v, PM).is_empty(), "SA-11: the manager is listed");
    for a in [LEAD, TEAM, GUARDIAN] {
        assert!(
            rows_of(&v, a).is_empty(),
            "SA-11: applicant {} is listed: {text}",
            a.raw()
        );
    }
    for r in rows(&v) {
        let role = str_member(&r, "role").unwrap_or_default();
        assert!(
            !matches!(
                role.as_str(),
                "applicant" | "applicant_team_member" | "guardian"
            ),
            "SA-11: {role} is listed"
        );
    }
    let admin = actions(&v);
    for a in ["grant", "end", "reinstate"] {
        assert!(admin.iter().any(|x| x == a), "{a} for an admin: {admin:?}");
    }
    let by_pm = team(&mut seed, PM, p).unwrap_or_else(|e| panic!("team.list by PM: {e}"));
    let pm = actions(&by_pm);
    for a in ["grant", "end", "reinstate"] {
        assert!(!pm.iter().any(|x| x == a), "{a} for the manager: {pm:?}");
    }
    assert_eq!(rows(&by_pm).len(), rows(&v).len());
}

/// SA-11: nobody else reads the team page: the committee, the
/// coordinator, the lead, and a manager of another programme.
#[test]
fn sa11_team_page_refuses_everyone_but_the_manager_and_the_admins() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    let p = programme(&w);
    for a in [
        MEMBER, COORD, CHAIR, LEAD, FINANCE, AUDITOR, PM_OTHER, UNBOUND,
    ] {
        assert!(
            team(&mut seed, a, p).is_err(),
            "SA-11: {} read the team page",
            a.raw()
        );
    }
}

/// SA-11: the member page lists each member account with its display
/// name, its login email and its roles, the tenant admins included, and
/// no account that holds only Receiving roles.
#[test]
fn sa11_member_page_lists_accounts_with_roles_across_programmes() {
    let w = world(StateTag::Stage1);
    let mut seed = seeder(&w);
    seed.ports
        .accounts
        .set_login_email(PM, "manager@example.invalid");
    set_name(&mut seed, PM, s("Synthetic Programme Lead")).unwrap();
    let v = seed
        .api(ADMIN_PLAIN, GET, "/admin/members", &Value::Null)
        .unwrap_or_else(|e| panic!("admin.members: {e}"));
    let text = v.to_compact();
    let members: Vec<Value> = v
        .get("members")
        .and_then(Value::as_array)
        .map(|a| a.iter().cloned().collect())
        .unwrap_or_default();
    let of = |a: AccountId| {
        members
            .iter()
            .find(|m| str_member(m, "account") == Some(a.raw().to_string()))
            .cloned()
    };
    let pm = of(PM).unwrap_or_else(|| panic!("SA-11: PM is no member: {text}"));
    assert_eq!(
        str_member(&pm, "display_name").as_deref(),
        Some("Synthetic Programme Lead")
    );
    assert_eq!(
        str_member(&pm, "email").as_deref(),
        Some("manager@example.invalid")
    );
    let roles = pm.get("roles").and_then(Value::as_array).expect("roles");
    assert!(
        roles.iter().any(|r| {
            str_member(r, "role").as_deref() == Some("programme_manager")
                && str_member(r, "programme") == Some(programme(&w).raw().to_string())
        }),
        "SA-11: {text}"
    );
    let admin = of(ADMIN_PLAIN).unwrap_or_else(|| panic!("SA-11: no admin: {text}"));
    assert_eq!(admin.get("tenant_admin"), Some(&Value::Bool(true)));
    for a in [LEAD, TEAM, GUARDIAN] {
        assert!(of(a).is_none(), "SA-11: applicant {} listed", a.raw());
    }
    for a in [PM, MEMBER, COORD, LEAD] {
        assert!(
            seed.api(a, GET, "/admin/members", &Value::Null).is_err(),
            "SA-11: {} read the member page",
            a.raw()
        );
    }
}

/// The path of a GET read route filled from the world's targets as
/// `who` would call it, or `None` when a parameter has no value here.
fn read_path(route: &str, w: &Built, who: AccountId) -> Option<String> {
    let t = &w.targets;
    let mut out = String::new();
    for seg in route.split('/').filter(|x| !x.is_empty()) {
        out.push('/');
        let value = match seg.strip_prefix('{').and_then(|x| x.strip_suffix('}')) {
            None => seg.to_owned(),
            Some("programme") => t.programme?.raw().to_string(),
            Some("call") => t.call?.raw().to_string(),
            Some("proposal") => t.proposal?.raw().to_string(),
            Some("assignment") => t
                .assignments
                .get(&who)
                .or_else(|| t.assignments.get(&REVIEWER))?
                .raw()
                .to_string(),
            Some("irc_assignment") => t
                .irc
                .get(&who)
                .or_else(|| t.irc.get(&IRC_ASSIGNEE))?
                .raw()
                .to_string(),
            Some("round") => t.round?.raw().to_string(),
            Some(_) => return None,
        };
        out.push_str(&value);
    }
    Some(out)
}

/// I-17, P-11, I-27, SA-11: with a canary display name on every account
/// of the world, no read an applicant or a Judging role makes holds one,
/// in every state the world reaches, and neither does any message or
/// record of the ledger. The tenant admin's team page does show them, so
/// the canaries are set (teeth).
#[test]
fn sa11_i17_p11_i27_display_names_never_reach_applicant_or_judging_reads_or_messages() {
    let readers = [
        LEAD,
        TEAM,
        GUARDIAN,
        COORD,
        CHAIR,
        MEMBER,
        REVIEWER,
        IRC_MEMBER,
        IRC_ASSIGNEE,
        DRAFTER,
    ];
    let named: Vec<AccountId> = readers
        .iter()
        .copied()
        .chain([PM, FINANCE, RELEASER, SIGNATORY, AUDITOR, ADMIN_PLAIN])
        .collect();
    let excluded = ["team.list", "admin.members", "me.display_name"];
    for state in [StateTag::Draft, StateTag::Stage1, StateTag::IrcReview] {
        let w = world(state);
        let mut seed = seeder(&w);
        for a in &named {
            set_name(&mut seed, *a, s(&format!("SA11CANARY{}", a.raw())))
                .unwrap_or_else(|e| panic!("{state:?}: name of {}: {e}", a.raw()));
        }
        let mut served = 0usize;
        for spec in fstp_access::OPS {
            let Some((fstp_access::Method::Get, route)) = spec.route else {
                continue;
            };
            if excluded.contains(&spec.name) || route.starts_with("/p/") {
                continue;
            }
            for who in readers {
                let Some(path) = read_path(route, &w, who) else {
                    continue;
                };
                if let Ok(v) = seed.api(who, GET, &path, &Value::Null) {
                    served += 1;
                    let text = v.to_compact();
                    assert!(
                        !text.contains("SA11CANARY"),
                        "I-17, P-11: {} by {} in {state:?} shows a display name: {text}",
                        spec.name,
                        who.raw()
                    );
                }
            }
        }
        assert!(served > 20, "{state:?}: only {served} reads served");
        let ledger = format!("{:?}", seed.ports.engine.state());
        assert!(
            !ledger.contains("SA11CANARY"),
            "I-27: a display name reached the ledger or a message in {state:?}"
        );
        // Teeth: the tenant admin's team page shows the canaries.
        if let Some(p) = w.targets.programme {
            let v = team(&mut seed, ADMIN_PLAIN, p).unwrap();
            assert!(v.to_compact().contains("SA11CANARY"), "{state:?}");
        }
    }
}
