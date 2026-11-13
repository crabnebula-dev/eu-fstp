//! The M5 reads follow-up through the API (`docs/handoff/m5-ui.md`):
//! `grant.list_mine`, `contract.awaiting_me` and the plan and milestones
//! of `grant.overview`.
//!
//! - R-AC-01, D11, SoD: the grant list of every account of the cast holds
//!   exactly the grants `grant.overview` serves that account. A programme
//!   manager of another programme, an ended binding and a committee
//!   member see none.
//! - R-CT-01, P-30: a contract version waits on the grantee side first and
//!   on the signatory only once the grantee side signed. It leaves each
//!   list once its party signed.
//! - R-PR-07, I-58, ADR-006: the milestones of `grant.overview` carry the
//!   cell's own paid, pending and available sums, the same strings as the
//!   domain view, and a new request lowers what is available.
//! - I-86: no reply names an account, an email or a bank value.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;
use fstp_domain::id::MilestoneId;

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

fn seeder(w: Built) -> Seeder {
    Seeder {
        ports: w.ports,
        core: w.core,
        now: w.now,
        command: 900_000,
        cookies: BTreeMap::new(),
        next_id: 90_000_000,
        admins: w.admins.iter().copied().collect(),
    }
}

/// I-86: an email, or a member that names an account, vault evidence or
/// bank details.
fn leaks(json: &str) -> bool {
    json.contains('@')
        || json.contains("account")
        || json.contains("evidence")
        || json.contains("iban")
        || json.contains("bank")
}

fn read(seed: &mut Seeder, who: AccountId, path: &str) -> Value {
    let v = seed
        .api(who, GET, path, &Value::Null)
        .unwrap_or_else(|e| panic!("{path} by {who:?}: {e}"));
    let text = v.to_compact();
    assert!(!leaks(&text), "I-86: {path} leaks: {text}");
    v
}

fn rows(v: &Value) -> Vec<Value> {
    v.as_array()
        .unwrap_or_else(|| panic!("not an array: {}", v.to_compact()))
        .iter()
        .cloned()
        .collect()
}

/// The proposals of `who`'s grant list, with the `via` of each.
fn grant_list(seed: &mut Seeder, who: AccountId) -> Vec<(String, String)> {
    rows(&read(seed, who, "/me/grants"))
        .iter()
        .map(|r| {
            (
                str_member(r, "proposal").expect("proposal"),
                str_member(r, "via").expect("via"),
            )
        })
        .collect()
}

/// The `(contract, role, state)` of each row of `who`'s signing list.
fn to_sign(seed: &mut Seeder, who: AccountId) -> Vec<(String, String, String)> {
    rows(&read(seed, who, "/me/contracts-awaiting-signature"))
        .iter()
        .map(|r| {
            (
                str_member(r, "contract").expect("contract"),
                str_member(r, "role").expect("role"),
                str_member(r, "state").expect("state"),
            )
        })
        .collect()
}

/// R-AC-01, D11, SoD: for every account of the cast, the grant list holds
/// X exactly when `grant.overview` of X serves that account, in each
/// state a grant can be in that the worlds build.
#[test]
fn r_ac_01_d11_grant_list_matches_overview_access_for_every_account() {
    for state in [
        StateTag::Negotiation,
        StateTag::InExecution,
        StateTag::Completed,
        StateTag::Stage1,
    ] {
        let w = world(state);
        let x = w.targets.proposal.expect("X").raw().to_string();
        let mut seed = seeder(w);
        for who in CAST
            .into_iter()
            .filter(|a| ![ADMIN_SOLE.raw(), 990, 991].contains(&a.raw()))
        {
            let listed = grant_list(&mut seed, who);
            let ids: Vec<&str> = listed.iter().map(|(p, _)| p.as_str()).collect();
            let served = seed
                .api(who, GET, &format!("/grants/{x}"), &Value::Null)
                .is_ok();
            assert_eq!(
                ids.contains(&x.as_str()),
                served,
                "R-AC-01 in {state:?}: {who:?} lists {ids:?}, overview served {served}"
            );
            // Every listed grant is one the overview serves.
            for p in &ids {
                assert!(
                    seed.api(who, GET, &format!("/grants/{p}"), &Value::Null)
                        .is_ok(),
                    "R-AC-01 in {state:?}: {who:?} lists {p} it may not read"
                );
            }
        }
    }
}

/// R-AC-01, SoD: the grant list names why each grant is there, and the
/// roles outside the grant's programme or bindings see nothing.
#[test]
fn r_ac_01_grant_list_names_the_admitting_role() {
    let w = world(StateTag::InExecution);
    let x = w.targets.proposal.expect("X").raw().to_string();
    let mut seed = seeder(w);
    let via = |seed: &mut Seeder, who| {
        grant_list(seed, who)
            .into_iter()
            .find(|(p, _)| *p == x)
            .map(|(_, v)| v)
    };
    assert_eq!(via(&mut seed, LEAD).as_deref(), Some("team"));
    assert_eq!(via(&mut seed, PM).as_deref(), Some("programme_manager"));
    assert_eq!(via(&mut seed, FINANCE).as_deref(), Some("finance_approver"));
    assert_eq!(
        via(&mut seed, RELEASER).as_deref(),
        Some("payment_releaser")
    );
    assert_eq!(
        via(&mut seed, SIGNATORY).as_deref(),
        Some("contract_signatory")
    );
    assert_eq!(via(&mut seed, AUDITOR).as_deref(), Some("auditor"));
    // SoD-12, R-PR-08 (2026-11-13): the assigned reviewer reads the
    // overview after NEGOTIATION, for the line review.
    assert_eq!(
        via(&mut seed, REVIEWER).as_deref(),
        Some("assigned_reviewer")
    );
    for outsider in [PM_OTHER, PM_ENDED, MEMBER, UNBOUND, LEAD_Y] {
        assert_eq!(via(&mut seed, outsider), None, "{outsider:?} lists X");
    }
}

/// `who`'s signing list through the MCP tool `fstp_list_contracts_to_sign`
/// with a token of `scopes` (decided by Daniel on 2026-11-13).
fn to_sign_mcp(seed: &mut Seeder, who: AccountId, scopes: &[Scope]) -> Result<Value, String> {
    seed.tick();
    let token = seed.ports.tokens.issue(
        who,
        agent_of(who),
        scopes.iter().copied(),
        LoginMethod::Passkey,
    );
    let r = decode_tool("fstp_list_contracts_to_sign", b"{}").and_then(|op| {
        block_on(
            seed.core
                .dispatch(Credential::Bearer(token), &RequestHead::new(), op),
        )
    });
    match r {
        Ok(OpResult::Done { body, .. }) => Ok(body.to_json()),
        Ok(other) => Err(other.to_json().to_compact()),
        Err(e) => Err(e.to_json().to_compact()),
    }
}

/// R-CT-01, P-30, I-86: the signing list follows the signing order. The
/// grantee side waits first; the signatory only after it; nobody once the
/// version is effective. The programme manager is never a party.
#[test]
fn r_ct_01_contracts_awaiting_me_follow_the_signing_order() {
    let w = world(StateTag::Negotiation);
    let x = w.targets.proposal.expect("X");
    let plan = w.targets.plan.expect("plan");
    let mut seed = seeder(w);
    seed.at(1_798_761_600 * SECOND);
    let fake = fstp_contract::fake::FakeTrustServices::new(seed.now / SECOND).unwrap();
    let trust = fake.trusted_list();
    seed.core = Arc::new(fstp_api_core::port::api_core_with_signing(
        seed.ports.clone(),
        Box::new(fake),
        Box::new(trust),
    ));
    seed.api(
        REVIEWER,
        POST,
        &format!("/grants/{}/amount-determination", x.raw()),
        &obj(vec![
            ("agreed", dec(plan)),
            ("deductions", Value::Array(Array::new())),
            ("currency", s("EUR")),
        ]),
    )
    .unwrap();
    let o = read(&mut seed, LEAD, &format!("/grants/{}", x.raw()));
    let det = obj(vec![(
        "determination",
        s(&str_member(&o, "determination").unwrap()),
    )]);
    seed.api(LEAD, POST, &format!("/grants/{}/acceptance", x.raw()), &det)
        .unwrap();
    seed.api(PM, POST, &format!("/grants/{}/approval", x.raw()), &det)
        .unwrap();
    let v = seed
        .api(
            PM,
            POST,
            &format!("/grants/{}/contract", x.raw()),
            &obj(vec![]),
        )
        .unwrap();
    let k = str_member(&v, "contract").unwrap();
    // A drafted version waits on nobody.
    for who in [LEAD, SIGNATORY, PM] {
        assert!(to_sign(&mut seed, who).is_empty(), "{who:?} before send");
    }
    seed.api(PM, POST, &format!("/contracts/{k}/send"), &obj(vec![]))
        .unwrap();
    assert_eq!(
        to_sign(&mut seed, LEAD),
        vec![(k.clone(), "lead".to_owned(), "sent".to_owned())]
    );
    assert!(
        to_sign(&mut seed, SIGNATORY).is_empty(),
        "P-30: the signatory countersigns last"
    );
    assert!(to_sign(&mut seed, PM).is_empty());
    // I-84, I-86 (decided by Daniel on 2026-11-13): the MCP tool answers
    // the same rows as the web read, names no account or bank value, and
    // needs the scope of `contract.view`.
    let web = read(&mut seed, LEAD, "/me/contracts-awaiting-signature");
    let agent = to_sign_mcp(&mut seed, LEAD, &Scope::ALL).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(agent.to_compact(), web.to_compact(), "I-84: as the web");
    assert!(!leaks(&agent.to_compact()), "I-86: {}", agent.to_compact());
    let e = to_sign_mcp(&mut seed, LEAD, &[]).expect_err("no scope");
    assert!(e.contains("\"scope\""), "I-84: refused for its scope: {e}");
    let signatory =
        to_sign_mcp(&mut seed, SIGNATORY, &Scope::ALL).unwrap_or_else(|e| panic!("{e}"));
    assert_eq!(signatory.to_compact(), "[]", "P-30 through MCP");
    seed.api(
        LEAD,
        POST,
        &format!("/contracts/{k}/signature"),
        &obj(vec![("route", s("wallet_qes"))]),
    )
    .unwrap();
    assert!(to_sign(&mut seed, LEAD).is_empty(), "signed, yet listed");
    let guardian = to_sign(&mut seed, GUARDIAN);
    if !guardian.is_empty() {
        assert_eq!(guardian[0].1, "guardian");
        assert!(to_sign(&mut seed, SIGNATORY).is_empty());
        seed.api(
            GUARDIAN,
            POST,
            &format!("/contracts/{k}/signature"),
            &obj(vec![("route", s("wallet_qes"))]),
        )
        .unwrap();
    }
    assert_eq!(
        to_sign(&mut seed, SIGNATORY),
        vec![(
            k.clone(),
            "signatory".to_owned(),
            "signed_by_grantee".to_owned()
        )]
    );
    seed.api(
        SIGNATORY,
        POST,
        &format!("/contracts/{k}/signature"),
        &obj(vec![("route", s("qtsp_remote_qes"))]),
    )
    .unwrap();
    for who in [LEAD, GUARDIAN, SIGNATORY, PM] {
        assert!(to_sign(&mut seed, who).is_empty(), "{who:?} after effect");
    }
}

/// The member `k` of `v` as an array of objects.
fn milestones(v: &Value) -> Vec<Value> {
    rows(v.get("milestones").expect("milestones"))
}

/// R-PR-07, I-58, ADR-006: the overview's milestones are the domain
/// view's, as strings the cell formats, and a request lowers what is
/// available on its milestone by its amount.
#[test]
fn r_pr_07_i58_overview_milestones_are_the_cells_sums() {
    let w = world(StateTag::InExecution);
    let x = w.targets.proposal.expect("X");
    let mut seed = seeder(w);
    let agree = |seed: &mut Seeder| -> Value {
        let o = read(seed, LEAD, &format!("/grants/{}", x.raw()));
        let state = seed.ports.engine.state();
        let view = fstp_domain::payment::grant_milestones(&state.core, x).expect("a view");
        assert_eq!(
            str_member(&o, "plan"),
            Some(view.plan.raw().to_string()),
            "the plan"
        );
        let ms = milestones(&o);
        assert_eq!(ms.len(), view.milestones.len());
        for (row, m) in ms.iter().zip(view.milestones.iter()) {
            let id = m.milestone.raw().to_string();
            assert_eq!(str_member(row, "milestone"), Some(id.clone()));
            for (k, want) in [
                ("amount", m.amount.amount().to_string()),
                ("paid", m.paid.amount().to_string()),
                ("pending", m.pending.amount().to_string()),
                ("available", m.available.amount().to_string()),
            ] {
                assert_eq!(str_member(row, k), Some(want), "{k} of {id}");
            }
            assert_eq!(
                str_member(row, "due").map(|d| d.len()),
                Some(10),
                "due is a day"
            );
        }
        o
    };
    let before = agree(&mut seed);
    let first = milestones(&before)
        .into_iter()
        .find(|m| str_member(m, "available").is_some_and(|a| a != "0.00"))
        .expect("a milestone with money available");
    let milestone =
        MilestoneId::from_raw(str_member(&first, "milestone").unwrap().parse().unwrap());
    let line = obj(vec![
        ("milestone", dec(milestone.raw())),
        ("amount", s("1.00")),
        (
            "evidence",
            obj(vec![
                ("location", s("https://forge.example/synthetic/repo")),
                ("release", s("v1.0.0")),
                ("licence", s("MIT")),
                ("report", s("SYNTHETIC DELIVERY REPORT")),
            ]),
        ),
    ]);
    seed.api(
        LEAD,
        POST,
        &format!("/grants/{}/payment-requests", x.raw()),
        &obj(vec![
            ("kind", obj(vec![("type", s("Milestone"))])),
            ("currency", s("EUR")),
            ("lines", Value::Array(Array::from(vec![line]))),
        ]),
    )
    .unwrap();
    let after = agree(&mut seed);
    let row = milestones(&after)
        .into_iter()
        .find(|m| str_member(m, "milestone") == Some(milestone.raw().to_string()))
        .unwrap();
    assert_ne!(
        str_member(&row, "available"),
        str_member(&first, "available"),
        "I-58: the request held nothing"
    );
    assert_ne!(str_member(&row, "pending").as_deref(), Some("0.00"));
    // The overview stays closed to outsiders, milestones and all.
    assert!(
        seed.api(MEMBER, GET, &format!("/grants/{}", x.raw()), &Value::Null)
            .is_err()
    );
}

/// R-NG-03, R-AC-01, I-03, R-CF-02, I-86: in NEGOTIATION the assigned
/// reviewer reads the determination view of X. The view names the plan
/// the determination starts from and nothing about money paid, the
/// contract or requests. An unassigned committee member, an undeclared
/// and a conflicted reviewer, the lead and the programme manager are
/// refused. After the determination the view names it, and the domain
/// accepts the plan it named.
#[test]
fn r_ng_03_assigned_reviewer_reads_the_determination_view() {
    let w = world(StateTag::Negotiation);
    let x = w.targets.proposal.expect("X");
    let plan = w.targets.plan.expect("plan");
    let mut seed = seeder(w);
    let path = format!("/grants/{}/determination", x.raw());
    let v = read(&mut seed, REVIEWER, &path);
    let keys: Vec<String> = v
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, _)| k.to_owned())
        .collect();
    assert_eq!(
        keys,
        [
            "proposal",
            "state",
            "determination",
            "plan",
            "plan_total",
            "granted"
        ],
        "I-86: only what the determination needs"
    );
    assert_eq!(str_member(&v, "state").as_deref(), Some("NEGOTIATION"));
    assert_eq!(str_member(&v, "plan"), Some(plan.to_string()));
    assert!(str_member(&v, "plan_total").is_some(), "the plan total");
    let refused = |seed: &mut Seeder, who: AccountId| -> String {
        seed.api(who, GET, &path, &Value::Null)
            .expect_err("refused")
    };
    assert!(refused(&mut seed, MEMBER).contains("R-AC-01"), "unassigned");
    assert!(
        refused(&mut seed, REVIEWER_UNDECLARED).contains("R-CF-02"),
        "undeclared"
    );
    assert!(
        refused(&mut seed, REVIEWER_CONFLICTED).contains("I-03"),
        "conflicted: {}",
        refused(&mut seed, REVIEWER_CONFLICTED)
    );
    for who in [LEAD, PM, REVIEWER_RELEASED, UNBOUND] {
        assert!(refused(&mut seed, who).contains("R-AC-01"), "{who:?}");
    }
    seed.api(
        REVIEWER,
        POST,
        &format!("/grants/{}/amount-determination", x.raw()),
        &obj(vec![
            ("agreed", s(&str_member(&v, "plan").unwrap())),
            ("deductions", Value::Array(Array::new())),
            ("currency", s("EUR")),
        ]),
    )
    .unwrap();
    let after = read(&mut seed, REVIEWER, &path);
    assert!(str_member(&after, "determination").is_some());
    assert_eq!(
        str_member(&after, "granted"),
        str_member(&after, "plan_total")
    );
}

/// R-NG-03, D11: outside NEGOTIATION the assigned reviewer reads no
/// determination view.
#[test]
fn r_ng_03_d11_determination_view_is_closed_outside_negotiation() {
    for state in [StateTag::Stage2, StateTag::InExecution, StateTag::Completed] {
        let w = world(state);
        let x = w.targets.proposal.expect("X");
        let mut seed = seeder(w);
        let e = seed
            .api(
                REVIEWER,
                GET,
                &format!("/grants/{}/determination", x.raw()),
                &Value::Null,
            )
            .expect_err("closed");
        assert!(
            e.contains("R-AC-01") || e.contains("I-03"),
            "{state:?}: {e}"
        );
    }
}

/// The path of the line review view of request `r` of grant `x`.
fn line_review_path(x: ProposalId, r: u128) -> String {
    format!("/grants/{}/payment-requests/{r}/line-review", x.raw())
}

/// R-PR-08, I-60, R-AC-01, I-03, R-CF-02, I-86 (lane m5/polish-access):
/// while a request is UNDER_REVIEW, the assigned reviewer of the grant
/// reads the line review view and decides each line from it. The view
/// names the request, its lines with their evidence, and the checks, and
/// no bank detail, account or email. An unassigned committee member, an
/// undeclared, a conflicted or a released reviewer, the lead, the
/// programme manager, finance, the releaser and an unbound person are
/// refused. Once the line is decided the request is ACCEPTED, the view
/// closes, and the reviewer cannot approve it either (SoD-04, I-05).
#[test]
fn r_pr_08_assigned_reviewer_reads_and_decides_the_line_review() {
    let w = world(StateTag::InExecution);
    let x = w.targets.proposal.expect("X");
    let r = w.targets.request.expect("a request under review");
    let accepted = w.targets.accepted.expect("an accepted request");
    let mut seed = seeder(w);
    let path = line_review_path(x, r);
    let v = seed
        .api(REVIEWER, GET, &path, &Value::Null)
        .unwrap_or_else(|e| panic!("{path}: {e}"));
    let text = v.to_compact();
    assert!(!text.contains('@'), "I-86: an email in {text}");
    for leak in ["account", "bank", "iban", "payee"] {
        assert!(!text.contains(leak), "I-86: {leak} in {text}");
    }
    let keys: Vec<String> = v
        .as_object()
        .expect("an object")
        .iter()
        .map(|(k, _)| k.to_owned())
        .collect();
    assert_eq!(
        keys,
        [
            "request",
            "proposal",
            "status",
            "kind",
            "submission_checks",
            "acceptance_checks",
            "lines"
        ],
        "I-86: only what the line review needs"
    );
    assert_eq!(str_member(&v, "status").as_deref(), Some("UNDER_REVIEW"));
    assert_eq!(str_member(&v, "request"), Some(r.to_string()));
    let lines = rows(v.get("lines").expect("lines"));
    assert_eq!(lines.len(), 1);
    let line = &lines[0];
    assert_eq!(
        str_member(line, "location").as_deref(),
        Some("https://forge.example/synthetic/repo"),
        "R-PR-01: the evidence the lead gave"
    );
    assert_eq!(str_member(line, "release").as_deref(), Some("v1.0.0"));
    assert_eq!(str_member(line, "licence").as_deref(), Some("MIT"));
    assert_eq!(
        str_member(line, "report").as_deref(),
        Some("SYNTHETIC DELIVERY REPORT")
    );
    assert_eq!(str_member(line, "requested").as_deref(), Some("100.00"));
    let refused = |seed: &mut Seeder, who: AccountId| -> String {
        seed.api(who, GET, &path, &Value::Null)
            .expect_err("refused")
    };
    assert!(refused(&mut seed, MEMBER).contains("R-AC-01"), "unassigned");
    assert!(
        refused(&mut seed, REVIEWER_UNDECLARED).contains("R-CF-02"),
        "undeclared"
    );
    assert!(
        refused(&mut seed, REVIEWER_CONFLICTED).contains("I-03"),
        "conflicted"
    );
    for who in [
        LEAD,
        TEAM,
        PM,
        FINANCE,
        RELEASER,
        AUDITOR,
        REVIEWER_RELEASED,
        UNBOUND,
    ] {
        assert!(refused(&mut seed, who).contains("R-AC-01"), "{who:?}");
    }
    // A request that is not UNDER_REVIEW has no line review view.
    let e = seed
        .api(REVIEWER, GET, &line_review_path(x, accepted), &Value::Null)
        .expect_err("ACCEPTED is closed");
    assert!(e.contains("R-AC-01"), "{e}");
    // R-PR-08, I-60: the reviewer approves a lower amount with a reason,
    // once the acceptance checks passed (I-32).
    let id = str_member(line, "line").expect("line id");
    m5_checks(
        &mut seed,
        fstp_domain::id::RequestId::from_raw(r),
        fstp_domain::id::LineId::from_raw(id.parse().unwrap()),
        fstp_domain::payment::CheckPhase::Acceptance,
    )
    .unwrap();
    let again = seed.api(REVIEWER, GET, &path, &Value::Null).unwrap();
    assert_eq!(
        again.get("acceptance_checks"),
        Some(&Value::Bool(true)),
        "I-32: the view shows the passed checks"
    );
    seed.api(
        REVIEWER,
        POST,
        &format!("/payment-requests/{r}/lines/{id}/decision"),
        &obj(vec![
            ("approved", s("80.00")),
            ("currency", s("EUR")),
            ("reason", s("SYNTHETIC REDUCTION REASON")),
        ]),
    )
    .unwrap();
    let e = seed
        .api(REVIEWER, GET, &path, &Value::Null)
        .expect_err("the review is over");
    assert!(e.contains("R-AC-01"), "{e}");
    // SoD-04, I-05: the line reviewer neither approves nor releases.
    assert!(
        seed.api(
            REVIEWER,
            POST,
            &format!("/payment-requests/{r}/approval"),
            &obj(vec![])
        )
        .is_err(),
        "SoD-04: the reviewer approved"
    );
}

/// R-PR-08, D11: outside IN_EXECUTION the assigned reviewer reads no
/// line review view.
#[test]
fn r_pr_08_d11_line_review_view_is_closed_outside_execution() {
    for state in [
        StateTag::Negotiation,
        StateTag::Granted,
        StateTag::Completed,
    ] {
        let w = world(state);
        let x = w.targets.proposal.expect("X");
        let mut seed = seeder(w);
        let e = seed
            .api(REVIEWER, GET, &line_review_path(x, 1), &Value::Null)
            .expect_err("closed");
        assert!(
            e.contains("R-AC-01") || e.contains("I-03"),
            "{state:?}: {e}"
        );
    }
}

/// R-PR-08, SoD-12, R-AC-01, I-03, R-CF-02, I-86 (decided by Daniel on
/// 2026-11-13): the assigned reviewer reads the grant overview after
/// NEGOTIATION, for the line review of payment requests. An undeclared or
/// conflicted assignee and an unassigned member are refused. In
/// NEGOTIATION the reviewer reads the determination view, not the
/// overview. The contract and payment status reads stay closed to the
/// reviewer, and the overview names no account or bank value.
#[test]
fn r_pr_08_sod_12_assigned_reviewer_reads_the_overview_after_negotiation() {
    for state in [
        StateTag::Granted,
        StateTag::InExecution,
        StateTag::Completed,
    ] {
        let w = world(state);
        let x = w.targets.proposal.expect("X").raw();
        let mut seed = seeder(w);
        let path = format!("/grants/{x}");
        let v = read(&mut seed, REVIEWER, &path);
        assert_eq!(str_member(&v, "proposal"), Some(x.to_string()));
        let refused = |seed: &mut Seeder, who: AccountId, p: &str| -> String {
            seed.api(who, GET, p, &Value::Null).expect_err("refused")
        };
        assert!(
            refused(&mut seed, REVIEWER_UNDECLARED, &path).contains("R-CF-02"),
            "{state:?}: undeclared"
        );
        assert!(
            refused(&mut seed, REVIEWER_CONFLICTED, &path).contains("I-03"),
            "{state:?}: conflicted"
        );
        for who in [MEMBER, REVIEWER_RELEASED, UNBOUND] {
            assert!(
                refused(&mut seed, who, &path).contains("R-AC-01"),
                "{state:?}: {who:?}"
            );
        }
        for other in [
            format!("/grants/{x}/contract"),
            format!("/grants/{x}/payment-requests"),
        ] {
            assert!(
                refused(&mut seed, REVIEWER, &other).contains("R-AC-01"),
                "{state:?}: the reviewer read {other}"
            );
        }
        let listed = grant_list(&mut seed, REVIEWER);
        assert!(
            listed
                .iter()
                .any(|(p, via)| *p == x.to_string() && via == "assigned_reviewer"),
            "{state:?}: {listed:?}"
        );
    }
    let w = world(StateTag::Negotiation);
    let x = w.targets.proposal.expect("X").raw();
    let mut seed = seeder(w);
    let e = seed
        .api(REVIEWER, GET, &format!("/grants/{x}"), &Value::Null)
        .expect_err("closed in NEGOTIATION");
    assert!(e.contains("R-AC-01"), "{e}");
}

/// The programme ids of `who`'s `report.programmes`.
fn report_programmes(seed: &mut Seeder, who: AccountId) -> Vec<String> {
    rows(&read(seed, who, "/me/report-programmes"))
        .iter()
        .map(|r| {
            let name = str_member(r, "name").expect("name");
            let id = str_member(r, "id").expect("id");
            assert_eq!(name, format!("Programme {id}"), "the synthetic name");
            id
        })
        .collect()
}

/// R-RP-03, R-AC-01, SoD (lane m5/report-programmes): the tenant-wide
/// Financial signatory, who approves funder reports, lists the programme
/// P and then reads its reports by clicking. A programme manager and an
/// auditor of P list it too. An applicant and a reviewer are refused,
/// and a programme manager of another programme does not list P. Every
/// listed programme is one `report.list` serves the caller.
#[test]
fn r_rp_03_report_programmes_admit_the_financial_signatory_only_among_outsiders() {
    let w = world(StateTag::Granted);
    let p = w.targets.programme.expect("P").raw().to_string();
    let mut seed = seeder(w);
    for who in [ORG_SIGNATORY, PM, AUDITOR] {
        let listed = report_programmes(&mut seed, who);
        assert!(listed.contains(&p), "R-RP-03: {who:?} lists {listed:?}");
        for q in &listed {
            assert!(
                seed.api(who, GET, &format!("/programmes/{q}/reports"), &Value::Null)
                    .is_ok(),
                "R-AC-01: {who:?} lists {q} whose reports it may not read"
            );
        }
    }
    assert!(
        !report_programmes(&mut seed, PM_OTHER).contains(&p),
        "R-AC-01: a manager of another programme lists P"
    );
    for who in [LEAD, REVIEWER] {
        let e = seed
            .api(who, GET, "/me/report-programmes", &Value::Null)
            .expect_err("refused");
        assert!(e.contains("R-AC-01"), "{who:?}: {e}");
    }
}
