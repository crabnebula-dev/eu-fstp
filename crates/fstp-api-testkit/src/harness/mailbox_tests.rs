//! Lane m6/mailbox (`docs/handoff/mailbox-design.md` section 7): the
//! mailbox read `me.mailbox` on the matrix worlds, through
//! `ApiCore::dispatch` with each principal's own passkey session.
//!
//! - T1 (I-86, R-AC-01, D11): every message of every principal opens a
//!   page whose read that principal may perform, in each state where
//!   work exists, and the kinds the worlds give are the ones expected.
//! - T2 (MB-D2): a signature, a payment approval, a ballot, a
//!   declaration and a discarded pending action each close their message
//!   on the next read, with no write of the mailbox's own.
//! - T3 (SoD-04, I-05): a releaser who approved a request gets no release
//!   message for it.
//! - T4 (I-27, I-86): every reply holds ids, kinds, instants, flags and
//!   `/app/` paths only, never an email or a world text.
//! - T6 (I-85): a pending action is listed for its own account only.
//!
//! Every account and text is synthetic.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

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
        command: 910_000,
        cookies: BTreeMap::new(),
        next_id: 91_000_000,
        admins: w.admins.iter().copied().collect(),
    }
}

/// The members a message may hold (design section 1).
const MEMBERS: [&str; 14] = [
    "id",
    "kind",
    "action",
    "href",
    "since",
    "due",
    "proposal",
    "call",
    "assignment",
    "round",
    "contract",
    "request",
    "pending",
    "programme",
];

/// The id members of a message.
const IDS: [&str; 10] = [
    "since",
    "due",
    "proposal",
    "call",
    "assignment",
    "round",
    "contract",
    "request",
    "pending",
    "programme",
];

fn is_decimal(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit())
}

/// Whether `href` is route `pattern` with each `{name}` a decimal id.
fn matches_route(href: &str, pattern: &str) -> bool {
    let a: Vec<&str> = href.split('/').collect();
    let b: Vec<&str> = pattern.split('/').collect();
    a.len() == b.len()
        && a.iter().zip(&b).all(|(x, y)| {
            if y.starts_with('{') {
                is_decimal(x)
            } else {
                x == y
            }
        })
}

/// The messages of a reply.
fn messages(v: &Value) -> Vec<Value> {
    match v.get("messages") {
        Some(Value::Array(a)) => a.iter().cloned().collect(),
        other => panic!("no messages: {other:?}"),
    }
}

fn text<'a>(m: &'a Value, k: &str) -> &'a str {
    m.get(k).and_then(Value::as_str).unwrap_or("")
}

/// T4, I-27, I-86: the reply is `{open, messages}`, each message holds
/// the members of design section 1 only, every id is a decimal string,
/// the page matches the route of its kind, `open` counts the work, and
/// no email or world text appears.
fn check_reply(v: &Value, texts: &[&str], who: Who) {
    let compact = v.to_compact();
    assert!(!compact.contains('@'), "I-86: {who:?}: {compact}");
    for t in texts {
        assert!(!compact.contains(t), "I-27: {who:?} shows {t:?}: {compact}");
    }
    let keys: Vec<&str> = v.as_object().unwrap().keys().collect();
    assert_eq!(keys.len(), 2, "{compact}");
    let mut work = 0i64;
    for m in messages(v) {
        let o = m.as_object().unwrap();
        for k in o.keys() {
            assert!(MEMBERS.contains(&k), "I-27: member {k} in {compact}");
        }
        for k in IDS {
            if let Some(x) = m.get(k) {
                assert!(x.as_str().is_some_and(is_decimal), "{k} in {compact}");
            }
        }
        let kind = text(&m, "kind");
        let wanted = fstp_api_core::mailbox::MailKind::ALL
            .into_iter()
            .find(|k| k.wire() == kind)
            .unwrap_or_else(|| panic!("an unknown kind {kind}"));
        assert!(
            matches_route(text(&m, "href"), wanted.route()),
            "{who:?}: {} is not {}",
            text(&m, "href"),
            wanted.route()
        );
        if m.get("action") == Some(&Value::Bool(true)) {
            work += 1;
        }
    }
    assert_eq!(v.get("open"), Some(&Value::from(work)), "{compact}");
}

fn mailbox(seed: &mut Seeder, who: AccountId) -> Value {
    seed.api(who, GET, "/me/mailbox", &Value::Null)
        .unwrap_or_else(|e| panic!("me.mailbox of {who:?}: {e}"))
}

/// The ids of the messages of kind `kind`.
fn of_kind(v: &Value, kind: &str) -> Vec<String> {
    messages(v)
        .into_iter()
        .filter(|m| text(m, "kind") == kind)
        .map(|m| text(&m, "id").to_owned())
        .collect()
}

/// The API read behind a message's page: the read `MailKind::read` names,
/// with the message's ids.
fn target_read(m: &Value) -> String {
    let id = |k: &str| text(m, k).to_owned();
    match text(m, "kind") {
        "pending.confirm" => "/me/pending-actions".to_owned(),
        "proposal.submit" => format!("/proposals/{}/workspace", id("proposal")),
        "stage2.respond" => format!("/proposals/{}/stage2", id("proposal")),
        "negotiation.acknowledge" => format!("/proposals/{}/negotiation", id("proposal")),
        "review.declare" | "irc.declare" => "/me/assignments".to_owned(),
        "review.score" => format!("/assignments/{}/score-sheet", id("assignment")),
        "irc.review" => format!("/irc-assignments/{}/case", id("assignment")),
        "intake.knock_out" => format!("/calls/{}/intake", id("call")),
        "round.vote" => format!("/cut-off-rounds/{}", id("round")),
        "admin.approve_activation" => "/admin/approvals".to_owned(),
        "contract.sign" => format!("/grants/{}/contract", id("proposal")),
        "payment.review" | "payment.approve" | "payment.release" | "payment.confirm" => {
            "/me/payment-queue".to_owned()
        }
        "notice.outcome" | "notice.irc_concern" => "/me/notices".to_owned(),
        other => panic!("no read for {other}"),
    }
}

/// The world texts no message may carry: the synthetic proposal text and
/// call texts the worlds write.
const WORLD_TEXTS: [&str; 3] = ["SYNTHETIC", "SuperSAFE", "Synthetic"];

/// The states where the worlds hold work for some principal.
const STATES: [StateTag; 11] = [
    StateTag::Draft,
    StateTag::Submitted,
    StateTag::Stage1,
    StateTag::Stage2,
    StateTag::Ranked,
    StateTag::IrcReview,
    StateTag::NotSelected,
    StateTag::Deferred,
    StateTag::Negotiation,
    StateTag::Granted,
    StateTag::InExecution,
];

/// T1, T4, I-86, R-AC-01, D11, I-27: in each state, every principal of the
/// main world reads its own mailbox; each message's page read is
/// admitted for that principal through dispatch; each reply holds ids,
/// kinds, instants and `/app/` paths only; a principal with no binding
/// has no message; and across the states the worlds give each kind
/// their seeds allow.
#[test]
fn i86_r_ac_01_mailbox_points_only_at_pages_the_reader_may_read() {
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for state in STATES {
        let mut seed = seeder(world(state));
        for who in Who::ALL {
            if Variant::of(who) != Variant::Main {
                continue;
            }
            let Some(a) = account_of(who) else {
                continue;
            };
            let v = mailbox(&mut seed, a);
            check_reply(&v, &WORLD_TEXTS, who);
            let list = messages(&v);
            if who == Who::Unbound {
                assert!(list.is_empty(), "I-86: {state:?}: {}", v.to_compact());
            }
            for m in list {
                let kind = text(&m, "kind").to_owned();
                let path = target_read(&m);
                if let Err(e) = seed.api(a, GET, &path, &Value::Null) {
                    panic!("D11: {state:?} {who:?} has {kind} but {path} refuses: {e}");
                }
                seen.insert(kind);
            }
        }
    }
    let expected = [
        "pending.confirm",
        "proposal.submit",
        "stage2.respond",
        "negotiation.acknowledge",
        "review.declare",
        "review.score",
        "irc.declare",
        "irc.review",
        "intake.knock_out",
        "payment.review",
        "payment.approve",
        "payment.release",
        "round.vote",
        "notice.outcome",
        "notice.irc_concern",
    ];
    for k in expected {
        assert!(seen.contains(k), "no world gave {k}: {seen:?}");
    }
}

/// T2, MB-D2, R-CF-02: a reviewer's declaration closes `review.declare`
/// on the next read, and nothing is written for the mailbox itself.
#[test]
fn r_cf_02_mailbox_declaration_closes_its_message() {
    let w = world(StateTag::Stage1);
    let a = *w
        .targets
        .assignments
        .get(&REVIEWER_UNDECLARED)
        .expect("an undeclared assignment");
    let mut seed = seeder(w);
    let before = mailbox(&mut seed, REVIEWER_UNDECLARED);
    assert!(
        !of_kind(&before, "review.declare").is_empty(),
        "{}",
        before.to_compact()
    );
    let head = seed.ports.engine.head();
    let _ = mailbox(&mut seed, REVIEWER_UNDECLARED);
    assert_eq!(
        seed.ports.engine.head(),
        head,
        "MB-D1: a read writes nothing"
    );
    seed.api(
        REVIEWER_UNDECLARED,
        POST,
        &format!("/assignments/{}/declaration", a.raw()),
        &obj(vec![
            ("conflicted", Value::Bool(false)),
            ("notifiable", Value::Bool(false)),
        ]),
    )
    .unwrap();
    let after = mailbox(&mut seed, REVIEWER_UNDECLARED);
    assert!(
        of_kind(&after, "review.declare").is_empty(),
        "{}",
        after.to_compact()
    );
}

/// T2, T6, I-85, MB-D2: each prepared action shows as `pending.confirm`
/// for its own account only, and a discard closes it.
#[test]
fn i85_mailbox_pending_action_is_listed_for_its_owner_and_closes() {
    let w = world(StateTag::Draft);
    let pending = w.targets.pending.clone();
    let (id, _) = pending.get(&PM).cloned().expect("a pending action of PM");
    let mut seed = seeder(w);
    let raw = id.raw().to_string();
    let mine = mailbox(&mut seed, PM);
    let listed: Vec<String> = messages(&mine)
        .into_iter()
        .filter(|m| text(m, "kind") == "pending.confirm")
        .map(|m| text(&m, "pending").to_owned())
        .collect();
    assert!(listed.contains(&raw), "{}", mine.to_compact());
    for other in [PM_DRAFTER, DRAFTER, LEAD, ADMIN_PLAIN] {
        let v = mailbox(&mut seed, other);
        assert!(
            messages(&v).iter().all(|m| text(m, "pending") != raw),
            "I-85: {other:?} sees PM's action: {}",
            v.to_compact()
        );
    }
    seed.api(
        PM,
        POST,
        &format!("/pending-actions/{raw}/discard"),
        &obj(vec![]),
    )
    .unwrap();
    let after = mailbox(&mut seed, PM);
    assert!(
        messages(&after).iter().all(|m| text(m, "pending") != raw),
        "{}",
        after.to_compact()
    );
}

/// The request ids of the messages of `kind`.
fn requests_of(v: &Value, kind: &str) -> BTreeSet<String> {
    messages(v)
        .into_iter()
        .filter(|m| text(m, "kind") == kind)
        .map(|m| text(&m, "request").to_owned())
        .collect()
}

/// T2, MB-D2, R-PR-01: the line review, approval and release messages
/// follow the requests. An approval moves its request from the finance
/// approver's mailbox to the releaser's.
#[test]
fn r_pr_01_mailbox_payment_messages_follow_the_request() {
    let w = world(StateTag::InExecution);
    let review = w
        .targets
        .request
        .expect("a request under review")
        .to_string();
    let accepted = w.targets.accepted.expect("an accepted request").to_string();
    let approved = w.targets.approved.expect("an approved request").to_string();
    let mut seed = seeder(w);
    assert!(requests_of(&mailbox(&mut seed, REVIEWER), "payment.review").contains(&review));
    let finance = mailbox(&mut seed, FINANCE);
    assert!(requests_of(&finance, "payment.approve").contains(&accepted));
    let releaser = mailbox(&mut seed, RELEASER);
    assert!(requests_of(&releaser, "payment.release").contains(&approved));
    assert!(!requests_of(&releaser, "payment.release").contains(&accepted));
    for who in [LEAD, AUDITOR, PM, MEMBER] {
        let v = mailbox(&mut seed, who);
        assert!(
            messages(&v)
                .iter()
                .all(|m| !text(m, "kind").starts_with("payment.")),
            "{who:?}: {}",
            v.to_compact()
        );
    }
    seed.api(
        FINANCE,
        POST,
        &format!("/payment-requests/{accepted}/approval"),
        &obj(vec![]),
    )
    .unwrap();
    assert!(!requests_of(&mailbox(&mut seed, FINANCE), "payment.approve").contains(&accepted));
    assert!(requests_of(&mailbox(&mut seed, RELEASER), "payment.release").contains(&accepted));
}

/// T3, SoD-04, I-05, R-EX-04: a releaser who also holds the finance
/// approver role and approved a request gets no release message for it,
/// and still gets one for a request another person approved.
#[test]
fn i05_sod04_mailbox_releaser_who_approved_gets_no_release_message() {
    let w = world(StateTag::InExecution);
    let p = w.targets.programme.expect("P");
    let accepted = w.targets.accepted.expect("an accepted request").to_string();
    let approved = w.targets.approved.expect("an approved request").to_string();
    let mut seed = seeder(w);
    grant(&mut seed, ADMIN_PLAIN, RELEASER, p, Role::FinanceApprover).unwrap();
    seed.at(seed.now.saturating_add(2 * SECOND));
    let both = mailbox(&mut seed, RELEASER);
    assert!(requests_of(&both, "payment.approve").contains(&accepted));
    seed.api(
        RELEASER,
        POST,
        &format!("/payment-requests/{accepted}/approval"),
        &obj(vec![]),
    )
    .unwrap();
    let v = mailbox(&mut seed, RELEASER);
    let release = requests_of(&v, "payment.release");
    assert!(!release.contains(&accepted), "SoD-04: {}", v.to_compact());
    assert!(release.contains(&approved), "{}", v.to_compact());
    // The domain refuses that release too, so the mailbox hid nothing a
    // person could do.
    assert!(
        seed.api(
            RELEASER,
            POST,
            &format!("/payment-requests/{accepted}/release"),
            &obj(vec![])
        )
        .is_err()
    );
}

/// T2, MB-D2, R-CT-02: once a contract version is sent, each grantee
/// party gets `contract.sign`; the signatory gets it only after the
/// grantee side signed; each signature closes the signer's message.
#[test]
fn r_ct_02_mailbox_contract_sign_follows_the_signing_order() {
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
    let o = seed
        .api(LEAD, GET, &format!("/grants/{}", x.raw()), &Value::Null)
        .unwrap();
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
    assert!(
        of_kind(&mailbox(&mut seed, LEAD), "contract.sign").is_empty(),
        "a draft is not sent"
    );
    seed.api(PM, POST, &format!("/contracts/{k}/send"), &obj(vec![]))
        .unwrap();
    let lead = mailbox(&mut seed, LEAD);
    assert_eq!(
        of_kind(&lead, "contract.sign").len(),
        1,
        "{}",
        lead.to_compact()
    );
    assert!(of_kind(&mailbox(&mut seed, SIGNATORY), "contract.sign").is_empty());
    assert!(of_kind(&mailbox(&mut seed, PM), "contract.sign").is_empty());
    let sign = |seed: &mut Seeder, who: AccountId, route: &str| {
        seed.api(
            who,
            POST,
            &format!("/contracts/{k}/signature"),
            &obj(vec![("route", s(route))]),
        )
        .unwrap();
    };
    sign(&mut seed, LEAD, "wallet_qes");
    assert!(of_kind(&mailbox(&mut seed, LEAD), "contract.sign").is_empty());
    if !of_kind(&mailbox(&mut seed, GUARDIAN), "contract.sign").is_empty() {
        sign(&mut seed, GUARDIAN, "wallet_qes");
        assert!(of_kind(&mailbox(&mut seed, GUARDIAN), "contract.sign").is_empty());
    }
    let sig = mailbox(&mut seed, SIGNATORY);
    assert_eq!(
        of_kind(&sig, "contract.sign").len(),
        1,
        "{}",
        sig.to_compact()
    );
    sign(&mut seed, SIGNATORY, "qtsp_remote_qes");
    assert!(of_kind(&mailbox(&mut seed, SIGNATORY), "contract.sign").is_empty());
}

/// T2, MB-D2, R-EV-08: a committee member's ballot closes `round.vote`
/// for that member only.
#[test]
fn r_ev_08_mailbox_ballot_closes_the_voters_message_only() {
    let mut seed = seeder(world(StateTag::Ranked));
    let committee = [CHAIR, MEMBER, REVIEWER, REVIEWER_2, DELEGATOR, RECUSED];
    let mut voters = Vec::new();
    for who in committee {
        let v = mailbox(&mut seed, who);
        if let Some(m) = messages(&v)
            .into_iter()
            .find(|m| text(m, "kind") == "round.vote")
        {
            voters.push((who, text(&m, "round").to_owned()));
        }
    }
    assert!(voters.len() >= 2, "{voters:?}");
    let (first, round) = voters[0].clone();
    seed.api(
        first,
        POST,
        &format!("/cut-off-rounds/{round}/ballot"),
        &obj(vec![("vote", s("For"))]),
    )
    .unwrap();
    assert!(of_kind(&mailbox(&mut seed, first), "round.vote").is_empty());
    let (second, _) = voters[1];
    assert_eq!(of_kind(&mailbox(&mut seed, second), "round.vote").len(), 1);
}
