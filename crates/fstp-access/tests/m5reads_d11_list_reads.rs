//! D11, R-AC-01, I-85, I-86 (M5 reads follow-up): the two caller lists
//! the post-grant screens read, `grant.list_mine` and
//! `contract.awaiting_me`.
//!
//! Each is the caller's own object: rule `Own`, open in every one of the
//! 16 proposal states, so no state leaves it unjudged. The dispatch then
//! keeps only the grants and contracts that `grant.overview` and
//! `contract.view` would serve the caller, so the lists never widen
//! those reads. Both are web only: no MCP tool, since `grant.overview`
//! has none (I-85). Each has a reply shape, so gen-ts emits a validator.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_access::{OpKind, ReadKind, ReadRule, op, read_rule, reply};
use fstp_domain::StateTag;

const LISTS: [(&str, ReadKind, &str); 2] = [
    ("grant.list_mine", ReadKind::ListMyGrants, "/me/grants"),
    (
        "contract.awaiting_me",
        ReadKind::ListMyContractsToSign,
        "/me/contracts-awaiting-signature",
    ),
];

/// D11: each list has one rule, `Own`, open in all 16 states.
#[test]
fn d11_m5_lists_are_own_reads_open_in_every_state() {
    for (name, kind, _) in LISTS {
        let (rule, open) = read_rule(kind).unwrap_or_else(|| panic!("{name} has no rule"));
        assert_eq!(rule, ReadRule::Own, "{name}");
        for s in StateTag::ALL {
            assert!(open.contains(&s), "D11: {name} is unjudged in {s:?}");
        }
        assert!(
            ReadKind::ALL.contains(&kind),
            "{name} is not in ReadKind::ALL"
        );
    }
}

/// I-85, R-AC-01: each list is a read with no tool, at its route, and is
/// neither high risk nor binding.
#[test]
fn i85_m5_lists_are_web_only_reads() {
    for (name, kind, path) in LISTS {
        let spec = op(name).unwrap_or_else(|| panic!("{name} is not in the registry"));
        assert_eq!(spec.kind, OpKind::Read(kind), "{name}");
        assert_eq!(spec.route.map(|(_, p)| p), Some(path), "{name}");
        assert!(spec.tool.is_none(), "I-85: {name} has an MCP tool");
        assert!(!spec.high_risk && !spec.binding, "{name}");
    }
}

/// I-86: each list has a reply shape, and none of its members names an
/// account, an email, a bank detail or vault evidence.
#[test]
fn i86_m5_list_replies_name_no_account_or_vault_value() {
    for (name, _, _) in LISTS {
        let shape = reply(name).unwrap_or_else(|| panic!("{name} has no reply shape"));
        let text = format!("{shape:?}").to_lowercase();
        for word in ["account", "email", "iban", "bank", "evidence"] {
            assert!(!text.contains(word), "I-86: {name} names {word}: {text}");
        }
    }
}

/// R-PR-07, I-58: `grant.overview` names the plan and each milestone's
/// amount, due date, paid, pending and available sums, as the cell
/// computes them (ADR-006).
#[test]
fn r_pr_07_overview_reply_names_plan_and_milestones() {
    let shape = reply("grant.overview").expect("grant.overview has a shape");
    let text = format!("{shape:?}");
    for member in [
        "\"plan\"",
        "\"milestones\"",
        "\"milestone\"",
        "\"due\"",
        "\"pending\"",
        "\"available\"",
        "\"closed\"",
    ] {
        assert!(
            text.contains(member),
            "grant.overview lacks {member}: {text}"
        );
    }
}

/// R-NG-03, D11, R-AC-01, I-03, R-CF-02: the determination view is the
/// assigned reviewer's alone, declared free of conflict, and open only in
/// NEGOTIATION. Every other state is a judged refusal. It is web only,
/// as `grant.determine_amount` is (I-85), and its reply carries only what
/// the determination needs.
#[test]
fn r_ng_03_d11_determination_view_is_the_assigned_reviewers_in_negotiation() {
    let (rule, open) = read_rule(ReadKind::GetDetermination).expect("a rule");
    assert_eq!(rule, ReadRule::ProposalReviewer);
    assert_eq!(open, &[StateTag::Negotiation]);
    assert!(ReadKind::ALL.contains(&ReadKind::GetDetermination));
    let spec = op("grant.determination_view").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetDetermination));
    assert_eq!(
        spec.route.map(|(_, p)| p),
        Some("/grants/{proposal}/determination")
    );
    assert!(
        spec.tool.is_none(),
        "I-85: the determination view has a tool"
    );
    let text = format!("{:?}", reply("grant.determination_view").expect("a shape"));
    for member in [
        "\"plan\"",
        "\"plan_total\"",
        "\"determination\"",
        "\"granted\"",
    ] {
        assert!(text.contains(member), "lacks {member}: {text}");
    }
    for leak in [
        "\"paid\"",
        "\"contract\"",
        "\"requests\"",
        "\"milestones\"",
        "account",
        "bank",
    ] {
        assert!(
            !text.contains(leak),
            "the determination view names {leak}: {text}"
        );
    }
}

/// R-PR-08, D11, R-AC-01, I-03, R-CF-02, I-86 (lane m5/polish-access):
/// the line review view is the assigned reviewer's alone, declared free
/// of conflict, and open only while the grant is IN_EXECUTION. Every
/// other state is a judged refusal. The dispatch narrows it further to a
/// request in UNDER_REVIEW. It is web only, as `payment.review_line` is
/// (I-85). Its reply carries the request, its lines, their evidence and
/// the checks, and nothing about bank details, accounts or the grant.
#[test]
fn r_pr_08_d11_line_review_view_is_the_assigned_reviewers_in_execution() {
    let (rule, open) = read_rule(ReadKind::GetLineReview).expect("a rule");
    assert_eq!(rule, ReadRule::ProposalReviewer);
    assert_eq!(open, &[StateTag::InExecution]);
    assert!(ReadKind::ALL.contains(&ReadKind::GetLineReview));
    let spec = op("payment.line_review_view").expect("in the registry");
    assert_eq!(spec.kind, OpKind::Read(ReadKind::GetLineReview));
    assert_eq!(
        spec.route.map(|(_, p)| p),
        Some("/grants/{proposal}/payment-requests/{request}/line-review")
    );
    assert!(spec.tool.is_none(), "I-85: the line review view has a tool");
    let text = format!("{:?}", reply("payment.line_review_view").expect("a shape"));
    for member in [
        "\"request\"",
        "\"status\"",
        "\"submission_checks\"",
        "\"acceptance_checks\"",
        "\"lines\"",
        "\"requested\"",
        "\"approved\"",
        "\"location\"",
        "\"release\"",
        "\"licence\"",
        "\"report\"",
    ] {
        assert!(text.contains(member), "lacks {member}: {text}");
    }
    for leak in [
        "account", "bank", "iban", "payee", "\"paid\"", "contract", "email",
    ] {
        assert!(
            !text.contains(leak),
            "the line review view names {leak}: {text}"
        );
    }
}
