//! Review reproducers for the W1c interface (spec fidelity lens).
//!
//! Each test fails against the code under review and passes once the
//! named defect is fixed. Production code is not changed here.

mod support;

use std::collections::BTreeSet;

use fstp_domain::command::CommandKind;
use fstp_domain::roles::Role;
use fstp_domain::rules::{ActorRule, TRANSITIONS, actor_rule};

use support::{read_spec, section, strip_note_refs, table};

/// Whether `rule` can only be met by an account that already holds a
/// binding in the programme the command acts on.
fn needs_programme_binding(rule: ActorRule) -> bool {
    match rule {
        ActorRule::Holder(_) => true,
        ActorRule::AnyOf(options) => options.iter().all(|o| needs_programme_binding(*o)),
        _ => false,
    }
}

/// Whether `rule` admits a holder of `role`, directly or through `AnyOf`.
fn admits_holder(rule: ActorRule, role: Role) -> bool {
    match rule {
        ActorRule::Holder(r) => r == role,
        ActorRule::AnyOf(options) => options.iter().any(|o| admits_holder(*o, role)),
        _ => false,
    }
}

/// `SPEC/02-domain/payment-requests.md` States table: PAID has actor
/// "System or finance". In record-only mode (P-20, R-EX-03) no port
/// confirms payment, so the finance approver must be able to. ACTOR_RULES
/// is the single source for the M4 matrix (I-84), so System alone over-denies.
#[test]
fn review_i84_confirm_paid_admits_finance_approver() {
    let doc = match read_spec("02-domain/payment-requests.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let lines = match section(&doc, "## States") {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let rows = match table(&lines, &["State", "Actor", "Meaning"]) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let paid_actor = rows
        .iter()
        .find(|r| r.first().is_some_and(|s| s == "PAID"))
        .and_then(|r| r.get(1).cloned())
        .unwrap_or_default();
    assert_eq!(paid_actor, "System or finance", "spec premise changed");

    let rule = match actor_rule(CommandKind::ConfirmPaid) {
        Some(r) => r,
        None => panic!("ConfirmPaid has no actor rule"),
    };
    assert!(
        admits_holder(rule, Role::FinanceApprover),
        "ConfirmPaid is {rule:?}, but the spec lets finance confirm PAID"
    );
}

/// Genesis bootstrap. `CreateProgramme` and the first `GrantRole` of a new
/// programme need `Holder(TenantAdmin)`, an active binding in that very
/// programme. No such binding can exist before the programme does, so no
/// command sequence from `State::genesis()` reaches a programme.
#[test]
fn review_genesis_programme_bootstrap_is_satisfiable() {
    let create = actor_rule(CommandKind::CreateProgramme);
    let grant = actor_rule(CommandKind::GrantRole);
    assert!(
        create.is_some_and(|r| !needs_programme_binding(r)),
        "CreateProgramme needs a binding in a programme that does not exist yet: {create:?}"
    );
    assert!(
        grant.is_some_and(|r| !needs_programme_binding(r)),
        "the first GrantRole of a programme needs a binding nobody can hold yet: {grant:?}"
    );
}

/// The `{ ... }` body that follows `opener` in `src`, up to the matching brace.
fn block_after<'a>(src: &'a str, opener: &str) -> Option<&'a str> {
    let start = src.find(opener)?;
    let body = src.get(start.checked_add(opener.len())?..)?;
    let mut depth = 1usize;
    for (i, c) in body.char_indices() {
        match c {
            '{' => depth = depth.checked_add(1)?,
            '}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return body.get(..i);
                }
            }
            _ => {}
        }
    }
    None
}

/// The text of a source file of this crate, or empty when it cannot be read.
fn src(rel: &str) -> String {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel);
    std::fs::read_to_string(path).unwrap_or_default()
}

/// R-LA-03 and design section 3.5. `Stage1Closed` carries a `DecisionId`,
/// but `Command::CloseStage1` carries none, and `due` must return
/// `CloseStage1` without one. The shell supplies every new id, so lane
/// L-LIFE has no source for the record's decision id.
#[test]
fn review_rla03_stage1_closed_decision_id_has_a_source() {
    let decision = src("src/decision.rs");
    let command = src("src/command.rs");
    let record = block_after(&decision, "pub struct Stage1Closed {").unwrap_or_default();
    let cmd = block_after(&command, "    CloseStage1 {").unwrap_or_default();
    assert!(!record.is_empty() && !cmd.is_empty(), "shapes not found");
    let record_has = record.contains("decision: DecisionId");
    let command_has = cmd.contains("decision:");
    assert!(
        !record_has || command_has,
        "Stage1Closed needs a DecisionId that CloseStage1 never supplies"
    );
}

/// I-09 and R-LA-03. `EffectiveScoreSet` carries a `DecisionId`, but
/// neither `RankAfterStage2` nor `RecordNoQuestions`, the two commands of
/// the STAGE2 to RANKED row, carries one.
#[test]
fn review_i09_effective_score_set_decision_id_has_a_source() {
    let decision = src("src/decision.rs");
    let command = src("src/command.rs");
    let record = block_after(&decision, "pub struct EffectiveScoreSet {").unwrap_or_default();
    let rank = block_after(&command, "    RankAfterStage2 {").unwrap_or_default();
    let none = block_after(&command, "    RecordNoQuestions {").unwrap_or_default();
    assert!(
        !record.is_empty() && !rank.is_empty() && !none.is_empty(),
        "shapes not found"
    );
    let record_has = record.contains("decision: DecisionId");
    assert!(
        !record_has || (rank.contains("decision:") && none.contains("decision:")),
        "EffectiveScoreSet needs a DecisionId that RankAfterStage2 and RecordNoQuestions never supply"
    );
}

/// `SPEC/03-architecture/overview.md` NOTE 5 and design sections 2.10 and
/// 4.4: each vault answer is recorded as a query digest and the answer bit.
/// `Record::VaultOutcome` stores the whole `Query`, so append-only ledger
/// bodies (I-23) keep every candidate set and per-account committed sum.
#[test]
fn review_overview_note5_vault_outcome_records_a_digest() {
    let doc = match read_spec("03-architecture/overview.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    assert!(
        doc.contains("recorded as a query digest and the answer bit"),
        "spec premise changed"
    );
    let record = src("src/record.rs");
    let body = block_after(&record, "    VaultOutcome {").unwrap_or_default();
    assert!(!body.is_empty(), "VaultOutcome not found");
    assert!(
        !body.contains(": Query,"),
        "VaultOutcome stores the full query instead of its digest"
    );
}

/// Spec identifiers (I-, SoD-, R-) cited in `text`, outside NOTE references.
fn cited_ids(text: &str) -> BTreeSet<String> {
    let text = strip_note_refs(text);
    let mut out = BTreeSet::new();
    let chars: Vec<char> = text.chars().collect();
    let mut i = 0usize;
    while i < chars.len() {
        let rest: String = chars.get(i..).unwrap_or(&[]).iter().collect();
        let prefix = ["SoD-", "I-", "R-"]
            .into_iter()
            .find(|p| rest.starts_with(p));
        let boundary = i == 0
            || chars
                .get(i.saturating_sub(1))
                .is_some_and(|c| !c.is_ascii_alphanumeric() && *c != '-');
        if let (Some(p), true) = (prefix, boundary) {
            let mut id: String = p.to_owned();
            let mut j = i.saturating_add(p.chars().count());
            if p == "R-" {
                while let Some(c) = chars.get(j).filter(|c| c.is_ascii_uppercase()) {
                    id.push(*c);
                    j = j.saturating_add(1);
                }
                if chars.get(j) == Some(&'-') {
                    id.push('-');
                    j = j.saturating_add(1);
                }
            }
            let digits_start = id.len();
            while let Some(c) = chars.get(j).filter(|c| c.is_ascii_digit()) {
                id.push(*c);
                j = j.saturating_add(1);
            }
            if id.len() > digits_start {
                out.insert(id);
            }
            i = j.max(i.saturating_add(1));
        } else {
            i = i.saturating_add(1);
        }
    }
    out
}

/// The transitions test compares only From, To and Actor, so a one-cell
/// edit of a Guard cell goes unnoticed. Every invariant, SoD rule and
/// requirement a Guard cell cites must be the rule of one of that row's
/// guards, or a spec edit to a guard can drift silently from `TRANSITIONS`.
#[test]
fn review_transition_guard_cells_match_guard_rules() {
    let doc = match read_spec("02-domain/state-machine.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let lines = match section(&doc, "## Transitions") {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let rows = match table(&lines, &["From", "To", "Actor", "Guard"]) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let mut missing = Vec::new();
    for row in rows {
        let from = row.first().cloned().unwrap_or_default();
        let to = row.get(1).cloned().unwrap_or_default();
        let guard = row.get(3).cloned().unwrap_or_default();
        let rules: Vec<_> = TRANSITIONS
            .iter()
            .filter(|r| {
                to.split(" or ").any(|t| t.trim() == r.to.spec_name())
                    && (from.starts_with("any ") || r.from.iter().any(|f| f.spec_name() == from))
            })
            .collect();
        let named: BTreeSet<String> = rules
            .iter()
            .flat_map(|r| r.guards.iter())
            .filter_map(|g| g.rule().spec_id())
            .map(str::to_owned)
            .collect();
        for id in cited_ids(&guard) {
            if !named.contains(&id) {
                missing.push(format!("{from} to {to}: {id}"));
            }
        }
    }
    assert!(
        missing.is_empty(),
        "Guard cells cite rules no guard of the row names: {missing:?}"
    );
}
