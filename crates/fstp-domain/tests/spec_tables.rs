//! Interface conformance against the spec tables (step W1c).
//!
//! Each test reads the markdown in `SPEC/` at test time and compares one
//! table with the matching constant of `fstp-domain`, in both directions.
//! A spec edit that the interface does not follow fails here.

mod support;

use std::collections::BTreeSet;

use fstp_domain::command::CommandKind;
use fstp_domain::oracle::QueryKind;
use fstp_domain::roles::{Group, Role};
use fstp_domain::rules::{
    ACTOR_RULES, ActorRule, CATALOGUE, Freeze, Level, ParamId, StateTag, TRANSITIONS,
};

use support::{read_spec, section, strip_note_refs, table};

const PARAM_HEADER: &[&str] = &["ID", "Parameter", "SuperSAFE default", "Frozen"];

/// Freeze flag and level as the Frozen column of `policy-parameters.md` states them.
fn freeze_and_level(cell: &str) -> Result<(Freeze, Level), String> {
    if cell == "Yes" {
        Ok((Freeze::Frozen, Level::Programme))
    } else if cell == "Not tenant-configurable" {
        Ok((Freeze::Live, Level::Fixed))
    } else if cell.starts_with("No") && cell.contains("tenant-level") {
        Ok((Freeze::Live, Level::Tenant))
    } else if cell == "No" || cell == "No (programme-level)" {
        Ok((Freeze::Live, Level::Programme))
    } else {
        Err(format!("unknown Frozen cell {cell:?}"))
    }
}

/// Every parameter row of both tables, as (id, freeze, level).
fn spec_catalogue() -> Result<Vec<(String, Freeze, Level)>, String> {
    let doc = read_spec("02-domain/policy-parameters.md")?;
    let all: Vec<&str> = doc.lines().collect();
    let added = section(&doc, "## Added parameters")?;
    let main_end = all
        .iter()
        .position(|l| l.trim_end() == "## Added parameters")
        .ok_or("no Added parameters heading")?;
    let main = table(all.get(..main_end).ok_or("bad split")?, PARAM_HEADER)?;
    let more = table(&added, PARAM_HEADER)?;
    let rows: Vec<Vec<String>> = main.into_iter().chain(more).collect();

    let id_lines = all.iter().filter(|l| l.starts_with("| P-")).count();
    if id_lines != rows.len() {
        return Err(format!(
            "{id_lines} parameter lines, but {} parsed rows",
            rows.len()
        ));
    }

    let mut out = Vec::new();
    for row in rows {
        let id = row.first().ok_or("empty row")?.clone();
        let frozen = row.last().ok_or("empty row")?;
        let (freeze, level) = freeze_and_level(frozen).map_err(|e| format!("{id}: {e}"))?;
        out.push((id, freeze, level));
    }
    Ok(out)
}

/// I-12 rests on the frozen flags of the catalogue. Every row of both
/// parameter tables matches `CATALOGUE` in id, frozen flag and level, and
/// every `CATALOGUE` entry has its row.
#[test]
fn spec_catalogue_matches_policy_parameters() {
    let spec = match spec_catalogue() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };

    let ours: Vec<(String, Freeze, Level)> = CATALOGUE
        .iter()
        .map(|p| (p.id.spec_id().to_owned(), p.freeze, p.level))
        .collect();

    for row in &spec {
        assert!(
            ours.contains(row),
            "spec row {row:?} missing from CATALOGUE"
        );
    }
    for entry in &ours {
        assert!(
            spec.contains(entry),
            "CATALOGUE entry {entry:?} missing from the spec"
        );
    }
    assert_eq!(spec, ours, "CATALOGUE order differs from the spec tables");

    let ids: Vec<ParamId> = CATALOGUE.iter().map(|p| p.id).collect();
    assert_eq!(
        ids,
        ParamId::ALL.to_vec(),
        "CATALOGUE is not in ParamId::ALL order"
    );
    let unique: BTreeSet<ParamId> = ids.iter().copied().collect();
    assert_eq!(unique.len(), ids.len(), "duplicate catalogue ids");
    for id in ParamId::ALL {
        assert_eq!(
            id.spec().map(|s| s.id),
            Some(id),
            "{id:?} has no catalogue entry"
        );
    }
}

/// The proposal states in table order, and the terminal ones.
fn spec_states() -> Result<Vec<(String, bool)>, String> {
    let doc = read_spec("02-domain/state-machine.md")?;
    let lines = section(&doc, "## States")?;
    let rows = table(&lines, &["State", "Meaning"])?;
    Ok(rows
        .into_iter()
        .map(|r| {
            let name = r.first().cloned().unwrap_or_default();
            let terminal = r.get(1).is_some_and(|m| m.contains("Terminal"));
            (name, terminal)
        })
        .collect())
}

/// The states NOTE 10 opens withdrawal in.
fn note10_states() -> Result<BTreeSet<String>, String> {
    let doc = read_spec("02-domain/state-machine.md")?;
    let line = doc
        .lines()
        .find(|l| l.starts_with("NOTE 10:"))
        .ok_or("NOTE 10 not found")?;
    let open = line
        .split_once("Withdrawal is open in ")
        .map(|(_, rest)| rest)
        .ok_or("NOTE 10 does not say where withdrawal is open")?;
    let list = open
        .split_once('.')
        .map(|(l, _)| l)
        .ok_or("NOTE 10 list has no end")?;
    Ok(list
        .split([',', ' '])
        .map(str::trim)
        .filter(|w| !w.is_empty() && *w != "and")
        .map(str::to_owned)
        .collect())
}

/// The non-terminal states listed before GRANTED in the states table.
fn before_granted(states: &[(String, bool)]) -> Result<Vec<String>, String> {
    let granted = states
        .iter()
        .position(|(n, _)| n == "GRANTED")
        .ok_or("no GRANTED state")?;
    Ok(states
        .get(..granted)
        .ok_or("bad split")?
        .iter()
        .filter(|(_, t)| !t)
        .map(|(n, _)| n.clone())
        .collect())
}

/// R-SB-03 and NOTE 10: the terminal set is the states table's "Terminal"
/// states, and the withdrawable set is NOTE 10's list. NOTE 10 equals the
/// non-terminal states before GRANTED in the states table.
#[test]
fn r_sb_03_states_terminal_and_withdrawable_sets_match_spec() {
    let states = match spec_states() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let note10 = match note10_states() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let before = match before_granted(&states) {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };

    let names: Vec<&str> = states.iter().map(|(n, _)| n.as_str()).collect();
    let ours: Vec<&str> = StateTag::ALL.iter().map(|s| s.spec_name()).collect();
    assert_eq!(names, ours, "StateTag::ALL differs from the states table");

    let spec_terminal: BTreeSet<&str> = states
        .iter()
        .filter(|(_, t)| *t)
        .map(|(n, _)| n.as_str())
        .collect();
    let our_terminal: BTreeSet<&str> = StateTag::TERMINAL.iter().map(|s| s.spec_name()).collect();
    assert_eq!(spec_terminal, our_terminal, "terminal set differs");
    for s in StateTag::ALL {
        assert_eq!(
            s.is_terminal(),
            spec_terminal.contains(s.spec_name()),
            "is_terminal wrong for {s:?}"
        );
    }

    let before_set: BTreeSet<String> = before.into_iter().collect();
    assert_eq!(
        note10, before_set,
        "NOTE 10 differs from the non-terminal states before GRANTED"
    );
    let our_withdrawable: BTreeSet<String> = StateTag::WITHDRAWABLE
        .iter()
        .map(|s| s.spec_name().to_owned())
        .collect();
    assert_eq!(
        note10, our_withdrawable,
        "withdrawable set differs from NOTE 10"
    );
    for s in StateTag::ALL {
        assert_eq!(
            s.is_withdrawable(),
            note10.contains(s.spec_name()),
            "is_withdrawable wrong for {s:?}"
        );
    }
}

/// The transitions table, expanded to (from, to, actor) triples in table order.
fn spec_transitions() -> Result<Vec<(String, String, String)>, String> {
    let doc = read_spec("02-domain/state-machine.md")?;
    let lines = section(&doc, "## Transitions")?;
    let rows = table(&lines, &["From", "To", "Actor", "Guard"])?;
    let states = spec_states()?;
    let names: BTreeSet<&str> = states.iter().map(|(n, _)| n.as_str()).collect();
    let mut out = Vec::new();
    for row in rows {
        let from = row.first().ok_or("empty row")?;
        let to = row.get(1).ok_or("no To cell")?;
        let actor = strip_note_refs(row.get(2).ok_or("no Actor cell")?);
        let froms = if from == "any non-terminal state before GRANTED" {
            before_granted(&states)?
        } else {
            vec![from.clone()]
        };
        let tos: Vec<String> = to.split(" or ").map(|t| t.trim().to_owned()).collect();
        for f in &froms {
            for t in &tos {
                for s in [f, t] {
                    if !names.contains(s.as_str()) {
                        return Err(format!("unknown state {s:?} in row {row:?}"));
                    }
                }
                out.push((f.clone(), t.clone(), actor.clone()));
            }
        }
    }
    Ok(out)
}

/// `TRANSITIONS` follows the transitions table row by row: the same
/// (from, to, actor) triples in the same order, with none extra on either side.
#[test]
fn spec_transitions_match_state_machine() {
    let spec = match spec_transitions() {
        Ok(s) => s,
        Err(e) => panic!("{e}"),
    };
    let mut ours = Vec::new();
    for rule in TRANSITIONS {
        let actor = match rule.actor.transition_label() {
            Some(a) => a.to_owned(),
            None => panic!("row {:?} has an actor with no spec label", rule.row),
        };
        for from in rule.from {
            ours.push((
                from.spec_name().to_owned(),
                rule.to.spec_name().to_owned(),
                actor.clone(),
            ));
        }
    }

    for triple in &spec {
        assert!(
            ours.contains(triple),
            "spec transition {triple:?} missing from TRANSITIONS"
        );
    }
    for triple in &ours {
        assert!(
            spec.contains(triple),
            "TRANSITIONS entry {triple:?} missing from the spec"
        );
    }
    assert_eq!(spec, ours, "TRANSITIONS order differs from the spec table");

    let rows: BTreeSet<_> = TRANSITIONS.iter().map(|r| r.row).collect();
    assert_eq!(rows.len(), TRANSITIONS.len(), "a row appears twice");
    for rule in TRANSITIONS {
        assert!(
            !rule.commands.is_empty(),
            "row {:?} names no command",
            rule.row
        );
        for from in rule.from {
            assert!(
                !from.is_terminal(),
                "row {:?} leaves terminal {from:?}",
                rule.row
            );
        }
    }
}

/// I-84: `ACTOR_RULES` gives every command kind exactly one actor rule, in
/// `CommandKind::ALL` order, so the M4 matrix and MCP parity have one source.
#[test]
fn i84_actor_rules_cover_every_command_once() {
    let kinds: Vec<CommandKind> = ACTOR_RULES.iter().map(|(k, _)| *k).collect();
    assert_eq!(
        kinds,
        CommandKind::ALL.to_vec(),
        "ACTOR_RULES is not one entry per kind in order"
    );
    for rule in TRANSITIONS {
        for kind in rule.commands {
            assert!(
                kinds.contains(kind),
                "row {:?} names an unknown command",
                rule.row
            );
        }
    }
    for (kind, rule) in ACTOR_RULES {
        if let ActorRule::AnyOf(options) = rule {
            assert!(options.len() >= 2, "{kind:?} has a degenerate AnyOf");
            assert!(
                options.iter().all(|o| !matches!(o, ActorRule::AnyOf(_))),
                "{kind:?} nests AnyOf"
            );
        }
    }
}

/// SoD-01 to SoD-03 rest on the groups. Every role of the roles table has a
/// `Role` with the same name and group, except the assigned reviewer, which
/// is an assignment over a committee member binding (design section 2.6).
#[test]
fn sod01_roles_match_roles_table() {
    let doc = match read_spec("02-domain/roles-and-sod.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let lines = match section(&doc, "## Roles") {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let rows = match table(&lines, &["Role", "Group", "Notes"]) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let group_name = |g: Group| match g {
        Group::Drafting => "Drafting",
        Group::Judging => "Judging",
        Group::Receiving => "Receiving",
        Group::Operations => "Operations",
    };
    let spec: Vec<(String, String)> = rows
        .into_iter()
        .filter(|r| r.first().is_some_and(|n| n != "Assigned reviewer"))
        .map(|r| {
            (
                r.first().cloned().unwrap_or_default(),
                r.get(1).cloned().unwrap_or_default(),
            )
        })
        .collect();
    let ours: Vec<(String, String)> = Role::ALL
        .iter()
        .map(|r| (r.spec_name().to_owned(), group_name(r.group()).to_owned()))
        .collect();
    assert_eq!(spec, ours, "Role differs from the roles table");
}

/// I-03, I-04, I-06, I-14, I-15 and I-18 use the vault queries. `QueryKind`
/// matches the query table of `SPEC/03-architecture/overview.md` row by row.
#[test]
fn i06_vault_queries_match_overview() {
    let doc = match read_spec("03-architecture/overview.md") {
        Ok(d) => d,
        Err(e) => panic!("{e}"),
    };
    let lines = match section(&doc, "## Identity vault") {
        Ok(l) => l,
        Err(e) => panic!("{e}"),
    };
    let rows = match table(&lines, &["Query", "Serves"]) {
        Ok(r) => r,
        Err(e) => panic!("{e}"),
    };
    let spec: Vec<String> = rows
        .into_iter()
        .filter_map(|r| r.first().cloned())
        .collect();
    let ours: Vec<String> = QueryKind::ALL
        .iter()
        .map(|q| q.spec_question().to_owned())
        .collect();
    assert_eq!(spec, ours, "QueryKind differs from the vault query table");
}
