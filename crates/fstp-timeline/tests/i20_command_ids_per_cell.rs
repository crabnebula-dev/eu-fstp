//! I-20: the timeline's command ids are keyed per cell.
//!
//! A timeline command can be the same in two cells: a plan of the P-57
//! reporting period events of a programme with the same id and the same
//! Data Sheet dates, or the firing of such an event. Its command id is
//! stored in clear in each ledger. Hashed from the command alone, the id
//! would link the two tenants (`t_iso_i20`). So the id is keyed by the
//! cell, as the vault-change reaction ids are (Daniel, 2026-11-13, M3
//! exit audit section 7 item 4, Q-ISO). Within one cell it stays a
//! function of the command, so a retry is a duplicate (I-23, ADR-007).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell_core::is_system_command_id;
use fstp_cell_core::timeline::{TimelineCommand, TimelineRecord, event_id};
use fstp_timeline::{command_id, kind};

const CELL_A: [u8; 16] = [0xA1; 16];
const CELL_B: [u8; 16] = [0xB2; 16];

/// The commands of a P-57 period end in a cell: its plan and its firing.
fn commands() -> Vec<TimelineCommand> {
    let event = event_id(kind::REPORTING_PERIOD_END, 0, b"p4.1", 0);
    let scheduled = TimelineRecord::EventScheduled {
        event,
        kind: kind::REPORTING_PERIOD_END,
        lead: 0,
        source: b"p4.1".to_vec(),
        source_version: 0,
        due: 1_830_297_600_000_000,
        offset_minutes: 0,
    };
    vec![
        TimelineCommand::Plan {
            records: vec![scheduled],
        },
        TimelineCommand::Plan {
            records: Vec::new(),
        },
        TimelineCommand::Fire {
            event,
            templates: Vec::new(),
            messages: Vec::new(),
            then: None,
        },
    ]
}

/// I-20: the same timeline command in two cells has two ids, and each
/// stays in the system task namespace.
#[test]
fn i20_timeline_command_ids_differ_across_cells() {
    for c in commands() {
        let (a, b) = (command_id(CELL_A, &c), command_id(CELL_B, &c));
        assert_ne!(a, b, "{c:?} has one id in two cells");
        assert!(is_system_command_id(a) && is_system_command_id(b));
    }
}

/// I-23, ADR-007: within one cell the id is a function of the command, so
/// every retry of a plan or a firing is a duplicate, and two commands
/// keep two ids.
#[test]
fn i20_timeline_command_ids_are_stable_within_a_cell() {
    let cs = commands();
    for c in &cs {
        assert_eq!(command_id(CELL_A, c), command_id(CELL_A, c));
    }
    let ids: std::collections::BTreeSet<[u8; 16]> =
        cs.iter().map(|c| command_id(CELL_A, c)).collect();
    assert_eq!(ids.len(), cs.len());
}
