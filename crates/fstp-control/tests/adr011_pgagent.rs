//! ADR-011, I-82, design section 4.1: the `fstp-pgagent` job decoder and the
//! DDL identifier renderer.
//!
//! `CREATE DATABASE` and `DROP DATABASE` cannot run inside a checked
//! function, so `fstp-pgagent` renders their identifiers itself, from the
//! closed grammar `^[cv]_[0-9a-f]{32}$`, quoted as an identifier. Input
//! outside the grammar is refused, so the rendered DDL never holds it.
//! `i82_ddl_identifier_grammar_matches_reference` in `fstp-celltest`
//! (lane W1f) pins the grammar on generated names. These tests add both
//! database names of every cell. They also add the near misses that a
//! hand-written matcher gets wrong: a trailing newline that a regex `$`
//! lets through, digits from other scripts, the role names that share the
//! database prefix, and lengths one off.
//!
//! The job decoder takes typed jobs only. No SQL text crosses the wire
//! (ADR-011 "fstp-pgagent").
//!
//! Gap, recorded for lane W2h: `PgagentJob` holds only a `u16` kind. ADR-011
//! lists the job enum, and `DbIdent` and `RoleIdent` as the only renderer
//! inputs. Neither exists yet, so these tests drive the string API of the
//! stub.
//!
//! Lane W2h test author. Red until lane W2h writes both: each is a W0 stub
//! that refuses with `ControlError::NotImplemented`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::{database_name, is_stub, random_cell, refused, role_name};
use fstp_control::pg::CellDatabase;
use fstp_control::pgagent::{decode_pgagent_job, render_ddl_identifier};
use fstp_cp_proto::RoleName;
use fstp_prop::{Gen, prop_assert_eq};

/// ADR-011, I-82: both database names of every cell render as one quoted
/// identifier, byte for byte.
#[test]
fn adr011_ddl_identifier_renders_every_cell_database_name() {
    fstp_prop::check(
        "adr011_ddl_identifier_renders_every_cell_database_name",
        |g: &mut Gen| {
            let cell = random_cell(g);
            for db in [CellDatabase::App, CellDatabase::Vault] {
                let name = database_name(db, cell);
                let out =
                    render_ddl_identifier(&name).map_err(|e| format!("{name} was refused: {e}"))?;
                prop_assert_eq!(out, format!("\"{name}\""));
            }
            Ok(())
        },
    );
}

/// ADR-011, I-82: names next to the grammar are refused. A role name is no
/// database name, even of the same cell.
#[test]
fn adr011_ddl_identifier_refuses_near_misses() {
    let hex = "0123456789abcdef0123456789abcdef";
    let cell = fstp_cp_proto::CellId([0x5a; 16]);
    let mut names = vec![
        format!("c_{hex}\n"),
        format!("c_{hex}\r\n"),
        format!("c_{hex}\0"),
        format!(" c_{hex}"),
        format!("c_{hex} "),
        format!("\"c_{hex}\""),
        format!("c_{}", &hex[..31]),
        format!("c_{hex}0"),
        format!("C_{hex}"),
        format!("c-{hex}"),
        format!("c__{}", &hex[..31]),
        format!("cv_{}", &hex[..31]),
        format!("c_{}", hex.replace('a', "A")),
        // Fullwidth digits and a Cyrillic "с" look like the grammar.
        format!("c_{}\u{ff10}", &hex[..31]),
        format!("\u{0441}_{hex}"),
        format!("c_{hex}\"; DROP DATABASE postgres; --"),
        String::new(),
    ];
    for db in [CellDatabase::App, CellDatabase::Vault] {
        for role in RoleName::ALL {
            names.push(role_name(db, cell, role));
        }
    }
    let failures: Vec<String> = names
        .iter()
        .filter_map(|n| refused(&format!("{n:?}"), render_ddl_identifier(n)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}

/// ADR-011: the job decoder answers every input with a job or a refusal,
/// never a stub error.
#[test]
fn adr011_pgagent_job_decoder_answers_every_input() {
    fstp_prop::check(
        "adr011_pgagent_job_decoder_answers_every_input",
        |g: &mut Gen| {
            let b = if g.bool() {
                g.bytes(0..=512)
            } else {
                g.ascii_string(0..=256).into_bytes()
            };
            match decode_pgagent_job(&b) {
                Err(e) if is_stub(&e) => Err(format!("{e}")),
                _ => Ok(()),
            }
        },
    );
}

/// ADR-011: no SQL text crosses the wire. Empty input and SQL statements
/// are refused as jobs.
#[test]
fn adr011_pgagent_job_decoder_refuses_sql_text() {
    let cases: [&[u8]; 6] = [
        b"",
        b"CREATE DATABASE c_0123456789abcdef0123456789abcdef",
        b"DROP DATABASE c_0123456789abcdef0123456789abcdef",
        b"ALTER ROLE c_0123456789abcdef0123456789abcdef_app SUPERUSER",
        b"SELECT pg_read_file('pg_hba.conf')",
        b"GRANT pg_read_all_data TO PUBLIC; --",
    ];
    let failures: Vec<String> = cases
        .iter()
        .filter_map(|b| refused(&String::from_utf8_lossy(b), decode_pgagent_job(b)).err())
        .collect();
    assert!(failures.is_empty(), "{failures:#?}");
}
