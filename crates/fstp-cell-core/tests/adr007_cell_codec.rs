//! The cell envelope codec (ADR-007, I-23, M3 design sections 5.1, 5.3
//! and 15, R-NF-02).
//!
//! - Every M2 record keeps its exact bytes in the cell envelope: the
//!   members `core` and `finding` decode through `fstp_engine::Record`
//!   unchanged.
//! - The new members are `auth`, `tenant`, `text`, `key`, `release` and
//!   `ops`. Every record and command of every member round-trips.
//! - `record_from_canonical_at` is the decode function `PgRecordStore`
//!   takes. It reads every published schema version and refuses others.
//! - Decode errors name no input content (R-NF-02).
//!
//! Lane W2c's test author wrote these before the codec. They are red
//! until the decoders land (stub `NotImplemented`) and the encoders exist
//! (`common::ENCODE_RECORD_SEAM`, `common::ENCODE_COMMAND_SEAM`).
//!
//! Reading, raised in the lane report: "every schema version
//! round-trips" (design section 15) is read strictly as "accepted bytes
//! re-encode byte for byte", so a stored record has one spelling, as the
//! ledger entry codec already requires (I-23).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

#[path = "../../fstp-domain/tests/codec_support/mod.rs"]
#[allow(unused_macros, unused_imports)]
mod codec_support;

mod cells;
mod common;

use cells::{COMMAND_MEMBERS, MEMBERS, any_command, any_record, command_in, member_of, record_in};
use common::{encode_command, encode_record, is_stub, shown};
use fstp_cell_core::codec::DecodeError;
use fstp_cell_core::{
    CellRecord, decode_cell_command, decode_cell_record, record_from_canonical_at,
};
use fstp_json::{ToJson, Value, parse, to_canonical};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// The RFC 8785 bytes of an M2 engine record: the stored form M2 writes.
fn m2_bytes(r: &fstp_engine::Record) -> Result<Vec<u8>, String> {
    to_canonical(&r.to_json())
        .map(String::into_bytes)
        .map_err(|e| format!("M2 canonical text: {e:?}"))
}

/// A decode result that must be a refusal of the codec itself, not the
/// stub's.
fn refused(what: &str, r: Result<impl std::fmt::Debug, DecodeError>) -> Result<(), String> {
    match r {
        Ok(v) => Err(format!("{what}: decoded to {v:?}")),
        Err(e) if is_stub(&shown(e)) => Err(format!("{what}: {e:?}")),
        Err(_) => Ok(()),
    }
}

// ---------------------------------------------------------------------------
// M2 records in the cell envelope.

/// ADR-007, I-23: every M2 core and finding record decodes from its exact
/// M2 bytes into the `Engine` member (design section 5.1).
#[test]
fn adr007_cell_record_decode_reads_every_m2_record() {
    check(
        "adr007_cell_record_decode_reads_every_m2_record",
        |g: &mut Gen| {
            let member = *g.pick(&["core", "finding"]);
            let cell = record_in(g, member)?;
            let CellRecord::Engine(m2) = &cell else {
                return Err("an M2 member gave a non-engine record".to_owned());
            };
            let bytes = m2_bytes(m2)?;
            prop_assert_eq!(decode_cell_record(&bytes), Ok(cell.clone()));
            Ok(())
        },
    );
}

/// ADR-007, I-23: `record_from_canonical_at` at schema 1, the published
/// M2 version, reads every M2 record from its exact M2 bytes (design
/// section 5.3, the decode function of `PgRecordStore`).
#[test]
fn adr007_record_from_canonical_at_v1_reads_every_m2_record() {
    check(
        "adr007_record_from_canonical_at_v1_reads_every_m2_record",
        |g: &mut Gen| {
            let member = *g.pick(&["core", "finding"]);
            let cell = record_in(g, member)?;
            let CellRecord::Engine(m2) = &cell else {
                return Err("an M2 member gave a non-engine record".to_owned());
            };
            let bytes = m2_bytes(m2)?;
            prop_assert_eq!(
                record_from_canonical_at(&bytes, fstp_ledger::SCHEMA_V1),
                Ok(cell.clone())
            );
            Ok(())
        },
    );
}

/// ADR-007, I-23: an M2 record keeps its exact bytes. The cell encoding
/// of `Engine(r)` is the M2 encoding of `r`, byte for byte (design
/// section 5.1).
#[test]
fn adr007_m2_records_keep_their_exact_bytes_in_the_cell_envelope() {
    check(
        "adr007_m2_records_keep_their_exact_bytes_in_the_cell_envelope",
        |g: &mut Gen| {
            let member = *g.pick(&["core", "finding"]);
            let cell = record_in(g, member)?;
            let CellRecord::Engine(m2) = &cell else {
                return Err("an M2 member gave a non-engine record".to_owned());
            };
            let want = m2_bytes(m2)?;
            let got = encode_record(&cell).map_err(|s| s.to_string())?;
            prop_assert_eq!(got, want);
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Every member.

/// ADR-007, I-23: every cell record of every member and variant
/// round-trips through its encoding, with both decoders (design sections
/// 5.1 and 15).
#[test]
fn adr007_cell_record_round_trips_every_member() {
    check(
        "adr007_cell_record_round_trips_every_member",
        |g: &mut Gen| {
            let r = any_record(g)?;
            let bytes = encode_record(&r).map_err(|s| s.to_string())?;
            prop_assert_eq!(
                decode_cell_record(&bytes),
                Ok(r.clone()),
                "{}",
                member_of(&r)
            );
            prop_assert_eq!(
                record_from_canonical_at(&bytes, fstp_ledger::SCHEMA_V1),
                Ok(r.clone()),
                "{}",
                member_of(&r)
            );
            Ok(())
        },
    );
}

/// ADR-007, I-23: a cell record's bytes are the RFC 8785 text of an
/// object with exactly one member, named for its side of the envelope
/// (design section 5.1). Encoding is deterministic.
#[test]
fn adr007_cell_record_encoding_is_canonical_with_one_member() {
    check(
        "adr007_cell_record_encoding_is_canonical_with_one_member",
        |g: &mut Gen| {
            let member = *g.pick(&MEMBERS);
            let r = record_in(g, member)?;
            let bytes = encode_record(&r).map_err(|s| s.to_string())?;
            prop_assert_eq!(encode_record(&r).map_err(|s| s.to_string())?, bytes.clone());
            let v = parse(&bytes).map_err(|e| format!("parse: {e:?}"))?;
            let again = to_canonical(&v).map_err(|e| format!("canonical: {e:?}"))?;
            prop_assert_eq!(again.as_bytes(), bytes.as_slice(), "not RFC 8785 text");
            let Value::Object(o) = &v else {
                return Err(format!("{member}: the stored form is not an object"));
            };
            let names: Vec<&str> = o.iter().map(|(k, _)| k).collect();
            prop_assert_eq!(names, vec![member]);
            Ok(())
        },
    );
}

/// ADR-007, I-23: decoded bytes re-encode byte for byte, so a stored
/// record has one spelling. Respellings of a valid record (inner
/// whitespace, a member moved, an escaped letter) either fail to decode
/// or re-encode to the very input.
#[test]
fn adr007_accepted_cell_record_bytes_reencode_byte_for_byte() {
    check(
        "adr007_accepted_cell_record_bytes_reencode_byte_for_byte",
        |g: &mut Gen| {
            let r = any_record(g)?;
            let bytes = encode_record(&r).map_err(|s| s.to_string())?;
            let text = String::from_utf8(bytes).map_err(|_| "not UTF-8".to_owned())?;
            let respelled = match g.u8_in(0..=2) {
                0 => text.replacen(':', ": ", 1),
                1 => text.replacen('{', "{ ", 1),
                _ => text.replacen('a', "\\u0061", 1),
            };
            match decode_cell_record(respelled.as_bytes()) {
                Err(e) => prop_assert!(!is_stub(&shown(e)), "{e:?}"),
                Ok(d) => {
                    let again = encode_record(&d).map_err(|s| s.to_string())?;
                    prop_assert_eq!(again, respelled.into_bytes());
                }
            }
            Ok(())
        },
    );
}

/// ADR-007, I-23: every cell command of every member and variant
/// round-trips through its encoding (design sections 8.4 and 15).
#[test]
fn adr007_cell_command_round_trips_every_member() {
    check(
        "adr007_cell_command_round_trips_every_member",
        |g: &mut Gen| {
            let member = *g.pick(&COMMAND_MEMBERS);
            let c = command_in(g, member)?;
            let bytes = encode_command(&c).map_err(|s| s.to_string())?;
            prop_assert_eq!(decode_cell_command(&bytes), Ok(c.clone()), "{member}");
            Ok(())
        },
    );
}

/// I-78, design section 8.4: the command encoding is deterministic and
/// injective on generated pairs, so the action digest names one command.
#[test]
fn i78_cell_command_encoding_is_deterministic_and_injective() {
    check(
        "i78_cell_command_encoding_is_deterministic_and_injective",
        |g: &mut Gen| {
            let a = any_command(g)?;
            let b = any_command(g)?;
            let ea = encode_command(&a).map_err(|s| s.to_string())?;
            prop_assert_eq!(encode_command(&a).map_err(|s| s.to_string())?, ea.clone());
            let eb = encode_command(&b).map_err(|s| s.to_string())?;
            prop_assert_eq!(ea == eb, a == b, "{a:?} and {b:?}");
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// Refusals.

/// The inputs every decoder must refuse: not an envelope, an unknown
/// member, two members, no member, and bytes that are not JSON.
const NOT_ENVELOPES: [&[u8]; 12] = [
    b"",
    b"null",
    b"[]",
    b"\"core\"",
    b"{}",
    b"{\"vault\":{}}",
    b"{\"core\":{},\"auth\":{}}",
    b"{\"Core\":{}}",
    b"{\"core\":null}",
    b"{\"tenant\":7}",
    b"{\"text\":{}",
    b"\xff\xfe{\"key\":{}}",
];

/// ADR-007: `decode_cell_record` refuses every input that is not a cell
/// envelope with a codec refusal, never with the stub's (design section
/// 5.1).
#[test]
fn adr007_cell_record_decode_refuses_non_envelopes() {
    for input in NOT_ENVELOPES {
        refused(
            &format!("{:?}", String::from_utf8_lossy(input)),
            decode_cell_record(input),
        )
        .unwrap();
    }
}

/// ADR-007: `decode_cell_command` refuses every input that is not a cell
/// command envelope with a codec refusal, never with the stub's.
#[test]
fn adr007_cell_command_decode_refuses_non_envelopes() {
    for input in NOT_ENVELOPES {
        refused(
            &format!("{:?}", String::from_utf8_lossy(input)),
            decode_cell_command(input),
        )
        .unwrap();
    }
}

/// ADR-007, I-23: `record_from_canonical_at` refuses schema versions
/// outside the published set before it reads the body. Schema 0 is no
/// version (`fstp_ledger` numbers them from 1), and 65535 is unpublished.
///
/// Gap: the stubs publish no list of cell schema versions, so only these
/// two are checked. The M2 list is `fstp_domain::codec::PUBLISHED_SCHEMAS`.
#[test]
fn adr007_record_from_canonical_at_refuses_unpublished_schemas() {
    let m2 = fstp_engine::Record::Core(fstp_domain::Record::ProgrammeCreated {
        programme: fstp_domain::id::ProgrammeId::from_raw(1),
        currency: fstp_money::Currency::Eur,
        by: fstp_domain::id::AccountId::from_raw(1),
    });
    let bytes = m2_bytes(&m2).unwrap();
    assert_eq!(
        record_from_canonical_at(&bytes, fstp_ledger::SCHEMA_V1),
        Ok(CellRecord::Engine(m2)),
        "schema 1 must read the record"
    );
    for schema in [0u16, u16::MAX] {
        refused(
            &format!("schema {schema}"),
            record_from_canonical_at(&bytes, schema),
        )
        .unwrap();
    }
}

/// The canary that the R-NF-02 test plants in inputs.
const CANARY: &str = "zqxcanaryqz";

/// R-NF-02, ADR-007: a decode error names schema members only. No error
/// of either decoder holds input content, here a canary planted as a
/// member name and as a string value.
#[test]
fn r_nf_02_cell_decode_errors_hold_no_input_content() {
    let inputs = [
        format!("{{\"{CANARY}\":{{}}}}"),
        format!("{{\"core\":{{\"{CANARY}\":1}}}}"),
        format!("{{\"tenant\":\"{CANARY}\"}}"),
        format!("{{\"auth\":{{\"kind\":\"{CANARY}\"}}}}"),
        CANARY.to_owned(),
    ];
    for input in &inputs {
        for (which, e) in [
            ("record", decode_cell_record(input.as_bytes()).err()),
            ("command", decode_cell_command(input.as_bytes()).err()),
            (
                "canonical_at",
                record_from_canonical_at(input.as_bytes(), fstp_ledger::SCHEMA_V1).err(),
            ),
        ] {
            let Some(e) = e else {
                panic!("{which} decoded {input}");
            };
            let text = shown(e);
            assert!(!is_stub(&text), "{which}: {text}");
            assert!(!text.contains(CANARY), "{which} leaks input: {text}");
        }
    }
}
