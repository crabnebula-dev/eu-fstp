//! `fstp_cell::http::decode_command_request`, the body decoder of
//! `POST /api/v1/commands` (I-18, TH-26, R-NF-02, design sections 8.7
//! and 15).
//!
//! Design section 15 asks the decoder for no panic, size limits, and a
//! refused `minor` field. Lane W3a's test author wrote these tests before
//! the decoder exists. The W0 stub refuses every body with
//! `CellError::NotImplemented`, and a test that needs a real answer is red
//! for that reason only.
//!
//! Body grammar read here. The W0 `CommandRequest` holds `command_id` and
//! `stepup`. The `fstp-celltest` test
//! `i18_route_never_takes_minor_flag_from_the_request` (lane W1c) already
//! fixes `{"command_id":"<32 lowercase hex>"}` as a body that decodes. So
//! ids are 32 lowercase hexadecimal digits, and `stepup` is an optional
//! member of the same form. Members are written in RFC 8785 order with no
//! white space, so a decoder that accepts only canonical text accepts
//! them too.
//!
//! Gaps for lane W3a:
//! - `CommandRequest` carries no command. Once the body names one, the
//!   control bodies below gain that member, as the W1c test says too.
//! - `CellError` has only `NotImplemented`, so a refusal cannot be told
//!   apart from a size refusal here. `routes_sweep.rs` checks the size
//!   limit as 413 over HTTP.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_cell::CellError;
use fstp_cell::http::{CommandRequest, decode_command_request};
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

/// What the decoder said.
#[derive(Debug)]
enum Got {
    Ok(CommandRequest),
    Refused(String, String),
    Stub(&'static str),
}

fn decode(body: &[u8]) -> Got {
    match decode_command_request(body) {
        Ok(r) => Got::Ok(r),
        Err(CellError::NotImplemented(op)) => Got::Stub(op),
        #[allow(unreachable_patterns, reason = "fstp-cell gains variants in lane W3a")]
        Err(e) => Got::Refused(e.to_string(), format!("{e:?}")),
    }
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn id16(g: &mut Gen) -> [u8; 16] {
    g.bytes(16..=16).try_into().unwrap()
}

/// The canonical body for `id` and `stepup`.
fn body(id: [u8; 16], stepup: Option<[u8; 16]>) -> String {
    match stepup {
        Some(s) => format!(
            "{{\"command_id\":\"{}\",\"stepup\":\"{}\"}}",
            hex(&id),
            hex(&s)
        ),
        None => format!("{{\"command_id\":\"{}\"}}", hex(&id)),
    }
}

/// Checks that `body` decodes to `id` and `stepup`.
fn expect_ok(body: &str, id: [u8; 16], stepup: Option<[u8; 16]>) -> Result<(), String> {
    match decode(body.as_bytes()) {
        Got::Ok(r) => {
            prop_assert_eq!(r.command_id, id, "command_id of {body}");
            prop_assert_eq!(r.stepup, stepup, "stepup of {body}");
            Ok(())
        }
        Got::Stub(op) => Err(format!("{op} is NotImplemented")),
        Got::Refused(e, _) => Err(format!("the control body {body} was refused: {e}")),
    }
}

/// Checks that `body` is refused, and not by the stub.
fn expect_refused(body: &[u8]) -> Result<(), String> {
    match decode(body) {
        Got::Refused(..) => Ok(()),
        Got::Stub(op) => Err(format!("{op} is NotImplemented")),
        Got::Ok(r) => Err(format!(
            "decoded {r:?} from {:?}",
            String::from_utf8_lossy(body)
        )),
    }
}

/// The JSON values a `minor` member is tried with.
const MINOR_VALUES: &[&str] = &[
    "true", "false", "0", "1", "null", "\"yes\"", "\"\"", "{}", "[]", "[true]",
];

/// I-18, R-ID-04, NOTE 14, design section 15: a body with a `minor` member
/// is refused, for any JSON value and in any member position. The same
/// body without it decodes to the same ids, so the refusal is the
/// member's.
#[test]
fn i18_command_request_refuses_a_minor_member() {
    fstp_prop::check(
        "i18_command_request_refuses_a_minor_member",
        |g: &mut Gen| {
            let id = id16(g);
            let stepup = g.option(id16);
            expect_ok(&body(id, stepup), id, stepup)?;
            let value = *g.pick(MINOR_VALUES);
            let mut members = vec![format!("\"command_id\":\"{}\"", hex(&id))];
            if let Some(s) = stepup {
                members.push(format!("\"stepup\":\"{}\"", hex(&s)));
            }
            let at = g.usize_in(0..=members.len());
            members.insert(at, format!("\"minor\":{value}"));
            let with = format!("{{{}}}", members.join(","));
            expect_refused(with.as_bytes())
        },
    );
}

/// I-18, design section 15: a `minor` member whose name is spelled with
/// JSON escapes is refused too. A decoder that matched raw bytes would
/// miss it, while one that compares decoded names refuses it.
#[test]
fn i18_command_request_refuses_an_escaped_minor_member() {
    fstp_prop::check(
        "i18_command_request_refuses_an_escaped_minor_member",
        |g: &mut Gen| {
            let id = id16(g);
            expect_ok(&body(id, None), id, None)?;
            let name = *g.pick(&[
                "min\\u006fr",
                "\\u006dinor",
                "\\u006D\\u0069\\u006E\\u006F\\u0072",
                "mi\\u006eor",
            ]);
            let value = *g.pick(MINOR_VALUES);
            let with = if g.bool() {
                format!("{{\"{name}\":{value},\"command_id\":\"{}\"}}", hex(&id))
            } else {
                format!("{{\"command_id\":\"{}\",\"{name}\":{value}}}", hex(&id))
            };
            expect_refused(with.as_bytes())
        },
    );
}

/// TH-26, design section 8.4: a canonical body decodes to exactly its
/// command id and step-up id. An absent `stepup` decodes as none.
#[test]
fn th_26_command_request_decodes_its_ids() {
    fstp_prop::check("th_26_command_request_decodes_its_ids", |g: &mut Gen| {
        let id = id16(g);
        let stepup = g.option(id16);
        expect_ok(&body(id, stepup), id, stepup)
    });
}

/// TH-26, design section 15: ids have one spelling, 32 lowercase
/// hexadecimal digits in a JSON string. Every other spelling of either id
/// is refused, and `"stepup":null` is not a second spelling of none.
#[test]
fn th_26_command_request_refuses_other_id_spellings() {
    let good = hex(&[0xAB; 16]);
    let upper = good.to_ascii_uppercase();
    let short = &good[..31];
    let long = format!("{good}0");
    let bad_values: Vec<String> = vec![
        format!("\"{upper}\""),
        format!("\"{short}\""),
        format!("\"{long}\""),
        format!("\"{}g\"", &good[..31]),
        format!("\"0x{}\"", &good[..30]),
        format!("\" {}\"", &good[..31]),
        "\"\"".to_owned(),
        "null".to_owned(),
        "12345".to_owned(),
        "[]".to_owned(),
        "{}".to_owned(),
        format!("\"{}\\u0030\"", &good[..31]),
    ];
    for v in &bad_values {
        let as_id = format!("{{\"command_id\":{v}}}");
        let as_stepup = format!("{{\"command_id\":\"{good}\",\"stepup\":{v}}}");
        for b in [as_id, as_stepup] {
            if let Err(e) = expect_refused(b.as_bytes()) {
                panic!("{e}");
            }
        }
    }
    if let Err(e) = expect_ok(&format!("{{\"command_id\":\"{good}\"}}"), [0xAB; 16], None) {
        panic!("{e}");
    }
}

/// TH-26: a member given twice is refused, so no two parsers can read the
/// body differently. This holds for equal and for different values.
#[test]
fn th_26_command_request_refuses_duplicate_members() {
    let a = hex(&[1; 16]);
    let b = hex(&[2; 16]);
    for body in [
        format!("{{\"command_id\":\"{a}\",\"command_id\":\"{b}\"}}"),
        format!("{{\"command_id\":\"{a}\",\"command_id\":\"{a}\"}}"),
        format!("{{\"command_id\":\"{a}\",\"stepup\":\"{a}\",\"stepup\":\"{b}\"}}"),
    ] {
        if let Err(e) = expect_refused(body.as_bytes()) {
            panic!("{e}");
        }
    }
}

/// TH-26, I-18, design section 15: a body holds its schema's members and
/// no other, as the `fstp-auth` codecs do. An unknown member is refused,
/// so a client cannot believe it set a field the cell ignores. The names
/// carry an `x_` prefix, so none can be a member the schema later gains.
#[test]
fn th_26_command_request_refuses_unknown_members() {
    fstp_prop::check(
        "th_26_command_request_refuses_unknown_members",
        |g: &mut Gen| {
            let id = id16(g);
            expect_ok(&body(id, None), id, None)?;
            let len = g.usize_in(1..=12);
            let tail: String = (0..len)
                .map(|_| char::from(*g.pick(b"abcdefghijklmnopqrstuvwxyz_0123456789")))
                .collect();
            let name = format!("x_{tail}");
            let value = *g.pick(MINOR_VALUES);
            let with = format!("{{\"command_id\":\"{}\",\"{name}\":{value}}}", hex(&id));
            expect_refused(with.as_bytes())
        },
    );
}

/// TH-26, I-18: names that differ from a member only in case are unknown
/// members, and are refused. `Minor` and `MINOR` must not slip past a
/// check for `minor`.
#[test]
fn th_26_command_request_refuses_case_variants_of_member_names() {
    let id = hex(&[3; 16]);
    for name in [
        "Minor",
        "MINOR",
        "Command_id",
        "COMMAND_ID",
        "Stepup",
        "stepUp",
    ] {
        let with = format!("{{\"command_id\":\"{id}\",\"{name}\":true}}");
        if let Err(e) = expect_refused(with.as_bytes()) {
            panic!("{e}");
        }
    }
}

/// TH-26: anything that is not one JSON object of the schema is refused:
/// no body, other JSON types, an empty object, trailing bytes, a byte
/// order mark, a NUL, broken UTF-8, and an unterminated object.
#[test]
fn th_26_command_request_refuses_bodies_that_are_not_one_object() {
    let good = format!("{{\"command_id\":\"{}\"}}", hex(&[4; 16]));
    let cases: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"x\"".to_vec(),
        b"{}".to_vec(),
        format!("{good}x").into_bytes(),
        format!("{good}{good}").into_bytes(),
        [b"\xEF\xBB\xBF".as_slice(), good.as_bytes()].concat(),
        [good.as_bytes(), b"\0"].concat(),
        [
            b"{\"command_id\":\"".as_slice(),
            &hex(&[4; 16]).as_bytes()[..31],
            b"\xff\"}",
        ]
        .concat(),
        good.as_bytes()[..good.len() - 1].to_vec(),
    ];
    for c in &cases {
        if let Err(e) = expect_refused(c) {
            panic!("{e}");
        }
    }
}

/// TH-26, design section 15: deep nesting is refused without exhausting
/// the stack. A recursive decoder with no depth limit aborts this test.
#[test]
fn th_26_command_request_refuses_deep_nesting() {
    let id = hex(&[5; 16]);
    for depth in [64usize, 1_000, 100_000] {
        let open = "[".repeat(depth);
        let close = "]".repeat(depth);
        let nested = format!("{{\"command_id\":\"{id}\",\"x_deep\":{open}{close}}}");
        if let Err(e) = expect_refused(nested.as_bytes()) {
            panic!("depth {depth}: {e}");
        }
        if let Err(e) = expect_refused(open.as_bytes()) {
            panic!("bare depth {depth}: {e}");
        }
    }
}

/// TH-26, design section 15: a body far over any route's limit is
/// refused. The padding is a string member, so the body stays well formed
/// JSON apart from its size.
#[test]
fn th_26_command_request_refuses_an_oversize_body() {
    let id = hex(&[6; 16]);
    let pad = "a".repeat(16 << 20);
    let big = format!("{{\"command_id\":\"{id}\",\"x_pad\":\"{pad}\"}}");
    if let Err(e) = expect_refused(big.as_bytes()) {
        panic!("{e}");
    }
}

/// TH-26, design section 15: the decoder never panics. Inputs are random
/// bytes, canonical bodies and canonical bodies with one byte changed,
/// inserted or removed. Each canonical body must also decode, so the
/// property is not met by a decoder that refuses everything.
#[test]
fn th_26_command_request_decode_never_panics() {
    fstp_prop::check(
        "th_26_command_request_decode_never_panics",
        |g: &mut Gen| {
            let id = id16(g);
            let stepup = g.option(id16);
            let valid = body(id, stepup).into_bytes();
            match g.usize_in(0..=2) {
                0 => {
                    let raw = g.bytes(0..=256);
                    let _ = decode(&raw);
                    Ok(())
                }
                1 => expect_ok(&body(id, stepup), id, stepup),
                _ => {
                    let mut m = valid;
                    let at = g.usize_in(0..=m.len() - 1);
                    match g.usize_in(0..=2) {
                        0 => m[at] = g.u8(),
                        1 => m.insert(at, g.u8()),
                        _ => {
                            m.remove(at);
                        }
                    }
                    let _ = decode(&m);
                    Ok(())
                }
            }
        },
    );
}

/// R-NF-02, TH-26: a refusal never quotes the body. A canary in a member
/// name, a member value or an id is absent from the error's `Display` and
/// `Debug` output, in plain and in hexadecimal form.
#[test]
fn r_nf_02_command_request_refusals_never_quote_the_body() {
    fstp_prop::check(
        "r_nf_02_command_request_refusals_never_quote_the_body",
        |g: &mut Gen| {
            let id = id16(g);
            let mark = hex(&g.bytes(8..=8));
            let canary = format!("CNRY-a1-text-{mark}{mark}{mark}{mark}");
            let bad = match g.usize_in(0..=2) {
                0 => format!("{{\"command_id\":\"{}\",\"x_{canary}\":1}}", hex(&id)),
                1 => format!(
                    "{{\"command_id\":\"{}\",\"x_note\":\"{canary}\"}}",
                    hex(&id)
                ),
                _ => format!("{{\"command_id\":\"{canary}\"}}"),
            };
            match decode(bad.as_bytes()) {
                Got::Refused(shown, debug) => {
                    for text in [&shown, &debug] {
                        prop_assert!(
                            !text.contains(&canary) && !text.contains(&mark),
                            "the refusal quotes the body: {text}"
                        );
                    }
                    Ok(())
                }
                Got::Stub(op) => Err(format!("{op} is NotImplemented")),
                Got::Ok(r) => Err(format!("decoded {r:?} from {bad}")),
            }
        },
    );
}
