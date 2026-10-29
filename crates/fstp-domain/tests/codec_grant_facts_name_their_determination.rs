//! TH-26, R-NG-03, NOTE 9: `AcceptGrant` and `ApproveGrant` name the amount
//! determination they accept (Q-W7-7, decided 2026-10-28).
//!
//! Daniel answered Q-W7-7 on 2026-10-28: each command names the amount
//! determination it accepts, by its decision id, and is refused unless that
//! determination is the current one for the proposal. The command codec
//! carries it as the member `determination`, a decision id in its one
//! decimal string spelling. A command without the member is refused, as is
//! every missing member (design section 7).
//!
//! The texts are the canonical seeds `accept_grant` and `approve_grant` of
//! `crates/fstp-domain/fuzz/seeds/command_decode`. Lead a's proposal 11
//! names its first determination 21101 (`amount_decision(PA, 1)` of the
//! test kit).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::PathBuf;

use fstp_domain::command::{Command, CommandKind};
use fstp_json::{FromJson, ToJson, parse, to_canonical};

const ACCEPT: &str =
    r#"{"decision":"21011","determination":"21101","proposal":"11","type":"AcceptGrant"}"#;
const APPROVE: &str =
    r#"{"decision":"22011","determination":"21101","proposal":"11","type":"ApproveGrant"}"#;
const ACCEPT_WITHOUT: &str = r#"{"decision":"21011","proposal":"11","type":"AcceptGrant"}"#;
const APPROVE_WITHOUT: &str = r#"{"decision":"22011","proposal":"11","type":"ApproveGrant"}"#;

fn decode(text: &str) -> Result<Command, String> {
    let v = parse(text.as_bytes()).map_err(|e| format!("not JSON: {e:?}"))?;
    Command::from_json(&v).map_err(|e| format!("{e:?}"))
}

/// Decodes `text`, checks the kind, and checks that the canonical encoding
/// of the decoded command is `text` again, so the member survives.
fn round_trip(text: &str, kind: CommandKind) {
    let c = decode(text).unwrap_or_else(|e| {
        panic!("Q-W7-7: the command codec refuses the member determination: {e}\n  {text}")
    });
    assert_eq!(c.kind(), kind);
    let back = to_canonical(&c.to_json()).unwrap_or_else(|e| panic!("no canonical form: {e:?}"));
    assert_eq!(
        back, text,
        "Q-W7-7: the encoding drops or changes the determination"
    );
}

/// TH-26, R-NG-03, NOTE 9 (Q-W7-7, decided 2026-10-28): `AcceptGrant`
/// carries the determination it accepts, and its canonical form keeps it.
#[test]
fn th26_r_ng_03_accept_grant_carries_its_determination() {
    round_trip(ACCEPT, CommandKind::AcceptGrant);
}

/// TH-26, R-NG-03, NOTE 9 (Q-W7-7, decided 2026-10-28): `ApproveGrant`
/// carries the determination it approves, and its canonical form keeps it.
#[test]
fn th26_r_ng_03_approve_grant_carries_its_determination() {
    round_trip(APPROVE, CommandKind::ApproveGrant);
}

/// TH-26, R-NG-03 (Q-W7-7, decided 2026-10-28): an `AcceptGrant` without
/// the determination is refused, as is every missing member.
#[test]
fn th26_r_ng_03_accept_grant_without_its_determination_is_refused() {
    let got = decode(ACCEPT_WITHOUT);
    assert!(
        got.is_err(),
        "Q-W7-7: an acceptance that names no determination decodes: {got:?}"
    );
}

/// TH-26, R-NG-03 (Q-W7-7, decided 2026-10-28): an `ApproveGrant` without
/// the determination is refused, as is every missing member.
#[test]
fn th26_r_ng_03_approve_grant_without_its_determination_is_refused() {
    let got = decode(APPROVE_WITHOUT);
    assert!(
        got.is_err(),
        "Q-W7-7: an approval that names no determination decodes: {got:?}"
    );
}

/// TH-26, ADR-007 (Q-W7-7): the determination is a decision id, so it has
/// one spelling, a decimal string. A JSON number in its place is refused.
#[test]
fn th26_r_ng_03_grant_fact_determination_has_one_spelling() {
    for text in [
        r#"{"decision":"21011","determination":21101,"proposal":"11","type":"AcceptGrant"}"#,
        r#"{"decision":"21011","determination":"021101","proposal":"11","type":"AcceptGrant"}"#,
        r#"{"decision":"22011","determination":null,"proposal":"11","type":"ApproveGrant"}"#,
    ] {
        let got = decode(text);
        assert!(got.is_err(), "Q-W7-7: {text} decodes to {got:?}");
    }
}

/// TH-26 (Q-W7-7): the `command_decode` corpus holds the new encoding of
/// both grant facts, so the fuzzer starts from valid canonical inputs.
#[test]
fn th26_codec_seeds_hold_grant_facts_naming_their_determination() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/command_decode");
    for (name, want, kind) in [
        ("accept_grant", ACCEPT, CommandKind::AcceptGrant),
        ("approve_grant", APPROVE, CommandKind::ApproveGrant),
    ] {
        let bytes = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("seed {name}: {e}"));
        assert_eq!(bytes, want.as_bytes(), "seed {name}");
        round_trip(want, kind);
    }
}
