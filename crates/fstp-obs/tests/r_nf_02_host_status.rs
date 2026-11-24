//! R-NF-02 over the host status file (ADR-028 record of lane L20): the
//! file `fstp-admin` writes and the cell reads holds operational facts
//! only. Every value is an integer, a boolean, `null` or one word of a
//! closed list, so no free text, name, address, path, account or domain
//! can reach it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_obs::host_status::{
    CustodianState, HostStatus, HostStatusError, MAX_LEN, Next, PartState, Parts, RouteState,
    decode, encode,
};
use fstp_prop::{Gen, check};

fn sample() -> HostStatus {
    HostStatus {
        written_at: 1_795_000_000,
        setup_done: true,
        parts: Parts {
            cell: PartState::Running,
            vault: PartState::Running,
            witness: PartState::Running,
            edge: PartState::Unhealthy,
            databases: PartState::Running,
            keys: PartState::Stopped,
        },
        backups_configured: true,
        last_backup: Some(1_794_990_000),
        last_key_copy: None,
        last_vault_erasure: Some(1_794_980_000),
        last_app_snapshot: Some(1_794_995_000),
        app_snapshot_failed: false,
        last_vault_snapshot: None,
        vault_snapshot_failed: true,
        certificate_days: Some(5),
        self_signed: false,
        route: RouteState::Mismatch,
        next: Next::RenewRoute,
        custodian: CustodianState::Unreachable,
        guard_owed: true,
        guard_copy_owed: false,
    }
}

const STATES: [PartState; 3] = [PartState::Running, PartState::Unhealthy, PartState::Stopped];
const ROUTES: [RouteState; 3] = [
    RouteState::Current,
    RouteState::Mismatch,
    RouteState::Unknown,
];

fn pick<T: Copy>(g: &mut Gen, xs: &[T]) -> T {
    *g.pick(xs)
}

fn opt_time(g: &mut Gen) -> Option<i64> {
    if g.bool() {
        None
    } else {
        Some(g.i64_in(0..=253_402_300_799))
    }
}

fn arbitrary(g: &mut Gen) -> HostStatus {
    HostStatus {
        written_at: g.i64_in(0..=253_402_300_799),
        setup_done: g.bool(),
        parts: Parts {
            cell: pick(g, &STATES),
            vault: pick(g, &STATES),
            witness: pick(g, &STATES),
            edge: pick(g, &STATES),
            databases: pick(g, &STATES),
            keys: pick(g, &STATES),
        },
        backups_configured: g.bool(),
        last_backup: opt_time(g),
        last_key_copy: opt_time(g),
        last_vault_erasure: opt_time(g),
        last_app_snapshot: opt_time(g),
        app_snapshot_failed: g.bool(),
        last_vault_snapshot: opt_time(g),
        vault_snapshot_failed: g.bool(),
        certificate_days: if g.bool() {
            None
        } else {
            Some(g.i64_in(-36_500..=36_500))
        },
        self_signed: g.bool(),
        route: pick(g, &ROUTES),
        next: pick(g, &Next::ALL),
        custodian: pick(g, &CustodianState::ALL),
        guard_owed: g.bool(),
        guard_copy_owed: g.bool(),
    }
}

/// R-NF-02, ADR-028 record of lane L20: every status encodes to one line
/// of at most `MAX_LEN` bytes and decodes back to itself.
#[test]
fn r_nf_02_host_status_round_trips() {
    assert_eq!(decode(encode(&sample()).as_bytes()), Ok(sample()));
    check("host status round trip", |g| {
        let s = arbitrary(g);
        let text = encode(&s);
        assert!(text.len() <= MAX_LEN, "{text}");
        assert_eq!(text.matches('\n').count(), 1, "{text}");
        assert!(text.ends_with('\n'));
        assert_eq!(decode(text.as_bytes()), Ok(s), "{text}");
        Ok(())
    });
}

/// R-NF-02: the encoded file holds no string that is not a member name or
/// a word of a closed list. Its only strings are lowercase ASCII words
/// with underscores, so an email, a domain, a path or a name has no slot.
#[test]
fn r_nf_02_host_status_holds_no_free_text() {
    check("host status words", |g| {
        let text = encode(&arbitrary(g));
        let v = fstp_json::parse(text.as_bytes()).unwrap();
        let mut strings = Vec::new();
        collect_strings(&v, &mut strings);
        for s in strings {
            assert!(
                !s.is_empty() && s.bytes().all(|b| b.is_ascii_lowercase() || b == b'_'),
                "a free string {s:?} in {text}"
            );
        }
        Ok(())
    });
}

fn collect_strings(v: &fstp_json::Value, out: &mut Vec<String>) {
    if let Some(s) = v.as_str() {
        out.push(s.to_owned());
    } else if let Some(a) = v.as_array() {
        for x in a.iter() {
            collect_strings(x, out);
        }
    } else if let Some(o) = v.as_object() {
        for (k, x) in o.iter() {
            out.push(k.to_owned());
            collect_strings(x, out);
        }
    }
}

/// R-NF-02, ADR-028 record of lane L20: the member set is closed, every
/// value is checked, and an over-long input is refused before parsing.
#[test]
fn r_nf_02_host_status_refuses_bad_input() {
    let good = encode(&sample());
    let swap = |from: &str, to: &str| {
        assert!(good.contains(from), "{from}");
        good.replacen(from, to, 1)
    };
    let cases: Vec<(String, HostStatusError)> = vec![
        ("[]".into(), HostStatusError::NotAnObject),
        ("{".into(), HostStatusError::NotJson),
        (
            swap("\"version\":1", "\"version\":2"),
            HostStatusError::Version,
        ),
        (
            swap("\"version\":1", "\"version\":1,\"email\":\"a\""),
            HostStatusError::UnknownMember,
        ),
        (
            swap(",\"version\":1", ""),
            HostStatusError::MissingMember("version"),
        ),
        (
            swap("\"route\":\"mismatch\"", "\"route\":\"grants.example.eu\""),
            HostStatusError::Invalid("route"),
        ),
        (
            swap("\"cell\":\"running\"", "\"cell\":\"Running\""),
            HostStatusError::Invalid("parts.cell"),
        ),
        (
            swap(
                "\"cell\":\"running\",",
                "\"cell\":\"running\",\"host\":\"x\",",
            ),
            HostStatusError::UnknownMember,
        ),
        (
            swap("\"certificate_days\":5", "\"certificate_days\":5.5"),
            HostStatusError::Invalid("certificate_days"),
        ),
        (
            swap("\"last_key_copy\":null", "\"last_key_copy\":-1"),
            HostStatusError::Invalid("last_key_copy"),
        ),
        (
            swap("\"setup_done\":true", "\"setup_done\":1"),
            HostStatusError::Invalid("setup_done"),
        ),
        // ADR-028 record of lane L26: the keystore snapshot facts of L27.
        (
            swap("\"last_vault_snapshot\":null", "\"last_vault_snapshot\":-1"),
            HostStatusError::Invalid("last_vault_snapshot"),
        ),
        (
            swap(
                "\"vault_snapshot_failed\":true",
                "\"vault_snapshot_failed\":\"yes\"",
            ),
            HostStatusError::Invalid("vault_snapshot_failed"),
        ),
        (
            swap("\"app_snapshot_failed\":false,", ""),
            HostStatusError::MissingMember("app_snapshot_failed"),
        ),
        // ADR-028 record of lane `m10/guard-key`: the custodian facts.
        (
            swap("\"custodian\":\"unreachable\"", "\"custodian\":\"down\""),
            HostStatusError::Invalid("custodian"),
        ),
        (
            swap("\"guard_owed\":true,", ""),
            HostStatusError::MissingMember("guard_owed"),
        ),
        // Part 2 (Q-F018-4): an owed fresh copy for the custodian.
        (
            swap("\"guard_copy_owed\":false,", "\"guard_copy_owed\":0,"),
            HostStatusError::Invalid("guard_copy_owed"),
        ),
        (
            swap("\"guard_copy_owed\":false,", ""),
            HostStatusError::MissingMember("guard_copy_owed"),
        ),
        (
            format!("{good}{}", " ".repeat(MAX_LEN)),
            HostStatusError::TooLong,
        ),
    ];
    for (text, want) in cases {
        assert_eq!(decode(text.as_bytes()), Err(want), "{text}");
    }
    // A repeated member is refused by the parser.
    let twice = swap("\"version\":1", "\"version\":1,\"version\":1");
    assert_eq!(decode(twice.as_bytes()), Err(HostStatusError::NotJson));
}

/// R-NF-02: a refusal names its rule only. Its text never quotes a byte of
/// the input, whatever the input holds.
#[test]
fn r_nf_02_host_status_errors_never_quote_bytes() {
    let canary = "canary-applicant@example.eu";
    let good = encode(&sample());
    for text in [
        good.replacen("\"mismatch\"", &format!("\"{canary}\""), 1),
        good.replacen("\"version\":1", &format!("\"{canary}\":1"), 1),
        format!("{{\"{canary}\""),
    ] {
        let e = decode(text.as_bytes()).unwrap_err();
        let shown = format!("{e} {e:?}");
        assert!(!shown.contains("canary"), "{shown}");
    }
}
