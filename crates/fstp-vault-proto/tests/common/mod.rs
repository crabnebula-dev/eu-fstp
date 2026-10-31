//! Shared helpers of the `fstp-vault-proto` test binaries: generators of
//! canonical messages, the non-canonical rewrites every decoder must
//! refuse, and outcome helpers.

#![allow(
    dead_code,
    unreachable_pub,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "a shared test module: each test binary uses part of it"
)]

pub mod wire;

use std::collections::{BTreeMap, BTreeSet};

use fstp_prop::Gen;
use fstp_vault_proto::{
    ProtoError, RelationshipKind, VaultRefusal, VaultRequest, VaultResponse, WireAccount,
    WireAnswer, WireProgramme, WireProposal, WireQuery,
};

use wire::RQuery;

/// The largest integer RFC 8785 writes exactly, 2^53 - 1. Every integer
/// member of a vault message stays within it (as `fstp-domain` keeps ids
/// in strings for the same reason).
pub const MAX_SAFE: u64 = 9_007_199_254_740_991;

/// [`MAX_SAFE`] as a signed integer.
pub const MAX_SAFE_I64: i64 = 9_007_199_254_740_991;

/// An integer member: mostly small, sometimes at the bound.
pub fn gen_u64(g: &mut Gen) -> u64 {
    match g.u8_in(0..=5) {
        0 => MAX_SAFE,
        1 => g.u64_in(0..=MAX_SAFE),
        _ => g.u64_in(0..=20),
    }
}

/// The largest EUR amount ADR-006 admits, in cents.
pub const MAX_CENTS: i64 = 999_999_999_999_999_999;

/// An id: mostly small, so sets collide, sometimes at the `u128` bounds.
pub fn gen_id(g: &mut Gen) -> u128 {
    match g.u8_in(0..=9) {
        0 => u128::MAX,
        1 => 0,
        2 => (u128::from(g.u64()) << 64) | u128::from(g.u64()),
        _ => u128::from(g.u64_in(1..=40)),
    }
}

/// A set of ids.
pub fn gen_ids(g: &mut Gen) -> BTreeSet<u128> {
    g.vec(0..=4, gen_id).into_iter().collect()
}

/// A non-negative EUR amount in cents, with the bounds and both scale
/// edges likely.
pub fn gen_cents(g: &mut Gen) -> i64 {
    match g.u8_in(0..=5) {
        0 => 0,
        1 => MAX_CENTS,
        2 => g.i64_in(0..=MAX_CENTS),
        _ => g.i64_in(0..=1_000_000),
    }
}

/// A map from accounts to amounts.
pub fn gen_committed(g: &mut Gen) -> BTreeMap<u128, i64> {
    g.vec(0..=4, |g| (gen_id(g), gen_cents(g)))
        .into_iter()
        .collect()
}

/// Any query.
pub fn gen_query(g: &mut Gen) -> RQuery {
    match g.u16_in(0..=(wire::kind::COUNT - 1)) {
        0 => RQuery::IsVerified { account: gen_id(g) },
        1 => RQuery::SameIdentityAsAny {
            subject: gen_id(g),
            others: gen_ids(g),
        },
        2 => RQuery::HasConflict {
            reviewer: gen_id(g),
            team: gen_ids(g),
        },
        3 => RQuery::InExcludedClass {
            account: gen_id(g),
            programme: gen_id(g),
            classes: gen_ids(g),
        },
        4 => RQuery::WithinRecipientCap {
            subject: gen_id(g),
            amount: gen_cents(g),
            committed: gen_committed(g),
            cap: gen_cents(g),
        },
        5 => RQuery::AllRecipientsWithinCap {
            committed: gen_committed(g),
            cap: gen_cents(g),
        },
        6 => RQuery::HasGuardianConsent {
            proposal: gen_id(g),
        },
        7 => RQuery::IsVerifiedAdultAtDeadline {
            account: gen_id(g),
            deadline: g.i64_in(-MAX_SAFE_I64..=MAX_SAFE_I64),
        },
        8 => RQuery::DeclaresAffiliationOnList {
            team: gen_ids(g),
            list: gen_id(g),
        },
        9 => RQuery::MeetsTieBreakCountry {
            account: gen_id(g),
            programme: gen_id(g),
        },
        _ => RQuery::ChangedSince { epoch: gen_u64(g) },
    }
}

fn accounts(set: &BTreeSet<u128>) -> Vec<WireAccount> {
    set.iter().map(|a| WireAccount(*a)).collect()
}

fn link(g: &mut Gen) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (slot, b) in out.iter_mut().zip(g.bytes(32..=32)) {
        *slot = b;
    }
    out
}

/// Any canonical request.
pub fn gen_request(g: &mut Gen) -> VaultRequest {
    match g.u8_in(0..=5) {
        0 => VaultRequest::Epoch,
        1 => VaultRequest::Ask {
            at: gen_u64(g),
            reaction_for: g.option(gen_u64),
            queries: g.vec(0..=4, |g| gen_query(g).wire()),
        },
        2 => VaultRequest::Ack {
            epoch: gen_u64(g),
            ledger_seq: gen_u64(g),
            link: link(g),
        },
        3 => VaultRequest::NegotiationOpened {
            proposal: WireProposal(gen_id(g)),
            accounts: accounts(&gen_ids(g)),
            ledger_seq: gen_u64(g),
        },
        4 => VaultRequest::NegotiationClosed {
            proposal: WireProposal(gen_id(g)),
            ledger_seq: gen_u64(g),
        },
        _ => VaultRequest::RecordRelationship {
            a: WireAccount(gen_id(g)),
            b: WireAccount(gen_id(g)),
            kind: RelationshipKind::Conflict,
            programme: WireProgramme(gen_id(g)),
            ledger_seq: gen_u64(g),
        },
    }
}

/// Any lawful answer: one bit with no set, or a `ChangedSince` set whose
/// bit says whether it is non-empty.
pub fn gen_answer(g: &mut Gen) -> WireAnswer {
    let epoch = gen_u64(g);
    if g.bool() {
        let set = gen_ids(g);
        WireAnswer {
            holds: !set.is_empty(),
            accounts: Some(accounts(&set)),
            epoch,
        }
    } else {
        WireAnswer {
            holds: g.bool(),
            accounts: None,
            epoch,
        }
    }
}

/// Any refusal.
pub fn gen_refusal(g: &mut Gen) -> VaultRefusal {
    match g.u8_in(0..=4) {
        0 => VaultRefusal::Pending { epoch: gen_u64(g) },
        1 => VaultRefusal::StaleEpoch {
            current: gen_u64(g),
        },
        2 => VaultRefusal::NotThisCell,
        3 => VaultRefusal::Malformed,
        _ => VaultRefusal::Unavailable,
    }
}

/// Any canonical response.
pub fn gen_response(g: &mut Gen) -> VaultResponse {
    match g.u8_in(0..=3) {
        0 => VaultResponse::Epoch(gen_u64(g)),
        1 => VaultResponse::Answers(g.vec(0..=4, gen_answer)),
        2 => VaultResponse::Acked,
        _ => VaultResponse::Refused(gen_refusal(g)),
    }
}

/// The rewrites of a canonical message that keep its JSON meaning, or add
/// to it, and that no canonical decoder accepts. Each has a label.
pub fn non_canonical(canonical: &[u8]) -> Vec<(&'static str, Vec<u8>)> {
    let text = String::from_utf8_lossy(canonical).into_owned();
    let mut out = vec![
        ("leading space", format!(" {text}").into_bytes()),
        ("trailing newline", format!("{text}\n").into_bytes()),
        ("trailing byte", [canonical, b"0"].concat()),
        (
            "space after the first colon",
            text.replacen(':', ": ", 1).into_bytes(),
        ),
        (
            "escaped key",
            text.replacen("\"type\"", "\"t\\u0079pe\"", 1).into_bytes(),
        ),
    ];
    if let Some(body) = text.strip_suffix('}') {
        out.push(("unknown member", format!("{body},\"zz\":0}}").into_bytes()));
        out.push((
            "duplicate member",
            format!("{body},\"type\":\"epoch\"}}").into_bytes(),
        ));
    }
    out
}

/// Whether `e` is the W0 stub refusal.
pub fn is_stub(e: &ProtoError) -> bool {
    matches!(e, ProtoError::NotImplemented(_))
}

/// The outcome of a decode, for a property report.
pub fn shown<T: std::fmt::Debug>(r: &Result<T, ProtoError>) -> String {
    format!("{r:?}")
}

/// A wire query from a kind and its arguments text.
pub fn raw_query(kind: u16, args: &str) -> WireQuery {
    WireQuery {
        kind,
        args: args.as_bytes().to_vec(),
    }
}

/// An `ask` request text with one query of `kind` and `args`.
pub fn ask_with(kind: u16, args: &str) -> Vec<u8> {
    format!(
        "{{\"at\":1,\"queries\":[{{\"args\":{args},\"kind\":{kind}}}],\"reaction_for\":null,\"type\":\"ask\"}}"
    )
    .into_bytes()
}
