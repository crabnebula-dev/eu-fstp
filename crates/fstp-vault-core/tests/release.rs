//! The vault side of a release (I-17, ADR-009 "Tickets" and "Releases",
//! design section 6.5): `fstp_vault_core::release_allowed`.
//!
//! The vault pins its cell id and the cell's current and next ticket keys
//! at provisioning. A release ticket is honoured only when its Ed25519
//! signature verifies under a pinned key, it names this cell, it is a
//! release ticket, it is within its window and at most 5 minutes long, and
//! the vault's own negotiation fact for its proposal lists its subject.
//!
//! Single use is the service's part (`vault.ticket_used`), so it is tested
//! in `fstp-vault`. The core check is pure and reads no used set.
//!
//! Every test here waits on `common::PROVISION_SEAM`: the core has no
//! provisioning call, no negotiation fact and no route in
//! `ReleaseClaims` yet (W1c `PROVISION_SEAM`).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::wire::RTicket;
use common::{Fail, Signer, Vault, refusal, set};
use fstp_prop::{Gen, prop_assert_eq};
use fstp_vault_core::TicketRefusal;
use fstp_vault_proto::VaultRefusal;

const CELL: [u8; 16] = [0xCE; 16];
const OTHER_CELL: [u8; 16] = [0xCF; 16];
const SUBJECT: u128 = 501;
const OTHER: u128 = 502;
const PR: u128 = 1;
const PR2: u128 = 2;
const ISSUED: i64 = 10_000_000_000;
const LIFETIME_MAX: i64 = 5 * 60 * 1_000_000;
const NOW: i64 = ISSUED + 1_000_000;

fn ticket() -> RTicket {
    RTicket {
        kind: "release".to_owned(),
        cell: CELL,
        account: SUBJECT,
        proposal: Some(PR),
        scope: "identity".to_owned(),
        issued_at: ISSUED,
        expires_at: ISSUED + LIFETIME_MAX,
        nonce: [7; 16],
    }
}

/// A vault of `CELL` that pins `current` and `next`, with a negotiation
/// fact for `PR` listing `SUBJECT`.
fn provisioned(current: &Signer, next: &Signer) -> Result<Vault, Fail> {
    let mut v = Vault::new();
    v.provision(CELL, &[current.public(), next.public()])?;
    v.negotiation_opened(PR, &set([SUBJECT, OTHER]))?;
    Ok(v)
}

/// I-17, design section 6.5 "Second guard": the vault refuses a release
/// unless its own negotiation fact for the ticket's proposal lists the
/// subject.
#[test]
fn i17_vault_refuses_release_without_negotiation_fact() -> Result<(), Fail> {
    let key = Signer::new(1);
    let bytes = key.sign(&ticket());
    let mut v = Vault::new();
    v.provision(CELL, &[key.public()])?;
    refusal(v.release(&bytes, NOW))?;
    v.negotiation_opened(PR, &set([OTHER]))?;
    refusal(v.release(&bytes, NOW))?;
    v.negotiation_opened(PR2, &set([SUBJECT]))?;
    refusal(v.release(&bytes, NOW))?;
    v.negotiation_opened(PR, &set([SUBJECT, OTHER]))?;
    v.release(&bytes, NOW)?;
    v.negotiation_closed(PR)?;
    refusal(v.release(&bytes, NOW))?;
    Ok(())
}

/// I-17, ADR-009 "Tickets": a ticket with no proposal names no
/// negotiation fact, so it is refused.
#[test]
fn i17_release_ticket_without_proposal_is_refused() -> Result<(), Fail> {
    let key = Signer::new(1);
    let v = provisioned(&key, &Signer::new(2))?;
    v.release(&key.sign(&ticket()), NOW)?;
    let t = RTicket {
        proposal: None,
        ..ticket()
    };
    refusal(v.release(&key.sign(&t), NOW))?;
    Ok(())
}

/// I-17, ADR-009 "Tickets": the signature is checked over the exact
/// body under a pinned key. A flipped signature or body byte, or a key
/// the vault did not pin, is refused. The next pinned key verifies.
#[test]
fn i17_release_ticket_signature_is_checked_under_pinned_keys() -> Result<(), Fail> {
    let current = Signer::new(1);
    let next = Signer::new(2);
    let v = provisioned(&current, &next)?;
    let good = current.sign(&ticket());
    v.release(&good, NOW)?;
    v.release(&next.sign(&ticket()), NOW)?;
    refusal(v.release(&Signer::new(3).sign(&ticket()), NOW))?;
    let last = good.len() - 1;
    let mut sig_flip = good.clone();
    sig_flip[last] ^= 1;
    refusal(v.release(&sig_flip, NOW))?;
    let mut body_flip = good.clone();
    body_flip[13] ^= 1;
    refusal(v.release(&body_flip, NOW))?;
    refusal(v.release(&good[..last], NOW))?;
    refusal(v.release(&[], NOW))?;
    Ok(())
}

/// I-17, I-19, ADR-009 "Binding": a ticket for another cell is refused as
/// not this cell's, even when its signature verifies.
#[test]
fn i17_release_ticket_for_another_cell_is_refused() -> Result<(), Fail> {
    let key = Signer::new(1);
    let v = provisioned(&key, &Signer::new(2))?;
    v.release(&key.sign(&ticket()), NOW)?;
    let t = RTicket {
        cell: OTHER_CELL,
        ..ticket()
    };
    assert_eq!(
        refusal(v.release(&key.sign(&t), NOW))?,
        VaultRefusal::NotThisCell
    );
    Ok(())
}

/// I-17, ADR-009 "Binding": a write ticket is never honoured as a
/// release, whatever its write kind.
#[test]
fn i17_write_ticket_is_never_a_release() -> Result<(), Fail> {
    let key = Signer::new(1);
    let v = provisioned(&key, &Signer::new(2))?;
    v.release(&key.sign(&ticket()), NOW)?;
    for kind in [
        "write:country_stated",
        "write:verification_recorded",
        "write:guardian_consent",
        "releases",
        "",
    ] {
        let t = RTicket {
            kind: kind.to_owned(),
            ..ticket()
        };
        refusal(v.release(&key.sign(&t), NOW))?;
    }
    Ok(())
}

/// I-17, ADR-009 "Lifetime": a ticket is valid from its issue instant and
/// strictly before its expiry, and lives at most 5 minutes (Q37 interim).
#[test]
fn i17_release_ticket_window_and_lifetime_are_enforced() -> Result<(), Fail> {
    let key = Signer::new(1);
    let v = provisioned(&key, &Signer::new(2))?;
    let t = ticket();
    let bytes = key.sign(&t);
    v.release(&bytes, t.issued_at)?;
    v.release(&bytes, t.expires_at - 1)?;
    refusal(v.release(&bytes, t.issued_at - 1))?;
    refusal(v.release(&bytes, t.expires_at))?;
    let long = RTicket {
        expires_at: ISSUED + LIFETIME_MAX + 1,
        ..ticket()
    };
    refusal(v.release(&key.sign(&long), NOW))?;
    let backwards = RTicket {
        expires_at: ISSUED - 1,
        ..ticket()
    };
    refusal(v.release(&key.sign(&backwards), ISSUED - 2))?;
    Ok(())
}

/// I-17, ADR-009 "Format": only the canonical body verifies into claims.
/// A signed body with another spelling of the same claims is refused.
#[test]
fn i17_release_ticket_needs_the_canonical_body() -> Result<(), Fail> {
    let key = Signer::new(1);
    let v = provisioned(&key, &Signer::new(2))?;
    v.release(&key.sign(&ticket()), NOW)?;
    let body = String::from_utf8(ticket().body()).unwrap();
    for spelled in [
        body.replacen(':', ": ", 1),
        body.replacen("\"account\":\"501\"", "\"account\":\"0501\"", 1),
        format!("{body} "),
    ] {
        let sig = fstp_crypto::sig::Ed25519SigningKey::from_seed(&[1; 32])
            .unwrap()
            .sign(spelled.as_bytes())
            .unwrap();
        let bytes = [spelled.as_bytes(), sig.as_slice()].concat();
        refusal(v.release(&bytes, NOW))?;
    }
    Ok(())
}

/// One way to build a ticket, after lane W1c's `Mutation` in
/// `fstp-celltest/tests/i17_identity_release.rs`. Single use is the
/// service's part, so `Replayed` is not here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Mutation {
    Valid,
    SignedWithNextKey,
    Forged,
    Tampered,
    Expired,
    AtExpiry,
    Future,
    TooLong,
    Foreign,
    WriteTicketOnReleaseRoute,
}

const MUTATIONS: [Mutation; 10] = [
    Mutation::Valid,
    Mutation::SignedWithNextKey,
    Mutation::Forged,
    Mutation::Tampered,
    Mutation::Expired,
    Mutation::AtExpiry,
    Mutation::Future,
    Mutation::TooLong,
    Mutation::Foreign,
    Mutation::WriteTicketOnReleaseRoute,
];

impl Mutation {
    /// The exact refusal `check_ticket` must give, as W1c's
    /// `Mutation::expected`.
    fn expected(self) -> Option<TicketRefusal> {
        match self {
            Mutation::Valid | Mutation::SignedWithNextKey => None,
            Mutation::Forged | Mutation::Tampered => Some(TicketRefusal::BadSignature),
            Mutation::Expired | Mutation::AtExpiry => Some(TicketRefusal::Expired),
            Mutation::Future => Some(TicketRefusal::NotYetValid),
            Mutation::TooLong => Some(TicketRefusal::TooLong),
            Mutation::Foreign => Some(TicketRefusal::ForeignCell),
            Mutation::WriteTicketOnReleaseRoute => Some(TicketRefusal::WrongKind),
        }
    }
}

/// A release ticket for `SUBJECT` and `PR` at `NOW`, built with `m`.
fn mutated(g: &mut Gen, m: Mutation) -> Vec<u8> {
    let life = g.i64_in(1..=LIFETIME_MAX);
    let issued = NOW - g.i64_in(0..=life - 1);
    let mut t = RTicket {
        issued_at: issued,
        expires_at: issued + life,
        nonce: [g.u8_in(0..=255); 16],
        ..ticket()
    };
    let mut key = Signer::new(1);
    match m {
        Mutation::Valid | Mutation::Tampered => {}
        Mutation::SignedWithNextKey => key = Signer::new(2),
        Mutation::Forged => key = Signer::new(3),
        Mutation::Expired => {
            t.expires_at = NOW - g.i64_in(1..=1_000);
            t.issued_at = t.expires_at - life;
        }
        Mutation::AtExpiry => {
            t.expires_at = NOW;
            t.issued_at = NOW - life;
        }
        Mutation::Future => {
            t.issued_at = NOW + g.i64_in(1..=1_000);
            t.expires_at = t.issued_at + life;
        }
        Mutation::TooLong => {
            t.issued_at = NOW - 1;
            t.expires_at = t.issued_at + LIFETIME_MAX + g.i64_in(1..=1_000);
        }
        Mutation::Foreign => t.cell = OTHER_CELL,
        Mutation::WriteTicketOnReleaseRoute => {
            t.kind = (*g.pick(&["write:country_stated", "write:guardian_consent"])).to_owned();
        }
    }
    let mut bytes = key.sign(&t);
    if m == Mutation::Tampered {
        let i = g.usize_in(0..=bytes.len() - 65);
        bytes[i] ^= 1 << g.u8_in(0..=7);
    }
    bytes
}

/// I-17, ADR-009 "Tickets": `check_ticket` gives the exact refusal of
/// each W1c mutation on the release route, not only some refusal. A
/// check that reported `Expired` for a future ticket, or `Malformed` for
/// a bad signature, fails here.
#[test]
fn i17_check_ticket_gives_the_exact_refusal_of_each_mutation() {
    fstp_prop::check(
        "i17_check_ticket_gives_the_exact_refusal_of_each_mutation",
        |g: &mut Gen| {
            let v = provisioned(&Signer::new(1), &Signer::new(2)).map_err(|e| format!("{e:?}"))?;
            let m = *g.pick(&MUTATIONS);
            let got = v.check_release(&mutated(g, m), NOW).err();
            prop_assert_eq!(got, m.expected(), "I-17: ticket {m:?}");
            Ok(())
        },
    );
}

/// I-17, ADR-009 "Tickets": an unprovisioned vault refuses as
/// unprovisioned, and bytes with no room for a signature as malformed.
#[test]
fn i17_check_ticket_refuses_unprovisioned_and_unframed_tickets() -> Result<(), Fail> {
    let key = Signer::new(1);
    let bytes = key.sign(&ticket());
    assert_eq!(
        Vault::new().check_release(&bytes, NOW).err(),
        Some(TicketRefusal::Unprovisioned)
    );
    let v = provisioned(&key, &Signer::new(2))?;
    assert_eq!(
        v.check_release(&bytes[..64], NOW).err(),
        Some(TicketRefusal::Malformed)
    );
    assert!(v.check_release(&bytes, NOW).is_ok());
    Ok(())
}
