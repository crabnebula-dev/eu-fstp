//! I-33, I-86 and R-PR-04 end to end through the vault: origin writes
//! under signed tickets, the NOTE 4 acknowledgements, and the cell's
//! internal `ask` (M5 design sections 5, 8 and 12.1, Q1 A).
//!
//! - Every bank detail write, the first included, starts re-verification
//!   and the P-36 hold. A release asked inside the hold, before the
//!   verification or while a write is provisional is refused (I-33).
//! - Bank details and hardship evidence appear in no internal reply, no
//!   write reply and no identity release. Only the bank view on the vault
//!   origin shows them (I-86).
//! - `BankReleasable` and `HardshipEvidenceVerified` answer one bit.

#![allow(
    clippy::unwrap_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::origin_write;
use common::vc::Signer;
use common::vc::wire::RTicket;
use fstp_vault::{OriginRefusal, Vault};
use fstp_vault_proto::{
    Query, VaultRefusal, VaultRequest, VaultResponse, WireAccount, WireEvidence, WireProposal,
    encode_response,
};

const CELL: [u8; 16] = [0xCE; 16];
const GRANT: u128 = 77;
const LEAD: u128 = 10;
const FINANCE: u128 = 20;
const DAY: i64 = 86_400_000_000;
const SEC: i64 = 1_000_000;
const HOLD: u16 = 7;
const T0: i64 = 100 * DAY;
const IBAN: &str = "DE89370400440532013000";
const HOLDER: &str = "Synthetic Holder";
const STATEMENT: &str = "Synthetic hardship statement";

fn ticket(kind: &str, account: u128, issued_at: i64, nonce: u8) -> RTicket {
    RTicket {
        kind: kind.to_owned(),
        cell: CELL,
        account,
        proposal: Some(GRANT),
        scope: String::new(),
        issued_at,
        expires_at: issued_at + 240 * SEC,
        nonce: [nonce; 16],
    }
}

fn bank_body() -> String {
    format!(
        "{{\"account\":\"{LEAD}\",\"grant\":\"{GRANT}\",\"holder\":\"{HOLDER}\",\"iban\":\"{IBAN}\"}}"
    )
}

fn verify_body(verifier: u128) -> String {
    format!(
        "{{\"checks\":[\"holder_matches\",\"iban_matches\"],\"grant\":\"{GRANT}\",\"method\":\"bank_statement\",\"verifier\":\"{verifier}\"}}"
    )
}

/// The vault, and every byte it sent the cell or a browser outside the
/// bank view.
struct World {
    v: Vault,
    key: Signer,
    sent: Vec<Vec<u8>>,
    seq: u64,
}

impl World {
    fn new() -> World {
        let key = Signer::new(3);
        World {
            v: Vault::new(CELL, &[key.public()]).unwrap(),
            key,
            sent: Vec::new(),
            seq: 0,
        }
    }

    /// `POST /w` through the origin router. Returns the status.
    fn write(&mut self, t: &RTicket, body: &str, now: i64) -> u16 {
        let bytes = origin_write(&self.key.sign(t), body);
        let r = self.v.origin("POST", "/w", &bytes, now);
        self.sent.push(r.body.clone());
        r.status
    }

    fn internal(&mut self, req: &VaultRequest, now: i64) -> VaultResponse {
        let r = self.v.internal(req, now);
        self.sent.push(encode_response(&r).unwrap());
        r
    }

    /// Acknowledges the provisional epoch, as the cell's reaction does.
    fn ack(&mut self, now: i64) {
        let Some(epoch) = self.v.state().provisional().map(|p| p.epoch()) else {
            panic!("no provisional epoch");
        };
        self.seq += 1;
        let r = self.internal(
            &VaultRequest::Ack {
                epoch,
                ledger_seq: self.seq,
                link: [7; 32],
            },
            now,
        );
        assert_eq!(r, VaultResponse::Acked);
    }

    fn ask(&mut self, q: Query, now: i64) -> Result<bool, VaultRefusal> {
        let req = VaultRequest::Ask {
            at: u64::try_from(now).unwrap(),
            reaction_for: None,
            queries: vec![q.to_wire().unwrap()],
        };
        match self.internal(&req, now) {
            VaultResponse::Answers(a) => {
                assert_eq!(a.len(), 1);
                assert!(a[0].accounts.is_none(), "I-86: one bit, no account");
                Ok(a[0].holds)
            }
            VaultResponse::Refused(r) => Err(r),
            other => panic!("unexpected {other:?}"),
        }
    }

    fn releasable(&mut self, at: i64) -> Result<bool, VaultRefusal> {
        self.ask(
            Query::BankReleasable {
                grant: WireProposal(GRANT),
                at,
                hold: HOLD,
            },
            at,
        )
    }

    fn assert_never_sent(&self, secret: &str) {
        for (i, b) in self.sent.iter().enumerate() {
            let text = String::from_utf8_lossy(b);
            assert!(
                !text.contains(secret),
                "I-86: reply {i} holds {secret:?}: {text}"
            );
        }
    }
}

/// I-33 end to end: the first write holds, the verification and P-36 both
/// gate, a provisional write fails closed, and a change starts again.
#[test]
fn i_33_release_refused_inside_hold_or_before_reverification_through_the_vault() {
    let mut w = World::new();
    assert_eq!(w.releasable(T0), Ok(false), "no bank details: fail closed");

    let t = ticket("write:bank_details", LEAD, T0 - SEC, 1);
    assert_eq!(w.write(&t, &bank_body(), T0), 204);
    assert!(
        matches!(
            w.releasable(T0 + 30 * DAY),
            Err(VaultRefusal::Pending { .. })
        ),
        "a provisional write fails the release closed"
    );
    w.ack(T0);
    assert_eq!(w.releasable(T0 + 30 * DAY), Ok(false), "unverified");

    // A verification ticket issued before the write does not verify it.
    let early = ticket("write:bank_verification", FINANCE, T0 - SEC, 2);
    assert_eq!(w.write(&early, &verify_body(FINANCE), T0 + SEC), 403);
    // The writer never verifies their own details.
    let own = ticket("write:bank_verification", LEAD, T0 + SEC, 3);
    assert_eq!(w.write(&own, &verify_body(LEAD), T0 + 2 * SEC), 403);
    // The browser never sets the instant or the version.
    let stamped = ticket("write:bank_verification", FINANCE, T0 + SEC, 4);
    let forged = format!(
        "{{\"at\":0,\"checks\":[\"iban_matches\"],\"grant\":\"{GRANT}\",\"method\":\"bank_letter\",\"verifier\":\"{FINANCE}\"}}"
    );
    assert_eq!(w.write(&stamped, &forged, T0 + 2 * SEC), 400);

    let ok = ticket("write:bank_verification", FINANCE, T0 + SEC, 5);
    assert_eq!(w.write(&ok, &verify_body(FINANCE), T0 + 2 * SEC), 204);
    w.ack(T0 + 2 * SEC);
    assert_eq!(w.releasable(T0 + 7 * DAY - 1), Ok(false), "inside P-36");
    assert_eq!(w.releasable(T0 + 7 * DAY), Ok(true));

    // A dispute freezes releases until a verifier resolves it.
    let open = ticket("write:bank_dispute", LEAD, T0 + 8 * DAY, 6);
    let open_body = format!("{{\"account\":\"{LEAD}\",\"grant\":\"{GRANT}\",\"open\":true}}");
    assert_eq!(w.write(&open, &open_body, T0 + 8 * DAY), 204);
    w.ack(T0 + 8 * DAY);
    assert_eq!(w.releasable(T0 + 9 * DAY), Ok(false), "dispute open");
    let close = ticket("write:bank_verification", FINANCE, T0 + 9 * DAY, 7);
    let close_body = format!("{{\"account\":\"{FINANCE}\",\"grant\":\"{GRANT}\",\"open\":false}}");
    assert_eq!(w.write(&close, &close_body, T0 + 9 * DAY), 204);
    w.ack(T0 + 9 * DAY);
    assert_eq!(w.releasable(T0 + 9 * DAY), Ok(true));

    // A change of bank details needs a new verification and a new hold.
    let t1 = T0 + 10 * DAY;
    let change = ticket("write:bank_details", LEAD, t1 - SEC, 8);
    assert_eq!(w.write(&change, &bank_body(), t1), 204);
    w.ack(t1);
    assert_eq!(
        w.releasable(t1 + 30 * DAY),
        Ok(false),
        "I-33: change unverified"
    );
    let again = ticket("write:bank_verification", FINANCE, t1 + SEC, 9);
    assert_eq!(w.write(&again, &verify_body(FINANCE), t1 + 2 * SEC), 204);
    w.ack(t1 + 2 * SEC);
    assert_eq!(w.releasable(t1 + 7 * DAY - 1), Ok(false));
    assert_eq!(w.releasable(t1 + 7 * DAY), Ok(true));

    w.assert_never_sent(IBAN);
    w.assert_never_sent(HOLDER);
}

/// R-PR-04, I-86: hardship evidence returns only its reference, counts
/// once another account verifies it, and its statement leaves no reply.
#[test]
fn r_pr_04_hardship_evidence_verified_through_the_vault() {
    let mut w = World::new();
    let t = ticket("write:hardship_evidence", LEAD, T0 - SEC, 0x21);
    let bytes = origin_write(
        &w.key.sign(&t),
        &format!("{{\"account\":\"{LEAD}\",\"grant\":\"{GRANT}\",\"statement\":\"{STATEMENT}\"}}"),
    );
    let r = w.v.origin("POST", "/w", &bytes, T0);
    assert_eq!(r.status, 200);
    let evidence = u128::from_be_bytes([0x21; 16]);
    assert_eq!(
        r.body,
        format!("{{\"evidence\":\"{evidence}\"}}").into_bytes(),
        "the reply holds the reference only"
    );
    w.ack(T0);
    let q = || Query::HardshipEvidenceVerified {
        grant: WireProposal(GRANT),
        evidence: WireEvidence(evidence),
    };
    assert_eq!(w.ask(q(), T0), Ok(false), "submitted, not verified");
    let body = |v: u128| {
        format!("{{\"evidence\":\"{evidence}\",\"grant\":\"{GRANT}\",\"verifier\":\"{v}\"}}")
    };
    let own = ticket("write:hardship_verification", LEAD, T0, 0x22);
    assert_eq!(w.write(&own, &body(LEAD), T0 + SEC), 403);
    let ok = ticket("write:hardship_verification", FINANCE, T0, 0x23);
    assert_eq!(w.write(&ok, &body(FINANCE), T0 + SEC), 204);
    w.ack(T0 + SEC);
    assert_eq!(w.ask(q(), T0 + SEC), Ok(true));
    let other = Query::HardshipEvidenceVerified {
        grant: WireProposal(GRANT + 1),
        evidence: WireEvidence(evidence),
    };
    assert_eq!(w.ask(other, T0 + SEC), Ok(false), "another grant");
    w.assert_never_sent(STATEMENT);
}

/// I-86: an identity release shows no bank detail. Only the bank view
/// ticket of the grant shows them, server-rendered with no script.
#[test]
fn i_86_bank_details_shown_only_on_the_bank_view() {
    let mut w = World::new();
    let t = ticket("write:bank_details", LEAD, T0 - SEC, 1);
    assert_eq!(w.write(&t, &bank_body(), T0), 204);
    w.ack(T0);
    w.v.negotiation_opened(
        WireProposal(GRANT),
        &[WireAccount(LEAD)].into_iter().collect(),
        1,
    )
    .unwrap();
    let release = ticket("release", LEAD, T0, 2);
    let r = w.v.post_release(&w.key.sign(&release), T0 + SEC).unwrap();
    let text = String::from_utf8(r.body).unwrap();
    assert!(!text.contains(IBAN) && !text.contains(HOLDER), "{text}");

    let view = ticket("view:bank", FINANCE, T0, 3);
    let r = w.v.post_release(&w.key.sign(&view), T0 + SEC).unwrap();
    let text = String::from_utf8(r.body).unwrap();
    assert!(text.contains(IBAN) && text.contains(HOLDER), "{text}");
    assert!(!text.contains("<script"), "the document runs no script");
    assert!(
        r.headers
            .iter()
            .any(|(n, v)| *n == "content-security-policy" && v == "default-src 'none'")
    );
    assert_eq!(
        w.v.post_release(&w.key.sign(&view), T0 + SEC),
        Err(OriginRefusal::Replayed),
        "single use"
    );
    // A view ticket is no write ticket.
    assert_eq!(
        w.write(&ticket("view:bank", LEAD, T0, 4), &bank_body(), T0),
        403
    );
}

/// I-33, R-PR-05: a malformed IBAN or holder is refused before it is
/// stored, and the IBAN check is MOD 97-10.
#[test]
fn r_pr_05_bank_details_are_validated() {
    let mut w = World::new();
    for (n, (holder, iban)) in [
        (HOLDER, "DE89370400440532013001"),
        (HOLDER, "de89370400440532013000"),
        (HOLDER, "DE8937040044"),
        ("", IBAN),
        (" Leading", IBAN),
    ]
    .into_iter()
    .enumerate()
    {
        let t = ticket(
            "write:bank_details",
            LEAD,
            T0 - SEC,
            0x40 + u8::try_from(n).unwrap(),
        );
        let body = format!(
            "{{\"account\":\"{LEAD}\",\"grant\":\"{GRANT}\",\"holder\":\"{holder}\",\"iban\":\"{iban}\"}}"
        );
        assert_eq!(w.write(&t, &body, T0), 400, "{holder:?} {iban:?}");
    }
    assert!(fstp_vault_core::fact::iban_ok("GB82WEST12345698765432"));
    assert!(!fstp_vault_core::fact::iban_ok("GB82WEST12345698765433"));
}
