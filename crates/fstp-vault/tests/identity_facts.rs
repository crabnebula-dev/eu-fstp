//! Identity facts at the vault's intake, without a database (ADR-004
//! record of lane L13, rows "Intake", "Idempotence" and "Verification").
//!
//! - A bank detail or hardship write of an account that no identity
//!   registration binds is refused, before its ticket is used.
//! - Once the account is bound, its identity facts are journaled for its
//!   identity's fact key, and every other fact for the shared key.
//! - A binding never moves an account to another identity.

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
use fstp_vault::{JournalEntry, OriginRefusal, Vault};
use fstp_vault_core::fact::{Check, DocumentType, VerificationMethod, VerificationRecord};
use fstp_vault_core::{Fact, Person};
use fstp_vault_proto::{WireAccount, WireProgramme};

const CELL: [u8; 16] = [0xCE; 16];
const GRANT: u128 = 77;
const LEAD: u128 = 10;
const OTHER: u128 = 12;
const SEC: i64 = 1_000_000;
const T0: i64 = 100 * 86_400 * SEC;
const IBAN: &str = "DE89370400440532013000";
const MK_A: [u8; 32] = [0xA1; 32];
const MK_B: [u8; 32] = [0xB2; 32];

fn ticket(kind: &str, account: u128, nonce: u8) -> RTicket {
    RTicket {
        kind: kind.to_owned(),
        cell: CELL,
        account,
        proposal: Some(GRANT),
        scope: String::new(),
        issued_at: T0 - SEC,
        expires_at: T0 + 200 * SEC,
        nonce: [nonce; 16],
    }
}

fn bank_body(account: u128) -> String {
    format!(
        "{{\"account\":\"{account}\",\"grant\":\"{GRANT}\",\"holder\":\"Synthetic Holder\",\"iban\":\"{IBAN}\"}}"
    )
}

fn hardship_body(account: u128) -> String {
    format!(
        "{{\"account\":\"{account}\",\"grant\":\"{GRANT}\",\"statement\":\"Synthetic statement\"}}"
    )
}

fn written(entries: &[JournalEntry]) -> Vec<(u16, Option<Person>)> {
    entries
        .iter()
        .filter_map(|e| match e {
            JournalEntry::Written {
                fact, sealed_for, ..
            } => Some((fact.kind(), *sealed_for)),
            _ => None,
        })
        .collect()
}

/// I-81, ADR-004 record of lane L13 "Intake": `POST /w` refuses a bank
/// detail and a hardship write of an unregistered account with 403, and
/// journals nothing, so the ticket stays unused. Once a registration binds
/// the account, the same tickets are taken.
#[test]
fn i81_unregistered_identity_facts_refused_at_intake() {
    let key = Signer::new(3);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    let bank = origin_write(
        &key.sign(&ticket("write:bank_details", LEAD, 1)),
        &bank_body(LEAD),
    );
    let hardship = origin_write(
        &key.sign(&ticket("write:hardship_evidence", LEAD, 2)),
        &hardship_body(LEAD),
    );
    assert_eq!(
        v.post_write(&bank, T0).unwrap_err(),
        OriginRefusal::Unregistered
    );
    assert_eq!(
        v.post_write(&hardship, T0).unwrap_err(),
        OriginRefusal::Unregistered
    );
    assert_eq!(OriginRefusal::Unregistered.status(), 403);
    assert!(
        v.take_journal().is_empty(),
        "a refused identity fact journaled something"
    );
    assert!(
        v.used_tickets().is_empty(),
        "a refused write used its ticket"
    );

    let p = v.resolve_identity(MK_A).unwrap();
    assert!(v.bind_account(WireAccount(LEAD), p, T0).unwrap());
    v.take_journal();
    assert!(v.post_write(&bank, T0).is_ok());
    assert!(v.post_write(&hardship, T0).is_ok());
    assert_eq!(
        written(&v.take_journal()),
        vec![(14, Some(p)), (17, Some(p))],
        "I-81: an identity fact is not journaled for its identity's key"
    );
}

/// I-81, ADR-004 record of lane L13 "Fact seal": a fact of a bound
/// account is journaled for its identity's fact key when it is an
/// identity fact (kinds 14 and 17), whatever path took it, and for the
/// shared key otherwise. Another account's facts name no identity.
#[test]
fn i81_identity_facts_sealed_for_the_bound_identity() {
    let mut v = Vault::new(CELL, &[[3; 32]]).unwrap();
    let p = v.resolve_identity(MK_A).unwrap();
    v.bind_account(WireAccount(LEAD), p, T0).unwrap();
    v.take_journal();
    let bank = |account: u128| Fact::BankDetails {
        grant: fstp_vault_proto::WireProposal(GRANT),
        account: WireAccount(account),
        at: T0,
        holder: "Synthetic Holder".to_owned(),
        iban: IBAN.to_owned(),
    };
    v.take_fact(bank(LEAD), T0).unwrap();
    v.take_fact(
        Fact::CountryStated {
            account: WireAccount(LEAD),
            programme: WireProgramme(5),
            country: 276,
        },
        T0,
    )
    .unwrap();
    v.take_fact(bank(OTHER), T0).unwrap();
    assert_eq!(
        written(&v.take_journal()),
        vec![(14, Some(p)), (1, None), (14, None)]
    );
}

/// ADR-004 record of lane L13 "Idempotence": a second binding of an
/// account to its identity changes nothing, a second account may join the
/// identity, and an account never moves to another identity, through a
/// binding or through a verification.
#[test]
fn adr004_identity_binding_is_idempotent_and_never_moves_an_account() {
    let mut v = Vault::new(CELL, &[[3; 32]]).unwrap();
    let a = v.resolve_identity(MK_A).unwrap();
    let b = v.resolve_identity(MK_B).unwrap();
    assert!(v.bind_account(WireAccount(LEAD), a, T0).unwrap());
    let first = v.take_journal();
    assert!(first.iter().any(|e| matches!(
        e,
        JournalEntry::IdentityRegistered { account, identity, .. }
            if *account == WireAccount(LEAD) && *identity == a
    )));
    assert!(!v.bind_account(WireAccount(LEAD), a, T0).unwrap());
    assert!(v.take_journal().is_empty(), "a repeat journaled a change");
    assert!(v.bind_account(WireAccount(OTHER), a, T0).unwrap());
    v.take_journal();
    assert!(v.bind_account(WireAccount(LEAD), b, T0).is_err());
    assert!(v.take_journal().is_empty());
    assert_eq!(v.registered(WireAccount(LEAD)), Some(a));
    let record = VerificationRecord {
        method: VerificationMethod::Manual,
        document_type: DocumentType::Passport,
        checks: [Check::DocumentAuthentic].into_iter().collect(),
        at: T0,
        verifier: WireAccount(99),
    };
    assert!(
        v.verification_fact(WireAccount(99), WireAccount(LEAD), record.clone(), MK_B)
            .is_err(),
        "a verification moved a registered account to another identity"
    );
    assert!(
        v.verification_fact(WireAccount(99), WireAccount(LEAD), record, MK_A)
            .is_ok()
    );
}

/// I-81, ADR-004 record of lane L13 "Erasure": once an identity is
/// erased, its accounts are unbound, so their identity facts are refused
/// again until they register as a new identity.
#[test]
fn i81_erased_identity_unbinds_its_accounts() {
    let key = Signer::new(3);
    let mut v = Vault::new(CELL, &[key.public()]).unwrap();
    let p = v.resolve_identity(MK_A).unwrap();
    v.bind_account(WireAccount(LEAD), p, T0).unwrap();
    v.record_erasure(1, [9; 32], &[p]);
    assert!(v.take_journal().iter().any(|e| matches!(
        e,
        JournalEntry::IdentityErased { identity } if *identity == p
    )));
    assert_eq!(v.registered(WireAccount(LEAD)), None);
    let bank = origin_write(
        &key.sign(&ticket("write:bank_details", LEAD, 4)),
        &bank_body(LEAD),
    );
    assert_eq!(
        v.post_write(&bank, T0).unwrap_err(),
        OriginRefusal::Unregistered
    );
}
