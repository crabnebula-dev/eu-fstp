//! The audit reads of a programme on the matrix worlds (R-AU-01, I-24,
//! ADR-007, ADR-022, ADR-023, I-86).
//!
//! - `audit.entries` lists the ledger entries of P, newest first, for its
//!   auditor. Each row names its side, record kind, actor and the actor's
//!   role in P, its object and the ids of the texts it references. The
//!   hash is the SHA-256 of the entry's stored text, so a row checks
//!   against the ledger (I-24).
//! - The admin acts on P show: role grants by a tenant admin, the
//!   activation, an I-67 override (`ActivationOverridden`, ADR-022) and an
//!   unmask (`PartyUnmasked`, ADR-023).
//! - ADR-007: no text is shown. The unmask purpose and the override
//!   reason appear by id only.
//! - `audit.vault_outcomes` lists the vault answers the decisions of P
//!   used, by digest and answer bit only.
//! - The auditor of P, every tenant admin and the FSTP coordinator of P
//!   read both, read-only (`roles-and-sod.md`, roles table, SA-08).
//!   `audit.vault_outcomes` has no tool (I-86).

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]

use super::*;
use crate::reference::authz::Policy;

const POST: ApiMethod = ApiMethod::Post;
const GET: ApiMethod = ApiMethod::Get;

/// A purpose of the synthetic corpus.
const PURPOSE: &str = "SYNTHETIC AUDIT PURPOSE: check the declared affiliation.";
/// An override reason of the synthetic corpus.
const REASON: &str = "SYNTHETIC AUDIT REASON: the second admin is on leave.";

fn built(state: StateProfile) -> Built {
    build(WorldKey {
        state,
        policy: Policy::SUPERSAFE,
        variant: Variant::Main,
    })
    .unwrap_or_else(|e| panic!("world {state:?}: {e}"))
}

fn seeder(w: &Built) -> Seeder {
    Seeder {
        ports: w.ports.clone(),
        core: w.core.clone(),
        now: w.now,
        command: 931_000,
        cookies: BTreeMap::new(),
        next_id: 93_100_000,
        admins: w.admins.iter().copied().collect(),
    }
}

fn entries_path(p: ProgrammeId) -> String {
    format!("/programmes/{}/audit", p.raw())
}

fn outcomes_path(p: ProgrammeId) -> String {
    format!("/programmes/{}/audit/vault-outcomes", p.raw())
}

fn rows<'a>(v: &'a Value, member: &str) -> &'a Array {
    v.get(member)
        .and_then(Value::as_array)
        .unwrap_or_else(|| panic!("no {member}: {}", v.to_compact()))
}

fn kinds(v: &Value) -> Vec<String> {
    rows(v, "entries")
        .iter()
        .filter_map(|r| str_member(r, "kind"))
        .collect()
}

fn row_of<'a>(v: &'a Value, kind: &str) -> &'a Value {
    rows(v, "entries")
        .iter()
        .find(|r| str_member(r, "kind").as_deref() == Some(kind))
        .unwrap_or_else(|| panic!("no {kind} row: {}", v.to_compact()))
}

fn texts(row: &Value) -> Vec<String> {
    row.get("texts")
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(|t| t.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// The ledger of the world's engine, in order.
fn ledger(seed: &Seeder) -> Vec<fstp_ledger::Entry<Record>> {
    let store = seed.ports.engine.store_copy();
    let mut out = Vec::new();
    store
        .read(fstp_ledger::Seq::from_raw(1), usize::MAX, &mut out)
        .unwrap_or_else(|e| panic!("the store: {e:?}"));
    out
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// R-AU-01, I-17 (ADR-023): after an unmask in IRC_REVIEW, the auditor of
/// P reads the programme's ledger entries, newest first. The admin acts
/// show (the role grants of the tenant admins and the activation), and so
/// does the unmask, by the coordinator acting as FSTP coordinator.
#[test]
fn r_au_01_audit_entries_list_admin_acts_and_the_unmask() {
    let w = built(StateProfile::Proposal(StateTag::IrcReview));
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let lead = seed
        .ports
        .engine
        .state()
        .core
        .roster()
        .bindings()
        .find(|(_, b)| b.account == LEAD && b.programme == p && b.role == Role::Applicant)
        .map(|(id, _)| id)
        .expect("the lead's binding");
    seed.api(
        COORD,
        POST,
        &format!("/programmes/{}/unmask", p.raw()),
        &obj(vec![
            (
                "subject",
                obj(vec![("type", s("Binding")), ("binding", dec(lead.raw()))]),
            ),
            ("purpose", s(PURPOSE)),
        ]),
    )
    .unwrap_or_else(|e| panic!("the unmask: {e}"));
    let v = seed
        .api(AUDITOR, GET, &entries_path(p), &Value::Null)
        .unwrap_or_else(|e| panic!("R-AU-01: the auditor's read: {e}"));
    assert_eq!(str_member(&v, "programme"), Some(p.raw().to_string()));
    let k = kinds(&v);
    for kind in ["PartyUnmasked", "BindingGranted", "ActivationApproved"] {
        assert!(k.iter().any(|x| x == kind), "R-AU-01: no {kind}: {k:?}");
    }
    let unmask = row_of(&v, "PartyUnmasked");
    assert_eq!(str_member(unmask, "actor"), Some(COORD.raw().to_string()));
    assert_eq!(
        str_member(unmask, "actor_role").as_deref(),
        Some("fstp_coordinator")
    );
    assert_eq!(str_member(unmask, "side").as_deref(), Some("core"));
    let granted = rows(&v, "entries")
        .iter()
        .filter(|r| str_member(r, "kind").as_deref() == Some("BindingGranted"))
        .any(|r| str_member(r, "actor_role").as_deref() == Some("tenant_admin"));
    assert!(granted, "R-AU-01: no role grant by a tenant admin");
    // Newest first, each entry once.
    let seqs: Vec<u64> = rows(&v, "entries")
        .iter()
        .map(|r| str_member(r, "seq").unwrap().parse().unwrap())
        .collect();
    assert!(seqs.windows(2).all(|w| w[0] > w[1]), "{seqs:?}");
}

/// I-24, R-AU-01: each row's hash is the SHA-256 of the stored text of
/// the ledger entry at its sequence number, so the read checks against
/// the ledger, and every entry of the list belongs to P's ledger.
#[test]
fn i24_audit_entry_hashes_match_the_ledger() {
    let w = built(StateProfile::Proposal(StateTag::Stage1));
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let v = seed
        .api(AUDITOR, GET, &entries_path(p), &Value::Null)
        .unwrap_or_else(|e| panic!("{e}"));
    let by_seq: BTreeMap<u64, String> = ledger(&seed)
        .iter()
        .map(|e| {
            let text = e.canonical_text().expect("stored text");
            (e.seq.raw(), hex(&fstp_crypto::sha256(text.as_bytes())))
        })
        .collect();
    let list = rows(&v, "entries");
    assert!(!list.is_empty());
    for r in list {
        let seq: u64 = str_member(r, "seq").unwrap().parse().unwrap();
        assert_eq!(
            str_member(r, "hash").as_ref(),
            by_seq.get(&seq),
            "I-24: the hash of entry {seq}"
        );
    }
}

/// ADR-007, R-AU-01, I-17: the audit rows name texts by id only. The
/// unmask purpose is a confidential text of P, and the read shows its
/// reference, never the text.
#[test]
fn adr007_audit_entries_show_text_references_never_texts() {
    let w = built(StateProfile::Proposal(StateTag::IrcReview));
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let lead = seed
        .ports
        .engine
        .state()
        .core
        .roster()
        .bindings()
        .find(|(_, b)| b.account == LEAD && b.programme == p && b.role == Role::Applicant)
        .map(|(id, _)| id)
        .expect("the lead's binding");
    seed.api(
        COORD,
        POST,
        &format!("/programmes/{}/unmask", p.raw()),
        &obj(vec![
            (
                "subject",
                obj(vec![("type", s("Binding")), ("binding", dec(lead.raw()))]),
            ),
            ("purpose", s(PURPOSE)),
        ]),
    )
    .unwrap_or_else(|e| panic!("the unmask: {e}"));
    let purpose = seed
        .ports
        .engine
        .state()
        .core
        .unmasks()
        .of(p)
        .last()
        .map(|u| u.purpose)
        .expect("the unmask record");
    let v = seed
        .api(AUDITOR, GET, &entries_path(p), &Value::Null)
        .unwrap_or_else(|e| panic!("{e}"));
    let body = v.to_compact();
    assert!(!body.contains("SYNTHETIC AUDIT PURPOSE"), "ADR-007: {body}");
    let unmask = row_of(&v, "PartyUnmasked");
    assert_eq!(texts(unmask), vec![purpose.id().raw().to_string()]);
}

/// I-67 (ADR-022), R-AU-01: a tenant admin who built the draft overrides
/// I-67 with a reason. The auditor later granted on P reads the override
/// as its own row by that admin, with the reason by id only.
#[test]
fn i67_adr022_audit_entries_list_the_override() {
    let w = built(StateProfile::ProgrammeDraft);
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let rev = draft_revision(&mut seed, PM, p).unwrap_or_else(|e| panic!("{e}"));
    seed.api(
        ADMIN_BUILDER,
        POST,
        &format!("/programmes/{}/activation-override", p.raw()),
        &obj(vec![("revision", s(&rev)), ("reason", s(REASON))]),
    )
    .unwrap_or_else(|e| panic!("ADR-022: the override: {e}"));
    grant(&mut seed, ADMIN_PLAIN, AUDITOR, p, Role::Auditor).unwrap_or_else(|e| panic!("{e}"));
    seed.at(seed.now.saturating_add(2 * SECOND));
    let v = seed
        .api(AUDITOR, GET, &entries_path(p), &Value::Null)
        .unwrap_or_else(|e| panic!("R-AU-01: {e}"));
    let row = row_of(&v, "ActivationOverridden");
    assert_eq!(str_member(row, "side").as_deref(), Some("creator"));
    assert_eq!(
        str_member(row, "actor"),
        Some(ADMIN_BUILDER.raw().to_string())
    );
    assert_eq!(
        str_member(row, "actor_role").as_deref(),
        Some("tenant_admin")
    );
    assert_eq!(texts(row).len(), 1, "ADR-007: the reason by id: {row:?}");
    assert!(!v.to_compact().contains("SYNTHETIC AUDIT REASON"));
}

/// `roles-and-sod.md` roles table, R-AU-01, SA-08 (Daniel, 2026-11-15):
/// the auditor of P, every tenant admin and the FSTP coordinator of P read
/// its audit entries and vault outcomes, read-only. A committee member,
/// an applicant, the programme manager, an unbound account and the
/// manager of P2 are refused. The coordinator of P reading P2, where it
/// holds no binding, is refused as a coordinator of another programme.
#[test]
fn r_au_01_sa08_auditor_admins_and_coordinator_read_the_audit_log() {
    let w = built(StateProfile::Proposal(StateTag::Stage1));
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let p2 = other_programme_of(&seed, p);
    for path in [entries_path(p), outcomes_path(p)] {
        for who in [AUDITOR, ADMIN_PLAIN, ADMIN_BUILDER, COORD] {
            let ok = seed.api(who, GET, &path, &Value::Null);
            assert!(ok.is_ok(), "{path}: {} refused: {ok:?}", who.raw());
        }
        for who in [MEMBER, CHAIR, LEAD, TEAM, PM, PM_OTHER, UNBOUND] {
            let r = seed.api(who, GET, &path, &Value::Null);
            assert!(r.is_err(), "{path}: {} read it: {r:?}", who.raw());
        }
    }
    for path in [entries_path(p2), outcomes_path(p2)] {
        let r = seed.api(COORD, GET, &path, &Value::Null);
        assert!(r.is_err(), "{path}: the coordinator of P read P2: {r:?}");
        let ok = seed.api(ADMIN_PLAIN, GET, &path, &Value::Null);
        assert!(ok.is_ok(), "{path}: a tenant admin refused P2: {ok:?}");
    }
}

/// The other programme of the tenant, P2.
fn other_programme_of(seed: &Seeder, p: ProgrammeId) -> ProgrammeId {
    let state = seed.ports.engine.state();
    state
        .core
        .roster()
        .bindings()
        .map(|(_, b)| b.programme)
        .find(|q| *q != p)
        .expect("P2")
}

/// `overview.md` NOTE 5, I-86: the vault outcomes of P are its ledger's
/// `VaultOutcome` records whose command also recorded an entry of P.
/// Each names the query kind, digest, answer bit and epoch, and nothing
/// else.
#[test]
fn note5_vault_outcomes_list_the_answers_of_the_programme() {
    let w = built(StateProfile::Proposal(StateTag::Stage1));
    let mut seed = seeder(&w);
    let p = w.targets.programme.expect("P");
    let v = seed
        .api(AUDITOR, GET, &outcomes_path(p), &Value::Null)
        .unwrap_or_else(|e| panic!("{e}"));
    let ledger = ledger(&seed);
    let recorded = ledger
        .iter()
        .filter(|e| {
            matches!(
                e.record,
                Record::Core(fstp_domain::record::Record::VaultOutcome { .. })
            )
        })
        .count();
    let list = rows(&v, "outcomes");
    assert!(list.len() <= recorded, "{} > {recorded}", list.len());
    for r in list {
        let seq: u64 = str_member(r, "seq").unwrap().parse().unwrap();
        let e = ledger.iter().find(|e| e.seq.raw() == seq).expect("entry");
        let Record::Core(fstp_domain::record::Record::VaultOutcome { holds, .. }) = &e.record
        else {
            panic!("row {seq} is no VaultOutcome");
        };
        assert_eq!(r.get("holds").and_then(Value::as_bool), Some(*holds));
        let digest = str_member(r, "digest").unwrap();
        assert_eq!(digest.len(), 64, "{digest}");
    }
}
