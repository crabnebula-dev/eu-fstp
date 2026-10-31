//! Query evaluation over effective facts (design section 6.4,
//! `overview.md` query table, NOTE 1, NOTE 5, NOTE 6, ADR-006).
//!
//! Each test commits facts through the NOTE 4 protocol (write, then
//! acknowledge) and asks one query kind. Every answer is one bit, except
//! `ChangedSince`, which lists account ids only. The readings follow
//! W1c's `reference::vault::Facts`, which `seam_pg_vault_matches_synthetic_vault`
//! and M-VCP check the core against over random facts.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use std::collections::BTreeMap;

use common::wire::kind;
use common::{Fail, RQuery, Vault, fact, refusal, set};
use fstp_prop::{Gen, prop_assert_eq};
use fstp_vault_core::FactWrite;
use fstp_vault_proto::{VaultRefusal, WireAccount, WireQuery};

const A: u128 = 101;
const B: u128 = 102;
const C: u128 = 103;
const D: u128 = 104;
const R: u128 = 106;
const PERSON_AB: u128 = 1_001;
const PERSON_C: u128 = 1_003;
const PERSON_R: u128 = 1_006;
const PROGRAMME: u128 = 1;
const OTHER_PROGRAMME: u128 = 2;
const K1: u128 = 1;
const K2: u128 = 2;
const O1: u128 = 31;
const O2: u128 = 32;
const L1: u128 = 41;
const L2: u128 = 42;

fn verified_ab_c() -> Result<Vault, Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::verification(A, PERSON_AB),
        fact::verification(B, PERSON_AB),
        fact::verification(C, PERSON_C),
    ])?;
    Ok(v)
}

/// I-06, SoD-09: `IsVerified` holds only once a verification is
/// effective.
#[test]
fn i06_is_verified_needs_an_effective_verification() -> Result<(), Fail> {
    let mut v = Vault::new();
    assert!(!v.holds(RQuery::IsVerified { account: A })?);
    v.commit(fact::verification(A, PERSON_AB))?;
    assert!(v.holds(RQuery::IsVerified { account: A })?);
    assert!(!v.holds(RQuery::IsVerified { account: B })?);
    Ok(())
}

/// I-06, SoD-09: `SameIdentityAsAny` holds when the subject's verified
/// person is the person of an account in the set.
#[test]
fn i06_same_identity_as_any_matches_a_shared_person() -> Result<(), Fail> {
    let v = verified_ab_c()?;
    let q = |subject, others| RQuery::SameIdentityAsAny { subject, others };
    assert!(v.holds(q(A, set([B, C])))?);
    assert!(v.holds(q(B, set([A])))?);
    assert!(!v.holds(q(A, set([C])))?);
    assert!(!v.holds(q(A, set([])))?, "an empty set never matches");
    assert!(
        !v.holds(q(D, set([A])))?,
        "an unverified subject never matches"
    );
    Ok(())
}

/// I-15, NOTE 5: a one-member set answers whether two accounts share a
/// verified identity. Both must be verified.
#[test]
fn i15_same_identity_needs_both_accounts_verified() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    let q = RQuery::SameIdentityAsAny {
        subject: A,
        others: set([B]),
    };
    assert!(!v.holds(q.clone())?);
    v.commit(fact::verification(B, PERSON_AB))?;
    assert!(v.holds(q)?);
    Ok(())
}

/// I-03: a reviewer who shares a verified person with a team member has
/// a conflict.
#[test]
fn i03_has_conflict_over_a_shared_person() -> Result<(), Fail> {
    let v = verified_ab_c()?;
    let q = |reviewer, team| RQuery::HasConflict { reviewer, team };
    assert!(v.holds(q(A, set([B, D])))?);
    assert!(!v.holds(q(A, set([C, D])))?);
    assert!(!v.holds(q(A, set([])))?);
    Ok(())
}

/// I-54, I-03: a recorded relationship is a conflict, also through
/// another account of either person.
#[test]
fn i54_recorded_relationship_is_a_conflict() -> Result<(), Fail> {
    let mut v = verified_ab_c()?;
    v.commit(fact::verification(R, PERSON_R))?;
    let q = |reviewer, team| RQuery::HasConflict { reviewer, team };
    assert!(!v.holds(q(R, set([C])))?);
    v.commit(fact::relationship(R, C))?;
    assert!(v.holds(q(R, set([C])))?);
    assert!(
        v.holds(q(C, set([R])))?,
        "the relationship has no direction"
    );
    v.commit(fact::relationship(R, B))?;
    assert!(
        v.holds(q(R, set([A])))?,
        "B and A are one person, so R's relationship with B covers A"
    );
    Ok(())
}

/// I-03, Q31 (design section 6.8): a relative the reviewer declared is a
/// conflict once that relative's account is verified as that person.
#[test]
fn i03_declared_relative_is_a_conflict() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::verification(R, PERSON_R),
        fact::reviewer(R, None, &set([PERSON_C])),
    ])?;
    let q = RQuery::HasConflict {
        reviewer: R,
        team: set([C]),
    };
    assert!(!v.holds(q.clone())?, "C is not verified yet");
    v.commit(fact::verification(C, PERSON_C))?;
    assert!(v.holds(q.clone())?);
    v.commit(fact::reviewer(R, None, &set([])))?;
    assert!(!v.holds(q)?, "a new declaration replaces the old one");
    Ok(())
}

/// I-03, Q31: the reviewer's declared employer among a team member's
/// declared affiliations is a conflict. Ending the affiliation ends it.
#[test]
fn i03_declared_employer_is_a_conflict() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::reviewer(R, Some(O1), &set([])),
        fact::affiliation(C, O2, None),
    ])?;
    let q = RQuery::HasConflict {
        reviewer: R,
        team: set([C]),
    };
    assert!(!v.holds(q.clone())?);
    v.commit(fact::affiliation(C, O1, None))?;
    assert!(v.holds(q.clone())?);
    v.commit(fact::affiliation_ended(C, O1))?;
    assert!(!v.holds(q)?);
    Ok(())
}

/// I-04, P-13: `InExcludedClass` holds when an effective affiliation of
/// the account's person carries a class in the set.
#[test]
fn i04_in_excluded_class_counts_classed_affiliations() -> Result<(), Fail> {
    let mut v = verified_ab_c()?;
    let q = |account, classes| RQuery::InExcludedClass {
        account,
        programme: PROGRAMME,
        classes,
    };
    v.commit(fact::affiliation(A, O1, Some(K1)))?;
    assert!(v.holds(q(A, set([K1])))?);
    assert!(v.holds(q(A, set([K2, K1])))?);
    assert!(!v.holds(q(A, set([K2])))?);
    assert!(!v.holds(q(A, set([])))?);
    assert!(v.holds(q(B, set([K1])))?, "B is A's person");
    assert!(!v.holds(q(C, set([K1])))?);
    v.commit(fact::affiliation_ended(A, O1))?;
    assert!(!v.holds(q(A, set([K1])))?);
    Ok(())
}

/// I-04: an affiliation declared without a class is in no excluded class.
#[test]
fn i04_unclassed_affiliation_is_in_no_class() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::affiliation(C, O1, None))?;
    assert!(!v.holds(RQuery::InExcludedClass {
        account: C,
        programme: PROGRAMME,
        classes: set([K1, K2]),
    })?);
    Ok(())
}

/// I-04, ADR-009 "Write kinds" (W1c reading): a plain affiliation write
/// carries no class. A class travels only as a partner staff declaration,
/// so a plain write that names one is malformed.
#[test]
fn i04_plain_affiliation_write_carries_no_class() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::affiliation(C, O1, None))?;
    let classed = FactWrite {
        kind: fact::AFFILIATION_DECLARED,
        body: format!("{{\"account\":\"{C}\",\"class\":\"{K1}\",\"org\":\"{O1}\"}}").into_bytes(),
    };
    assert_eq!(refusal(v.write(classed))?, VaultRefusal::Malformed);
    Ok(())
}

fn cap_query(subject: u128, amount: i64, committed: &[(u128, i64)], cap: i64) -> RQuery {
    RQuery::WithinRecipientCap {
        subject,
        amount,
        committed: committed.iter().copied().collect(),
        cap,
    }
}

/// I-14, NOTE 1: the vault groups committed amounts by verified identity
/// and adds the amount to the subject's group.
#[test]
fn i14_within_recipient_cap_groups_by_identity() -> Result<(), Fail> {
    let mut v = verified_ab_c()?;
    let committed = [(A, 6_000), (C, 9_000)];
    assert!(!v.holds(cap_query(B, 5_000, &committed, 10_000))?);
    assert!(
        v.holds(cap_query(D, 5_000, &committed, 10_000))?,
        "D is its own group"
    );
    assert!(v.holds(cap_query(B, 4_000, &committed, 10_000))?);
    v.commit(fact::verification(D, PERSON_C))?;
    assert!(
        !v.holds(cap_query(D, 5_000, &committed, 10_000))?,
        "D joins C's group once verified"
    );
    Ok(())
}

/// I-14, ADR-006: the cap is inclusive and the comparison exact to the
/// cent.
#[test]
fn i14_within_recipient_cap_is_inclusive_and_exact() -> Result<(), Fail> {
    let v = verified_ab_c()?;
    let committed = [(A, 6_000)];
    assert!(v.holds(cap_query(B, 4_000, &committed, 10_000))?);
    assert!(!v.holds(cap_query(B, 4_001, &committed, 10_000))?);
    assert!(v.holds(cap_query(D, 0, &[], 0))?);
    assert!(!v.holds(cap_query(D, 1, &[], 0))?);
    Ok(())
}

/// I-14: every identity group of the programme stays within the cap.
#[test]
fn i14_all_recipients_within_cap_groups_by_identity() -> Result<(), Fail> {
    let v = verified_ab_c()?;
    let q = |committed: &[(u128, i64)], cap| RQuery::AllRecipientsWithinCap {
        committed: committed.iter().copied().collect(),
        cap,
    };
    assert!(!v.holds(q(&[(A, 6_000), (B, 5_000)], 10_000))?);
    assert!(v.holds(q(&[(A, 6_000), (B, 5_000)], 11_000))?);
    assert!(v.holds(q(&[(A, 6_000), (C, 6_000)], 6_000))?);
    assert!(v.holds(q(&[], 0))?, "no recipients, none over the cap");
    Ok(())
}

/// I-14, ADR-006: a group sum that overflows the ADR-006 range answers
/// no. It never wraps.
#[test]
fn i14_cap_sum_overflow_answers_no() -> Result<(), Fail> {
    let v = verified_ab_c()?;
    let max = 999_999_999_999_999_999;
    assert!(!v.holds(cap_query(B, max, &[(A, max)], max))?);
    assert!(!v.holds(RQuery::AllRecipientsWithinCap {
        committed: [(A, max), (B, max)].into_iter().collect(),
        cap: max,
    })?);
    Ok(())
}

/// I-35, P-38: `DeclaresAffiliationOnList` holds when a team member's
/// person declares an affiliation on the list. A new list replaces the
/// old one.
#[test]
fn i35_declares_affiliation_on_list() -> Result<(), Fail> {
    let mut v = verified_ab_c()?;
    v.commit_all([
        fact::proximity_list(L1, &set([O1])),
        fact::affiliation(A, O1, None),
    ])?;
    let q = |team, list| RQuery::DeclaresAffiliationOnList { team, list };
    assert!(v.holds(q(set([C, B]), L1))?, "B is A's person");
    assert!(!v.holds(q(set([C]), L1))?);
    assert!(!v.holds(q(set([B]), L2))?, "an unknown list has no members");
    v.commit(fact::proximity_list(L1, &set([O2])))?;
    assert!(!v.holds(q(set([B]), L1))?);
    Ok(())
}

/// R-EV-08, P-17, NOTE 6: the P-17 query answers one bit over the stated
/// country and the programme's condition. The country never leaves the
/// vault.
#[test]
fn r_ev_08_meets_tie_break_country_answers_one_bit() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.set_p17(PROGRAMME, &[250, 380].into_iter().collect())?;
    let q = |account, programme| RQuery::MeetsTieBreakCountry { account, programme };
    assert!(!v.holds(q(C, PROGRAMME))?, "no country stated");
    v.commit(fact::country(C, PROGRAMME, 250))?;
    assert!(v.holds(q(C, PROGRAMME))?);
    assert!(!v.holds(q(C, OTHER_PROGRAMME))?);
    v.commit(fact::country(C, PROGRAMME, 276))?;
    assert!(!v.holds(q(C, PROGRAMME))?, "the latest statement counts");
    Ok(())
}

/// NOTE 3, overview query table: `ChangedSince` lists the accounts that
/// effective facts after the epoch touched, in ascending order, and its
/// bit says whether the list is non-empty.
#[test]
fn note3_changed_since_lists_the_accounts_touched_after_the_epoch() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit_all([
        fact::verification(C, PERSON_C),
        fact::affiliation(A, O1, None),
        fact::relationship(D, B),
    ])?;
    let q = |epoch| RQuery::ChangedSince { epoch };
    let a = v.ask(&[q(0), q(1), q(3), q(9)])?;
    let accounts = |ids: &[u128]| Some(ids.iter().map(|x| WireAccount(*x)).collect::<Vec<_>>());
    assert_eq!(a[0].accounts, accounts(&[A, B, C, D]));
    assert_eq!(a[1].accounts, accounts(&[A, B, D]));
    assert_eq!(a[2].accounts, accounts(&[]));
    assert_eq!(a[3].accounts, accounts(&[]));
    assert_eq!(
        a.iter().map(|x| x.holds).collect::<Vec<_>>(),
        vec![true, true, false, false]
    );
    Ok(())
}

/// NOTE 4 step 2 (confirmed 2026-10-25): after a verification, the
/// change lists every other account the revealed facts touch.
#[test]
fn note4_changed_since_lists_accounts_a_verification_reveals() -> Result<(), Fail> {
    let mut v = Vault::new();
    v.commit(fact::verification(A, PERSON_AB))?;
    let e = v.commit(fact::verification(B, PERSON_AB))?;
    let a = v.ask(&[RQuery::ChangedSince { epoch: e - 1 }])?;
    assert_eq!(a[0].accounts, Some(vec![WireAccount(A), WireAccount(B)]));
    Ok(())
}

fn gen_fact(g: &mut Gen) -> FactWrite {
    let accounts = [A, B, C, D, R];
    let a = *g.pick(&accounts);
    let b = *g.pick(&accounts);
    match g.u8_in(0..=6) {
        0 => fact::verification(a, *g.pick(&[PERSON_AB, PERSON_C, PERSON_R])),
        1 => fact::affiliation(a, *g.pick(&[O1, O2]), g.option(|g| *g.pick(&[K1, K2]))),
        2 => fact::relationship(a, b),
        3 => fact::reviewer(a, g.option(|g| *g.pick(&[O1, O2])), &set([PERSON_C])),
        4 => fact::proximity_list(*g.pick(&[L1, L2]), &set([O1])),
        5 => fact::consent(1, a),
        _ => fact::adult(a, 0),
    }
}

fn gen_one_bit_query(g: &mut Gen) -> RQuery {
    let accounts = [A, B, C, D, R];
    let a = *g.pick(&accounts);
    let team = set([*g.pick(&accounts), *g.pick(&accounts)]);
    match g.u8_in(0..=8) {
        0 => RQuery::IsVerified { account: a },
        1 => RQuery::SameIdentityAsAny {
            subject: a,
            others: team,
        },
        2 => RQuery::HasConflict { reviewer: a, team },
        3 => RQuery::InExcludedClass {
            account: a,
            programme: PROGRAMME,
            classes: set([K1]),
        },
        4 => RQuery::WithinRecipientCap {
            subject: a,
            amount: 100,
            committed: team.iter().map(|x| (*x, 50)).collect::<BTreeMap<_, _>>(),
            cap: 150,
        },
        5 => RQuery::AllRecipientsWithinCap {
            committed: team.iter().map(|x| (*x, 50)).collect::<BTreeMap<_, _>>(),
            cap: 75,
        },
        6 => RQuery::HasGuardianConsent { proposal: 1 },
        7 => RQuery::IsVerifiedAdultAtDeadline {
            account: a,
            deadline: 10,
        },
        _ => RQuery::DeclaresAffiliationOnList { team, list: L1 },
    }
}

/// NOTE 5, design section 6.2: over random effective facts, every answer
/// to a one-bit query carries no account set, and every answer carries
/// the effective epoch.
#[test]
fn note5_one_bit_answers_carry_no_account_set() {
    fstp_prop::check(
        "note5_one_bit_answers_carry_no_account_set",
        |g: &mut Gen| {
            let mut v = Vault::new();
            let stub = |f: Fail| format!("{f:?}");
            for _ in 0..g.usize_in(0..=8) {
                v.commit(gen_fact(g)).map_err(stub)?;
            }
            let qs = g.vec(1..=6, gen_one_bit_query);
            let answers = v.ask(&qs).map_err(stub)?;
            prop_assert_eq!(answers.len(), qs.len());
            for (q, a) in qs.iter().zip(&answers) {
                prop_assert_eq!(a.accounts.clone(), None, "{q:?}");
                prop_assert_eq!(a.epoch, v.effective(), "{q:?}");
            }
            Ok(())
        },
    );
}

/// ADR-006, NOTE 2: a query whose amount is not an exact ADR-006 string
/// is refused as malformed, while its canonical twin is answered.
#[test]
fn adr006_ask_refuses_non_canonical_amounts() -> Result<(), Fail> {
    let v = Vault::new();
    let args = |amount: &str| {
        format!(
            "{{\"amount\":{{\"amount\":\"{amount}\",\"currency\":\"EUR\"}},\"cap\":{{\"amount\":\"100.00\",\"currency\":\"EUR\"}},\"committed\":{{}},\"subject\":\"{A}\"}}"
        )
    };
    let q = |amount: &str| WireQuery {
        kind: kind::WITHIN_RECIPIENT_CAP,
        args: args(amount).into_bytes(),
    };
    assert_eq!(v.ask_raw(&[q("50.00")])?.len(), 1);
    for bad in ["50.0", "50", "050.00", "-50.00", "5e1", "50.000"] {
        assert_eq!(
            refusal(v.ask_raw(&[q(bad)]))?,
            VaultRefusal::Malformed,
            "{bad}"
        );
    }
    Ok(())
}

/// NOTE 2, design section 6.2: an unknown query kind or arguments of
/// another kind are refused as malformed. Nothing is answered.
#[test]
fn note2_ask_refuses_malformed_queries() -> Result<(), Fail> {
    let v = Vault::new();
    let good = WireQuery {
        kind: kind::IS_VERIFIED,
        args: format!("{{\"account\":\"{A}\"}}").into_bytes(),
    };
    assert_eq!(v.ask_raw(std::slice::from_ref(&good))?.len(), 1);
    let bad = [
        WireQuery {
            kind: kind::COUNT,
            args: good.args.clone(),
        },
        WireQuery {
            kind: kind::HAS_GUARDIAN_CONSENT,
            args: good.args.clone(),
        },
        WireQuery {
            kind: kind::IS_VERIFIED,
            args: b"{\"account\":7}".to_vec(),
        },
        WireQuery {
            kind: kind::IS_VERIFIED,
            args: b"{\"account\":\"7\"} ".to_vec(),
        },
    ];
    for q in bad {
        assert_eq!(
            refusal(v.ask_raw(&[good.clone(), q.clone()]))?,
            VaultRefusal::Malformed,
            "{q:?}"
        );
    }
    Ok(())
}

/// NOTE 2, H-05: a fact write of an unknown kind, or with a body that is
/// not its kind's canonical body, is refused as malformed and opens no
/// epoch.
#[test]
fn note2_write_refuses_malformed_fact_bodies() -> Result<(), Fail> {
    let mut v = Vault::new();
    let good = fact::verification(A, PERSON_AB);
    let bad = [
        FactWrite {
            kind: 0,
            body: good.body.clone(),
        },
        FactWrite {
            kind: 14,
            body: good.body.clone(),
        },
        FactWrite {
            kind: fact::GUARDIAN_CONSENT,
            body: good.body.clone(),
        },
        FactWrite {
            kind: good.kind,
            body: b"{\"account\":\"101\"}".to_vec(),
        },
        FactWrite {
            kind: good.kind,
            body: fact::verification_body(A, PERSON_AB, fact::SYNTHETIC_VERIFIER)
                .replace("\"verifier\"", "\"x\":0,\"verifier\"")
                .into_bytes(),
        },
        FactWrite {
            kind: good.kind,
            body: fact::verification_body(A, PERSON_AB, fact::SYNTHETIC_VERIFIER)
                .replace("\"at\":0,", "")
                .replace("{", "{\"at\":0,")
                .into_bytes(),
        },
        FactWrite {
            kind: good.kind,
            body: vec![0xff],
        },
    ];
    for w in bad {
        assert_eq!(
            refusal(v.write(w.clone()))?,
            VaultRefusal::Malformed,
            "{w:?}"
        );
        assert_eq!(v.effective(), 0);
    }
    assert_eq!(v.commit(good)?, 1, "no refused write took an epoch");
    Ok(())
}

/// R-ID-02, design sections 4.3 and 6.7: a verification fact holds the
/// method, document type, checks, time and verifier, and round-trips in
/// its one spelling. A record with no checks, or an unknown method,
/// document type or check, is refused.
#[test]
fn r_id_02_verification_record_holds_method_document_type_checks_time_and_verifier() {
    use fstp_vault_core::{Check, DocumentType, Fact, VerificationMethod, decode_fact};
    let body = fact::verification_body(A, PERSON_AB, R);
    let f = decode_fact(fact::VERIFICATION_RECORDED, body.as_bytes()).unwrap();
    let Fact::VerificationRecorded { record, .. } = &f else {
        panic!("not a verification: {f:?}");
    };
    assert_eq!(record.method, VerificationMethod::Manual);
    assert_eq!(record.document_type, DocumentType::Passport);
    assert_eq!(
        record.checks.iter().copied().collect::<Vec<_>>(),
        vec![Check::DocumentAuthentic, Check::PhotoMatch]
    );
    assert_eq!(record.at, 0);
    assert_eq!(record.verifier, WireAccount(R));
    assert_eq!(f.body().unwrap(), body.as_bytes(), "one spelling");
    for (from, to) in [
        ("[\"document_authentic\",\"photo_match\"]", "[]"),
        (
            "[\"document_authentic\",\"photo_match\"]",
            "[\"photo_match\",\"document_authentic\"]",
        ),
        (
            "[\"document_authentic\",\"photo_match\"]",
            "[\"document_number\"]",
        ),
        ("\"manual\"", "\"eudi\""),
        ("\"passport\"", "\"photo\""),
    ] {
        let bad = body.replace(from, to);
        assert!(
            decode_fact(fact::VERIFICATION_RECORDED, bad.as_bytes()).is_err(),
            "accepted {bad}"
        );
    }
}

/// Design section 6.7, ADR-008 guard: no recorder verifies their own
/// account, or an account that shares their identity. Such a write is
/// refused and takes no epoch.
#[test]
fn r_id_02_self_verification_is_refused() -> Result<(), Fail> {
    let mut v = Vault::new();
    let own = FactWrite {
        kind: fact::VERIFICATION_RECORDED,
        body: fact::verification_body(A, PERSON_AB, A).into_bytes(),
    };
    assert_eq!(refusal(v.write(own))?, VaultRefusal::Malformed);
    v.commit(fact::verification(R, PERSON_R))?;
    v.commit(fact::verification(B, PERSON_R))?;
    // C would join the recorder's identity. B already shares it.
    for (account, person) in [(C, PERSON_R), (B, PERSON_C)] {
        let shared = FactWrite {
            kind: fact::VERIFICATION_RECORDED,
            body: fact::verification_body(account, person, R).into_bytes(),
        };
        assert_eq!(refusal(v.write(shared))?, VaultRefusal::Malformed);
    }
    v.commit(fact::verification(D, PERSON_C))?;
    let other = FactWrite {
        kind: fact::VERIFICATION_RECORDED,
        body: fact::verification_body(D, PERSON_C, R).into_bytes(),
    };
    assert_eq!(v.commit(other)?, 4, "a recorder of another identity");
    Ok(())
}
