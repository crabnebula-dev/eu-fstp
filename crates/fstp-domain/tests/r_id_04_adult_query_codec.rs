//! R-ID-04, I-18: the over-18 attestation query in the domain and its codec.
//!
//! `SPEC/03-architecture/overview.md` NOTE 7 adds the query "Does this
//! proposal's lead have an effective verified over-18 attestation at the
//! call deadline?" to the vault query table (decided 2026-10-28). It is
//! named `IsVerifiedAdultAtDeadline` in code, and it answers one bit. The
//! domain records each vault answer as a `VaultOutcome` with the query
//! kind (overview NOTE 5), so the new kind must have one spelling in the
//! record codec and survive a round trip with stable bytes (I-23, ADR-007).
//!
//! The tests find the kind by its name, so they compile before the kind
//! exists and fail until it does.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{ContentDigest, VaultEpoch};
use fstp_domain::oracle::QueryKind;
use fstp_domain::record::Record;
use fstp_json::{FromJson, ToJson, parse, to_canonical};

/// The name overview NOTE 7 gives the query in code.
const NAME: &str = "IsVerifiedAdultAtDeadline";

/// The query as the overview table spells it.
const QUESTION: &str = "Does this proposal's lead have an effective verified over-18 attestation at the call deadline?";

/// The seeds of the `record_decode` corpus that hold the new kind.
const SEEDS: [&str; 2] = [
    "vault_outcome_adult_at_deadline",
    "vault_outcome_adult_at_deadline_no",
];

/// The kind named [`NAME`], if the domain has it.
fn adult_kind() -> Option<QueryKind> {
    QueryKind::ALL
        .into_iter()
        .find(|k| format!("{k:?}") == NAME)
}

/// The RFC 8785 text of `r`.
fn canonical(r: &Record) -> String {
    to_canonical(&r.to_json()).unwrap_or_else(|e| panic!("no RFC 8785 form: {e}"))
}

/// Decodes `text` as a record.
fn decode(text: &str) -> Result<Record, String> {
    let v = parse(text.as_bytes()).map_err(|e| format!("parse: {e:?}"))?;
    Record::from_json(&v).map_err(|e| format!("decode: {e}"))
}

/// R-ID-04, overview NOTE 7: the domain has a query kind named
/// `IsVerifiedAdultAtDeadline`, and it asks the question of the table row.
#[test]
fn r_id_04_adult_query_kind_is_named_as_note_7_says() {
    let kind = adult_kind()
        .unwrap_or_else(|| panic!("overview NOTE 7: QueryKind::ALL holds no kind named {NAME}"));
    assert_eq!(kind.spec_question(), QUESTION, "the question of {NAME}");
}

/// R-ID-04, I-23, ADR-007: a `VaultOutcome` of the over-18 attestation
/// query, with either answer bit, decodes from its one spelling and
/// re-encodes to the same bytes.
#[test]
fn r_id_04_vault_outcome_of_the_adult_query_round_trips() {
    for holds in [true, false] {
        // The spelling of another kind, with only the kind replaced, so the
        // test does not fix the member names of the record.
        let known = Record::VaultOutcome {
            kind: QueryKind::HasGuardianConsent,
            digest: ContentDigest::from_bytes([0x5a; 32]),
            holds,
            epoch: VaultEpoch::from_raw(7),
        };
        let text = canonical(&known).replace("\"HasGuardianConsent\"", &format!("\"{NAME}\""));
        let decoded = decode(&text).unwrap_or_else(|e| {
            panic!("R-ID-04: a VaultOutcome of {NAME} is refused ({e}): {text}")
        });
        match &decoded {
            Record::VaultOutcome { kind, .. } => {
                assert_eq!(format!("{kind:?}"), NAME, "the decoded kind");
            }
            other => panic!("decoded to another record: {other:?}"),
        }
        assert_eq!(canonical(&decoded), text, "I-23: the bytes are stable");
    }
}

/// R-ID-04, TH-26: the `record_decode` corpus holds a canonical seed of a
/// `VaultOutcome` of the over-18 attestation query for each answer bit.
#[test]
fn r_id_04_adult_query_seeds_decode_canonically() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("fuzz/seeds/record_decode");
    let mut bits = Vec::new();
    for name in SEEDS {
        let text = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("seed {name} unreadable: {e}"));
        let decoded =
            decode(&text).unwrap_or_else(|e| panic!("R-ID-04: seed {name} is refused: {e}"));
        let Record::VaultOutcome { kind, holds, .. } = &decoded else {
            panic!("seed {name} decodes to another record: {decoded:?}");
        };
        assert_eq!(format!("{kind:?}"), NAME, "seed {name}");
        assert_eq!(canonical(&decoded), text, "seed {name} is not canonical");
        bits.push(*holds);
    }
    bits.sort_unstable();
    assert_eq!(bits, vec![false, true], "one seed for each answer bit");
}

/// I-06, I-23: a `VaultOutcome` of every query kind, the over-18
/// attestation query included once it exists, round-trips with stable
/// bytes, and no two kinds share a spelling.
#[test]
fn i06_every_query_kind_round_trips_in_a_vault_outcome() {
    let mut spellings = std::collections::BTreeSet::new();
    for kind in QueryKind::ALL {
        let r = Record::VaultOutcome {
            kind,
            digest: ContentDigest::from_bytes([0xa5; 32]),
            holds: true,
            epoch: VaultEpoch::from_raw(3),
        };
        let text = canonical(&r);
        let back = decode(&text).unwrap_or_else(|e| panic!("{kind:?}: {e}"));
        assert_eq!(back, r, "{kind:?}");
        assert_eq!(canonical(&back), text, "{kind:?}: the bytes are stable");
        assert!(spellings.insert(text), "{kind:?} shares a spelling");
    }
}
