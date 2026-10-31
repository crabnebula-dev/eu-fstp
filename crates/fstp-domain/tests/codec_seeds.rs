//! The fuzz seed corpora of `fstp-domain` (TH-26, H-05, design section 7).
//!
//! Seeds are files under `crates/fstp-domain/fuzz/seeds/<target>`. A seed
//! that decodes must be the RFC 8785 text of its own encoding, so the fuzzer
//! starts from valid canonical inputs. Seeds that do not decode, such as
//! `empty_object`, are plain fuzz inputs and are skipped here.
//!
//! The witness payloads, the four of M2 and `ProgrammeActivated` since M4
//! change D2, have no public constructor. Their seeds are the
//! only way to test their codec from outside the crate, so the corpus must
//! hold one for each. The round trip of each lives in `codec_round_trip.rs`.

mod codec_support;

use std::collections::BTreeSet;

use codec_support::{RecordTag, codec_for, decoded_seeds};
use fstp_domain::command::Command;
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::Record;

/// TH-26: the `record_decode` corpus holds a canonical seed for each of the
/// witness payloads, `ProgrammeActivated` included (I-67, D2), and every
/// seed that decodes is canonical.
#[test]
fn th26_codec_seeds_cover_witness_payload_records() {
    let codec = codec_for!(Record);
    let seeds = decoded_seeds(&codec, "record_decode");
    assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
    let found: BTreeSet<RecordTag> = seeds
        .unwrap_or_default()
        .iter()
        .map(|(_, r)| RecordTag::of(r))
        .collect();
    let missing: Vec<RecordTag> = RecordTag::WITNESS
        .into_iter()
        .filter(|t| !found.contains(t))
        .collect();
    assert!(
        missing.is_empty(),
        "no seed decodes to these witness payloads: {missing:?}"
    );
}

/// TH-26: the `command_decode` corpus holds at least one canonical seed that
/// decodes, and every seed that decodes is canonical.
#[test]
fn th26_codec_seeds_decode_canonically_command() {
    let codec = codec_for!(Command);
    let seeds = decoded_seeds(&codec, "command_decode");
    assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
    assert!(
        !seeds.unwrap_or_default().is_empty(),
        "no seed in fuzz/seeds/command_decode decodes"
    );
}

/// TH-26: the `policy_decode` corpus holds at least one canonical seed that
/// decodes, and every seed that decodes is canonical.
#[test]
fn th26_codec_seeds_decode_canonically_policy() {
    let codec = codec_for!(PolicyVersion);
    let seeds = decoded_seeds(&codec, "policy_decode");
    assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
    assert!(
        !seeds.unwrap_or_default().is_empty(),
        "no seed in fuzz/seeds/policy_decode decodes"
    );
}

/// Design sections 5.1 and 7: an unknown member at any object of a witness
/// payload encoding is refused. The check runs over the decoded seeds.
#[test]
fn th26_codec_witness_seeds_reject_unknown_members() {
    let codec = codec_for!(Record);
    let seeds = decoded_seeds(&codec, "record_decode");
    assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
    let witness: Vec<(String, Record)> = seeds
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, r)| RecordTag::of(r).witness())
        .collect();
    assert!(!witness.is_empty(), "no witness payload seed decodes");
    for (name, r) in &witness {
        let checked = codec.rejects_unknown_members(r);
        assert!(
            checked.is_ok(),
            "seed {name}: {}",
            checked.err().unwrap_or_default()
        );
    }
}

/// ADR-006, P-02: in the seeds of `GrantDecided` and `Stage1Closed`, the
/// granted amount and the P-02 threshold are decimal strings, and a JSON
/// number or another spelling in their place is refused.
#[test]
fn adr006_codec_witness_seeds_reject_number_amounts() {
    let codec = codec_for!(Record);
    let seeds = decoded_seeds(&codec, "record_decode");
    assert!(seeds.is_ok(), "{}", seeds.err().unwrap_or_default());
    let with_amounts: Vec<(String, Record)> = seeds
        .unwrap_or_default()
        .into_iter()
        .filter(|(_, r)| {
            matches!(
                RecordTag::of(r),
                RecordTag::GrantDecided | RecordTag::Stage1Closed
            )
        })
        .collect();
    assert!(
        !with_amounts.is_empty(),
        "no GrantDecided or Stage1Closed seed decodes"
    );
    for (name, r) in &with_amounts {
        let numbers = codec.rejects_number_amounts(r);
        assert!(
            numbers.is_ok(),
            "seed {name}: {}",
            numbers.err().unwrap_or_default()
        );
        let spellings = codec.rejects_other_amount_spellings(r);
        assert!(
            spellings.is_ok(),
            "seed {name}: {}",
            spellings.err().unwrap_or_default()
        );
    }
}
