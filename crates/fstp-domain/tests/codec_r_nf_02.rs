//! R-NF-02: codec errors never hold input content.
//!
//! Errors reach logs, so an error value carries kinds and schema member
//! names only. It never carries a member name, string or other content taken
//! from the input. Each property plants a marker in the codec's own encoding
//! of a generated value and checks the Display, Debug and full path forms of
//! the error:
//!
//! - an unknown member named by the marker, at every object;
//! - the marker in place of each string value;
//! - an object keyed by the marker in place of each string value.

mod codec_support;

use codec_support::{Draw, RecordTag, codec_for, command, decoded_seeds, policy, record};
use fstp_domain::command::{Command, CommandKind};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::Record;
use fstp_prop::check;

/// R-NF-02: no record decode error holds input content.
#[test]
fn r_nf_02_codec_errors_hold_no_input_content_record() {
    let codec = codec_for!(Record);
    let tags = RecordTag::generated();
    check("r_nf_02_codec_errors_hold_no_input_content_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::plain();
        let r = record(g, &mut d, tag)?;
        codec.errors_hold_no_input_content(&r)
    });
}

/// R-NF-02: no command decode error holds input content.
#[test]
fn r_nf_02_codec_errors_hold_no_input_content_command() {
    let codec = codec_for!(Command);
    check("r_nf_02_codec_errors_hold_no_input_content_command", |g| {
        let kind = *g.pick(&CommandKind::ALL);
        let mut d = Draw::plain();
        let c = command(g, &mut d, kind)?;
        codec.errors_hold_no_input_content(&c)
    });
}

/// R-NF-02: no policy version decode error holds input content, map keys
/// included.
#[test]
fn r_nf_02_codec_errors_hold_no_input_content_policy() {
    let codec = codec_for!(PolicyVersion);
    check("r_nf_02_codec_errors_hold_no_input_content_policy", |g| {
        let mut d = Draw::plain();
        let p = policy(g, &mut d)?;
        codec.errors_hold_no_input_content(&p)
    });
}

/// R-NF-02: no decode error of a witness payload holds input content. The
/// payloads have no public constructor, so the check runs over the decoded
/// seeds of the `record_decode` corpus.
#[test]
fn r_nf_02_codec_errors_hold_no_input_content_witness_seeds() {
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
        let checked = codec.errors_hold_no_input_content(r);
        assert!(
            checked.is_ok(),
            "seed {name}: {}",
            checked.err().unwrap_or_default()
        );
    }
}
