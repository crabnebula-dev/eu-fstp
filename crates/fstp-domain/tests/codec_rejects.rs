//! What the JSON codecs refuse (design sections 2.1, 2.3, 5.1 and 7).
//!
//! - Unknown members are refused at every object of an encoding.
//! - Amounts and percentages are ADR-006 decimal strings. A JSON number in
//!   their place is refused, and so is every other spelling.
//! - Every u128 id and every `Seq` is a decimal string, because RFC 8785
//!   numbers are exact only up to 2^53. Each has exactly one spelling, so
//!   the stored canonical bytes of a record are unique (ADR-007).
//!
//! The checks mutate the codec's own encoding of a generated value, so they
//! do not depend on member names the codec chooses.

mod codec_support;

use codec_support::{Draw, RecordTag, codec_for, command, command_holds_amounts, policy, record};
use fstp_domain::command::{Command, CommandKind};
use fstp_domain::policy::PolicyVersion;
use fstp_domain::record::Record;
use fstp_prop::check;

/// Design sections 5.1 and 7: an unknown member at any object of a record
/// encoding is refused, whatever its value.
#[test]
fn th26_codec_rejects_unknown_members_record() {
    let codec = codec_for!(Record);
    let tags = RecordTag::generated();
    check("th26_codec_rejects_unknown_members_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::plain();
        let r = record(g, &mut d, tag)?;
        codec.rejects_unknown_members(&r)
    });
}

/// Design section 7: an unknown member at any object of a command encoding
/// is refused, whatever its value.
#[test]
fn th26_codec_rejects_unknown_members_command() {
    let codec = codec_for!(Command);
    check("th26_codec_rejects_unknown_members_command", |g| {
        let kind = *g.pick(&CommandKind::ALL);
        let mut d = Draw::plain();
        let c = command(g, &mut d, kind)?;
        codec.rejects_unknown_members(&c)
    });
}

/// Design section 7: an unknown member at any object of a policy version
/// encoding is refused, whatever its value.
#[test]
fn th26_codec_rejects_unknown_members_policy() {
    let codec = codec_for!(PolicyVersion);
    check("th26_codec_rejects_unknown_members_policy", |g| {
        let mut d = Draw::plain();
        let p = policy(g, &mut d)?;
        codec.rejects_unknown_members(&p)
    });
}

/// ADR-006, design section 2.3: in every record that holds amounts, each
/// amount and percentage is a decimal string, and a JSON number in its place
/// is refused.
#[test]
fn adr006_codec_rejects_json_number_amounts_record() {
    let codec = codec_for!(Record);
    let tags: Vec<RecordTag> = RecordTag::generated()
        .into_iter()
        .filter(|t| t.holds_amounts())
        .collect();
    check("adr006_codec_rejects_json_number_amounts_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::amounts();
        let r = record(g, &mut d, tag)?;
        codec.rejects_number_amounts(&r)
    });
}

/// ADR-006, design section 2.3: in every command that holds amounts, each
/// amount and percentage is a decimal string, and a JSON number in its place
/// is refused.
#[test]
fn adr006_codec_rejects_json_number_amounts_command() {
    let codec = codec_for!(Command);
    let kinds: Vec<CommandKind> = CommandKind::ALL
        .into_iter()
        .filter(|k| command_holds_amounts(*k))
        .collect();
    check("adr006_codec_rejects_json_number_amounts_command", |g| {
        let kind = *g.pick(&kinds);
        let mut d = Draw::amounts();
        let c = command(g, &mut d, kind)?;
        codec.rejects_number_amounts(&c)
    });
}

/// ADR-006, P-02, design section 2.3: in a policy version, P-02, P-04, P-05,
/// P-56 and P-58 are decimal strings, and a JSON number in their place is
/// refused.
#[test]
fn adr006_codec_rejects_json_number_amounts_policy() {
    let codec = codec_for!(PolicyVersion);
    check("adr006_codec_rejects_json_number_amounts_policy", |g| {
        let mut d = Draw::amounts();
        let p = policy(g, &mut d)?;
        codec.rejects_number_amounts(&p)
    });
}

/// ADR-006: in every record that holds amounts, any other spelling of an
/// amount or percentage is refused, never normalised. Examples are
/// `"1234.5"`, `"01234.50"`, `"+1234.50"`, `"-1234.50"` and `"1234.500"`.
#[test]
fn adr006_codec_rejects_other_amount_spellings_record() {
    let codec = codec_for!(Record);
    let tags: Vec<RecordTag> = RecordTag::generated()
        .into_iter()
        .filter(|t| t.holds_amounts())
        .collect();
    check("adr006_codec_rejects_other_amount_spellings_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::amounts();
        let r = record(g, &mut d, tag)?;
        codec.rejects_other_amount_spellings(&r)
    });
}

/// ADR-006: in every command that holds amounts, any other spelling of an
/// amount or percentage is refused, never normalised.
#[test]
fn adr006_codec_rejects_other_amount_spellings_command() {
    let codec = codec_for!(Command);
    let kinds: Vec<CommandKind> = CommandKind::ALL
        .into_iter()
        .filter(|k| command_holds_amounts(*k))
        .collect();
    check("adr006_codec_rejects_other_amount_spellings_command", |g| {
        let kind = *g.pick(&kinds);
        let mut d = Draw::amounts();
        let c = command(g, &mut d, kind)?;
        codec.rejects_other_amount_spellings(&c)
    });
}

/// ADR-006, P-02: in a policy version, any other spelling of an amount or
/// percentage is refused, never normalised.
#[test]
fn adr006_codec_rejects_other_amount_spellings_policy() {
    let codec = codec_for!(PolicyVersion);
    check("adr006_codec_rejects_other_amount_spellings_policy", |g| {
        let mut d = Draw::amounts();
        let p = policy(g, &mut d)?;
        codec.rejects_other_amount_spellings(&p)
    });
}

/// ADR-007, design section 2.1: every u128 id and every `Seq` in a record
/// is a decimal string, even above 2^53, and a JSON number in its place is
/// refused.
#[test]
fn adr007_codec_ids_are_decimal_strings_record() {
    let codec = codec_for!(Record);
    let tags = RecordTag::generated();
    check("adr007_codec_ids_are_decimal_strings_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::marked();
        let r = record(g, &mut d, tag)?;
        codec.ids_are_decimal_strings(&r, &d)
    });
}

/// ADR-007, design section 2.1: every u128 id in a command is a decimal
/// string, even above 2^53, and a JSON number in its place is refused.
#[test]
fn adr007_codec_ids_are_decimal_strings_command() {
    let codec = codec_for!(Command);
    check("adr007_codec_ids_are_decimal_strings_command", |g| {
        let kind = *g.pick(&CommandKind::ALL);
        let mut d = Draw::marked();
        let c = command(g, &mut d, kind)?;
        codec.ids_are_decimal_strings(&c, &d)
    });
}

/// ADR-007, design section 2.1: every u128 id in a policy version is a
/// decimal string, including map keys, and a JSON number in its place is
/// refused.
#[test]
fn adr007_codec_ids_are_decimal_strings_policy() {
    let codec = codec_for!(PolicyVersion);
    check("adr007_codec_ids_are_decimal_strings_policy", |g| {
        let mut d = Draw::marked();
        let p = policy(g, &mut d)?;
        codec.ids_are_decimal_strings(&p, &d)
    });
}

/// ADR-007, I-23: each id and `Seq` in a record has one spelling. A leading
/// zero, a sign, space, a fraction or hex is refused, so the stored bytes of
/// a record are unique.
#[test]
fn adr007_codec_ids_have_one_spelling_record() {
    let codec = codec_for!(Record);
    let tags = RecordTag::generated();
    check("adr007_codec_ids_have_one_spelling_record", |g| {
        let tag = *g.pick(&tags);
        let mut d = Draw::marked();
        let r = record(g, &mut d, tag)?;
        codec.ids_have_one_spelling(&r, &d)
    });
}

/// ADR-007: each id in a command has one spelling.
#[test]
fn adr007_codec_ids_have_one_spelling_command() {
    let codec = codec_for!(Command);
    check("adr007_codec_ids_have_one_spelling_command", |g| {
        let kind = *g.pick(&CommandKind::ALL);
        let mut d = Draw::marked();
        let c = command(g, &mut d, kind)?;
        codec.ids_have_one_spelling(&c, &d)
    });
}

/// ADR-007, I-23: each id in a policy version has one spelling, as a value
/// and as a map key.
#[test]
fn adr007_codec_ids_have_one_spelling_policy() {
    let codec = codec_for!(PolicyVersion);
    check("adr007_codec_ids_have_one_spelling_policy", |g| {
        let mut d = Draw::marked();
        let p = policy(g, &mut d)?;
        codec.ids_have_one_spelling(&p, &d)
    });
}
