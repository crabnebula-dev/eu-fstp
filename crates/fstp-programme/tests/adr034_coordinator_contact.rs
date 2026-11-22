//! ADR-034 section 3: the coordinator contact of the funding card is a
//! step 1 field like the grant agreement number and the coordinator's
//! name, so a gap is a `FieldUnset` failure (I-69, I-66).

use fstp_programme::{
    Field, FieldId, FieldKind, FieldValue, Narrative, Step, decode_spec, encode_spec,
    supersafe_fixture,
};

/// I-69: the three values of the funding card are step 1 artefact
/// fields, keyed as the creator names them.
#[test]
fn i69_funding_card_fields_are_step_1_artefacts() {
    for key in [
        "funder.action_number",
        "funder.coordinator_name",
        "funder.coordinator_contact",
    ] {
        let f = FieldId::from_key(key).expect(key);
        let spec = f.spec().expect("a row");
        assert_eq!(spec.step, Step::Funder, "{key}");
        assert_eq!(spec.kind, FieldKind::Artefact, "{key}");
        assert_eq!(f.key(), key);
    }
    let contact = FieldId::CoordinatorContact.spec().expect("a row");
    assert!(!contact.importable);
}

/// I-69: the SuperSAFE fixture names a coordinator contact, and a spec
/// without one has the gap that blocks activation.
#[test]
fn i69_fixture_sets_the_contact_and_a_gap_is_unset() {
    let mut spec = supersafe_fixture().expect("fixture").spec;
    assert!(matches!(
        spec.get(FieldId::CoordinatorContact),
        Field::Set(FieldValue::CoordinatorContact(Narrative::Inline(_)))
    ));
    spec.unset(FieldId::CoordinatorContact);
    let back = decode_spec(encode_spec(&spec).as_bytes()).expect("round trip");
    assert_eq!(back.get(FieldId::CoordinatorContact), Field::Unset);
}

/// ADR-034 section 3: a spec written before the field existed has no
/// `coordinator_contact` member. It decodes with the field unset. Any
/// other missing member is still refused.
#[test]
fn adr034_older_spec_without_the_contact_decodes_with_a_gap() {
    let spec = supersafe_fixture().expect("fixture").spec;
    let text = encode_spec(&spec);
    let member = "\"coordinator_contact\":";
    let at = text.find(member).expect("member");
    let end = text[at..].find(",\"").expect("next member") + at + 1;
    let older = format!("{}{}", &text[..at], &text[end..]);
    let back = decode_spec(older.as_bytes()).expect("older spec decodes");
    assert_eq!(back.get(FieldId::CoordinatorContact), Field::Unset);

    let name = "\"coordinator_name\":";
    let at = text.find(name).expect("member");
    let end = text[at..].find(",\"").expect("next member") + at + 1;
    let broken = format!("{}{}", &text[..at], &text[end..]);
    assert!(decode_spec(broken.as_bytes()).is_err());
}
