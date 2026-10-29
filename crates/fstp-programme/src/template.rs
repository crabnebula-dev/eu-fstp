//! The SuperSAFE fixture and the templates shipped with the platform.
//!
//! The fixture `fixtures/supersafe.programme.json` is canonical RFC 8785
//! text with exactly two members. `"spec"` is the SuperSAFE spec, which
//! sets every field. `"provenance"` lists each field whose SuperSAFE value
//! the spec does not give. A policy field is listed by its parameter, such
//! as `"P-58"`, when its cell in `policy-parameters.md` gives no concrete
//! value. An artefact field is listed by its key, such as
//! `"funder.action_number"`. Each entry holds `"synthetic": true` and the
//! open point in `"open"`. The flag never reaches the policy. Listing
//! artefact fields by key is interim, pending Daniel.
//!
//! The shipped SuperSAFE template is the fixture's spec with every
//! synthetic field left unset. A programme built from it therefore fails
//! validation (`FieldUnset`) until a person supplies those values, so a
//! synthetic placeholder never reaches a real programme. Interim, pending
//! Daniel.

use std::collections::BTreeMap;
use std::num::NonZeroU32;

use fstp_domain::rules::{CATALOGUE, ParamId};
use fstp_json::{FromJsonError, Value};

use crate::kinds::ProfileRef;
use crate::profile::FunderProfile;
use crate::spec::{DecodeError, FieldId, FieldKind, ProgrammeSpec, decode_spec, encode_spec};
use crate::value::{Licence, object};

/// The SuperSAFE fixture's text.
pub const SUPERSAFE_FIXTURE: &str = include_str!("../fixtures/supersafe.programme.json");

/// The SuperSAFE fixture, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixture {
    /// The spec. It sets every field.
    pub spec: ProgrammeSpec,
    /// The fields holding synthetic values, each with its open point.
    pub synthetic: BTreeMap<FieldId, String>,
}

/// The parameter whose spec id is `s`, such as `"P-58"`.
fn param(s: &str) -> Option<ParamId> {
    CATALOGUE.iter().map(|p| p.id).find(|p| p.spec_id() == s)
}

/// The field a provenance key names: a policy field by its parameter, or
/// an artefact field by its [`FieldId::key`]. Each field has one spelling.
fn provenance_field(key: &str) -> Option<FieldId> {
    match param(key) {
        Some(p) => FieldId::for_param(p),
        None => FieldId::from_key(key)
            .filter(|f| f.spec().is_some_and(|s| s.kind == FieldKind::Artefact)),
    }
}

/// Decodes a fixture text: exactly `"provenance"` and `"spec"`.
pub fn decode_fixture(text: &str) -> Result<Fixture, DecodeError> {
    let v = fstp_json::parse_str(text).map_err(DecodeError::Json)?;
    let shape = |m: &'static str| DecodeError::Shape(FromJsonError::invalid(m));
    let o = object(&v, &["provenance", "spec"]).map_err(DecodeError::Shape)?;
    let spec_text = match o.get("spec") {
        Some(s) => crate::spec::canonical(s),
        None => return Err(shape("the fixture has no spec")),
    };
    let spec = decode_spec(spec_text.as_bytes())?;
    let Some(prov) = o.get("provenance").and_then(Value::as_object) else {
        return Err(shape("the fixture has no provenance object"));
    };
    let mut synthetic = BTreeMap::new();
    for (k, entry) in prov.iter() {
        let p = provenance_field(k).ok_or_else(|| shape("provenance names no field"))?;
        let e = object(entry, &["open", "synthetic"]).map_err(DecodeError::Shape)?;
        if e.get("synthetic").and_then(Value::as_bool) != Some(true) {
            return Err(shape("a provenance entry is not marked synthetic"));
        }
        let open = e
            .get("open")
            .and_then(Value::as_str)
            .ok_or_else(|| shape("a provenance entry names no open point"))?;
        synthetic.insert(p, open.to_owned());
    }
    Ok(Fixture { spec, synthetic })
}

/// The SuperSAFE fixture shipped with the crate.
pub fn supersafe_fixture() -> Result<Fixture, DecodeError> {
    decode_fixture(SUPERSAFE_FIXTURE)
}

/// A programme template id. Shipped templates use fixed ids; tenant
/// templates get ids from the shell.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TemplateId(u128);

impl TemplateId {
    /// The id with raw value `r`.
    pub const fn from_raw(r: u128) -> TemplateId {
        TemplateId(r)
    }

    /// The raw value.
    pub const fn raw(self) -> u128 {
        self.0
    }
}

/// The shipped SuperSAFE template.
pub const SUPERSAFE_TEMPLATE: TemplateId = TemplateId::from_raw(1);

/// Who published a template.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Publisher {
    /// Shipped with the platform.
    Platform,
}

/// A programme template with its provenance (`programme-creator.md`,
/// Template library). It never holds people or programme history.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Template {
    /// The template.
    pub id: TemplateId,
    /// Its version.
    pub version: NonZeroU32,
    /// Its display name.
    pub name: &'static str,
    /// Who published it.
    pub publisher: Publisher,
    /// The funder profile it is built for.
    pub profile: ProfileRef,
    /// Its licence. `None` until Daniel names one for shipped templates
    /// (P-69 covers tenant publications only). Interim, pending Daniel.
    pub licence: Option<Licence>,
    /// The spec a draft starts from. Narrative and links are shown in the
    /// creator as editable text, never applied silently.
    pub spec: ProgrammeSpec,
}

/// The templates shipped with the platform.
pub fn shipped_templates() -> Result<Vec<Template>, DecodeError> {
    let fixture = supersafe_fixture()?;
    let mut spec = fixture.spec;
    for f in fixture.synthetic.keys() {
        spec.unset(*f);
    }
    Ok(vec![Template {
        id: SUPERSAFE_TEMPLATE,
        version: NonZeroU32::MIN,
        name: "SuperSAFE",
        publisher: Publisher::Platform,
        profile: FunderProfile::horizon_europe().reference(),
        licence: None,
        spec,
    }])
}

/// The canonical text of a template's spec, for its content digest.
pub fn template_text(t: &Template) -> String {
    encode_spec(&t.spec)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use fstp_domain::id::{PolicyVersionId, ProgrammeId};

    use super::*;
    use crate::{CompileIds, Field, compile};

    fn ids() -> CompileIds {
        CompileIds::new(ProgrammeId::from_raw(1), PolicyVersionId::from_raw(2), None)
    }

    /// R-PG-02: the shipped SuperSAFE template leaves exactly the fields of
    /// the synthetic parameters unset, so each is a `FieldUnset` failure,
    /// and it compiles under its own profile.
    #[test]
    fn r_pg_02_shipped_template_leaves_synthetic_fields_unset() {
        let fixture = match supersafe_fixture() {
            Ok(f) => f,
            Err(e) => panic!("{e}"),
        };
        let templates = match shipped_templates() {
            Ok(t) => t,
            Err(e) => panic!("{e}"),
        };
        let [t] = templates.as_slice() else {
            panic!("expected one shipped template");
        };
        let want: BTreeSet<FieldId> = fixture.synthetic.keys().copied().collect();
        assert!(!want.is_empty());
        let compiled = match compile(&t.spec, &FunderProfile::horizon_europe(), ids()) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(compiled.unset, want);
        assert_eq!(t.profile, FunderProfile::horizon_europe().reference());
    }

    /// R-PG-02: a blank start names the profile and leaves every other
    /// field unset.
    #[test]
    fn r_pg_02_blank_start_sets_only_the_profile() {
        let profile = FunderProfile::horizon_europe();
        let blank = profile.blank();
        assert!(blank.funder.p53_funder_profile.is_set());
        let compiled = match compile(&blank, &profile, ids()) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        assert_eq!(compiled.unset.len(), crate::FIELDS.len().saturating_sub(1));
        assert!(!compiled.unset.contains(&FieldId::P53));
        assert_eq!(compiled.policy.live.p58, None);
    }

    /// R-PG-01: a spec naming another funder profile does not compile
    /// under Horizon Europe.
    #[test]
    fn r_pg_01_compile_refuses_another_profile() {
        let mut spec = FunderProfile::horizon_europe().blank();
        let mut other = FunderProfile::horizon_europe().reference();
        other.version = std::num::NonZeroU16::MAX;
        spec.funder.p53_funder_profile = Field::Set(other);
        assert_eq!(
            compile(&spec, &FunderProfile::horizon_europe(), ids()),
            Err(crate::CompileError::ProfileMismatch)
        );
    }

    /// ADR-007: inline P-09 wording keeps the policy out of a ledger body
    /// until it is stored as a `TextRef`.
    #[test]
    fn adr007_inline_p09_wording_is_not_ledger_ready() {
        let fixture = match supersafe_fixture() {
            Ok(f) => f,
            Err(e) => panic!("{e}"),
        };
        let compiled = match compile(&fixture.spec, &FunderProfile::horizon_europe(), ids()) {
            Ok(c) => c,
            Err(e) => panic!("{e}"),
        };
        assert!(!compiled.ledger_ready());
        assert_eq!(compiled.artefacts.knock_out_texts().len(), 3);
    }

    /// R-PG-01: the profile's P-53 token is a valid token.
    #[test]
    fn r_pg_01_profile_reference_is_a_valid_token() {
        let r = FunderProfile::horizon_europe().reference();
        assert_eq!(
            crate::value::Token::new(r.profile.as_str()),
            Some(r.profile)
        );
    }

    /// R-PG-01: a provenance key names a policy field only by its
    /// parameter and an artefact field only by its path, so each field has
    /// one spelling.
    #[test]
    fn r_pg_01_provenance_keys_have_one_spelling() {
        assert_eq!(provenance_field("P-58"), Some(FieldId::P58));
        assert_eq!(
            provenance_field("funder.action_number"),
            Some(FieldId::ActionNumber)
        );
        assert_eq!(provenance_field("funder.p58_recipient_ceiling"), None);
        assert_eq!(provenance_field("action_number"), None);
        assert_eq!(provenance_field("P-99"), None);
        for f in FieldId::ALL {
            assert_eq!(FieldId::from_key(&f.key()), Some(*f), "{f:?}");
        }
    }
}
