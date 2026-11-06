//! Vocabulary packs: the plain pack and the optional Voyage pack (`SPEC/12-journey-ui.md` section 4, ADR-015, O-55, I-72).
//!
//! Both packs are terminology override sets of interface labels
//! (`white-labelling.md`). The plain pack is the platform default and
//! names every label key. The Voyage pack is optional: a tenant switches
//! it on, and its label then shows as a secondary line beside the plain
//! one. The labels are those of `docs/design/07-vocabulary-pack.md`.
//!
//! A pack file is one I-JSON object, read only through `fstp-json`, with
//! exactly these members:
//!
//! | Member | Value |
//! | --- | --- |
//! | `vocab_pack_version` | the integer 1 |
//! | `pack` | `plain` or `voyage` |
//! | `labels` | an object from label key to label text |
//!
//! Rules, each refused with its own [`VocabErrorKind`]:
//!
//! - A key must be one of [`LABEL_KEYS`], the closed list of interface
//!   labels. No approved wording, contract, notice, Guide text, funder
//!   document or email has a key there, so no pack can reach one (I-72,
//!   I-94).
//! - A text is 1 to [`MAX_LABEL_BYTES`] bytes of plain text: no control
//!   character, no brace, no angle bracket and no space at either end.
//!   A label takes no placeholder and no markup (I-68).
//! - The keys of [`FIXED`] hold fixed respectful wording: the negative
//!   outcomes and the withdrawal action (design 07 content rules). A pack
//!   may repeat it and never change it.
//! - The plain pack names every key. A Voyage pack may leave a key out,
//!   and then shows no secondary line for it.
//!
//! Formal state names never come from a pack. [`Vocabulary::state`] takes
//! them from the domain core, so they stay visible in both packs (I-96).
//! The parser has the fuzz target `vocab_parse` in `fuzz/` (ADR-003).

use std::collections::BTreeMap;

use fstp_domain::rules::StateTag;
use fstp_json::{Object, Value};

/// The pack format version this parser reads.
pub const FORMAT_VERSION: u64 = 1;

/// The longest label text, in bytes.
pub const MAX_LABEL_BYTES: usize = 200;

/// The bytes of `vocab/plain.v1.json`, the platform default pack.
pub const PLAIN_V1: &[u8] = include_bytes!("../vocab/plain.v1.json");

/// The bytes of `vocab/voyage.v1.json`, the optional Voyage pack.
pub const VOYAGE_V1: &[u8] = include_bytes!("../vocab/voyage.v1.json");

const MEMBERS: [&str; 3] = ["vocab_pack_version", "pack", "labels"];

/// Every label key a pack may name, in byte order: the rows of design 07
/// catalogues 1 to 5 that hold no placeholder.
pub const LABEL_KEYS: &[&str] = &[
    "home.activity.open_full",
    "home.applicant.answer_questions",
    "home.applicant.empty.body",
    "home.applicant.empty.title",
    "home.primary.kicker.applicant",
    "home.recent_activity",
    "journey.diary.anchor_pending",
    "journey.map.reenter",
    "journey.map.status.complete",
    "journey.map.status.current",
    "journey.map.status.end",
    "journey.map.status.upcoming",
    "journey.map.title",
    "journey.map.withdraw_bracket",
    "journey.node.completed",
    "journey.node.declined",
    "journey.node.deferred",
    "journey.node.draft",
    "journey.node.granted",
    "journey.node.in_execution",
    "journey.node.ineligible",
    "journey.node.irc_review",
    "journey.node.negotiation",
    "journey.node.not_selected",
    "journey.node.ranked",
    "journey.node.stage1",
    "journey.node.stage2",
    "journey.node.submitted",
    "journey.node.terminated",
    "journey.node.withdrawn",
    "journey.strip.title",
    "journey.withdraw.action",
    "nav.audit_trail",
    "nav.history_export",
    "nav.my_applications",
    "nav.programme_setup",
    "nav.tenant_settings",
    "place.chronicle",
    "place.diary",
    "place.onboarding",
    "place.route_map",
    "place.seal",
    "place.strip",
    "place.studio",
    "place.studio.group1",
    "place.studio.group2",
    "place.studio.group3",
    "place.studio.group4",
    "place.studio.group5",
    "role.applicant",
    "role.committee",
    "role.irc",
    "role.planner",
    "role.reviewer",
    "vocab.audit_trail",
    "vocab.call",
    "vocab.committee",
    "vocab.contract",
    "vocab.guide",
    "vocab.hardship",
    "vocab.knock_out",
    "vocab.milestone",
    "vocab.negotiation",
    "vocab.payment_request",
    "vocab.pre_check",
    "vocab.proposal_draft",
    "vocab.review_stages",
    "vocab.submission",
    "vocab.team",
    "vocab.timeline",
];

/// A label with fixed wording in both packs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fixed {
    /// The label key.
    pub key: &'static str,
    /// The plain wording.
    pub plain: &'static str,
    /// The Voyage wording.
    pub voyage: &'static str,
}

/// The respectful wording of the negative outcomes and of the withdrawal
/// action, which has legal effect (design 07 catalogues 1 and 4, content
/// rule 6). It is data of the platform, never of a pack.
pub const FIXED: &[Fixed] = &[
    Fixed {
        key: "journey.node.ineligible",
        plain: "Not eligible",
        voyage: "Route closed at the border",
    },
    Fixed {
        key: "journey.node.not_selected",
        plain: "Not selected",
        voyage: "Route ended",
    },
    Fixed {
        key: "journey.node.declined",
        plain: "Declined",
        voyage: "Route ended",
    },
    Fixed {
        key: "journey.node.withdrawn",
        plain: "Withdrawn",
        voyage: "Route ended",
    },
    Fixed {
        key: "journey.node.terminated",
        plain: "Grant terminated",
        voyage: "Route ended",
    },
    Fixed {
        key: "journey.withdraw.action",
        plain: "Withdraw this proposal",
        voyage: "Withdraw this proposal",
    },
];

/// Which pack a file holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum PackKind {
    /// `plain`, the platform default (O-55).
    Plain,
    /// `voyage`, switched on per tenant (O-55).
    Voyage,
}

impl PackKind {
    /// Every kind.
    pub const ALL: [PackKind; 2] = [PackKind::Plain, PackKind::Voyage];

    /// The kind as a pack file spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            PackKind::Plain => "plain",
            PackKind::Voyage => "voyage",
        }
    }
}

/// Why a pack was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum VocabErrorKind {
    /// The bytes are not one I-JSON text.
    Json,
    /// A value has the wrong JSON type.
    WrongType,
    /// A required member is absent.
    MissingMember,
    /// A member outside the pack shape is present.
    UnknownMember,
    /// `vocab_pack_version` is not the integer 1.
    UnsupportedVersion,
    /// `pack` is neither `plain` nor `voyage`.
    InvalidValue,
    /// A key is no interface label of [`LABEL_KEYS`] (I-72).
    NotALabel,
    /// A text is not plain label text.
    InvalidText,
    /// A [`FIXED`] key holds other wording.
    FixedWording,
    /// The plain pack lacks a label key.
    MissingLabel,
}

impl VocabErrorKind {
    fn describe(self) -> &'static str {
        match self {
            VocabErrorKind::Json => "not an I-JSON text",
            VocabErrorKind::WrongType => "wrong JSON type",
            VocabErrorKind::MissingMember => "missing member",
            VocabErrorKind::UnknownMember => "unknown member",
            VocabErrorKind::UnsupportedVersion => "unsupported vocab_pack_version",
            VocabErrorKind::InvalidValue => "invalid value",
            VocabErrorKind::NotALabel => "not an interface label (I-72)",
            VocabErrorKind::InvalidText => "not plain label text",
            VocabErrorKind::FixedWording => "changes fixed wording",
            VocabErrorKind::MissingLabel => "missing label",
        }
    }
}

/// A refused pack: the kind and where it was found. A key outside the
/// closed list is not copied into `at`, since it may be any text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VocabError {
    kind: VocabErrorKind,
    at: String,
}

impl VocabError {
    fn new(kind: VocabErrorKind, at: impl Into<String>) -> VocabError {
        VocabError {
            kind,
            at: at.into(),
        }
    }

    /// Why the pack was refused.
    pub fn kind(&self) -> VocabErrorKind {
        self.kind
    }

    /// Where it was refused, such as `labels.vocab.team`. Empty for the
    /// whole text.
    pub fn at(&self) -> &str {
        &self.at
    }
}

impl core::fmt::Display for VocabError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.at.is_empty() {
            write!(f, "vocabulary pack: {}", self.kind.describe())
        } else {
            write!(f, "vocabulary pack: {}: {}", self.at, self.kind.describe())
        }
    }
}

impl std::error::Error for VocabError {}

/// A checked vocabulary pack.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pack {
    kind: PackKind,
    labels: BTreeMap<String, String>,
}

impl Pack {
    /// A pack of `kind` with `labels`, checked by the rules of the file
    /// format.
    pub fn new(kind: PackKind, labels: BTreeMap<String, String>) -> Result<Pack, VocabError> {
        use VocabErrorKind as K;
        for (key, text) in &labels {
            if !LABEL_KEYS.contains(&key.as_str()) {
                return Err(VocabError::new(K::NotALabel, "labels"));
            }
            let at = format!("labels.{key}");
            if !plain_text(text) {
                return Err(VocabError::new(K::InvalidText, at));
            }
            if let Some(f) = FIXED.iter().find(|f| f.key == key) {
                let want = match kind {
                    PackKind::Plain => f.plain,
                    PackKind::Voyage => f.voyage,
                };
                if text != want {
                    return Err(VocabError::new(K::FixedWording, at));
                }
            }
        }
        if kind == PackKind::Plain
            && let Some(key) = LABEL_KEYS.iter().find(|k| !labels.contains_key(**k))
        {
            return Err(VocabError::new(K::MissingLabel, format!("labels.{key}")));
        }
        Ok(Pack { kind, labels })
    }

    /// The pack's kind.
    pub fn kind(&self) -> PackKind {
        self.kind
    }

    /// The text of `key`, if the pack names it.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.labels.get(key).map(String::as_str)
    }

    /// Every key and text, in key order.
    pub fn labels(&self) -> impl Iterator<Item = (&str, &str)> {
        self.labels.iter().map(|(k, t)| (k.as_str(), t.as_str()))
    }

    /// The pack as file text, which [`parse`] reads back to an equal pack.
    pub fn encode(&self) -> String {
        let mut labels = Object::new();
        for (k, t) in &self.labels {
            let _ = labels.insert(k.as_str(), Value::from(t.as_str()));
        }
        let mut top = Object::new();
        let _ = top.insert("vocab_pack_version", Value::from(FORMAT_VERSION));
        let _ = top.insert("pack", Value::from(self.kind.as_str()));
        let _ = top.insert("labels", Value::Object(labels));
        fstp_json::to_pretty(&Value::Object(top))
    }
}

fn plain_text(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_LABEL_BYTES
        && text.trim() == text
        && !text
            .chars()
            .any(|c| c.is_control() || matches!(c, '{' | '}' | '<' | '>'))
}

/// Parses a vocabulary pack from its file bytes, with the default limits
/// of `fstp_json::parse`.
pub fn parse(bytes: &[u8]) -> Result<Pack, VocabError> {
    use VocabErrorKind as K;
    let value = fstp_json::parse(bytes).map_err(|_| VocabError::new(K::Json, ""))?;
    let top = value
        .as_object()
        .ok_or_else(|| VocabError::new(K::WrongType, ""))?;
    if top.keys().any(|k| !MEMBERS.contains(&k)) {
        return Err(VocabError::new(K::UnknownMember, ""));
    }
    let member = |name: &'static str| {
        top.get(name)
            .ok_or_else(|| VocabError::new(K::MissingMember, name))
    };
    match member("vocab_pack_version")? {
        Value::Number(n) => {
            if n.as_u64() != Some(FORMAT_VERSION) {
                return Err(VocabError::new(K::UnsupportedVersion, "vocab_pack_version"));
            }
        }
        _ => return Err(VocabError::new(K::WrongType, "vocab_pack_version")),
    }
    let name = member("pack")?
        .as_str()
        .ok_or_else(|| VocabError::new(K::WrongType, "pack"))?;
    let kind = PackKind::ALL
        .into_iter()
        .find(|k| k.as_str() == name)
        .ok_or_else(|| VocabError::new(K::InvalidValue, "pack"))?;
    let raw = member("labels")?
        .as_object()
        .ok_or_else(|| VocabError::new(K::WrongType, "labels"))?;
    let mut labels = BTreeMap::new();
    for (key, v) in raw.iter() {
        if !LABEL_KEYS.contains(&key) {
            return Err(VocabError::new(K::NotALabel, "labels"));
        }
        let text = v
            .as_str()
            .ok_or_else(|| VocabError::new(K::WrongType, format!("labels.{key}")))?;
        let _ = labels.insert(key.to_owned(), text.to_owned());
    }
    Pack::new(kind, labels)
}

/// The shipped plain pack, [`PLAIN_V1`].
pub fn plain_v1() -> Result<Pack, VocabError> {
    parse(PLAIN_V1)
}

/// The shipped Voyage pack, [`VOYAGE_V1`].
pub fn voyage_v1() -> Result<Pack, VocabError> {
    parse(VOYAGE_V1)
}

/// A label as a page shows it: the plain label first, then the Voyage
/// label as a secondary line when the tenant switched it on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown<'a> {
    /// The plain label, which always leads.
    pub plain: &'a str,
    /// The Voyage label, when switched on and different from the plain.
    pub secondary: Option<&'a str>,
}

/// A proposal state as a page shows it (I-96, R-JV-01).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StateShown<'a> {
    /// The formal state name, such as `STAGE2`, from the domain core.
    pub formal: &'static str,
    /// The plain label.
    pub plain: &'a str,
    /// The Voyage label, when switched on and different from the plain.
    pub secondary: Option<&'a str>,
}

/// The label lookup of one tenant: the plain pack, and the Voyage pack
/// when the tenant switched it on (O-55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Vocabulary {
    plain: Pack,
    voyage: Option<Pack>,
}

impl Vocabulary {
    /// The lookup over `plain` and, when switched on, `voyage`. A pack of
    /// the other kind in either place is refused.
    pub fn new(plain: Pack, voyage: Option<Pack>) -> Result<Vocabulary, VocabError> {
        if plain.kind != PackKind::Plain {
            return Err(VocabError::new(VocabErrorKind::InvalidValue, "pack"));
        }
        if voyage.as_ref().is_some_and(|v| v.kind != PackKind::Voyage) {
            return Err(VocabError::new(VocabErrorKind::InvalidValue, "pack"));
        }
        Ok(Vocabulary { plain, voyage })
    }

    /// The shipped packs, with the Voyage pack when `voyage_on`.
    pub fn platform(voyage_on: bool) -> Result<Vocabulary, VocabError> {
        let voyage = if voyage_on { Some(voyage_v1()?) } else { None };
        Vocabulary::new(plain_v1()?, voyage)
    }

    /// The label of `key`, or `None` for a key no pack may name.
    pub fn label(&self, key: &str) -> Option<Shown<'_>> {
        let plain = self.plain.get(key)?;
        let secondary = self
            .voyage
            .as_ref()
            .and_then(|v| v.get(key))
            .filter(|t| *t != plain);
        Some(Shown { plain, secondary })
    }

    /// The labels of `state`, beside its formal name.
    pub fn state(&self, state: StateTag) -> Option<StateShown<'_>> {
        let formal = state.spec_name();
        let key = format!("journey.node.{}", formal.to_ascii_lowercase());
        let shown = self.label(&key)?;
        Some(StateShown {
            formal,
            plain: shown.plain,
            secondary: shown.secondary,
        })
    }
}
