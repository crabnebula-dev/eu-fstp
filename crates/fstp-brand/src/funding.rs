//! The funding card (ADR-034): the "Funded by the European Union" logo,
//! the programme's grant agreement number and its coordinator's name and
//! contact, shown in every footer, PDF and email where a programme is in
//! context (I-69).
//!
//! The logo is a platform asset Daniel supplied on 2026-11-22, never
//! tenant data. The web copy is the vendored SVG with the editor
//! metadata removed; the PNG was rasterised once (ADR-034 section 1).
//! Neither is ever recoloured.
//!
//! TODO(legal): the emblem usage rules and the acknowledgement sentence
//! (L-08). Nothing here states either.

use crate::{Rgb, ThemeMode};

/// The logo for pages, served at [`SVG_PATH`].
pub const FUNDED_BY_EU_SVG: &str = include_str!("../assets/funded-by-eu.svg");

/// The logo for PDFs and emails: 1166 by 240 pixels, opaque on white.
pub const FUNDED_BY_EU_PNG: &[u8] = include_bytes!("../assets/funded-by-eu.png");

/// The logo's alternative text: the words it shows (R-NF-04).
pub const FUNDED_BY_EU_ALT: &str = "Funded by the European Union";

/// Where the web serves the SVG.
pub const SVG_PATH: &str = "/brand/funded-by-eu.svg";

/// Where the web serves the funding cards as JSON.
pub const CARDS_PATH: &str = "/brand/funding";

/// The accessible name of the card's region.
pub const CARD_LABEL_TEXT: &str = "EU funding";

/// The label of the grant agreement number.
pub const LABEL_GRANT: &str = "Grant agreement number";
/// The label of the coordinator's name.
pub const LABEL_COORDINATOR: &str = "Coordinator";
/// The label of the coordinator's contact.
pub const LABEL_CONTACT: &str = "Contact";
/// What a line shows while its value is missing.
pub const NOT_SET: &str = "Not set yet";

/// A fixed colour of the card in light and dark. No brand token and no
/// theme changes it (I-69, I-70).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CardColour {
    /// In the light theme.
    pub light: Rgb,
    /// In the dark theme.
    pub dark: Rgb,
}

impl CardColour {
    /// The colour in `mode`.
    pub const fn of(self, mode: ThemeMode) -> Rgb {
        match mode {
            ThemeMode::Light => self.light,
            ThemeMode::Dark => self.dark,
        }
    }

    const fn fixed(v: u32) -> CardColour {
        CardColour {
            light: Rgb::hex(v),
            dark: Rgb::hex(v),
        }
    }
}

/// The card's ground: white in both themes, so the logo's official
/// colours always show.
pub const CARD_GROUND: CardColour = CardColour::fixed(0xffffff);
/// The card's text.
pub const CARD_TEXT: CardColour = CardColour::fixed(0x1f2328);
/// The card's labels.
pub const CARD_LABEL: CardColour = CardColour::fixed(0x4b5563);

/// The longest tenant default, in bytes.
pub const MAX_DEFAULT_BYTES: usize = 200;

/// Whether `s` may be a tenant default: 1 to [`MAX_DEFAULT_BYTES`]
/// bytes, no control character, no angle bracket, and no leading or
/// trailing white space (I-68).
pub fn plain_text(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= MAX_DEFAULT_BYTES
        && !s.chars().any(|c| c.is_control() || c == '<' || c == '>')
        && s.trim() == s
}

/// The tenant's default coordinator name and contact (ADR-034 section
/// 3). Shared code holds no value: each tenant sets its own.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FundingDefaults {
    name: String,
    contact: String,
}

impl FundingDefaults {
    /// The defaults, if both values are [`plain_text`].
    pub fn new(name: &str, contact: &str) -> Option<FundingDefaults> {
        (plain_text(name) && plain_text(contact)).then(|| FundingDefaults {
            name: name.to_owned(),
            contact: contact.to_owned(),
        })
    }

    /// The default coordinator name.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The default coordinator contact.
    pub fn contact(&self) -> &str {
        &self.contact
    }
}

/// One programme's funding card (ADR-034 section 2). Each value reaches
/// pages, PDFs and emails as text only (I-68).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FundingCard {
    /// The programme's id.
    pub programme: u128,
    /// The programme's name.
    pub name: String,
    /// The grant agreement number (`funder.action_number`).
    pub grant_number: Option<String>,
    /// The coordinator's name (`funder.coordinator_name`).
    pub coordinator_name: Option<String>,
    /// The coordinator's contact (`funder.coordinator_contact`).
    pub coordinator_contact: Option<String>,
}

/// `v` when it holds text after trimming.
fn present(v: Option<&String>) -> Option<&str> {
    v.map(|s| s.trim()).filter(|s| !s.is_empty())
}

impl FundingCard {
    /// The card with each missing coordinator value taken from the
    /// tenant's defaults, if any.
    #[must_use]
    pub fn with_defaults(mut self, d: Option<&FundingDefaults>) -> FundingCard {
        if let Some(d) = d {
            if present(self.coordinator_name.as_ref()).is_none() {
                self.coordinator_name = Some(d.name.clone());
            }
            if present(self.coordinator_contact.as_ref()).is_none() {
                self.coordinator_contact = Some(d.contact.clone());
            }
        }
        self
    }

    /// Whether the card names its grant agreement number, coordinator
    /// and contact (I-69).
    pub fn complete(&self) -> bool {
        present(self.grant_number.as_ref()).is_some()
            && present(self.coordinator_name.as_ref()).is_some()
            && present(self.coordinator_contact.as_ref()).is_some()
    }

    /// The card's lines, label then value, in a fixed order. A missing
    /// value shows [`NOT_SET`].
    pub fn lines(&self) -> [(&'static str, &str); 3] {
        fn v(x: Option<&String>) -> &str {
            present(x).unwrap_or(NOT_SET)
        }
        [
            (LABEL_GRANT, v(self.grant_number.as_ref())),
            (LABEL_COORDINATOR, v(self.coordinator_name.as_ref())),
            (LABEL_CONTACT, v(self.coordinator_contact.as_ref())),
        ]
    }

    /// The card as plain-text lines for PDFs and emails: the programme
    /// name, then each label with its value.
    pub fn text_lines(&self) -> Vec<String> {
        let mut out = vec![self.name.clone()];
        out.extend(self.lines().iter().map(|(l, v)| format!("{l}: {v}")));
        out
    }
}
