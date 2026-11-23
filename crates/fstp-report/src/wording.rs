//! The approved wording store (ADR-036 section 1, L-08, `legal/README.md`
//! Q7).
//!
//! A funder profile names each visibility element by a wording ref. When
//! Daniel approves the text behind a ref, the text is stored here, in
//! `crates/fstp-report/wording/<ref>.txt`, with who approved it and when.
//! Only a code change adds a text.
//!
//! A text is fixed words plus slots written `{{name}}`, from the closed
//! list [`Slot`]. [`parse_text`] splits it (fuzz target
//! `wording_text_parse`). [`ApprovedWording::render`] fills the slots, and
//! gives nothing at all when any slot has no value, never a broken
//! sentence (Daniel, 2026-11-22). Values are inserted once, as text
//! (I-68): callers write the result as a text node or plain text.

/// A slot of an approved text. The names match the Guide's placeholders.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Slot {
    /// `{{programme.name}}`: the programme's `identity.name`.
    ProgrammeName,
    /// `{{action.number}}`: the grant agreement number,
    /// `funder.action_number`.
    ActionNumber,
    /// `{{action.acronym}}`: the action acronym, `funder.action_acronym`.
    ActionAcronym,
}

impl Slot {
    /// Every slot.
    pub const ALL: [Slot; 3] = [Slot::ProgrammeName, Slot::ActionNumber, Slot::ActionAcronym];

    /// The name between the braces.
    pub const fn name(self) -> &'static str {
        match self {
            Slot::ProgrammeName => "programme.name",
            Slot::ActionNumber => "action.number",
            Slot::ActionAcronym => "action.acronym",
        }
    }

    /// The slot of a name.
    pub fn from_name(name: &str) -> Option<Slot> {
        Slot::ALL.into_iter().find(|s| s.name() == name)
    }

    /// The stable code of the slot in the `/brand/funding` answer's
    /// `acknowledgement_missing` list.
    pub const fn code(self) -> &'static str {
        match self {
            Slot::ProgrammeName => "programme_name",
            Slot::ActionNumber => "action_number",
            Slot::ActionAcronym => "action_acronym",
        }
    }
}

/// One piece of a parsed text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Piece<'a> {
    /// Fixed words.
    Text(&'a str),
    /// A slot.
    Slot(Slot),
}

/// Why a text was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WordingError {
    /// The text is empty or longer than [`MAX_TEXT_BYTES`].
    Empty,
    /// A slot names no slot of [`Slot`].
    UnknownSlot,
    /// A `{{` has no closing `}}`.
    Unclosed,
    /// A `}}` closes nothing.
    StrayClose,
}

/// The longest stored text, in bytes.
pub const MAX_TEXT_BYTES: usize = 4096;

/// Splits `text` into fixed words and slots (module documentation).
///
/// # Errors
///
/// [`WordingError`] for an empty or oversized text, an unknown or
/// unclosed slot, or a stray `}}`.
pub fn parse_text(text: &str) -> Result<Vec<Piece<'_>>, WordingError> {
    if text.is_empty() || text.len() > MAX_TEXT_BYTES {
        return Err(WordingError::Empty);
    }
    let mut out = Vec::new();
    let mut rest = text;
    while !rest.is_empty() {
        let open = rest.find("{{");
        if let Some(close) = rest.find("}}")
            && open.is_none_or(|o| close < o)
        {
            return Err(WordingError::StrayClose);
        }
        match open {
            Some(open) => {
                let (words, from) = rest.split_at(open);
                if !words.is_empty() {
                    out.push(Piece::Text(words));
                }
                let inner = from.get(2..).ok_or(WordingError::Unclosed)?;
                let end = inner.find("}}").ok_or(WordingError::Unclosed)?;
                let name = inner.get(..end).ok_or(WordingError::Unclosed)?;
                let slot = Slot::from_name(name).ok_or(WordingError::UnknownSlot)?;
                out.push(Piece::Slot(slot));
                rest = inner.get(end.saturating_add(2)..).unwrap_or("");
            }
            None => {
                out.push(Piece::Text(rest));
                rest = "";
            }
        }
    }
    Ok(out)
}

/// The values a text's slots read. A `None` or blank value is a gap.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotValues<'a> {
    /// The programme's name.
    pub programme_name: Option<&'a str>,
    /// The grant agreement number.
    pub action_number: Option<&'a str>,
    /// The action acronym.
    pub action_acronym: Option<&'a str>,
}

impl<'a> SlotValues<'a> {
    /// The trimmed value of `slot`, if it holds text.
    pub fn get(&self, slot: Slot) -> Option<&'a str> {
        match slot {
            Slot::ProgrammeName => self.programme_name,
            Slot::ActionNumber => self.action_number,
            Slot::ActionAcronym => self.action_acronym,
        }
        .map(str::trim)
        .filter(|s| !s.is_empty())
    }
}

/// One approved text behind a wording ref.
#[derive(Debug, PartialEq, Eq)]
pub struct ApprovedWording {
    reference: &'static str,
    text: &'static str,
    approved_by: &'static str,
    approved_on: &'static str,
}

/// A text file's content without its one trailing newline.
const fn trim_newline(s: &'static str) -> &'static str {
    match s.as_bytes().split_last() {
        Some((b'\n', head)) => match std::str::from_utf8(head) {
            Ok(h) => h,
            Err(_) => s,
        },
        _ => s,
    }
}

/// Every approved text, by ref.
static STORE: [ApprovedWording; 1] = [ApprovedWording {
    reference: "horizon-europe/visibility/acknowledgement",
    text: trim_newline(include_str!(
        "../wording/horizon-europe/visibility/acknowledgement.txt"
    )),
    // L-08: approved by Daniel, 2026-11-22, with no disclaimer.
    approved_by: "Daniel",
    approved_on: "2026-11-22",
}];

/// The approved text behind `reference`, if any.
pub fn approved(reference: &str) -> Option<&'static ApprovedWording> {
    STORE.iter().find(|w| w.reference == reference)
}

/// Every approved text.
pub fn all() -> &'static [ApprovedWording] {
    &STORE
}

impl ApprovedWording {
    /// The wording ref.
    pub fn reference(&self) -> &'static str {
        self.reference
    }

    /// The text as approved, with its slots.
    pub fn text(&self) -> &'static str {
        self.text
    }

    /// Who approved it.
    pub fn approved_by(&self) -> &'static str {
        self.approved_by
    }

    /// The date of the approval, `YYYY-MM-DD`.
    pub fn approved_on(&self) -> &'static str {
        self.approved_on
    }

    /// The slots of the text that `values` leaves without text, in text
    /// order, each once.
    pub fn missing(&self, values: &SlotValues<'_>) -> Vec<Slot> {
        let mut out = Vec::new();
        for p in parse_text(self.text).unwrap_or_default() {
            if let Piece::Slot(s) = p
                && values.get(s).is_none()
                && !out.contains(&s)
            {
                out.push(s);
            }
        }
        out
    }

    /// The text with its slots filled from `values`, or `None` when any
    /// slot has no text (Daniel, 2026-11-22: no broken sentence).
    pub fn render(&self, values: &SlotValues<'_>) -> Option<String> {
        let mut out = String::new();
        for p in parse_text(self.text).ok()? {
            match p {
                Piece::Text(t) => out.push_str(t),
                Piece::Slot(s) => out.push_str(values.get(s)?),
            }
        }
        Some(out)
    }
}
