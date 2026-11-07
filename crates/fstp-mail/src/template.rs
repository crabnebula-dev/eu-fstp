//! Versioned default templates in English (M6 design section 5.3).
//!
//! - A template is a Rust value: fixed text and [`Slot`]s. Its fields are
//!   private, so only this module makes templates, and no text from
//!   outside the binary enters one (I-27).
//! - A version never changes (I-25). The test
//!   `i_25_template_versions_are_pinned` pins each version's digest. A new
//!   wording is a new version, and the old one stays in [`TEMPLATES`].
//! - Every message ends with [`BANK_DETAILS_SENTENCE`]
//!   (`SPEC/03-architecture/notifications.md`, content rules).
//! - The outcome, copy and contractual notice wordings are interim and
//!   carry `TODO(legal)`. Request W10 in
//!   `docs/legal/requests/04-product-wording.md` asks for them.

use std::collections::BTreeSet;

use crate::MailError;
use crate::address::Origin;
use crate::placeholder::{Bindings, Slot, Value};

/// The fixed closing sentence of every message. No message asks for bank
/// details or links to a bank detail change.
pub const BANK_DETAILS_SENTENCE: &str =
    "We never ask for bank details by email. Bank details change only inside the platform.";

/// Which message a template is for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TemplateId {
    /// A proposal reached a state the applicant is told about (P-08).
    ProposalOutcome,
    /// An IRC concern waits for the applicant (R-IR-02).
    IrcConcern,
    /// A notifiable conflict for the coordinator (R-CF-04).
    NotifiableConflict,
    /// A milestone reminder (P-31).
    MilestoneReminder,
    /// A milestone is overdue (P-33).
    MilestoneOverdue,
    /// A corrigendum to a call (I-53).
    Corrigendum,
    /// A contractual notice was issued (I-40).
    ContractNotice,
    /// The copy of a submission record the applicant asked for (R-SB-04).
    SubmissionCopy,
}

impl TemplateId {
    /// Every template id.
    pub const ALL: [TemplateId; 8] = [
        TemplateId::ProposalOutcome,
        TemplateId::IrcConcern,
        TemplateId::NotifiableConflict,
        TemplateId::MilestoneReminder,
        TemplateId::MilestoneOverdue,
        TemplateId::Corrigendum,
        TemplateId::ContractNotice,
        TemplateId::SubmissionCopy,
    ];

    /// The stable code, as `X-FSTP-Template` and the ledger record carry it.
    pub const fn code(self) -> &'static str {
        match self {
            TemplateId::ProposalOutcome => "proposal-outcome",
            TemplateId::IrcConcern => "irc-concern",
            TemplateId::NotifiableConflict => "notifiable-conflict",
            TemplateId::MilestoneReminder => "milestone-reminder",
            TemplateId::MilestoneOverdue => "milestone-overdue",
            TemplateId::Corrigendum => "corrigendum",
            TemplateId::ContractNotice => "contract-notice",
            TemplateId::SubmissionCopy => "submission-copy",
        }
    }
}

/// A template's language. M6 has English only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Locale {
    /// English.
    En,
}

impl Locale {
    /// The language tag.
    pub const fn code(self) -> &'static str {
        match self {
            Locale::En => "en",
        }
    }
}

/// One piece of a template: fixed text, or a slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Part {
    /// Fixed text. `\n` is a line break.
    Text(&'static str),
    /// A gap filled from the bindings.
    Slot(Slot),
}

/// One version of one template.
#[derive(Debug)]
pub struct Template {
    id: TemplateId,
    version: u32,
    locale: Locale,
    pdf: bool,
    subject: &'static [Part],
    body: &'static [Part],
}

/// A rendered template. `text` and `html` use `\n` line breaks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rendered {
    /// The subject, one line.
    pub subject: String,
    /// The plain-text part.
    pub text: String,
    /// The HTML part.
    pub html: String,
}

impl Template {
    /// The template id.
    pub const fn id(&self) -> TemplateId {
        self.id
    }

    /// The version.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// The language.
    pub const fn locale(&self) -> Locale {
        self.locale
    }

    /// Whether the message may carry a PDF part, when P-48 says attach.
    pub const fn allows_pdf(&self) -> bool {
        self.pdf
    }

    /// The subject parts.
    pub const fn subject_parts(&self) -> &'static [Part] {
        self.subject
    }

    /// The body parts, before the fixed footer.
    pub const fn body_parts(&self) -> &'static [Part] {
        self.body
    }

    /// The slots this template fills.
    pub fn slots(&self) -> BTreeSet<Slot> {
        self.subject
            .iter()
            .chain(self.body)
            .filter_map(|p| match p {
                Part::Slot(s) => Some(*s),
                Part::Text(_) => None,
            })
            .collect()
    }

    /// The version `version` of template `id` in `locale`.
    pub fn get(id: TemplateId, version: u32, locale: Locale) -> Option<&'static Template> {
        TEMPLATES
            .iter()
            .find(|t| t.id == id && t.version == version && t.locale == locale)
    }

    /// The newest version of template `id` in `locale`.
    pub fn latest(id: TemplateId, locale: Locale) -> Option<&'static Template> {
        TEMPLATES
            .iter()
            .filter(|t| t.id == id && t.locale == locale)
            .max_by_key(|t| t.version)
    }

    /// SHA-256 over a length-prefixed encoding of the id, version,
    /// locale, attachment rule, every part and the footer. The ledger's
    /// `TemplateVersionRecorded` carries it (M6 design section 3.1).
    pub fn digest(&self) -> [u8; 32] {
        let mut b: Vec<u8> = Vec::new();
        let field = |b: &mut Vec<u8>, bytes: &[u8]| {
            let n = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
            b.extend_from_slice(&n.to_be_bytes());
            b.extend_from_slice(bytes);
        };
        field(&mut b, b"fstp-template-v1");
        field(&mut b, self.id.code().as_bytes());
        field(&mut b, &self.version.to_be_bytes());
        field(&mut b, self.locale.code().as_bytes());
        field(&mut b, &[u8::from(self.pdf)]);
        for (name, parts) in [("subject", self.subject), ("body", self.body)] {
            field(&mut b, name.as_bytes());
            for p in parts {
                match p {
                    Part::Text(t) => {
                        field(&mut b, b"T");
                        field(&mut b, t.as_bytes());
                    }
                    Part::Slot(s) => {
                        field(&mut b, b"S");
                        field(&mut b, s.code().as_bytes());
                    }
                }
            }
        }
        field(&mut b, b"footer");
        field(&mut b, BANK_DETAILS_SENTENCE.as_bytes());
        fstp_crypto::sha256(&b)
    }

    /// Renders this template with `bindings`, links under `origin`.
    ///
    /// # Errors
    ///
    /// [`MailError::MissingSlot`], [`MailError::UnexpectedSlot`] or
    /// [`MailError::WrongKind`] unless the bindings fill exactly this
    /// template's slots with values of the right kind, and
    /// [`MailError::DateOutOfRange`] from a value.
    pub fn render(&self, bindings: &Bindings, origin: &Origin) -> Result<Rendered, MailError> {
        let slots = self.slots();
        for s in bindings.slots() {
            if !slots.contains(&s) {
                return Err(MailError::UnexpectedSlot(s));
            }
        }
        for s in &slots {
            let v = bindings.get(*s).ok_or(MailError::MissingSlot(*s))?;
            if v.kind() != s.kind() {
                return Err(MailError::WrongKind(*s));
            }
        }
        let value = |s: Slot| -> Result<(Value, String), MailError> {
            let v = *bindings.get(s).ok_or(MailError::MissingSlot(s))?;
            let r = v.render(origin)?;
            Ok((v, r))
        };

        let mut subject = String::new();
        for p in self.subject {
            match p {
                Part::Text(t) => subject.push_str(t),
                Part::Slot(s) => subject.push_str(&value(*s)?.1),
            }
        }

        let mut text = String::new();
        let mut html = String::from("<p>");
        for p in self.body {
            match p {
                Part::Text(t) => {
                    text.push_str(t);
                    html.push_str(
                        &escape_html(t)
                            .replace("\n\n", "\u{1}")
                            .replace('\n', "<br>\n")
                            .replace('\u{1}', "</p>\n<p>"),
                    );
                }
                Part::Slot(s) => {
                    let (v, r) = value(*s)?;
                    text.push_str(&r);
                    let e = escape_html(&r);
                    if matches!(v, Value::Link(_)) {
                        html.push_str(&format!("<a href=\"{e}\">{e}</a>"));
                    } else {
                        html.push_str(&e);
                    }
                }
            }
        }
        text.push_str("\n\n");
        text.push_str(BANK_DETAILS_SENTENCE);
        text.push('\n');
        let page = format!(
            "<!DOCTYPE html>\n<html lang=\"{lang}\">\n<head>\n<meta charset=\"utf-8\">\n\
             <title>{title}</title>\n</head>\n<body>\n{html}</p>\n<p>{bank}</p>\n</body>\n</html>\n",
            lang = self.locale.code(),
            title = escape_html(&subject),
            bank = escape_html(BANK_DETAILS_SENTENCE),
        );
        Ok(Rendered {
            subject,
            text,
            html: page,
        })
    }
}

fn escape_html(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

use Part::{Slot as S, Text as T};

/// Every template version, oldest first. Versions are never edited or
/// removed (I-25).
pub static TEMPLATES: &[Template] = &[
    // TODO(legal): W10 outcome wording for selected, not selected,
    // ineligible and declined. The text below states the state change only.
    Template {
        id: TemplateId::ProposalOutcome,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Proposal "),
            S(Slot::Proposal),
            T(": status "),
            S(Slot::State),
        ],
        body: &[
            T("The status of proposal "),
            S(Slot::Proposal),
            T(" changed to "),
            S(Slot::State),
            T(" on "),
            S(Slot::When),
            T(".\n\nSign in to read the decision and any next steps:\n"),
            S(Slot::Link),
        ],
    },
    Template {
        id: TemplateId::IrcConcern,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Proposal "),
            S(Slot::Proposal),
            T(": a notice is waiting"),
        ],
        body: &[
            T("A notice about proposal "),
            S(Slot::Proposal),
            T(" is waiting for you on the platform.\n\nSign in to read it:\n"),
            S(Slot::Link),
        ],
    },
    Template {
        id: TemplateId::NotifiableConflict,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Call "),
            S(Slot::Call),
            T(": a conflict notification needs your attention"),
        ],
        body: &[
            T("A conflict notification about proposal "),
            S(Slot::Proposal),
            T(" in call "),
            S(Slot::Call),
            T(" needs your attention.\n\nSign in to review it:\n"),
            S(Slot::Link),
        ],
    },
    Template {
        id: TemplateId::MilestoneReminder,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Milestone "),
            S(Slot::Milestone),
            T(" of proposal "),
            S(Slot::Proposal),
            T(": reminder"),
        ],
        body: &[
            T("Milestone "),
            S(Slot::Milestone),
            T(" of proposal "),
            S(Slot::Proposal),
            T(" is due on "),
            S(Slot::Due),
            T(".\nDays left: "),
            S(Slot::Count),
            T(".\n\nSign in to report progress or request a payment:\n"),
            S(Slot::Link),
        ],
    },
    Template {
        id: TemplateId::MilestoneOverdue,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Milestone "),
            S(Slot::Milestone),
            T(" of proposal "),
            S(Slot::Proposal),
            T(" is overdue"),
        ],
        body: &[
            T("Milestone "),
            S(Slot::Milestone),
            T(" of proposal "),
            S(Slot::Proposal),
            T(" was due on "),
            S(Slot::Due),
            T(" and is overdue.\n\nSign in to see its status:\n"),
            S(Slot::Link),
        ],
    },
    Template {
        id: TemplateId::Corrigendum,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Call "),
            S(Slot::Call),
            T(": corrigendum "),
            S(Slot::Count),
        ],
        body: &[
            T("Corrigendum "),
            S(Slot::Count),
            T(" to call "),
            S(Slot::Call),
            T(" was published on "),
            S(Slot::When),
            T(".\n\nSign in to read the updated Guide:\n"),
            S(Slot::Link),
        ],
    },
    // TODO(legal): W10 contractual notice wording. The text below names
    // the notice and its date only. The sealed PDF is the notice itself.
    Template {
        id: TemplateId::ContractNotice,
        version: 1,
        locale: Locale::En,
        pdf: true,
        subject: &[
            T("Contract "),
            S(Slot::Contract),
            T(": a contractual notice was issued"),
        ],
        body: &[
            T("A contractual notice about contract "),
            S(Slot::Contract),
            T(" for proposal "),
            S(Slot::Proposal),
            T(" was issued on "),
            S(Slot::When),
            T(
                ".\n\nWhere a PDF is attached, it is the notice. The notice is also on the platform:\n",
            ),
            S(Slot::Link),
        ],
    },
    // TODO(legal): W10 wording for the copy of a submission. The text
    // below holds ids and times only (docs/design/03-applicant-screens.md).
    Template {
        id: TemplateId::SubmissionCopy,
        version: 1,
        locale: Locale::En,
        pdf: false,
        subject: &[
            T("Proposal "),
            S(Slot::Proposal),
            T(": copy of your submission record"),
        ],
        body: &[
            T("You asked for a copy of the submission record of proposal "),
            S(Slot::Proposal),
            T(".\nIt was submitted on "),
            S(Slot::When),
            T(".\n\nSign in to see the full submission:\n"),
            S(Slot::Link),
        ],
    },
];
