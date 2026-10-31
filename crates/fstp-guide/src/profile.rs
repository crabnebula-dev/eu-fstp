//! Funder profiles and their sources (M4 design sections 1.3 rule A9b and
//! 3.10).
//!
//! A [`FunderProfile`] holds a profile's Guide template and the wording
//! status of its legal sections. Code outside this crate cannot build one
//! from its own data: the type has no public constructor. A profile comes
//! only from a [`ProfileSource`], through [`ProfileSource::profile`].
//!
//! - [`ShippedProfiles`] is the only production source. It compiles in
//!   the files under `crates/fstp-guide/profiles/**`.
//! - A test source, such as the synthetic legal-wording variant of
//!   `fstp-api-testkit`, implements [`ProfileSource::files`] over its own
//!   files. Rule A9b keeps every other implementation out of `fstp-cell`
//!   and `fstp-control`, and the synthetic wording out of this crate.
//!
//! # Legal wording
//!
//! The template marks each statement that still needs approved wording
//! with `TODO(legal)` (`guide-for-applicants.md`, Rules). A marker is any
//! occurrence of that text, at any place on any line. The one exception
//! is the code span of the text, a backtick on each side, in the template
//! header: the text up to and including the first thematic break, which
//! `parse_template` never renders. There it names the marker rather than
//! placing one, as the shipped template's preamble does. Past the header,
//! a code span of the text is a marker like any other. A template with
//! no thematic break has no header, so nothing is exempt (Q6).
//!
//! - A profile with a marker anywhere in its template is pending, so
//!   `LegalWordingPending` fails validation (Q6). Its wording is approved
//!   only once the template holds no marker at all.
//! - Each profile also names its legal sections in [`LEGAL_SECTIONS`], as
//!   detail. A legal section is [`WordingStatus::Pending`] while its
//!   heading is missing, repeated or empty, or its body holds a marker.
//!   It is [`WordingStatus::Supplied`] once the source's text for it has
//!   no marker. A missing legal section keeps the profile pending too.
//!
//! The shipped profile keeps both markers of sections 9 and 11 until
//! Daniel supplies the approved wording, so it is pending.
//!
//! Interim, pending Daniel: the status is read from the markers of the
//! source's template. The design names a wording status, not where it
//! is kept. The shipped tree is the source of truth for production.

/// The name of the Horizon Europe profile, as `fstp_programme` names it.
pub const HORIZON_EUROPE: &str = "horizon-europe";

/// The text that marks wording still to be approved, wherever it stands
/// (module documentation).
pub const LEGAL_MARKER: &str = "TODO(legal)";

/// The legal sections of each profile, by profile name: the headings of
/// the sections whose statements need approved wording.
pub const LEGAL_SECTIONS: &[(&str, &[&str])] = &[(
    HORIZON_EUROPE,
    &[
        "## 9. Financial support to third parties",
        "## 11. Visibility and publication",
    ],
)];

/// The largest Guide template a source may supply, in bytes.
pub const MAX_GUIDE_BYTES: usize = 256 * 1024;

/// The shipped Horizon Europe Guide template, version 1. A test checks
/// that it equals `SPEC/profiles/horizon-europe/guide-for-applicants.md`
/// byte for byte.
const HORIZON_EUROPE_GUIDE_V1: &[u8] = include_bytes!("../profiles/horizon-europe/guide.v1.md");

/// Why a profile could not be loaded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ProfileError {
    /// The source holds no profile with this name.
    UnknownProfile,
    /// The Guide template is empty or above [`MAX_GUIDE_BYTES`].
    GuideSize,
    /// The Guide template is not UTF-8.
    NotUtf8,
}

impl std::fmt::Display for ProfileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ProfileError::UnknownProfile => "the source holds no profile with this name",
            ProfileError::GuideSize => "the Guide template is empty or too large",
            ProfileError::NotUtf8 => "the Guide template is not UTF-8",
        };
        f.write_str(s)
    }
}

impl std::error::Error for ProfileError {}

/// Whether a legal section's wording can be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WordingStatus {
    /// The section is missing, repeated or empty, or its body still holds
    /// a `TODO(legal)` marker. Validation fails with `LegalWordingPending` (Q6).
    Pending,
    /// The source supplied text for the section with no marker.
    Supplied,
}

/// One legal section of a profile and its wording status.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LegalSection {
    /// The section heading line, as [`LEGAL_SECTIONS`] names it.
    pub heading: &'static str,
    /// Its wording status.
    pub status: WordingStatus,
}

/// The files a source supplies for one profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ProfileFiles<'a> {
    /// The Guide template, as Markdown text.
    pub guide: &'a [u8],
}

/// A funder profile, as a [`ProfileSource`] supplies it.
///
/// It has no public constructor (rule A9b). Its parts are read through
/// the accessors.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfile {
    name: &'static str,
    guide: String,
    legal: Vec<LegalSection>,
    /// Whether the template holds a marker anywhere.
    marked: bool,
}

impl FunderProfile {
    /// Builds the profile `name` from `files`. Only
    /// [`ProfileSource::profile`] calls it.
    fn load(name: &'static str, files: ProfileFiles<'_>) -> Result<FunderProfile, ProfileError> {
        if files.guide.is_empty() || files.guide.len() > MAX_GUIDE_BYTES {
            return Err(ProfileError::GuideSize);
        }
        let guide = std::str::from_utf8(files.guide).map_err(|_| ProfileError::NotUtf8)?;
        let headings = legal_headings(name).ok_or(ProfileError::UnknownProfile)?;
        let legal = headings
            .iter()
            .map(|heading| LegalSection {
                heading,
                status: section_status(guide, heading),
            })
            .collect();
        Ok(FunderProfile {
            name,
            guide: guide.to_owned(),
            legal,
            marked: holds_marker(guide),
        })
    }

    /// The profile name, such as [`HORIZON_EUROPE`].
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// The Guide template text.
    pub fn guide_template(&self) -> &str {
        &self.guide
    }

    /// Every legal section with its status, in [`LEGAL_SECTIONS`] order.
    /// This is detail: [`FunderProfile::legal_wording_pending`] also reads
    /// markers outside these sections.
    pub fn legal_sections(&self) -> &[LegalSection] {
        &self.legal
    }

    /// Whether the wording is still pending (Q6): the template holds a
    /// marker anywhere, or a legal section is pending.
    pub fn legal_wording_pending(&self) -> bool {
        self.marked
            || self
                .legal
                .iter()
                .any(|s| s.status == WordingStatus::Pending)
    }
}

/// A source of funder profiles. In production only [`ShippedProfiles`]
/// implements it (layering rule A9b).
pub trait ProfileSource {
    /// The files of the profile `name`, or why there are none.
    fn files(&self, name: &str) -> Result<ProfileFiles<'_>, ProfileError>;

    /// The profile `name`, built from [`ProfileSource::files`]. Only the
    /// profiles [`LEGAL_SECTIONS`] names exist.
    fn profile(&self, name: &str) -> Result<FunderProfile, ProfileError> {
        let known = known_name(name).ok_or(ProfileError::UnknownProfile)?;
        let files = self.files(known)?;
        FunderProfile::load(known, files)
    }
}

/// The profiles compiled from `crates/fstp-guide/profiles/**`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ShippedProfiles;

impl ProfileSource for ShippedProfiles {
    fn files(&self, name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
        match name {
            HORIZON_EUROPE => Ok(ProfileFiles {
                guide: HORIZON_EUROPE_GUIDE_V1,
            }),
            _ => Err(ProfileError::UnknownProfile),
        }
    }
}

/// The static name of a known profile.
fn known_name(name: &str) -> Option<&'static str> {
    LEGAL_SECTIONS.iter().map(|(n, _)| *n).find(|n| *n == name)
}

/// The legal section headings of the profile `name`.
fn legal_headings(name: &str) -> Option<&'static [&'static str]> {
    LEGAL_SECTIONS
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, h)| *h)
}

/// The heading level of a Markdown heading line: the count of leading
/// `#` signs followed by a space.
fn heading_level(line: &str) -> Option<usize> {
    let hashes = line.bytes().take_while(|b| *b == b'#').count();
    let rest = line.get(hashes..)?;
    (hashes > 0 && rest.starts_with(' ')).then_some(hashes)
}

/// The byte offset just after the template header of `text`: the text up
/// to and including the first thematic break, with the rule
/// [`crate::parse_template`] uses. That break is a line that is exactly
/// `---` and follows a blank line or starts the text. Zero when `text`
/// has no such line, so it has no header.
fn header_end(text: &str) -> usize {
    let mut at = 0usize;
    let mut after_blank = true;
    for line in text.split_inclusive('\n') {
        let content = line.strip_suffix('\n').unwrap_or(line);
        at = at.saturating_add(line.len());
        if after_blank && content == "---" {
            return at;
        }
        after_blank = content.is_empty();
    }
    0
}

/// Whether `text` holds a marker (module documentation): an occurrence of
/// [`LEGAL_MARKER`] that is not the code span of the marker text in the
/// template header. The header is never rendered. Past it, a code span
/// counts as a marker too (Q6), so no rendered text can hide one behind
/// backticks.
fn holds_marker(text: &str) -> bool {
    let header = header_end(text);
    text.match_indices(LEGAL_MARKER).any(|(at, m)| {
        if at >= header {
            return true;
        }
        let before = text.get(..at).is_some_and(|s| s.ends_with('`'));
        let after = at
            .checked_add(m.len())
            .and_then(|end| text.get(end..))
            .is_some_and(|s| s.starts_with('`'));
        !(before && after)
    })
}

/// The status of the section `heading` in `guide`. The body runs from the
/// line after the heading to the next heading of the same or a higher
/// level. A missing heading, a repeated heading, a body with no text or a
/// marker anywhere in the body leaves the section pending.
fn section_status(guide: &str, heading: &str) -> WordingStatus {
    let Some(level) = heading_level(heading) else {
        return WordingStatus::Pending;
    };
    let mut lines = guide.lines();
    let mut found = 0usize;
    let mut marked = false;
    let mut text = false;
    while let Some(line) = lines.next() {
        if line != heading {
            continue;
        }
        found = found.saturating_add(1);
        for body in lines.by_ref() {
            if heading_level(body).is_some_and(|l| l <= level) {
                if body == heading {
                    found = found.saturating_add(1);
                }
                break;
            }
            // A section body is never preamble, so a code span of the
            // marker counts here too (Q6).
            if body.contains(LEGAL_MARKER) {
                marked = true;
            }
            if !body.trim().is_empty() {
                text = true;
            }
        }
    }
    if found == 1 && text && !marked {
        WordingStatus::Supplied
    } else {
        WordingStatus::Pending
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;

    /// A test source over one template text.
    struct Over<'a>(&'a str);

    impl ProfileSource for Over<'_> {
        fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
            Ok(ProfileFiles {
                guide: self.0.as_bytes(),
            })
        }
    }

    const TWO: &str = "# T\n\nSections marked `TODO(legal)` need approved wording.\n\n---\n\n## 9. Financial support to third parties\n\nText.\n\n### Sub\n\nMore.\n\n## 10. Contract and payments\n\nPaid in two parts.\n\n## 11. Visibility and publication\n\nWorded.\n";

    /// R-GA-01, Q6: the shipped Horizon Europe profile keeps both legal
    /// sections pending, so its wording blocks activation.
    #[test]
    fn r_ga_01_shipped_horizon_europe_legal_sections_are_pending() {
        let p = ShippedProfiles.profile(HORIZON_EUROPE).unwrap();
        assert_eq!(p.name(), HORIZON_EUROPE);
        assert!(p.legal_wording_pending());
        assert_eq!(p.legal_sections().len(), 2);
        assert!(
            p.legal_sections()
                .iter()
                .all(|s| s.status == WordingStatus::Pending)
        );
        assert!(p.guide_template().starts_with("# Guide for Applicants"));
    }

    /// Q6: a template with no marker and text in every legal section is
    /// supplied. The code span that names the marker is not a marker.
    #[test]
    fn q6_marker_free_legal_sections_are_supplied() {
        let p = Over(TWO).profile(HORIZON_EUROPE).unwrap();
        assert!(!p.legal_wording_pending());
        assert!(
            p.legal_sections()
                .iter()
                .all(|s| s.status == WordingStatus::Supplied)
        );
    }

    /// Q6: a marker outside the legal sections keeps the profile pending,
    /// while the named sections stay supplied as detail.
    #[test]
    fn q6_marker_outside_the_legal_sections_keeps_the_profile_pending() {
        let text = TWO.replace("Paid in two parts.", "TODO(legal): the payment terms.");
        let p = Over(&text).profile(HORIZON_EUROPE).unwrap();
        assert!(p.legal_wording_pending());
        assert!(
            p.legal_sections()
                .iter()
                .all(|s| s.status == WordingStatus::Supplied)
        );
    }

    /// Q6: a marker after other text on its line, in a list item or after
    /// a sentence, is a marker, in a legal section and outside one.
    #[test]
    fn q6_marker_inside_a_line_stays_pending() {
        for (from, to) in [
            ("Text.", "- Payments TODO(legal): approve."),
            ("Worded.", "Worded. TODO(legal)"),
            ("Paid in two parts.", "Paid in two parts (TODO(legal))."),
            ("Paid in two parts.", "Paid `TODO(legal)."),
        ] {
            let text = TWO.replace(from, to);
            let p = Over(&text).profile(HORIZON_EUROPE).unwrap();
            assert!(p.legal_wording_pending(), "{to}");
        }
        let in_section = TWO.replace("Text.", "- Payments TODO(legal): approve.");
        let p = Over(&in_section).profile(HORIZON_EUROPE).unwrap();
        assert_eq!(
            p.legal_sections()
                .iter()
                .map(|s| s.status)
                .collect::<Vec<_>>(),
            vec![WordingStatus::Pending, WordingStatus::Supplied]
        );
    }

    /// Q6 reproducer: a code span of the marker counted as approved
    /// wording anywhere, so a backticked marker in a section body let the
    /// profile pass. The exemption holds only in the template header, up
    /// to and including the first thematic break, which is never rendered.
    /// In a legal section, in another section and in a subsection the
    /// profile stays pending.
    #[test]
    fn q6_backticked_marker_in_a_section_body_stays_pending() {
        for (from, to, legal) in [
            ("Text.", "Text `TODO(legal)` here.", Some(0)),
            ("Worded.", "`TODO(legal)`", Some(1)),
            (
                "Paid in two parts.",
                "Paid `TODO(legal)` in two parts.",
                None,
            ),
            ("More.", "More `TODO(legal)`.", Some(0)),
        ] {
            let text = TWO.replace(from, to);
            let p = Over(&text).profile(HORIZON_EUROPE).unwrap();
            assert!(p.legal_wording_pending(), "{to}");
            for (i, s) in p.legal_sections().iter().enumerate() {
                let want = if legal == Some(i) {
                    WordingStatus::Pending
                } else {
                    WordingStatus::Supplied
                };
                assert_eq!(s.status, want, "{to}: {}", s.heading);
            }
        }
        // The header's code span still names the marker.
        assert!(
            !Over(TWO)
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
        // A code span under a heading inside the header is not rendered,
        // so it still names the marker.
        let early = TWO.replace("# T\n", "# T\n\n## Notes\n\nSee `TODO(legal)`.\n");
        assert!(
            !Over(&early)
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
        // Past the header, before any numbered section, the text is
        // rendered, so a code span there is a marker.
        let rendered = TWO.replace(
            "---\n\n",
            "---\n\n## Notes\n\nSee `TODO(legal)`.\n\nA paragraph with `TODO(legal)`.\n\n",
        );
        assert!(
            Over(&rendered)
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
        // With no thematic break the template has no header, so the
        // preamble's code span is a marker too.
        let headerless = TWO.replace("---\n\n", "");
        assert!(
            Over(&headerless)
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
    }

    /// Q6: the header ends with the first thematic break that follows a
    /// blank line or starts the text, the rule of `parse_template`.
    #[test]
    fn q6_the_first_thematic_break_ends_the_header() {
        assert_eq!(header_end("a\n\n---\n\nb\n"), 7);
        assert_eq!(header_end("---\nb\n"), 4);
        assert_eq!(header_end("a\n\n---"), 6);
        assert_eq!(header_end("a\n---\n"), 0);
        assert_eq!(header_end("a\n\n----\n"), 0);
        assert_eq!(header_end("a\n\n--- \n"), 0);
        assert_eq!(header_end("a\n## 1. b\n"), 0);
        // The offsets agree with the header `parse_template` finds.
        let t = crate::parse_template(TWO.as_bytes()).unwrap();
        assert_eq!(t.header, 3);
        let header = TWO.get(..header_end(TWO)).unwrap();
        assert!(header.ends_with("---\n"));
        assert!(
            crate::parse_template(header.as_bytes())
                .unwrap()
                .body()
                .is_empty()
        );
    }

    /// Q6: a marker in a subsection body, a missing section or a repeated
    /// heading keeps the section pending.
    #[test]
    fn q6_marker_missing_or_repeated_section_stays_pending() {
        let marked = Over(
            "## 9. Financial support to third parties\n\n### Sub\n\n  TODO(legal): x\n\n## 11. Visibility and publication\n\nok\n",
        );
        assert!(
            marked
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
        let missing = Over("## 9. Financial support to third parties\n\nok\n");
        let p = missing.profile(HORIZON_EUROPE).unwrap();
        assert_eq!(
            p.legal_sections()
                .iter()
                .map(|s| s.status)
                .collect::<Vec<_>>(),
            vec![WordingStatus::Supplied, WordingStatus::Pending]
        );
        let repeated = Over(
            "## 9. Financial support to third parties\n\nok\n\n## 9. Financial support to third parties\n\nok\n\n## 11. Visibility and publication\n\nok\n",
        );
        assert!(
            repeated
                .profile(HORIZON_EUROPE)
                .unwrap()
                .legal_wording_pending()
        );
    }

    /// A9b: only the profiles the crate names exist, whatever a source
    /// supplies, and a template must be UTF-8 within the size bound.
    #[test]
    fn a9b_unknown_names_and_bad_templates_are_refused() {
        assert_eq!(
            ShippedProfiles.profile("other"),
            Err(ProfileError::UnknownProfile)
        );
        assert_eq!(
            Over(TWO).profile("other"),
            Err(ProfileError::UnknownProfile)
        );
        assert_eq!(
            Over("").profile(HORIZON_EUROPE),
            Err(ProfileError::GuideSize)
        );
        struct Bytes;
        impl ProfileSource for Bytes {
            fn files(&self, _name: &str) -> Result<ProfileFiles<'_>, ProfileError> {
                Ok(ProfileFiles {
                    guide: &[0xff, 0xfe],
                })
            }
        }
        assert_eq!(Bytes.profile(HORIZON_EUROPE), Err(ProfileError::NotUtf8));
    }
}
