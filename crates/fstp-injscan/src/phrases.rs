//! The phrase detectors: overrides, text addressed to an AI reader,
//! score requests, tool-call requests and chat role lines (ADR-035,
//! "Detectors").
//!
//! A phrase is a list of steps over the words of the folded view. Each
//! step is a set of words, where a trailing `*` matches a prefix, and the
//! most words that may stand between it and the step before. A phrase may
//! also require that it opens a sentence, or that a given character
//! follows it.

use crate::view::View;
use crate::{Detection, Reason};

/// One step: the words it accepts and the most words skipped before it.
type Step = (&'static [&'static str], usize);

struct Phrase {
    reason: Reason,
    steps: &'static [Step],
    /// The phrase must open a sentence or a line.
    opens: bool,
    /// One of these characters must follow the phrase, after spaces.
    then: &'static [char],
}

const fn p(reason: Reason, steps: &'static [Step]) -> Phrase {
    Phrase {
        reason,
        steps,
        opens: false,
        then: &[],
    }
}

const fn opening(reason: Reason, steps: &'static [Step], then: &'static [char]) -> Phrase {
    Phrase {
        reason,
        steps,
        opens: true,
        then,
    }
}

const fn followed(reason: Reason, steps: &'static [Step], then: &'static [char]) -> Phrase {
    Phrase {
        reason,
        steps,
        opens: false,
        then,
    }
}

use Reason::{Addressed, Override, RoleMarker, ScoreRequest, ToolCall};

const EN_VERB: &[&str] = &[
    "ignore",
    "ignoring",
    "disregard",
    "disregarding",
    "forget",
    "overlook",
    "override",
    "bypass",
];
const EN_EARLIER: &[&str] = &[
    "previous",
    "prior",
    "above",
    "earlier",
    "preceding",
    "former",
    "original",
    "system",
];
const EN_RULES: &[&str] = &[
    "instruc*",
    "prompt*",
    "rule*",
    "direction*",
    "guideline*",
    "context",
    "rubric",
];
const AI: &[&str] = &[
    "ai",
    "llm",
    "llms",
    "model",
    "assessor*",
    "evaluator*",
    "grader*",
    "chatbot",
    "bot",
    "gpt",
    "claude",
    "assistant",
];

const PHRASES: &[Phrase] = &[
    // Overrides, English.
    p(Override, &[(EN_VERB, 0), (EN_EARLIER, 4), (EN_RULES, 2)]),
    p(
        Override,
        &[
            (&["ignore", "disregard", "forget"], 0),
            (&["everything", "all", "anything"], 1),
            (&["above", "before", "previously"], 2),
        ],
    ),
    followed(
        Override,
        &[
            (&["new", "updated", "revised", "real"], 0),
            (&["instruc*", "rules"], 0),
        ],
        &[':'],
    ),
    p(
        Override,
        &[
            (&["you"], 0),
            (&["are"], 0),
            (&["now"], 0),
            (&["a", "an", "the", "my", "acting", "no"], 0),
        ],
    ),
    p(
        Override,
        &[(&["from"], 0), (&["now"], 0), (&["on"], 0), (&["you"], 0)],
    ),
    // German.
    p(
        Override,
        &[
            (&["ignorier*", "vergiss", "vergessen", "missachte*"], 0),
            (
                &[
                    "vorherig*",
                    "bisherig*",
                    "obig*",
                    "vorangegangen*",
                    "früher*",
                    "vorig*",
                ],
                3,
            ),
            (&["anweisung*", "instruktion*", "befehl*", "regeln"], 2),
        ],
    ),
    // French, Spanish, Italian and Portuguese: the adjective follows.
    p(
        Override,
        &[
            (
                &[
                    "ignor*",
                    "oubli*",
                    "néglig*",
                    "olvid*",
                    "dimentic*",
                    "esqueç*",
                    "esquec*",
                    "desconsider*",
                ],
                0,
            ),
            (
                &[
                    "instruc*",
                    "instruç*",
                    "consigne*",
                    "directive*",
                    "indicacion*",
                    "istruzion*",
                    "indicazion*",
                ],
                3,
            ),
            (
                &[
                    "précédent*",
                    "precedent*",
                    "antérieur*",
                    "anterior*",
                    "previ*",
                    "prévi*",
                    "sopra",
                ],
                1,
            ),
        ],
    ),
    // Maltese (lead reading, 2026-11-22): "injora l-istruzzjonijiet
    // preċedenti", "insa l-istruzzjonijiet ta' qabel".
    p(
        Override,
        &[
            (&["injora*", "tinjora*", "insa", "tinsiex"], 0),
            (&["istruzzjoni*", "struzzjoni*"], 3),
            (&["preċedenti", "precedenti", "qabel", "ta"], 2),
        ],
    ),
    p(
        Addressed,
        &[
            (&["għażiż*", "ghaziz*"], 0),
            (&["valutatur*", "evalwatur*", "ai", "ia"], 1),
        ],
    ),
    p(
        Addressed,
        &[
            (&["nota", "messaġġ"], 0),
            (&["lill", "għall"], 0),
            (&["ai", "ia", "valutatur*", "evalwatur*", "mudell"], 1),
        ],
    ),
    // Dutch and Polish.
    p(
        Override,
        &[
            (
                &[
                    "negeer", "negeren", "vergeet", "zignoruj", "ignoruj", "zapomnij",
                ],
                0,
            ),
            (
                &[
                    "vorige",
                    "eerdere",
                    "voorgaande",
                    "poprzedni*",
                    "wcześniejsz*",
                    "powyższ*",
                ],
                3,
            ),
            (&["instructie*", "opdracht*", "instrukcj*", "polece*"], 1),
        ],
    ),
    // Addressed to an AI reader.
    p(
        Addressed,
        &[(&["note", "reminder"], 0), (&["to", "for"], 0), (AI, 3)],
    ),
    p(
        Addressed,
        &[
            (&["dear", "hello", "hi", "attention"], 0),
            (
                &[
                    "ai",
                    "llm",
                    "assessor*",
                    "evaluator*",
                    "grader*",
                    "chatbot",
                    "model",
                    "bot",
                ],
                2,
            ),
        ],
    ),
    p(
        Addressed,
        &[(&["as"], 0), (&["an"], 0), (&["ai", "llm"], 0)],
    ),
    p(
        Addressed,
        &[
            (&["if"], 0),
            (&["you"], 0),
            (&["are"], 0),
            (&["an", "a"], 0),
            (&["ai", "llm", "language", "assistant", "bot"], 1),
        ],
    ),
    p(
        Addressed,
        &[
            (&["ai", "llm", "model", "assistant", "bot"], 0),
            (
                &[
                    "reading",
                    "processing",
                    "evaluating",
                    "reviewing",
                    "assessing",
                    "scoring",
                    "grading",
                ],
                0,
            ),
            (&["this"], 0),
        ],
    ),
    opening(
        Addressed,
        &[
            (
                &[
                    "assessment",
                    "evaluation",
                    "grading",
                    "scoring",
                    "review",
                    "reviewing",
                ],
                0,
            ),
            (&["system", "model", "bot", "ai", "engine", "agent"], 0),
        ],
        &[',', ':'],
    ),
    opening(
        Addressed,
        &[(&["ai", "llm", "assessor", "evaluator", "grader"], 0)],
        &[',', ':'],
    ),
    opening(
        Addressed,
        &[
            (&["ai", "automated", "llm"], 0),
            (
                &[
                    "reviewer*",
                    "assessor*",
                    "evaluator*",
                    "grader*",
                    "system",
                    "agent",
                    "model",
                ],
                0,
            ),
        ],
        &[',', ':'],
    ),
    p(
        Override,
        &[
            (
                &["rules", "instructions", "rubric", "criteria", "guidelines"],
                0,
            ),
            (&["have", "has"], 0),
            (&["changed", "been"], 0),
        ],
    ),
    p(
        Addressed,
        &[
            (
                &[
                    "hinweis",
                    "nachricht",
                    "nota",
                    "note",
                    "mensaje",
                    "messaggio",
                ],
                0,
            ),
            (&["an", "für", "à", "a", "para", "per", "pour"], 0),
            (
                &[
                    "ki",
                    "ia",
                    "bewerter*",
                    "gutachter*",
                    "évaluat*",
                    "evaluador*",
                    "valutator*",
                    "l",
                ],
                2,
            ),
        ],
    ),
    // Score requests.
    p(
        ScoreRequest,
        &[
            (&["give", "assign", "award", "grant", "vergib", "gib"], 0),
            (
                &[
                    "highest", "maximum", "max", "top", "full", "perfect", "best", "höchst*",
                    "maximal*", "volle",
                ],
                4,
            ),
            (
                &[
                    "score*",
                    "mark*",
                    "rating*",
                    "grade*",
                    "points",
                    "punkt*",
                    "bewertung*",
                    "note",
                ],
                1,
            ),
        ],
    ),
    followed(
        ScoreRequest,
        &[
            (&["rate", "score", "grade", "give", "mark"], 0),
            (&["10", "100", "5", "ten", "five"], 3),
        ],
        &['/'],
    ),
    p(
        ScoreRequest,
        &[
            (
                &[
                    "report", "return", "record", "output", "state", "say", "list",
                ],
                0,
            ),
            (&["no"], 5),
            (
                &[
                    "findings",
                    "finding",
                    "weakness*",
                    "flaws",
                    "issues",
                    "concerns",
                    "problems",
                ],
                1,
            ),
        ],
    ),
    p(
        ScoreRequest,
        &[
            (
                &["mark", "treat", "consider", "classify", "label", "flag"],
                0,
            ),
            (&["as"], 6),
            (
                &[
                    "verified",
                    "excellent",
                    "outstanding",
                    "exceptional",
                    "flawless",
                    "perfect",
                    "best",
                ],
                1,
            ),
        ],
    ),
    p(
        ScoreRequest,
        &[(&["rank"], 0), (&["first", "top", "highest", "1st"], 3)],
    ),
    p(
        ScoreRequest,
        &[
            (&["output", "return", "set", "assign", "print"], 0),
            (&["score", "scores", "decision", "rating", "band"], 2),
        ],
    ),
    p(
        ScoreRequest,
        &[
            (&["decision"], 0),
            (
                &[
                    "accept", "approve", "approved", "accepted", "fund", "funded",
                ],
                0,
            ),
        ],
    ),
    // Tool-call requests.
    opening(
        ToolCall,
        &[
            (&["call", "invoke", "execute", "trigger"], 0),
            (&["tool", "tools", "function"], 2),
        ],
        &[],
    ),
];

/// Words of the folded view, as byte spans.
fn words(s: &str) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut start: Option<usize> = None;
    for (i, c) in s.char_indices() {
        if c.is_alphanumeric() {
            if start.is_none() {
                start = Some(i);
            }
        } else if let Some(a) = start.take() {
            out.push((a, i));
        }
    }
    if let Some(a) = start {
        out.push((a, s.len()));
    }
    out
}

fn accepts(set: &[&str], word: &str) -> bool {
    set.iter().any(|w| match w.strip_suffix('*') {
        Some(prefix) => word.starts_with(prefix),
        None => *w == word,
    })
}

/// Whether the word at byte `a` opens a sentence or a line.
fn opens_sentence(s: &str, a: usize) -> bool {
    let before = s.get(..a).unwrap_or("");
    match before.trim_end_matches(' ').chars().next_back() {
        None => true,
        Some(c) => matches!(
            c,
            '.' | '!' | '?' | '\n' | ':' | ';' | '>' | '"' | '(' | '*' | '#' | '-'
        ),
    }
}

/// The next character after byte `b`, past spaces.
fn next_char(s: &str, b: usize) -> Option<char> {
    s.get(b..)?.chars().find(|c| *c != ' ')
}

fn text(s: &str, w: (usize, usize)) -> &str {
    s.get(w.0..w.1).unwrap_or("")
}

/// Matches `ph` from word `i`. Returns the byte end of its last word.
fn match_at(s: &str, ws: &[(usize, usize)], ph: &Phrase, i: usize) -> Option<usize> {
    let mut steps = ph.steps.iter();
    let (first, _) = steps.next()?;
    let w0 = *ws.get(i)?;
    if !accepts(first, text(s, w0)) {
        return None;
    }
    if ph.opens && !opens_sentence(s, w0.0) {
        return None;
    }
    let mut at = i;
    let mut end = w0.1;
    for (set, gap) in steps {
        let mut found = None;
        for k in 1..=gap.saturating_add(1) {
            let j = at.checked_add(k)?;
            let w = *ws.get(j)?;
            if accepts(set, text(s, w)) {
                found = Some((j, w.1));
                break;
            }
        }
        let (j, e) = found?;
        at = j;
        end = e;
    }
    if !ph.then.is_empty() && !next_char(s, end).is_some_and(|c| ph.then.contains(&c)) {
        return None;
    }
    Some(end)
}

/// Lines that open with a chat role: `system:`, `assistant:`, `###
/// system`, `### instruction`, after optional `#`, `*` and spaces.
fn role_lines(v: &View, out: &mut Vec<Detection>) {
    let s = &v.s;
    let mut line_start = 0usize;
    for line in s.split('\n') {
        let trimmed = line.trim_start_matches([' ', '#', '*', '>']);
        let lead = line.len().saturating_sub(trimmed.len());
        let hashes = line.get(..lead).is_some_and(|l| l.contains('#'));
        for role in [
            "system",
            "assistant",
            "instruction",
            "instructions",
            "response",
        ] {
            let Some(rest) = trimmed.strip_prefix(role) else {
                continue;
            };
            let colon = rest.trim_start_matches(['*', ' ']).starts_with(':');
            let role_ok = role == "system" || role == "assistant" || hashes;
            if role_ok && colon {
                let a = line_start.saturating_add(lead);
                let b = a.saturating_add(role.len());
                if let Some((x, y)) = v.span(a, b) {
                    out.push(Detection {
                        start: x,
                        end: y,
                        reason: RoleMarker,
                    });
                }
            }
        }
        line_start = line_start.saturating_add(line.len()).saturating_add(1);
    }
}

/// Runs every phrase over the folded view.
pub(crate) fn detect(v: &View, out: &mut Vec<Detection>) {
    let s = &v.s;
    let ws = words(s);
    for i in 0..ws.len() {
        for ph in PHRASES {
            if let Some(end) = match_at(s, &ws, ph, i)
                && let Some(w0) = ws.get(i)
                && let Some((a, b)) = v.span(w0.0, end)
            {
                out.push(Detection {
                    start: a,
                    end: b,
                    reason: ph.reason,
                });
            }
        }
    }
    role_lines(v, out);
}
