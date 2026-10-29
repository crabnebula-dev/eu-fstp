//! Message catalogues for server-rendered text (R-NF-04) and the `Label`
//! and `ApprovedText` kinds (I-72 seam, R-WL-05).
//!
//! R-NF-04 makes the interface localisable, so every server-rendered
//! string comes from a catalogue per locale. I-72 lets terminology
//! overrides change interface labels only: notices, the Guide for
//! Applicants and other approved wording keep their text. M4 builds the
//! seam, so an override can name only a `Label`, and an `ApprovedText`
//! resolves to its catalogue text whatever overrides exist.
//!
//! The grammar, the catalogue rules and the fixture are in
//! `common::message` (interim reading, pending Daniel).
//!
//! Red against the W0 stub: `parse_message_format` refuses every input
//! with `NotImplemented`, and the catalogue API does not exist yet.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

mod common;

use common::bind;
use common::chars::{hostile_plain, is_typed};
use common::message::{
    self, CatSpec, Entry, Kind, LocaleCat, MAX_MESSAGE_BYTES, Override, entry, fixture,
};
use common::reference;
use common::spec::{self, Attr, Msg, Node};
use fstp_html::parse_message_format;
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq};

/// Message arguments by placeholder name.
type Args = Vec<(String, String)>;

fn args(pairs: &[(&str, &str)]) -> Args {
    pairs
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// R-NF-04, TH-26: `parse_message_format` accepts and refuses exactly the
/// cases of the shared corpus, and bounds the message length.
#[test]
fn r_nf_04_message_format_corpus() {
    let mut cases: Vec<(String, bool, Vec<u8>)> = common::corpus::read("message_format.corpus")
        .into_iter()
        .map(|c| (format!("line {}", c.line), c.accept, c.input))
        .collect();
    cases.push((
        "longest message".to_owned(),
        true,
        vec![b'a'; MAX_MESSAGE_BYTES],
    ));
    cases.push((
        "one byte too long".to_owned(),
        false,
        vec![b'a'; MAX_MESSAGE_BYTES + 1],
    ));
    let mut failures = Vec::new();
    for (name, accept, input) in cases {
        match parse_message_format(&input) {
            Ok(_) if accept => {}
            Err(e) if !accept && is_typed(&e) => {}
            other => failures.push(format!(
                "{name} {:?}: {other:?}",
                String::from_utf8_lossy(&input)
            )),
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// A literal chunk with its braces doubled.
fn literal(g: &mut Gen) -> String {
    hostile_plain(g).replace('{', "{{").replace('}', "}}")
}

/// A valid message source using each of `names` at least once.
fn message_with(g: &mut Gen, names: &[&str]) -> String {
    let mut uses: Vec<&str> = names.to_vec();
    for n in names {
        if g.bool() {
            uses.push(n);
        }
    }
    g.shuffle(&mut uses);
    let mut out = literal(g);
    for n in uses {
        out.push('{');
        out.push_str(n);
        out.push('}');
        out.push_str(&literal(g));
    }
    if out.is_empty() {
        out.push('x');
    }
    out
}

/// Bytes near the message grammar: valid messages, edited messages and
/// arbitrary bytes over the brace alphabet.
fn near_message(g: &mut Gen) -> Vec<u8> {
    const ALPHABET: &[&str] = &[
        "{", "}", "{{", "}}", "a", "z", "_", "0", "A", " ", "-", ".", "\u{e9}", "\r", "\u{0}",
        "\u{85}", "\u{fffe}",
    ];
    match g.u8_in(0..=2) {
        0 => message_with(g, &["a", "b_2"]).into_bytes(),
        1 => {
            let mut b = message_with(g, &["a"]).into_bytes();
            let at = g.usize_in(0..=b.len());
            let ins = g.pick(ALPHABET).as_bytes().to_vec();
            b.splice(at..at, ins);
            b
        }
        _ => {
            let mut b: Vec<u8> = g
                .vec(0..=12, |g| g.pick(ALPHABET).as_bytes().to_vec())
                .concat();
            if g.u8_in(0..=7) == 0 {
                b.push(0xFF);
            }
            b
        }
    }
}

/// R-NF-04, TH-26: on inputs near the grammar, `parse_message_format`
/// accepts exactly what the reference grammar accepts, refuses with a
/// typed error, and answers the same twice.
#[test]
fn r_nf_04_message_format_parse_agrees_with_reference() {
    check("r_nf_04_message_format_parse_agrees_with_reference", |g| {
        let input = near_message(g);
        g.note_with(|| String::from_utf8_lossy(&input).into_owned());
        let got = parse_message_format(&input);
        prop_assert_eq!(&got, &parse_message_format(&input));
        let want = message::parse(&input);
        match got {
            Ok(_) => prop_assert!(want.is_ok(), "accepted, the reference refuses: {want:?}"),
            Err(e) => {
                prop_assert!(is_typed(&e), "{e}");
                prop_assert!(want.is_err(), "refused, the reference accepts: {e}");
            }
        }
        Ok(())
    });
}

const NAMES: &[&str] = &["a", "b", "c_1"];

/// A valid catalogue set: English by default, then some of French and
/// Austrian German, with one to five entries of random kind.
fn catalogue_set(g: &mut Gen) -> CatSpec {
    let n = g.usize_in(1..=5);
    let shapes: Vec<(String, Kind, Vec<&str>)> = (0..n)
        .map(|i| {
            let kind = if g.bool() {
                Kind::Label
            } else {
                Kind::Approved
            };
            let names: Vec<&str> = NAMES.iter().copied().filter(|_| g.bool()).collect();
            (format!("m.{i}"), kind, names)
        })
        .collect();
    let locale = |g: &mut Gen, tag: &str| LocaleCat {
        locale: tag.to_owned(),
        entries: shapes
            .iter()
            .map(|(id, kind, names)| Entry {
                id: id.clone(),
                kind: *kind,
                message: message_with(g, names),
            })
            .collect(),
    };
    let default = locale(g, "en");
    let mut others = Vec::new();
    for tag in ["fr", "de-AT"] {
        if g.bool() {
            others.push(locale(g, tag));
        }
    }
    CatSpec { default, others }
}

/// Plain arguments for every placeholder of `id`.
fn args_for(g: &mut Gen, cats: &CatSpec, id: &str) -> Vec<(String, String)> {
    let e = cats.default.get(id).unwrap();
    message::names(&message::parse(e.message.as_bytes()).unwrap())
        .into_iter()
        .map(|n| (n, hostile_plain(g)))
        .collect()
}

/// R-NF-04: over generated catalogue sets, the set builds, and every id
/// resolves in every locale to the reference text, arguments verbatim.
#[test]
fn r_nf_04_resolve_agrees_with_reference_over_generated_catalogues() {
    check(
        "r_nf_04_resolve_agrees_with_reference_over_generated_catalogues",
        |g| {
            let spec_cats = catalogue_set(g);
            spec_cats.check()?;
            let cats = bind::catalogues(&spec_cats).map_err(|e| format!("refused: {e}"))?;
            for locale in spec_cats.locales() {
                for e in &spec_cats.default.entries {
                    let a = args_for(g, &spec_cats, &e.id);
                    let (want, _) = spec_cats.resolve(locale, e.kind, &e.id, &a)?;
                    let got = bind::resolve(&cats, locale, e.kind, &e.id, &a)
                        .map_err(|err| format!("{locale} {}: {err}", e.id))?;
                    prop_assert_eq!(got, want, "{} {}", locale, e.id);
                }
            }
            Ok(())
        },
    );
}

/// R-NF-04: resolution refuses an unknown locale or id and arguments that
/// differ from the placeholders, each with a typed error.
#[test]
fn r_nf_04_resolve_refuses_wrong_arguments() {
    let cats = bind::catalogues(&fixture()).unwrap_or_else(|e| panic!("{e}"));
    let cases: &[(&str, &str, &str, Args)] = &[
        ("missing argument", "en", "call.deadline", args(&[])),
        (
            "extra argument",
            "en",
            "call.deadline",
            args(&[("date", "1"), ("other", "2")]),
        ),
        (
            "argument given twice",
            "en",
            "call.deadline",
            args(&[("date", "1"), ("date", "2")]),
        ),
        ("wrong name", "en", "call.deadline", args(&[("day", "1")])),
        (
            "argument to a message without one",
            "en",
            "nav.home",
            args(&[("a", "1")]),
        ),
        ("unknown id", "en", "no.such.id", args(&[])),
        ("unknown locale", "de", "nav.home", args(&[])),
    ];
    let mut failures = Vec::new();
    for (name, locale, id, a) in cases {
        match bind::resolve(&cats, locale, Kind::Label, id, a) {
            Ok(s) => failures.push(format!("{name}: resolved to {s:?}")),
            Err(e) if !is_typed(&e) => failures.push(format!("{name}: {e}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// R-NF-04, I-72: building a catalogue set refuses every broken rule, each
/// with a typed error. Each case breaks one rule of the fixture.
#[test]
fn r_nf_04_catalogue_set_refuses_each_broken_rule() {
    let edit = |f: &dyn Fn(&mut CatSpec)| {
        let mut c = fixture();
        f(&mut c);
        c
    };
    let cases: Vec<(&str, CatSpec)> = vec![
        (
            "a locale lacks an id",
            edit(&|c| {
                c.others[0].entries.pop();
            }),
        ),
        (
            "a locale adds an id",
            edit(&|c| c.others[0].entries.push(entry("extra", Kind::Label, "x"))),
        ),
        (
            "an id twice in one locale",
            edit(&|c| {
                c.default
                    .entries
                    .push(entry("nav.home", Kind::Label, "Again"))
            }),
        ),
        (
            "a locale changes an id's kind",
            edit(&|c| c.others[0].entries[0].kind = Kind::Approved),
        ),
        (
            "a locale drops a placeholder",
            edit(&|c| c.others[0].entries[1].message = "Date limite".to_owned()),
        ),
        (
            "a locale renames a placeholder",
            edit(&|c| c.others[0].entries[1].message = "Date limite : {day}".to_owned()),
        ),
        (
            "a message outside the grammar",
            edit(&|c| c.default.entries[0].message = "Home {".to_owned()),
        ),
        (
            "an empty message",
            edit(&|c| c.default.entries[0].message = String::new()),
        ),
        (
            "a message with CR",
            edit(&|c| c.default.entries[0].message = "Ho\rme".to_owned()),
        ),
        (
            "a locale twice",
            edit(&|c| {
                let fr = c.others[0].clone();
                c.others.push(fr);
            }),
        ),
        (
            "a locale that is not a language tag",
            edit(&|c| c.others[0].locale = "f".to_owned()),
        ),
    ];
    let mut failures = Vec::new();
    for (name, c) in cases {
        assert!(c.check().is_err(), "the reference accepts {name}");
        match bind::catalogues(&c) {
            Ok(_) => failures.push(format!("built {name}")),
            Err(e) if !is_typed(&e) => failures.push(format!("{name}: {e}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// R-NF-04: a page renders its messages from its own locale's catalogue
/// and declares that locale in `lang`.
#[test]
fn r_nf_04_page_renders_in_its_locale() {
    let spec_cats = fixture();
    let cats = bind::catalogues(&spec_cats).unwrap_or_else(|e| panic!("{e}"));
    let home = Msg {
        kind: Kind::Label,
        id: "nav.home".to_owned(),
        args: Vec::new(),
    };
    for (locale, want) in [("en", "Home"), ("fr", "Accueil")] {
        let page = spec::page_with(
            locale,
            vec![spec::el("p", vec![], vec![Node::Msg(home.clone())])],
        );
        let r = bind::render(&page, &cats).unwrap_or_else(|e| panic!("{e}"));
        let tree = reference::parse(&r.bytes).unwrap_or_else(|e| panic!("{e}"));
        assert_eq!(tree.attrs.get("lang").map(String::as_str), Some(locale));
        assert_eq!(reference::texts(&tree), ["Page", want]);
    }
}

/// Overrides of some label ids of `cats`, each keeping the placeholder
/// names of the entry it replaces.
fn label_overrides(g: &mut Gen, cats: &CatSpec) -> Vec<Override> {
    let mut out = Vec::new();
    for locale in cats.locales() {
        let Some(cat) = cats.locale(locale) else {
            continue;
        };
        for e in &cat.entries {
            if e.kind == Kind::Label && g.bool() {
                let names = message::names(&message::parse(e.message.as_bytes()).unwrap());
                let names: Vec<&str> = names.iter().map(String::as_str).collect();
                out.push(Override {
                    locale: locale.to_owned(),
                    id: e.id.clone(),
                    message: format!("OVERRIDE {}", message_with(g, &names)),
                });
            }
        }
    }
    out
}

/// I-72, R-WL-05: an override replaces the text of the label it names, in
/// its locale, and nothing else. Approved wording resolves and renders to
/// its catalogue text whatever overrides exist.
#[test]
fn i72_overrides_reach_labels_only() {
    check("i72_overrides_reach_labels_only", |g| {
        let spec_cats = catalogue_set(g);
        let overrides = label_overrides(g, &spec_cats);
        let base = bind::catalogues(&spec_cats).map_err(|e| format!("refused: {e}"))?;
        let cats = bind::with_overrides(&base, &overrides).map_err(|e| format!("refused: {e}"))?;
        for locale in spec_cats.locales() {
            for e in &spec_cats.default.entries {
                let a = args_for(g, &spec_cats, &e.id);
                let source = overrides
                    .iter()
                    .find(|o| o.locale == locale && o.id == e.id)
                    .map(|o| o.message.clone())
                    .unwrap_or_else(|| {
                        spec_cats
                            .locale(locale)
                            .unwrap()
                            .get(&e.id)
                            .unwrap()
                            .message
                            .clone()
                    });
                let want = message::format(&message::parse(source.as_bytes())?, &a)?;
                let got = bind::resolve(&cats, locale, e.kind, &e.id, &a)
                    .map_err(|err| format!("{locale} {}: {err}", e.id))?;
                prop_assert_eq!(&got, &want, "{} {} ({:?})", locale, e.id, e.kind);
                if e.kind == Kind::Approved {
                    let msg = Msg {
                        kind: Kind::Approved,
                        id: e.id.clone(),
                        args: a.clone(),
                    };
                    let page =
                        spec::page_with(locale, vec![spec::el("p", vec![], vec![Node::Msg(msg)])]);
                    let r = bind::render(&page, &cats).map_err(|err| format!("render: {err}"))?;
                    let tree = reference::parse(&r.bytes)?;
                    let mut texts = vec!["Page".to_owned()];
                    if !want.is_empty() {
                        texts.push(want);
                    }
                    prop_assert_eq!(reference::texts(&tree), texts);
                }
            }
        }
        Ok(())
    });
}

/// I-72: an override of approved wording is refused, as are overrides of
/// unknown ids or locales, with bad messages, or with other placeholders.
#[test]
fn i72_override_of_approved_text_is_refused() {
    let base = bind::catalogues(&fixture()).unwrap_or_else(|e| panic!("{e}"));
    let ov = |locale: &str, id: &str, m: &str| Override {
        locale: locale.to_owned(),
        id: id.to_owned(),
        message: m.to_owned(),
    };
    let cases = [
        (
            "approved wording in the default locale",
            ov("en", "notice.synthetic", "Changed for {org}, {version}"),
        ),
        (
            "approved wording in another locale",
            ov("fr", "guide.synthetic", "Chang\u{e9} {date}"),
        ),
        ("an unknown id", ov("en", "no.such.id", "x")),
        ("an unknown locale", ov("de", "nav.home", "Start")),
        (
            "a message outside the grammar",
            ov("en", "nav.home", "Home }"),
        ),
        (
            "a dropped placeholder",
            ov("en", "call.deadline", "Deadline"),
        ),
        ("a new placeholder", ov("en", "nav.home", "Home {user}")),
    ];
    let mut failures = Vec::new();
    for (name, o) in cases {
        match bind::with_overrides(&base, &[o]) {
            Ok(_) => failures.push(format!("accepted {name}")),
            Err(e) if !is_typed(&e) => failures.push(format!("{name}: {e}")),
            Err(_) => {}
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// I-72: a `Label` cannot name approved wording and an `ApprovedText`
/// cannot name a label, in resolution, in text and in attributes.
#[test]
fn i72_kind_mismatch_is_refused() {
    let cats = bind::catalogues(&fixture()).unwrap_or_else(|e| panic!("{e}"));
    let mut failures = Vec::new();
    let deadline = args(&[("date", "1")]);
    let notice = args(&[("org", "o"), ("version", "1")]);
    let wrong = [
        (Kind::Approved, "call.deadline", deadline),
        (Kind::Label, "notice.synthetic", notice),
    ];
    for (kind, id, a) in wrong {
        match bind::resolve(&cats, "en", kind, id, &a) {
            Ok(s) => failures.push(format!("resolved {id} as {kind:?} to {s:?}")),
            Err(e) if !is_typed(&e) => failures.push(format!("{id}: {e}")),
            Err(_) => {}
        }
        let msg = Msg {
            kind,
            id: id.to_owned(),
            args: a,
        };
        let pages = [
            spec::page_with(
                "en",
                vec![spec::el("p", vec![], vec![Node::Msg(msg.clone())])],
            ),
            spec::page_with(
                "en",
                vec![spec::el("p", vec![("title", Attr::Msg(msg))], vec![])],
            ),
        ];
        for page in pages {
            match bind::render(&page, &cats) {
                Ok(_) => failures.push(format!("rendered {id} as {kind:?}")),
                Err(e) if !is_typed(&e) => failures.push(format!("{id}: {e}")),
                Err(_) => {}
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
