//! Tests of the structural `SCHEMAS` and `VALIDATORS` that `gen-ts`
//! writes into `web/src/gen/api.ts` (M4 design sections 3.7 and 3.9,
//! ADR-014, ADR-006, TH-26, lane scope m4reg).
//!
//! Written by the m4reg test author before the generator emits them.
//! `web/test/support/contract.ts` states what the web side needs:
//! `SCHEMAS`, a table of `Schema` values by name, and `VALIDATORS`, one
//! function per name that accepts a value parsed from JSON exactly when
//! it fits the schema. The `validators` fuzz target of `web/fuzz` checks
//! that equivalence against an independent reference. These tests check
//! the Rust side: the table exists, uses only the contract's kinds, and
//! has an entry for every reply shape the API core serves today and for
//! each m4reg read, keyed by operation name.
//!
//! Interim reading of this lane: a reply shape is keyed by the name of
//! the operation whose `data` it describes, such as `calls.get`. The
//! generated text writes each key as a quoted string, as `ts_str` does.
//! The tests read the text with a small brace matcher and spell nothing
//! else of the layout.
//!
//! Scratch roots live under the system temporary directory and are
//! removed at the end of each test.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

const API_TS: &str = "web/src/gen/api.ts";

/// A fresh scratch root, removed when dropped.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "fstp-gen-ts-schemas-{}-{tag}-{n}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("web/src/gen"))
            .unwrap_or_else(|e| panic!("cannot create {}: {e}", dir.display()));
        Scratch(dir)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The text the generator writes.
fn generated() -> String {
    let root = Scratch::new("gen");
    let arg = root
        .path()
        .to_str()
        .unwrap_or_else(|| panic!("non-UTF-8 path"))
        .to_string();
    let out = Command::new(env!("CARGO_BIN_EXE_gen-ts"))
        .args(["--root", &arg])
        .output()
        .unwrap_or_else(|e| panic!("cannot run gen-ts: {e}"));
    assert_eq!(out.status.code(), Some(0), "gen-ts write exit status");
    let bytes = std::fs::read(root.path().join(API_TS))
        .unwrap_or_else(|e| panic!("gen-ts wrote no {API_TS}: {e}"));
    String::from_utf8(bytes).unwrap_or_else(|e| panic!("not UTF-8: {e}"))
}

/// The byte index just past the `}` that closes the `{` at `open`, with
/// braces inside string literals ignored.
fn close_of(text: &str, open: usize) -> Option<usize> {
    let bytes = text.as_bytes();
    let mut depth = 0usize;
    let mut quote: Option<u8> = None;
    let mut escaped = false;
    for (i, b) in bytes.iter().enumerate().skip(open) {
        if let Some(q) = quote {
            if escaped {
                escaped = false;
            } else if *b == b'\\' {
                escaped = true;
            } else if *b == q {
                quote = None;
            }
            continue;
        }
        match b {
            b'"' | b'\'' | b'`' => quote = Some(*b),
            b'{' => depth = depth.checked_add(1)?,
            b'}' => {
                depth = depth.checked_sub(1)?;
                if depth == 0 {
                    return i.checked_add(1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The object literal assigned to `export const SCHEMAS`, braces
/// included.
fn schemas_block(text: &str) -> &str {
    let at = text
        .find("export const SCHEMAS")
        .unwrap_or_else(|| panic!("{API_TS} exports no SCHEMAS (lane m4reg)"));
    let eq = text[at..]
        .find('=')
        .and_then(|i| at.checked_add(i))
        .unwrap_or_else(|| panic!("SCHEMAS has no initialiser"));
    let open = text[eq..]
        .find('{')
        .and_then(|i| eq.checked_add(i))
        .unwrap_or_else(|| panic!("SCHEMAS is not an object literal"));
    let close = close_of(text, open).unwrap_or_else(|| panic!("SCHEMAS is not closed"));
    &text[open..close]
}

/// The schema literal of `key` in the SCHEMAS block, braces included.
fn entry<'a>(block: &'a str, key: &str) -> Option<&'a str> {
    let quoted = format!("\"{key}\"");
    let mut from = 0usize;
    while let Some(i) = block[from..].find(&quoted) {
        let after = from.checked_add(i)?.checked_add(quoted.len())?;
        let rest = block[after..].trim_start();
        if let Some(value) = rest.strip_prefix(':') {
            let open = block
                .len()
                .checked_sub(value.len())?
                .checked_add(value.find('{')?)?;
            let close = close_of(block, open)?;
            return Some(&block[open..close]);
        }
        from = after;
    }
    None
}

/// `s` with every whitespace character and every double quote removed,
/// so `kind: "amount"` and `"kind":"amount"` read alike.
fn squeeze(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_whitespace() && *c != '"')
        .collect()
}

/// The reply shapes the API core serves today (`fstp_api_core::ReadModel`
/// and dispatch), by operation.
const SERVED_TODAY: [&str; 7] = [
    "pending.list",
    "calls.list_open",
    "calls.get",
    "proposal.list_own",
    "me.assignments",
    "me.sessions",
    "me.begin_verification",
];

/// The reads lane m4reg adds, whose read models it adds too.
const M4REG_READS: [&str; 6] = [
    "tenant.list_admins",
    "me.get_verification",
    "creator.list_programmes",
    "creator.list_templates",
    "people.get_invitation",
    "review.assignments",
];

/// The kinds of `Schema` in `web/test/support/contract.ts`.
const KINDS: [&str; 10] = [
    "string", "id", "amount", "bool", "int", "null", "enum", "array", "nullable", "object",
];

/// TH-26, ADR-014, design section 3.9: the generated file exports the
/// `Schema` type, the `SCHEMAS` table and the `VALIDATORS` table, which
/// `web/fuzz/validators.fuzz.ts` loads. Red until gen-ts emits them.
#[test]
fn th26_gen_ts_exports_schemas_and_validators() {
    let text = generated();
    for item in [
        "export type Schema",
        "export const SCHEMAS",
        "export const VALIDATORS",
    ] {
        assert!(text.contains(item), "{API_TS} lacks `{item}`");
    }
    let block = schemas_block(&text);
    assert!(
        block.contains("kind"),
        "SCHEMAS is empty, so the validators target checks nothing"
    );
}

/// TH-26, ADR-014, design sections 3.7 and 3.9: SCHEMAS has an entry for
/// every reply shape the API core serves today and for each m4reg read,
/// keyed by operation name. Each entry names a kind of the contract.
#[test]
fn th26_gen_ts_schemas_cover_every_served_reply_shape() {
    let text = generated();
    let block = schemas_block(&text);
    let missing: Vec<&str> = SERVED_TODAY
        .iter()
        .chain(M4REG_READS.iter())
        .copied()
        .filter(|k| entry(block, k).is_none_or(|e| !e.contains("kind")))
        .collect();
    assert!(missing.is_empty(), "SCHEMAS lacks entries for {missing:?}");
}

/// TH-26, design section 3.9: every schema uses only the kinds that
/// `web/test/support/contract.ts` defines, so the reference `fits` of
/// the validators target judges each one.
#[test]
fn th26_gen_ts_schemas_use_only_the_contract_kinds() {
    let text = generated();
    let flat = squeeze(schemas_block(&text));
    let mut seen = 0usize;
    let mut unknown: Vec<String> = Vec::new();
    for part in flat.split("kind:").skip(1) {
        let word: String = part
            .chars()
            .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
            .collect();
        seen = seen.saturating_add(1);
        if !KINDS.contains(&word.as_str()) {
            unknown.push(word);
        }
    }
    assert!(seen > 0, "SCHEMAS names no kind");
    assert!(
        unknown.is_empty(),
        "kinds outside the contract: {unknown:?}"
    );
}

/// ADR-006, design section 3.7: a call's budget travels as a decimal
/// string in the currency's fixed scale, so its schema is an `amount`,
/// never an `int` or a plain string.
#[test]
fn adr006_gen_ts_call_budget_is_an_amount() {
    let text = generated();
    let block = schemas_block(&text);
    for key in ["calls.get", "calls.list_open"] {
        let e = entry(block, key).unwrap_or_else(|| panic!("SCHEMAS has no {key}"));
        assert!(
            squeeze(e).contains("budget:{schema:{kind:amount}"),
            "{key}: budget is not an amount in {e}"
        );
    }
}

/// I-17, design section 3.6: no Judging read model carries an identity
/// field, so the reply shapes of the assignment reads hold no name or
/// email member.
#[test]
fn i17_gen_ts_assignment_reply_shapes_carry_no_identity_field() {
    let text = generated();
    let block = schemas_block(&text);
    for key in ["review.assignments", "me.assignments"] {
        let e = entry(block, key).unwrap_or_else(|| panic!("SCHEMAS has no {key}"));
        let flat = squeeze(e);
        for field in ["email", "name", "given_name", "family_name"] {
            assert!(
                !flat.contains(&format!("{field}:{{schema:")),
                "{key} carries `{field}`: {e}"
            );
        }
    }
}

/// I-86, design section 2.2 J0: the verification reply holds the state
/// only, `unverified`, `pending` or `verified`, and no other member, so no
/// vault fact beyond it reaches the page.
#[test]
fn i86_gen_ts_verification_reply_is_the_state_only() {
    let text = generated();
    let block = schemas_block(&text);
    let e = entry(block, "me.get_verification")
        .unwrap_or_else(|| panic!("SCHEMAS has no me.get_verification"));
    let flat = squeeze(e);
    assert_eq!(flat.matches(":{schema:").count(), 1, "one member only: {e}");
    assert!(flat.contains("status:{schema:{kind:enum"), "status: {e}");
    for v in ["unverified", "pending", "verified"] {
        assert!(flat.contains(v), "status value {v}: {e}");
    }
}

/// A self-test of the brace matcher the tests above read the text with:
/// it skips braces in strings and finds a quoted key's literal.
#[test]
fn schema_reader_finds_quoted_entries() {
    let block = r#"{ "a.b": { kind: "enum", values: ["}", "{"] }, "c": { kind: "id" } }"#;
    assert_eq!(
        entry(block, "a.b"),
        Some(r#"{ kind: "enum", values: ["}", "{"] }"#)
    );
    assert_eq!(entry(block, "c"), Some(r#"{ kind: "id" }"#));
    assert_eq!(entry(block, "d"), None);
    assert_eq!(squeeze(r#"{ "kind": "id" }"#), "{kind:id}");
}
