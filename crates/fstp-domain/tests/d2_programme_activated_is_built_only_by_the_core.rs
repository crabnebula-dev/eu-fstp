//! I-66 and I-67: `ProgrammeActivated` has private fields, so only the core guard and the record decoder build it (M4 design section 3.4, D2).
//!
//! D2 gives `Record::ProgrammeActivated` a payload with private fields.
//! Outside the crate it is read through accessors only, and the engine's
//! fold pairs it with the creator's approval (D2e). The name of a missing
//! constructor cannot be written without a compile failure, so each test
//! scans the crate source at run time, as `review_api_sufficiency` does.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

/// Every source file of the crate, concatenated in sorted path order.
fn all_src() -> Result<String, String> {
    fn walk(dir: &Path, out: &mut String) -> Result<(), String> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                out.push_str(&text);
                out.push('\n');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    walk(&src_dir(), &mut out)?;
    Ok(out)
}

/// The text of the struct declaration of `ty`, up to its closing brace.
fn struct_body<'a>(text: &'a str, ty: &str) -> Option<&'a str> {
    let head = format!("pub struct {ty} {{");
    let start = text.find(&head)?;
    let body = text.get(start.checked_add(head.len())?..)?;
    let end = body.find("\n}")?;
    body.get(..end)
}

/// D2: `ProgrammeActivated` is a struct whose fields are all private, so
/// no code outside the crate can state an approver or a builder set.
#[test]
fn d2_programme_activated_has_private_fields() {
    let text = all_src().unwrap_or_default();
    let Some(body) = struct_body(&text, "ProgrammeActivated") else {
        panic!("no `pub struct ProgrammeActivated {{` in the crate source");
    };
    let public: Vec<&str> = body
        .lines()
        .map(str::trim_start)
        .filter(|l| l.starts_with("pub ") || l.starts_with("pub("))
        .collect();
    assert!(
        public.is_empty(),
        "public fields of ProgrammeActivated: {public:?}"
    );
}

/// D2: no public function returns a `ProgrammeActivated`. The core guard
/// and the codec build it through crate-private code only.
#[test]
fn d2_programme_activated_has_no_public_constructor() {
    let text = all_src().unwrap_or_default();
    let public: Vec<&str> = text
        .lines()
        .map(str::trim_start)
        .filter(|l| {
            l.starts_with("pub fn")
                && (l.contains("-> ProgrammeActivated")
                    || l.contains("-> Result<ProgrammeActivated,")
                    || l.contains("-> Option<ProgrammeActivated>"))
        })
        .collect();
    assert!(public.is_empty(), "public constructors: {public:?}");
}
