//! R-NF-02: shipped crates write no free text to stdout or stderr.
//!
//! M3 design section 11.1 bans `println!` and `eprintln!` in shipped crates
//! through clippy. The workspace `clippy.toml` must list the print macros in
//! `disallowed-macros` and the functions they expand to in
//! `disallowed-methods`, together with the raw `std::io::stdout` and
//! `std::io::stderr` handles, so `writeln!` on a handle is caught too. The
//! clippy gate then fails on any use that a crate has not explicitly allowed.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;

const MACROS: &[&str] = &["std::println", "std::eprintln", "std::print", "std::eprint"];
const METHODS: &[&str] = &[
    "std::io::_print",
    "std::io::_eprint",
    "std::io::stdout",
    "std::io::stderr",
];

/// The text of the array that `key` is set to, from `[` to its `]`.
fn array_of<'a>(toml: &'a str, key: &str) -> Option<&'a str> {
    let line_start = toml.lines().find(|l| {
        let t = l.trim_start();
        t.starts_with(key) && t[key.len()..].trim_start().starts_with('=')
    })?;
    let start = toml.find(line_start)?;
    let open = start + toml[start..].find('[')?;
    let mut depth = 0usize;
    let mut in_str = false;
    for (i, c) in toml[open..].char_indices() {
        match c {
            '"' => in_str = !in_str,
            '[' if !in_str => depth += 1,
            ']' if !in_str => {
                depth -= 1;
                if depth == 0 {
                    return Some(&toml[open..=open + i]);
                }
            }
            _ => {}
        }
    }
    None
}

/// Entries of `want` that `array` does not name, as a string or as a
/// `path = ".."` table entry.
fn missing(array: Option<&str>, want: &[&'static str]) -> Vec<&'static str> {
    want.iter()
        .filter(|p| !array.is_some_and(|a| a.contains(&format!("\"{p}\""))))
        .copied()
        .collect()
}

fn workspace_clippy_toml() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../clippy.toml");
    std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

/// R-NF-02 (design section 11.1): the workspace clippy configuration bans
/// the print macros, the functions they expand to and the raw stdout and
/// stderr handles.
#[test]
fn r_nf_02_clippy_bans_print_macros_in_shipped_crates() {
    let toml = workspace_clippy_toml();
    let mut gaps = missing(array_of(&toml, "disallowed-macros"), MACROS);
    gaps.extend(missing(array_of(&toml, "disallowed-methods"), METHODS));
    assert!(gaps.is_empty(), "clippy.toml does not ban: {gaps:?}");
}

/// Teeth for the clippy check: a configuration with every entry passes, and
/// one with an entry removed is caught.
#[test]
fn r_nf_02_teeth_clippy_check_catches_a_missing_entry() {
    let full = r#"
allow-unwrap-in-tests = true
disallowed-macros = [
    { path = "std::println", reason = "R-NF-02" },
    { path = "std::eprintln", reason = "R-NF-02" },
    "std::print",
    { path = "std::eprint", reason = "R-NF-02: use [fstp-obs]" },
]
disallowed-methods = [
    { path = "std::io::_print", reason = "R-NF-02" },
    { path = "std::io::_eprint", reason = "R-NF-02" },
    { path = "std::io::stdout", reason = "R-NF-02" },
    "std::io::stderr",
]
"#;
    let short = full.replace("\"std::eprintln\"", "\"std::dbg\"");
    let full_gaps = missing(array_of(full, "disallowed-macros"), MACROS).len()
        + missing(array_of(full, "disallowed-methods"), METHODS).len();
    let short_gaps = missing(array_of(&short, "disallowed-macros"), MACROS);
    assert!(
        full_gaps == 0 && short_gaps == ["std::eprintln"],
        "full {full_gaps}, short {short_gaps:?}"
    );
}
