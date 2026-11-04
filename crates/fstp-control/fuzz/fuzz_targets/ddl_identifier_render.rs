//! Fuzz target `ddl_identifier_render` of `fstp-control` (TH-26, H-05,
//! I-82, ADR-011, M3 design section 15).
//!
//! Design checks: identifiers outside the grammar refused; rendered DDL
//! never contains input outside it.
//!
//! The grammar is `^[cv]_[0-9a-f]{32}$` (design section 4.1, ADR-011). On
//! every input, as UTF-8 text when it is valid and as lossy text always:
//!
//! - a rendered name is in the grammar, and the output is exactly that
//!   name in double quotes, so no other byte reaches DDL;
//! - a name outside the grammar is refused.
//!
//! Random bytes rarely spell a grammar name, so the target also builds one
//! from the first 17 input bytes and requires that it renders.

#![no_main]

use fstp_control::pgagent::render_ddl_identifier;
use libfuzzer_sys::fuzz_target;

fn in_grammar(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() == 34
        && matches!(b.first(), Some(b'c' | b'v'))
        && b.get(1) == Some(&b'_')
        && b.get(2..)
            .is_some_and(|hex| hex.iter().all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f')))
}

fn check(name: &str) {
    match render_ddl_identifier(name) {
        Ok(out) => {
            assert!(in_grammar(name), "rendered {name:?} as {out:?}");
            assert_eq!(out, format!("\"{name}\""));
        }
        Err(e) => {
            assert!(!in_grammar(name), "refused {name:?}: {e}");
            assert!(!format!("{e}").is_empty());
        }
    }
}

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        check(text);
    }
    check(&String::from_utf8_lossy(data));
    if let Some((first, rest)) = data.split_first()
        && let Some(cell) = rest.get(..16)
    {
        let prefix = if first & 1 == 0 { 'c' } else { 'v' };
        let hex: String = cell.iter().map(|b| format!("{b:02x}")).collect();
        let name = format!("{prefix}_{hex}");
        match render_ddl_identifier(&name) {
            Ok(out) => assert_eq!(out, format!("\"{name}\"")),
            Err(e) => panic!("refused the grammar name {name}: {e}"),
        }
    }
});
