//! Helpers shared by the M3 `fstp-crypto` tests (lane W1h, test agent).
//!
//! Nothing here calls `fstp-crypto`. The helpers decode hex, probe trait
//! implementations at compile time and scan source files.

#![allow(
    dead_code,
    unreachable_pub,
    unused_macros,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; each test binary uses a subset"
)]

pub mod hybrid_vectors;

use std::fs;
use std::path::{Path, PathBuf};

/// Decodes hex, ignoring every byte that is not a hex digit.
pub fn hex(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
    assert_eq!(clean.len() % 2, 0, "odd hex length");
    clean
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).expect("ascii");
            u8::from_str_radix(text, 16).expect("hex digit")
        })
        .collect()
}

/// Decodes hex into a fixed-size array.
pub fn arr<const N: usize>(s: &str) -> [u8; N] {
    let v = hex(s);
    assert_eq!(v.len(), N, "hex length");
    let mut out = [0u8; N];
    out.copy_from_slice(&v);
    out
}

/// Whether the type implements the trait, decided at compile time.
///
/// An inherent associated constant takes precedence over a trait one.
/// When the inherent impl's bound does not hold, the trait constant
/// applies. So the value is `true` exactly when the bound holds, and the
/// test still compiles when it does not.
macro_rules! impls {
    ($t:ty: $($tr:tt)+) => {{
        #[allow(dead_code)]
        trait DoesNotImpl {
            const IMPLS: bool = false;
        }
        #[allow(dead_code)]
        impl<T: ?Sized> DoesNotImpl for T {}
        struct Wrapper<T: ?Sized>(::core::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $($tr)+> Wrapper<T> {
            const IMPLS: bool = true;
        }
        <Wrapper<$t>>::IMPLS
    }};
}
#[allow(unused_imports)]
pub(crate) use impls;

/// The repository root, two levels above this crate.
pub fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

/// Every `.rs` file under `dir`, recursively, sorted.
pub fn rust_files(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    walk(dir, &mut out);
    out.sort();
    out
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            walk(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// Removes `//` line comments and `/* */` block comments, so a scan sees
/// code only. String literals are kept, and a `//` inside a string is
/// treated as text. Raw strings are not special-cased, which only makes a
/// scan stricter.
pub fn strip_comments(text: &str) -> String {
    let b = text.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c as char);
            if c == b'\\' && i + 1 < b.len() {
                out.push(b[i + 1] as char);
                i += 2;
                continue;
            }
            if c == b'"' {
                in_str = false;
            }
            i += 1;
        } else if c == b'\'' && b.get(i + 2) == Some(&b'\'') {
            // A one-byte character literal such as '"'.
            out.extend(b[i..i + 3].iter().map(|&x| x as char));
            i += 3;
        } else if c == b'\'' && b.get(i + 1) == Some(&b'\\') && b.get(i + 3) == Some(&b'\'') {
            // An escaped character literal such as '\\' or '\''.
            out.extend(b[i..i + 4].iter().map(|&x| x as char));
            i += 4;
        } else if c == b'"' {
            in_str = true;
            out.push('"');
            i += 1;
        } else if c == b'/' && b.get(i + 1) == Some(&b'/') {
            while i < b.len() && b[i] != b'\n' {
                i += 1;
            }
        } else if c == b'/' && b.get(i + 1) == Some(&b'*') {
            i += 2;
            while i + 1 < b.len() && !(b[i] == b'*' && b[i + 1] == b'/') {
                i += 1;
            }
            i += 2;
        } else {
            out.push(c as char);
            i += 1;
        }
    }
    out
}

/// The lines of `text`, comments removed, that contain `needle`, as
/// `(1-based line, line)`.
pub fn lines_naming(text: &str, needle: &str) -> Vec<(usize, String)> {
    strip_comments(text)
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(needle))
        .map(|(n, l)| (n + 1, l.trim().to_string()))
        .collect()
}

/// The path of `p` relative to the repository root, with `/` separators.
pub fn rel(p: &Path) -> String {
    p.strip_prefix(repo_root())
        .unwrap_or(p)
        .to_string_lossy()
        .replace('\\', "/")
}
