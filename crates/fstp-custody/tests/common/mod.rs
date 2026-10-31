//! Helpers shared by the `fstp-custody` crate tests (lane W2f, test
//! author).
//!
//! [`Fail`] separates a refusal the crate means from a W0 stub that
//! refuses everything with `NotImplemented`. A refusal test passes only
//! on [`Fail::Refused`]. The trait probe [`impls!`] reads `true` exactly
//! when a bound holds, and still compiles when it does not, so a type
//! that gains `Clone` or `Debug` fails a test rather than the build.

#![allow(
    dead_code,
    unreachable_pub,
    unused_macros,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test helpers; each test binary uses a subset"
)]

/// Why a call did not succeed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Fail {
    /// A W0 stub refused with `NotImplemented`, or a test-side seam stands
    /// in for a call the stub lacks. Never a pass for a refusal test.
    Seam(String),
    /// The crate refused. The error's `Debug` and `Display` forms.
    Refused {
        /// The `Debug` form.
        debug: String,
        /// The `Display` form.
        display: String,
    },
}

impl std::fmt::Display for Fail {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Fail::Seam(s) => write!(f, "seam: {s}"),
            Fail::Refused { debug, .. } => write!(f, "refused: {debug}"),
        }
    }
}

impl From<Fail> for String {
    fn from(f: Fail) -> String {
        f.to_string()
    }
}

/// Sorts an error of the crate. Every W0 stub error is a `NotImplemented`
/// variant, so its `Debug` form names it. Any other error is a refusal.
pub fn classify<E: std::fmt::Debug + std::fmt::Display>(e: E) -> Fail {
    let debug = format!("{e:?}");
    if debug.starts_with("NotImplemented(") {
        Fail::Seam(debug)
    } else {
        Fail::Refused {
            debug,
            display: e.to_string(),
        }
    }
}

/// Passes only when `r` is a real refusal, and returns its two forms.
pub fn expect_refused<T: std::fmt::Debug>(
    r: Result<T, Fail>,
    what: &str,
) -> Result<(String, String), String> {
    match r {
        Err(Fail::Refused { debug, display }) => Ok((debug, display)),
        Err(Fail::Seam(s)) => Err(format!("{what}: seam: {s}")),
        Ok(v) => Err(format!("{what}: accepted {v:?}")),
    }
}

/// Lower-case hex of `bytes`.
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Upper-case hex of `bytes`.
pub fn hex_upper(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02X}")).collect()
}

/// Base64 of `bytes` in the standard or the URL alphabet, without
/// padding. Test-only, for canary searches.
pub fn base64(bytes: &[u8], url: bool) -> String {
    let table: &[u8; 64] = if url {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    } else {
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    };
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = chunk.len() + 1;
        for i in 0..chars {
            let ix = (n >> (18 - 6 * i)) & 0x3f;
            out.push(char::from(table[ix as usize]));
        }
    }
    out
}

/// Every spelling of `canary` a display could leak: hex in both cases and
/// base64 in both alphabets.
pub fn spellings(canary: &[u8]) -> Vec<String> {
    vec![
        hex(canary),
        hex_upper(canary),
        base64(canary, false),
        base64(canary, true),
    ]
}

/// Whether `text` holds any spelling of `canary`, or its raw bytes.
pub fn leaks(text: &str, canary: &[u8]) -> bool {
    spellings(canary).iter().any(|s| text.contains(s.as_str()))
        || text
            .as_bytes()
            .windows(canary.len().max(1))
            .any(|w| w == canary)
}

/// Reads `true` exactly when `$t` implements every bound, at compile
/// time, and compiles either way.
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
