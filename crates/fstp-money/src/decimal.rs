//! The fixed-scale decimal grammar shared by amounts and percentages.
//!
//! The grammar for scale `d > 0` is `(0|[1-9][0-9]*)\.[0-9]{d}`. For scale
//! zero it is `0|[1-9][0-9]*` with no full stop. No sign, whitespace,
//! separator, exponent or non-ASCII digit is allowed. Any other spelling is
//! refused, never normalised (ADR-006).
//!
//! The whole text is checked against the grammar before its value is
//! compared with the bound. So a range error is reported only for a text
//! that is otherwise canonical.

/// What is wrong with a text. Mirrors the public error kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Fault {
    /// The text is empty.
    Empty,
    /// A byte that the grammar does not allow at this position.
    UnexpectedByte,
    /// A leading zero before other integer digits.
    LeadingZero,
    /// The number of fraction digits differs from the scale.
    WrongScale,
    /// The spelling is canonical, but the value is above the bound.
    OutOfRange,
}

/// A refusal: the byte offset and the fault, never input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Refusal {
    pub(crate) offset: usize,
    pub(crate) fault: Fault,
}

const fn refuse(offset: usize, fault: Fault) -> Refusal {
    Refusal { offset, fault }
}

/// The number of leading ASCII digits of `bytes`.
fn digit_run(bytes: &[u8]) -> usize {
    bytes
        .iter()
        .position(|b| !b.is_ascii_digit())
        .unwrap_or(bytes.len())
}

/// Parses `text` in the grammar of `scale` fraction digits.
///
/// Returns the value in units of the last fraction digit, at most `max`.
pub(crate) fn parse_fixed(text: &[u8], scale: u8, max: u64) -> Result<u64, Refusal> {
    let scale = usize::from(scale);
    let Some(&first) = text.first() else {
        return Err(refuse(0, Fault::Empty));
    };
    if !first.is_ascii_digit() {
        return Err(refuse(0, Fault::UnexpectedByte));
    }
    let int_len = digit_run(text);
    if first == b'0' && int_len > 1 {
        return Err(refuse(1, Fault::LeadingZero));
    }
    let (int, rest) = text.split_at(int_len);
    let frac = if scale == 0 {
        if !rest.is_empty() {
            return Err(refuse(int_len, Fault::UnexpectedByte));
        }
        rest
    } else {
        let Some((&sep, frac)) = rest.split_first() else {
            return Err(refuse(int_len, Fault::WrongScale));
        };
        if sep != b'.' {
            return Err(refuse(int_len, Fault::UnexpectedByte));
        }
        let frac_start = int_len.saturating_add(1);
        let frac_len = digit_run(frac);
        let after = frac_start.saturating_add(frac_len);
        if frac_len > scale {
            return Err(refuse(frac_start.saturating_add(scale), Fault::WrongScale));
        }
        if frac_len < scale {
            let fault = if after == text.len() {
                Fault::WrongScale
            } else {
                Fault::UnexpectedByte
            };
            return Err(refuse(after, fault));
        }
        if after != text.len() {
            return Err(refuse(after, Fault::UnexpectedByte));
        }
        frac
    };
    let mut value: u64 = 0;
    for &b in int.iter().chain(frac) {
        let digit = u64::from(b.saturating_sub(b'0'));
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or(refuse(0, Fault::OutOfRange))?;
    }
    if value > max {
        return Err(refuse(0, Fault::OutOfRange));
    }
    Ok(value)
}

/// `10^scale`, or `None` when it does not fit in `u64`.
pub(crate) fn scale_factor(scale: u8) -> Option<u64> {
    10u64.checked_pow(u32::from(scale))
}
