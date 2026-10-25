//! Exact money amounts, percentages and ratios (ADR-006).
//!
//! - [`Amount`] is an exact signed amount in minor units of one [`Currency`].
//!   It has no `PartialOrd`, no `Ord`, no operator traits and no float
//!   conversion. Comparisons go through [`Amount::cmp_same`], which refuses
//!   mixed currencies. A negative value exists only as an intermediate
//!   result of checked arithmetic, because ADR-006 amounts are never
//!   negative.
//! - [`NonNegAmount`] and [`PosAmount`] hold the sign rules of grant amounts,
//!   budgets and payment lines. [`AmountRange`] is an inclusive range.
//! - [`Percent`] is a percentage from 0.00 to 100.00 in basis points.
//!   [`Ratio`] is an exact non-negative rational for the I-08 comparison.
//! - Amounts travel in JSON as ADR-006 decimal strings in the currency's
//!   fixed scale, never as JSON numbers. Percentages travel as two-decimal
//!   strings such as `"75.00"`.
//!
//! The text grammar has no sign: `(0|[1-9][0-9]*)\.[0-9]{2}` for EUR and for
//! percentages. Any other spelling is rejected, never normalised.

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod amount;
mod currency;
mod decimal;
mod json;
mod percent;
mod ratio;

pub use amount::{
    Amount, AmountParseError, AmountParseErrorKind, AmountRange, MoneyError, NonNegAmount,
    PosAmount, checked_sum,
};
pub use currency::{Currency, CurrencyError};
pub use json::{
    amount_from_json, nonneg_amount_from_json, percent_from_json, pos_amount_from_json,
};
pub use percent::{Percent, PercentParseError};
pub use ratio::Ratio;
