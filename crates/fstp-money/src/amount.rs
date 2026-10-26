//! Exact amounts in minor units (ADR-006).

use core::cmp::Ordering;
use core::fmt;

use crate::currency::Currency;
use crate::decimal::{Fault, parse_fixed, scale_factor};

/// Exact signed amount in minor units of one currency.
///
/// No `PartialOrd` or `Ord`: use [`Amount::cmp_same`]. No float conversion
/// exists. No operator traits.
///
/// ADR-006 states that a recorded amount is never negative. A negative
/// `Amount` exists only as an intermediate value of checked arithmetic, such
/// as a difference. Records hold [`NonNegAmount`] or [`PosAmount`]. The text
/// form of a negative amount has a leading minus, which [`Amount::parse`]
/// refuses.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amount {
    minor: i64,
    currency: Currency,
}

impl Amount {
    /// 18 digits. `i64::MIN` is never representable, so negation is total.
    pub const MAX_ABS_MINOR: i64 = 999_999_999_999_999_999;

    /// The amount of `minor` units, or `OutOfRange` beyond [`Amount::MAX_ABS_MINOR`].
    pub fn from_minor(minor: i64, c: Currency) -> Result<Amount, MoneyError> {
        if minor.unsigned_abs() > Amount::MAX_ABS_MINOR.unsigned_abs() {
            return Err(MoneyError::OutOfRange);
        }
        Ok(Amount { minor, currency: c })
    }

    /// Zero in currency `c`.
    pub fn zero(c: Currency) -> Amount {
        Amount {
            minor: 0,
            currency: c,
        }
    }

    /// The value in minor units.
    pub fn minor(self) -> i64 {
        self.minor
    }

    /// The currency.
    pub fn currency(self) -> Currency {
        self.currency
    }

    /// `self + o`, refusing mixed currencies and results out of range.
    pub fn checked_add(self, o: Amount) -> Result<Amount, MoneyError> {
        let c = self.same_currency(o)?;
        let sum = self
            .minor
            .checked_add(o.minor)
            .ok_or(MoneyError::Overflow)?;
        Amount::from_minor(sum, c).map_err(|_| MoneyError::Overflow)
    }

    /// `self - o`, refusing mixed currencies and results out of range.
    pub fn checked_sub(self, o: Amount) -> Result<Amount, MoneyError> {
        let c = self.same_currency(o)?;
        let diff = self
            .minor
            .checked_sub(o.minor)
            .ok_or(MoneyError::Overflow)?;
        Amount::from_minor(diff, c).map_err(|_| MoneyError::Overflow)
    }

    /// The negated amount. Total, because the range is symmetric.
    #[allow(
        clippy::should_implement_trait,
        reason = "Amount has no operator traits by design (m2-design section 2.3)"
    )]
    pub fn neg(self) -> Amount {
        // The range is symmetric and excludes `i64::MIN`, so this is exact.
        Amount {
            minor: self.minor.saturating_neg(),
            currency: self.currency,
        }
    }

    /// Compares two amounts of the same currency, refusing mixed currencies.
    pub fn cmp_same(self, o: Amount) -> Result<Ordering, MoneyError> {
        self.same_currency(o)?;
        Ok(self.minor.cmp(&o.minor))
    }

    /// Parses the canonical ADR-006 spelling in currency `c`.
    ///
    /// For EUR the grammar is `(0|[1-9][0-9]*)\.[0-9]{2}`, with the value at
    /// most [`Amount::MAX_ABS_MINOR`]. An amount is never negative and
    /// carries no sign, so `-` and `+` are refused at byte 0. Any other
    /// spelling is rejected, never normalised.
    ///
    /// A range error is reported only for a text that is otherwise
    /// canonical. The error holds a byte offset and a kind, never input
    /// content (R-NF-02).
    pub fn parse(text: &str, c: Currency) -> Result<Amount, AmountParseError> {
        let max = Amount::MAX_ABS_MINOR.unsigned_abs();
        let value =
            parse_fixed(text.as_bytes(), c.minor_digits(), max).map_err(|r| AmountParseError {
                offset: r.offset,
                kind: match r.fault {
                    Fault::Empty => AmountParseErrorKind::Empty,
                    Fault::UnexpectedByte => AmountParseErrorKind::UnexpectedByte,
                    Fault::LeadingZero => AmountParseErrorKind::LeadingZero,
                    Fault::WrongScale => AmountParseErrorKind::WrongScale,
                    Fault::OutOfRange => AmountParseErrorKind::OutOfRange,
                },
            })?;
        let minor = i64::try_from(value).map_err(|_| AmountParseError {
            offset: 0,
            kind: AmountParseErrorKind::OutOfRange,
        })?;
        Amount::from_minor(minor, c).map_err(|_| AmountParseError {
            offset: 0,
            kind: AmountParseErrorKind::OutOfRange,
        })
    }

    /// The common currency of `self` and `o`, or `CurrencyMismatch`.
    fn same_currency(self, o: Amount) -> Result<Currency, MoneyError> {
        if self.currency == o.currency {
            Ok(self.currency)
        } else {
            Err(MoneyError::CurrencyMismatch)
        }
    }
}

impl fmt::Display for Amount {
    /// Writes the canonical ADR-006 spelling, such as `1234.50` for EUR.
    ///
    /// A negative intermediate amount is written with a leading minus. That
    /// text is not an ADR-006 spelling, and [`Amount::parse`] refuses it.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scale = self.currency.minor_digits();
        let abs = self.minor.unsigned_abs();
        let sign = if self.minor < 0 { "-" } else { "" };
        match scale_factor(scale) {
            Some(factor) if scale > 0 => {
                let int = abs.checked_div(factor).unwrap_or(0);
                let frac = abs.checked_rem(factor).unwrap_or(0);
                let width = usize::from(scale);
                write!(f, "{sign}{int}.{frac:0width$}")
            }
            _ => write!(f, "{sign}{abs}"),
        }
    }
}

/// The checked sum of `it` in currency `c`. The empty sum is zero.
///
/// Every term must be in currency `c`, or the sum is `CurrencyMismatch`.
/// The sum is exact and independent of term order: a partial sum beyond
/// [`Amount::MAX_ABS_MINOR`] is accepted when the total is back in range.
/// A total out of range is `Overflow`.
pub fn checked_sum(
    c: Currency,
    it: impl IntoIterator<Item = Amount>,
) -> Result<Amount, MoneyError> {
    let mut total: i128 = 0;
    for a in it {
        if a.currency != c {
            return Err(MoneyError::CurrencyMismatch);
        }
        total = total
            .checked_add(i128::from(a.minor))
            .ok_or(MoneyError::Overflow)?;
    }
    let minor = i64::try_from(total).map_err(|_| MoneyError::Overflow)?;
    Amount::from_minor(minor, c).map_err(|_| MoneyError::Overflow)
}

/// Zero or more. Grant amounts, P-04, P-05, budgets, deductions, sums.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonNegAmount(Amount);

impl NonNegAmount {
    /// Wraps `a`, refusing a negative amount with `Negative`.
    pub fn new(a: Amount) -> Result<NonNegAmount, MoneyError> {
        if a.minor < 0 {
            Err(MoneyError::Negative)
        } else {
            Ok(NonNegAmount(a))
        }
    }

    /// The wrapped amount.
    pub fn amount(self) -> Amount {
        self.0
    }
}

/// Above zero. Milestone amounts and payment lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PosAmount(Amount);

impl PosAmount {
    /// Wraps `a`, refusing zero with `Zero` and a negative amount with
    /// `Negative`.
    pub fn new(a: Amount) -> Result<PosAmount, MoneyError> {
        match a.minor.cmp(&0) {
            Ordering::Greater => Ok(PosAmount(a)),
            Ordering::Equal => Err(MoneyError::Zero),
            Ordering::Less => Err(MoneyError::Negative),
        }
    }

    /// The wrapped amount.
    pub fn amount(self) -> Amount {
        self.0
    }
}

/// Same currency, `min <= max`, checked at construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AmountRange {
    min: NonNegAmount,
    max: NonNegAmount,
}

impl AmountRange {
    /// The range from `min` to `max`.
    ///
    /// Refuses mixed currencies with `CurrencyMismatch`, and `min > max`
    /// with `OutOfRange`. A range with `min == max` holds one amount.
    pub fn new(min: NonNegAmount, max: NonNegAmount) -> Result<AmountRange, MoneyError> {
        match min.0.cmp_same(max.0)? {
            Ordering::Greater => Err(MoneyError::OutOfRange),
            Ordering::Less | Ordering::Equal => Ok(AmountRange { min, max }),
        }
    }

    /// The lower bound.
    pub fn min(&self) -> NonNegAmount {
        self.min
    }

    /// The upper bound.
    pub fn max(&self) -> NonNegAmount {
        self.max
    }

    /// Whether `a` lies in the range, inclusive at both ends (Q7).
    ///
    /// Refuses an amount in another currency with `CurrencyMismatch`.
    pub fn contains(&self, a: NonNegAmount) -> Result<bool, MoneyError> {
        let above_min = a.0.cmp_same(self.min.0)? != Ordering::Less;
        let below_max = a.0.cmp_same(self.max.0)? != Ordering::Greater;
        Ok(above_min && below_max)
    }
}

/// Why an amount operation was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MoneyError {
    /// The operands have different currencies.
    CurrencyMismatch,
    /// The result is beyond [`Amount::MAX_ABS_MINOR`].
    Overflow,
    /// A negative amount where zero or more is required.
    Negative,
    /// Zero where an amount above zero is required.
    Zero,
    /// A value outside the allowed range, or a range whose minimum is above
    /// its maximum.
    OutOfRange,
}

impl MoneyError {
    /// A fixed message for the error. It never holds input content.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            MoneyError::CurrencyMismatch => "currency mismatch",
            MoneyError::Overflow => "amount overflow",
            MoneyError::Negative => "negative amount",
            MoneyError::Zero => "zero amount",
            MoneyError::OutOfRange => "amount out of range",
        }
    }
}

impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.message())
    }
}

impl std::error::Error for MoneyError {}

/// Why a text is not a canonical amount.
///
/// Byte offset and kind only, never input content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AmountParseError {
    /// Byte offset of the first offending byte. It is 0 for `Empty` and
    /// `OutOfRange`.
    pub offset: usize,
    /// What is wrong.
    pub kind: AmountParseErrorKind,
}

/// The kind of an [`AmountParseError`].
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AmountParseErrorKind {
    /// The text is empty.
    Empty,
    /// A byte that the grammar does not allow at this position. This covers
    /// any sign, whitespace, separator, exponent and non-ASCII byte.
    UnexpectedByte,
    /// A leading zero before other integer digits.
    LeadingZero,
    /// The number of fraction digits differs from the currency's scale.
    WrongScale,
    /// The spelling is canonical, but the value is beyond
    /// [`Amount::MAX_ABS_MINOR`].
    OutOfRange,
}

impl fmt::Display for AmountParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} at byte {}", self.kind.message(), self.offset)
    }
}

impl AmountParseErrorKind {
    /// A fixed message for the kind. It never holds input content.
    pub(crate) const fn message(self) -> &'static str {
        match self {
            AmountParseErrorKind::Empty => "empty amount",
            AmountParseErrorKind::UnexpectedByte => "unexpected byte",
            AmountParseErrorKind::LeadingZero => "leading zero",
            AmountParseErrorKind::WrongScale => "wrong number of fraction digits",
            AmountParseErrorKind::OutOfRange => "amount out of range",
        }
    }
}

impl std::error::Error for AmountParseError {}

#[cfg(test)]
mod tests {
    use core::cmp::Ordering;

    use super::{Amount, AmountRange, MoneyError, NonNegAmount, checked_sum};
    use crate::Currency;

    fn eur(minor: i64) -> Amount {
        Amount::from_minor(minor, Currency::Eur).expect("in range")
    }

    fn xts(minor: i64) -> Amount {
        Amount::from_minor(minor, Currency::Xts).expect("in range")
    }

    fn nonneg(a: Amount) -> NonNegAmount {
        NonNegAmount::new(a).expect("non-negative")
    }

    /// ADR-006, design 2.3: `cmp_same` refuses mixed currencies, even for
    /// equal minor values, and still compares within one currency.
    #[test]
    fn adr006_cmp_same_refuses_currency_mismatch() {
        assert_eq!(
            eur(100).cmp_same(xts(100)),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(xts(5).cmp_same(eur(7)), Err(MoneyError::CurrencyMismatch));
        assert_eq!(xts(5).cmp_same(xts(7)), Ok(Ordering::Less));
    }

    /// ADR-006: checked addition and subtraction refuse mixed currencies.
    /// The currency check comes before the overflow check.
    #[test]
    fn adr006_checked_add_and_sub_refuse_currency_mismatch() {
        let max = eur(Amount::MAX_ABS_MINOR);
        assert_eq!(
            eur(1).checked_add(xts(1)),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(max.checked_add(xts(1)), Err(MoneyError::CurrencyMismatch));
        assert_eq!(
            eur(1).checked_sub(xts(1)),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(
            max.neg().checked_sub(xts(1)),
            Err(MoneyError::CurrencyMismatch)
        );
    }

    /// ADR-006: `checked_sum` refuses any term in another currency, in any
    /// position, including a sum in the test currency with one EUR term.
    #[test]
    fn adr006_checked_sum_refuses_currency_mismatch() {
        assert_eq!(
            checked_sum(Currency::Eur, [xts(1)]),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(
            checked_sum(Currency::Eur, [eur(1), eur(2), xts(3)]),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(
            checked_sum(Currency::Xts, [xts(1), eur(2)]),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(checked_sum(Currency::Xts, [xts(1), xts(2)]), Ok(xts(3)));
    }

    /// ADR-006, design 2.3: `AmountRange::new` and `contains` refuse mixed
    /// currencies.
    #[test]
    fn adr006_amount_range_refuses_currency_mismatch() {
        assert_eq!(
            AmountRange::new(nonneg(eur(0)), nonneg(xts(10))),
            Err(MoneyError::CurrencyMismatch)
        );
        let r = AmountRange::new(nonneg(eur(0)), nonneg(eur(10))).expect("valid range");
        assert_eq!(
            r.contains(nonneg(xts(5))),
            Err(MoneyError::CurrencyMismatch)
        );
        assert_eq!(r.contains(nonneg(eur(5))), Ok(true));
    }
}
