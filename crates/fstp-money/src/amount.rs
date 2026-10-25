//! Exact amounts in minor units (ADR-006).

use core::cmp::Ordering;
use core::fmt;

use crate::currency::Currency;

/// Exact signed amount in minor units of one currency.
///
/// No `PartialOrd` or `Ord`: use [`Amount::cmp_same`]. No float conversion
/// exists. No operator traits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Amount {
    minor: i64,
    currency: Currency,
}

impl Amount {
    /// 18 digits. `i64::MIN` is never representable, so negation is total.
    pub const MAX_ABS_MINOR: i64 = 999_999_999_999_999_999;

    /// The amount of `minor` units, or `OutOfRange` beyond [`Amount::MAX_ABS_MINOR`].
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn from_minor(minor: i64, c: Currency) -> Result<Amount, MoneyError> {
        let _ = (minor, c);
        Err(MoneyError::NotImplemented)
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
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn checked_add(self, o: Amount) -> Result<Amount, MoneyError> {
        let _ = (self, o);
        Err(MoneyError::NotImplemented)
    }

    /// `self - o`, refusing mixed currencies and results out of range.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn checked_sub(self, o: Amount) -> Result<Amount, MoneyError> {
        let _ = (self, o);
        Err(MoneyError::NotImplemented)
    }

    /// The negated amount. Total, because the range is symmetric.
    ///
    /// Stub: returns `self` unchanged until lane W1a.
    #[allow(
        clippy::should_implement_trait,
        reason = "Amount has no operator traits by design (m2-design section 2.3)"
    )]
    pub fn neg(self) -> Amount {
        self
    }

    /// Compares two amounts of the same currency, refusing mixed currencies.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn cmp_same(self, o: Amount) -> Result<Ordering, MoneyError> {
        let _ = (self, o);
        Err(MoneyError::NotImplemented)
    }

    /// Parses the canonical ADR-006 spelling in currency `c`.
    ///
    /// For EUR the grammar is `-?(0|[1-9][0-9]*)\.[0-9]{2}`, excluding
    /// `-0.00`. Any other spelling is rejected, never normalised.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn parse(text: &str, c: Currency) -> Result<Amount, AmountParseError> {
        let _ = (text, c);
        Err(AmountParseError {
            offset: 0,
            kind: AmountParseErrorKind::NotImplemented,
        })
    }
}

impl fmt::Display for Amount {
    /// Writes the canonical ADR-006 spelling.
    ///
    /// Stub: writes the minor units as a plain integer until lane W1a.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.minor)
    }
}

/// The checked sum of `it` in currency `c`. The empty sum is zero.
///
/// Stub: returns `NotImplemented` until lane W1a.
pub fn checked_sum(
    c: Currency,
    it: impl IntoIterator<Item = Amount>,
) -> Result<Amount, MoneyError> {
    let _ = (c, it.into_iter());
    Err(MoneyError::NotImplemented)
}

/// Zero or more. Grant amounts, P-04, P-05, budgets, deductions, sums.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NonNegAmount(Amount);

impl NonNegAmount {
    /// Wraps `a`, refusing a negative amount.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn new(a: Amount) -> Result<NonNegAmount, MoneyError> {
        let _ = a;
        Err(MoneyError::NotImplemented)
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
    /// Wraps `a`, refusing zero and negative amounts.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn new(a: Amount) -> Result<PosAmount, MoneyError> {
        let _ = a;
        Err(MoneyError::NotImplemented)
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
    /// The range from `min` to `max`, refusing mixed currencies and `min > max`.
    ///
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn new(min: NonNegAmount, max: NonNegAmount) -> Result<AmountRange, MoneyError> {
        let _ = (min, max);
        Err(MoneyError::NotImplemented)
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
    /// Stub: returns `NotImplemented` until lane W1a.
    pub fn contains(&self, a: NonNegAmount) -> Result<bool, MoneyError> {
        let _ = (self, a);
        Err(MoneyError::NotImplemented)
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
    /// A value outside the allowed range.
    OutOfRange,
    /// Temporary: the operation is still a W0 stub. Lane W1a removes this
    /// variant when it replaces the stub bodies.
    NotImplemented,
}

impl fmt::Display for MoneyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            MoneyError::CurrencyMismatch => "currency mismatch",
            MoneyError::Overflow => "amount overflow",
            MoneyError::Negative => "negative amount",
            MoneyError::Zero => "zero amount",
            MoneyError::OutOfRange => "amount out of range",
            MoneyError::NotImplemented => "not implemented",
        })
    }
}

impl std::error::Error for MoneyError {}

/// Why a text is not a canonical amount.
///
/// Byte offset and kind only, never input content (R-NF-02).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AmountParseError {
    /// Byte offset of the first offending byte.
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
    /// A byte that the grammar does not allow at this position.
    UnexpectedByte,
    /// A leading zero before other integer digits.
    LeadingZero,
    /// The number of fraction digits differs from the currency's scale.
    WrongScale,
    /// The spelling `-0.00`, which ADR-006 rejects.
    NegativeZero,
    /// The value is beyond [`Amount::MAX_ABS_MINOR`].
    OutOfRange,
    /// Temporary: parsing is still a W0 stub. Lane W1a removes this variant
    /// when it replaces the stub bodies.
    NotImplemented,
}

impl fmt::Display for AmountParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let what = match self.kind {
            AmountParseErrorKind::Empty => "empty amount",
            AmountParseErrorKind::UnexpectedByte => "unexpected byte",
            AmountParseErrorKind::LeadingZero => "leading zero",
            AmountParseErrorKind::WrongScale => "wrong number of fraction digits",
            AmountParseErrorKind::NegativeZero => "negative zero",
            AmountParseErrorKind::OutOfRange => "amount out of range",
            AmountParseErrorKind::NotImplemented => "not implemented",
        };
        write!(f, "{what} at byte {}", self.offset)
    }
}

impl std::error::Error for AmountParseError {}
