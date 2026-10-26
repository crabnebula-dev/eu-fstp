//! Currencies and their fixed scales (ADR-006).

use core::fmt;

/// A currency with a fixed number of minor digits.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Currency {
    /// Euro, two minor digits.
    Eur,
    /// ISO 4217 `XTS`, the code reserved for testing, with two minor digits.
    /// It exists only in unit tests, so the `CurrencyMismatch` paths have
    /// coverage. [`Currency::from_code`] never returns it.
    #[cfg(test)]
    Xts,
}

impl Currency {
    /// The ISO 4217 code, such as `"EUR"`.
    pub const fn code(self) -> &'static str {
        match self {
            Currency::Eur => "EUR",
            #[cfg(test)]
            Currency::Xts => "XTS",
        }
    }

    /// The number of minor digits, which is the fixed scale of every amount.
    pub const fn minor_digits(self) -> u8 {
        match self {
            Currency::Eur => 2,
            #[cfg(test)]
            Currency::Xts => 2,
        }
    }

    /// The currency for an exact ISO 4217 code. Case and spacing must match.
    pub fn from_code(code: &str) -> Result<Currency, CurrencyError> {
        match code {
            "EUR" => Ok(Currency::Eur),
            _ => Err(CurrencyError::Unknown),
        }
    }
}

/// A currency code that names no supported currency.
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum CurrencyError {
    /// The code is not a supported currency. The code itself is not kept.
    Unknown,
}

impl fmt::Display for CurrencyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CurrencyError::Unknown => f.write_str("unknown currency code"),
        }
    }
}

impl std::error::Error for CurrencyError {}
