//! JSON codecs: amounts and percentages are always decimal strings.

use fstp_json::{FromJsonError, ToJson, Value};

use crate::amount::{Amount, NonNegAmount, PosAmount};
use crate::currency::Currency;
use crate::percent::Percent;

impl ToJson for Amount {
    /// Always a JSON string in the canonical ADR-006 spelling.
    ///
    /// A negative intermediate amount gives a string with a leading minus,
    /// which [`amount_from_json`] refuses. Records hold only non-negative
    /// amounts (ADR-006). A record field is a [`NonNegAmount`] or a
    /// [`PosAmount`], whose codecs keep the sign rule on both sides.
    fn to_json(&self) -> Value {
        Value::String(self.to_string())
    }
}

/// Decodes an amount in currency `c` from a JSON string.
///
/// JSON numbers are always rejected, because a number cannot keep the fixed
/// scale (ADR-006). Every other non-string value is rejected too. A string
/// is accepted exactly when [`Amount::parse`] accepts it. `FromJson` has no
/// currency context, so records decode their amounts through this function
/// with the programme currency.
///
/// The error names the kind of fault, never input content (R-NF-02).
pub fn amount_from_json(v: &Value, c: Currency) -> Result<Amount, FromJsonError> {
    match v {
        Value::String(s) => {
            Amount::parse(s, c).map_err(|e| FromJsonError::invalid(e.kind.message()))
        }
        other => Err(FromJsonError::wrong_type("a decimal amount string", other)),
    }
}

impl ToJson for NonNegAmount {
    /// Always a JSON string in the canonical ADR-006 spelling. The value is
    /// never negative, so [`nonneg_amount_from_json`] accepts every output.
    fn to_json(&self) -> Value {
        self.amount().to_json()
    }
}

impl ToJson for PosAmount {
    /// Always a JSON string in the canonical ADR-006 spelling. The value is
    /// above zero, so [`pos_amount_from_json`] accepts every output.
    fn to_json(&self) -> Value {
        self.amount().to_json()
    }
}

/// Decodes an amount of zero or more in currency `c` from a JSON string.
///
/// It accepts exactly what [`amount_from_json`] accepts. The ADR-006
/// grammar has no sign, so the `Negative` refusal is a second guard. The
/// error never holds input content (R-NF-02).
pub fn nonneg_amount_from_json(v: &Value, c: Currency) -> Result<NonNegAmount, FromJsonError> {
    let a = amount_from_json(v, c)?;
    NonNegAmount::new(a).map_err(|e| FromJsonError::invalid(e.message()))
}

/// Decodes an amount above zero in currency `c` from a JSON string.
///
/// It accepts what [`amount_from_json`] accepts, except `"0.00"`, which is
/// refused as a zero amount. The error never holds input content (R-NF-02).
pub fn pos_amount_from_json(v: &Value, c: Currency) -> Result<PosAmount, FromJsonError> {
    let a = amount_from_json(v, c)?;
    PosAmount::new(a).map_err(|e| FromJsonError::invalid(e.message()))
}

impl ToJson for Percent {
    /// Always a JSON string in the canonical two-decimal spelling, such as
    /// `"75.00"` (P-02).
    fn to_json(&self) -> Value {
        Value::String(self.to_string())
    }
}

/// Decodes a percentage from a JSON string, such as `"75.00"` (P-02).
///
/// JSON numbers and every other non-string value are rejected. A string is
/// accepted exactly when [`Percent::parse`] accepts it. The error never
/// holds input content (R-NF-02).
pub fn percent_from_json(v: &Value) -> Result<Percent, FromJsonError> {
    match v {
        Value::String(s) => Percent::parse(s).map_err(|e| FromJsonError::invalid(e.message())),
        other => Err(FromJsonError::wrong_type(
            "a decimal percentage string",
            other,
        )),
    }
}

#[cfg(test)]
mod tests {
    use fstp_json::{Number, ToJson, Value};

    use super::{
        amount_from_json, nonneg_amount_from_json, percent_from_json, pos_amount_from_json,
    };
    use crate::{Amount, Currency, NonNegAmount, Percent, PosAmount};

    /// P-02: a percentage travels as a two-decimal JSON string and decodes
    /// back. A JSON number is refused.
    #[test]
    fn p02_percent_json_is_a_canonical_string() {
        let p = Percent::parse("75.00").expect("canonical");
        let v = p.to_json();
        assert!(matches!(&v, Value::String(s) if s == "75.00"));
        assert_eq!(percent_from_json(&v), Ok(p));
        let number = Value::Number(Number::from_lexeme("75.00").expect("lexeme"));
        assert!(percent_from_json(&number).is_err());
        assert!(percent_from_json(&Value::String("75.0".to_owned())).is_err());
        assert!(percent_from_json(&Value::String("100.01".to_owned())).is_err());
    }

    /// ADR-006: a negative intermediate amount writes with a leading minus,
    /// and that string is refused on input.
    #[test]
    fn adr006_negative_amount_text_is_refused_on_input() {
        let a = Amount::from_minor(-123_450, Currency::Eur).expect("in range");
        assert_eq!(a.to_string(), "-1234.50");
        let v = a.to_json();
        assert!(matches!(&v, Value::String(s) if s == "-1234.50"));
        assert!(amount_from_json(&v, Currency::Eur).is_err());
    }

    /// ADR-006: a `NonNegAmount` writes a canonical string that its decoder
    /// accepts, zero included. A JSON number is refused.
    #[test]
    fn adr006_nonneg_amount_json_round_trips() {
        for minor in [0, 1, 123_450, Amount::MAX_ABS_MINOR] {
            let a = Amount::from_minor(minor, Currency::Eur).expect("in range");
            let n = NonNegAmount::new(a).expect("non-negative");
            let v = n.to_json();
            assert!(matches!(&v, Value::String(s) if *s == a.to_string()));
            assert_eq!(nonneg_amount_from_json(&v, Currency::Eur), Ok(n));
        }
        let number = Value::Number(Number::from_lexeme("1.00").expect("lexeme"));
        assert!(nonneg_amount_from_json(&number, Currency::Eur).is_err());
        let minus = Value::String("-1.00".to_owned());
        assert!(nonneg_amount_from_json(&minus, Currency::Eur).is_err());
    }

    /// ADR-006: a `PosAmount` writes a canonical string that its decoder
    /// accepts. The decoder refuses `"0.00"` and a negative spelling.
    #[test]
    fn adr006_pos_amount_json_round_trips_and_refuses_zero() {
        for minor in [1, 123_450, Amount::MAX_ABS_MINOR] {
            let a = Amount::from_minor(minor, Currency::Eur).expect("in range");
            let p = PosAmount::new(a).expect("positive");
            let v = p.to_json();
            assert!(matches!(&v, Value::String(s) if *s == a.to_string()));
            assert_eq!(pos_amount_from_json(&v, Currency::Eur), Ok(p));
        }
        let zero = Value::String("0.00".to_owned());
        assert!(pos_amount_from_json(&zero, Currency::Eur).is_err());
        let minus = Value::String("-1.00".to_owned());
        assert!(pos_amount_from_json(&minus, Currency::Eur).is_err());
    }
}
