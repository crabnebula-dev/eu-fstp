//! JSON codec for amounts: always an ADR-006 decimal string.

use fstp_json::{FromJsonError, ToJson, Value};

use crate::amount::Amount;
use crate::currency::Currency;

impl ToJson for Amount {
    /// Always a JSON string in the canonical ADR-006 spelling.
    fn to_json(&self) -> Value {
        Value::String(self.to_string())
    }
}

/// Decodes an amount in currency `c` from a JSON string.
///
/// JSON numbers are always rejected, because a number cannot keep the fixed
/// scale (ADR-006). `FromJson` has no currency context, so records decode
/// their amounts through this function with the programme currency.
///
/// Stub: rejects every value until lane W1a.
pub fn amount_from_json(v: &Value, c: Currency) -> Result<Amount, FromJsonError> {
    let _ = (v, c);
    Err(FromJsonError::invalid("amount decoding is not implemented"))
}
