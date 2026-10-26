//! The policy version codec (design sections 2.4 and 7, I-12, I-23).
//!
//! The decoder is structural. It keeps every value the type can hold,
//! including values that policy validation refuses, so a stored version
//! always decodes to the version that was appended. The version names its
//! own currency, and every amount inside it decodes with that currency
//! (ADR-006).

use fstp_json::{FromJson, FromJsonError, Object, ToJson, Value};
use fstp_money::Currency;

use super::wire::{Cx, Fields, Flat, R, Wire, flat_struct, flat_wire};
use crate::policy::{FrozenValues, LiveValues, PolicyVersion};

flat_struct!(FrozenValues {
    p01,
    p02,
    p03,
    p04,
    p07,
    p09,
    p10,
    p11,
    p14,
    p15,
    p16,
    p17,
    p21,
    p24,
    p26,
    p39,
    p53,
    p77,
    opaque,
});

flat_struct!(LiveValues {
    p05,
    p12,
    p13,
    p38,
    p56,
    p58,
    opaque
});

impl Flat for PolicyVersion {
    const NAMES: &'static [&'static str] =
        &["id", "programme", "parent", "currency", "frozen", "live"];

    fn put_into(&self, o: &mut Object) {
        let _ = o.insert("id", self.id.put());
        let _ = o.insert("programme", self.programme.put());
        let _ = o.insert("parent", self.parent.put());
        let _ = o.insert("currency", self.currency.put());
        let _ = o.insert("frozen", self.frozen.put());
        let _ = o.insert("live", self.live.put());
    }

    fn take_from(f: &Fields<'_>, _cx: Cx) -> R<Self> {
        let currency: Currency = f.get("currency", Cx::NONE)?;
        let cx = Cx::with(currency);
        Ok(PolicyVersion {
            id: f.get("id", cx)?,
            programme: f.get("programme", cx)?,
            parent: f.get("parent", cx)?,
            currency,
            frozen: f.get("frozen", cx)?,
            live: f.get("live", cx)?,
        })
    }

    fn flat_currency(&self) -> Option<Currency> {
        Some(self.currency)
    }
}

flat_wire!(PolicyVersion);

/// The JSON form of a policy version: one object with the version's ids,
/// its currency code and its frozen and live parameters.
impl ToJson for PolicyVersion {
    fn to_json(&self) -> Value {
        self.put()
    }
}

/// Decodes a policy version. Unknown and missing members are refused, and
/// every value has one spelling. Errors hold no input content (R-NF-02).
impl FromJson for PolicyVersion {
    fn from_json(value: &Value) -> Result<PolicyVersion, FromJsonError> {
        <PolicyVersion as Wire>::take(value, Cx::NONE)
    }
}
