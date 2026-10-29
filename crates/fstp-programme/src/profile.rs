//! Funder profiles (P-53).
//!
//! M4 ships the Horizon Europe profile only, with what SuperSAFE needs: its
//! P-53 reference, its currency, the placeholders a gap compiles to and the
//! flow-down obligation identifiers of I-49 (Q18, interim, pending Daniel).
//! M9 owns the profile bundle format.

use std::num::NonZeroU16;

use fstp_money::Currency;

use crate::kinds::{FlowDownObligation, ProfileRef};
use crate::spec::{FieldId, FieldValue, ProgrammeSpec};
use crate::value::Token;

/// The obligations every contract passes on under the Horizon Europe
/// profile (`02-domain/contracts.md`, I-49).
const HORIZON_EUROPE_FLOW_DOWN: &[FlowDownObligation] = FlowDownObligation::ALL;

/// Version 1, the only version of a shipped profile so far.
const VERSION_1: NonZeroU16 = NonZeroU16::MIN;

/// A funder profile that compiles programme specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfile {
    name: &'static str,
    version: NonZeroU16,
    currency: Currency,
    flow_down: &'static [FlowDownObligation],
}

impl FunderProfile {
    /// The Horizon Europe profile, version 1, in EUR.
    pub const fn horizon_europe() -> FunderProfile {
        FunderProfile {
            name: "horizon-europe",
            version: VERSION_1,
            currency: Currency::Eur,
            flow_down: HORIZON_EUROPE_FLOW_DOWN,
        }
    }

    /// The P-53 value that names this profile.
    pub fn reference(&self) -> ProfileRef {
        ProfileRef {
            profile: Token::trusted(self.name),
            version: self.version,
        }
    }

    /// The currency of every programme under this profile (ADR-006).
    pub const fn currency(&self) -> Currency {
        self.currency
    }

    /// The flow-down obligations every contract must carry (I-49). The
    /// creator's `FlowDownMissing` check compares the spec against it.
    pub const fn flow_down(&self) -> &'static [FlowDownObligation] {
        self.flow_down
    }

    /// The policy value a gap in `field` compiles to. P-53 compiles to this
    /// profile's reference. Every other gap gets a neutral placeholder that
    /// nobody chose, and the gap stays a validation failure (`FieldUnset`).
    pub fn placeholder(&self, field: FieldId, currency: Currency) -> Option<FieldValue> {
        match field {
            FieldId::P53 => Some(FieldValue::P53(self.reference())),
            other => FieldValue::placeholder(other, currency),
        }
    }

    /// A blank programme with this profile's defaults: every field unset
    /// except P-53, which names this profile (R-PG-02, blank start).
    pub fn blank(&self) -> ProgrammeSpec {
        let mut spec = ProgrammeSpec::empty(self.currency);
        spec.set(FieldValue::P53(self.reference()));
        spec
    }
}
