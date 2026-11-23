//! Funder profiles (P-53).
//!
//! M4 ships the Horizon Europe profile only, with what SuperSAFE needs: its
//! P-53 reference, its currency, the placeholders a gap compiles to and the
//! flow-down obligation identifiers of I-49 (Q18, interim, pending Daniel).
//! M9 owns the profile bundle format.
//!
//! Since 2026-11-23 (ADR-036 section 8, Daniel: "everything v2") a new
//! programme pins version 2, and a spec that still pins version 1 compiles
//! to version 2: the move is recorded in the next policy version. Version 2
//! keeps the outputs, fields and periods of version 1
//! (`fstp_report::profile::SUCCESSORS`).

use std::num::NonZeroU16;

use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_money::Currency;

use crate::kinds::{FlowDownObligation, ProfileRef};
use crate::spec::{FieldId, FieldValue, ProgrammeSpec};
use crate::value::{Codec, Token};

/// The obligations every contract passes on under the Horizon Europe
/// profile (`02-domain/contracts.md`, I-49).
const HORIZON_EUROPE_FLOW_DOWN: &[FlowDownObligation] = FlowDownObligation::ALL;

/// Version 1, which version 2 replaces (ADR-036 section 8).
const VERSION_1: NonZeroU16 = NonZeroU16::MIN;

/// Version 2, the current version: version 1 with the funding
/// acknowledgement approved (ADR-036; Daniel, 2026-11-22 and 2026-11-23).
const VERSION_2: NonZeroU16 = match NonZeroU16::new(2) {
    Some(v) => v,
    None => NonZeroU16::MIN,
};

/// A funder profile that compiles programme specs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct FunderProfile {
    name: &'static str,
    version: NonZeroU16,
    currency: Currency,
    flow_down: &'static [FlowDownObligation],
}

impl FunderProfile {
    /// The Horizon Europe profile at its current version, 2, in EUR. Every
    /// new programme pins it (ADR-036 section 8).
    pub const fn horizon_europe() -> FunderProfile {
        FunderProfile {
            name: "horizon-europe",
            version: VERSION_2,
            currency: Currency::Eur,
            flow_down: HORIZON_EUROPE_FLOW_DOWN,
        }
    }

    /// The Horizon Europe profile, version 1, which version 2 replaces. It
    /// never changes (P-53). Only older drafts and policies pin it.
    pub const fn horizon_europe_v1() -> FunderProfile {
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

    /// The P-53 value a compiled policy holds for this profile: the
    /// canonical opaque text of [`FunderProfile::reference`].
    pub fn policy_ref(&self) -> Option<FunderProfileRef> {
        OpaqueValue::from_value(&self.reference().encode())
            .ok()
            .map(FunderProfileRef)
    }

    /// The current profile for the P-53 value `r`: Horizon Europe version 2
    /// for a reference to version 1 or 2 (ADR-036 section 8). Any other
    /// value names no shipped profile.
    pub fn for_policy_ref(r: &FunderProfileRef) -> Option<FunderProfile> {
        let current = FunderProfile::horizon_europe();
        [FunderProfile::horizon_europe_v1(), current]
            .iter()
            .any(|p| p.policy_ref().as_ref() == Some(r))
            .then_some(current)
    }

    /// Whether this profile replaces the pin `r`: Horizon Europe version 2
    /// replaces version 1 (ADR-036 section 8). A spec that pins a replaced
    /// version compiles under this profile and moves to
    /// [`FunderProfile::reference`].
    pub fn replaces(&self, r: &ProfileRef) -> bool {
        self.name == "horizon-europe"
            && self.version == VERSION_2
            && r.profile.as_str() == self.name
            && r.version == VERSION_1
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
