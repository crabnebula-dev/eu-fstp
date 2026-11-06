//! The programme as data (M4 design section 3.1).
//!
//! A [`ProgrammeSpec`] is one programme as the creator captures it, in the
//! ten creator steps of `SPEC/02-domain/programme-creator.md`. People are
//! never part of it (I-73).
//!
//! - [`FIELDS`] names every field once, with its step, the parameters it
//!   sets, its kind and the rules that bound it. Every programme-level
//!   `CATALOGUE` entry has exactly one field.
//! - [`decode_spec`] and [`encode_spec`] are the strict JSON form.
//!   [`decode_field_value`] and [`encode_field_value`] decode one field.
//!   Unknown members are refused, and amounts travel only as ADR-006
//!   strings.
//! - [`compile`] turns a spec into an M2 policy version and the programme
//!   artefacts, deterministically. [`decompile`] is its exact inverse on
//!   accepted specs. Gaps survive both ways.
//! - [`FunderProfile::horizon_europe`] is the only profile in M4.
//! - [`supersafe_fixture`] and [`shipped_templates`] hold SuperSAFE.
//! - [`impact`] answers R-PG-04: which calls a change affects.
//!   [`programme_effects`] names what a change does beyond any call.
//!
//! Interim readings, each pending Daniel, are marked where they are built:
//! the JSON encodings of opaque values, the artefact fields the Guide binds
//! and their encodings, the placement of parameters no creator step names
//! (Q36), the synthetic placeholders and the impact effects (Q37, D12).

#![deny(
    clippy::float_arithmetic,
    clippy::float_cmp,
    clippy::cast_precision_loss,
    clippy::arithmetic_side_effects
)]

mod compile;
mod impact;
pub mod kinds;
mod profile;
mod spec;
mod template;
pub mod value;

pub use compile::{
    CompileError, CompileIds, Compiled, ProgrammeArtefacts, compile, decompile, opaque_text,
    policy_spec,
};
pub use impact::{
    CallFacts, CallImpact, CorrigendumNeed, ImpactEffect, ImpactError, ProgrammeEffect,
    PublishedLimits, affected, affected_calls, call_facts, impact, impact_on, programme_effects,
};
pub use profile::FunderProfile;
pub use spec::{
    CommsStep, ContractStep, DecodeError, EligibilityStep, EvaluationStep, FIELDS, Field, FieldId,
    FieldKind, FieldSpec, FieldValue, FunderStep, IdentityStep, MoneyStep, PeoplePolicyStep,
    ProgrammeSpec, SpecSchema, Step, SupportStep, WhatWeFundStep, decode_field_value,
    decode_field_value_in, decode_spec, encode_field_value, encode_spec,
};
pub use template::{
    Fixture, Publisher, SUPERSAFE_FIXTURE, SUPERSAFE_TEMPLATE, Template, TemplateId,
    decode_fixture, shipped_templates, supersafe_fixture, template_text,
};
pub use value::{INLINE_TEXT, Narrative, StoredText};
