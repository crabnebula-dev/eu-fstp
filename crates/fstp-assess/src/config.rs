//! The `config_id` derivation (M7 design section 2, reading 2; I-11,
//! R-LA-05).
//!
//! The id is the first 16 bytes of a labelled SHA-256 (aws-lc-rs through
//! `fstp-crypto`) over the canonical JSON of the provider, the model, the
//! decoding parameters, the prompt set digest, the rubric digest and the
//! call's P-01. It is derived at publication, once per P-21 model.

use core::fmt;

use fstp_domain::id::LlmConfigId;
use fstp_domain::scoring::Criteria;
use fstp_infer::{Decoding, ModelName};
use fstp_json::{Array, Number, Object, Value};

use crate::rubric::Rubric;

/// The inference provider of a configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Provider {
    /// The in-memory synthetic model. Never reported as an LLM result.
    Synthetic,
    /// An endpoint speaking the chat-completions JSON shape (ADR-019).
    ChatCompletions,
}

impl Provider {
    /// The provider as the derivation spells it.
    pub const fn as_str(self) -> &'static str {
        match self {
            Provider::Synthetic => "synthetic",
            Provider::ChatCompletions => "chat-completions",
        }
    }
}

/// Every pinned input of one configuration.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigInput<'a> {
    /// The provider.
    pub provider: Provider,
    /// The model of P-21.
    pub model: &'a ModelName,
    /// The decoding parameters.
    pub decoding: Decoding,
    /// The prompt set digest, from [`fstp_infer::prompt_set_digest`].
    pub prompt_set: [u8; 32],
    /// The pinned rubric.
    pub rubric: &'a Rubric,
    /// The call's frozen P-01.
    pub criteria: &'a Criteria,
}

impl<'a> ConfigInput<'a> {
    /// The input with the compiled prompt set.
    pub fn pinned(
        provider: Provider,
        model: &'a ModelName,
        decoding: Decoding,
        rubric: &'a Rubric,
        criteria: &'a Criteria,
    ) -> ConfigInput<'a> {
        ConfigInput {
            provider,
            model,
            decoding,
            prompt_set: fstp_infer::prompt_set_digest(),
            rubric,
            criteria,
        }
    }
}

/// The derivation input had no canonical form.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConfigError;

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("config_id input has no canonical form")
    }
}

impl std::error::Error for ConfigError {}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn num(n: u64) -> Value {
    Value::Number(Number::from(n))
}

/// The configuration id of `input`.
///
/// # Errors
///
/// Returns [`ConfigError`] when the input has no canonical JSON form.
pub fn config_id(input: &ConfigInput<'_>) -> Result<LlmConfigId, ConfigError> {
    let mut decoding = Object::new();
    decoding.insert("max_tokens", num(u64::from(input.decoding.max_tokens)));
    decoding.insert(
        "temperature_milli",
        num(u64::from(input.decoding.temperature_milli)),
    );
    decoding.insert("seed", num(u64::from(input.decoding.seed)));

    let criteria: Array = input
        .criteria
        .items()
        .iter()
        .map(|c| {
            let mut o = Object::new();
            // u128 ids travel as decimal strings (RFC 8785 exactness).
            o.insert("id", Value::String(c.id.raw().to_string()));
            o.insert("weight", num(u64::from(c.weight.get())));
            Value::Object(o)
        })
        .collect();
    let mut p01 = Object::new();
    p01.insert(
        "scale_max",
        num(u64::from(input.criteria.scale_max().get())),
    );
    p01.insert("criteria", Value::Array(criteria));

    let mut top = Object::new();
    top.insert("v", Value::from("fstp-assess/config-id/v1"));
    top.insert("provider", Value::from(input.provider.as_str()));
    top.insert("model", Value::from(input.model.as_str()));
    top.insert("decoding", Value::Object(decoding));
    top.insert(
        "prompt_set_version",
        Value::from(fstp_infer::PROMPT_SET_VERSION),
    );
    top.insert("prompt_set", Value::String(hex(&input.prompt_set)));
    top.insert("rubric_version", Value::from(input.rubric.version()));
    top.insert("rubric", Value::String(hex(&input.rubric.digest())));
    top.insert("p01", Value::Object(p01));
    let canonical = fstp_json::to_canonical(&Value::Object(top)).map_err(|_| ConfigError)?;

    let mut h = fstp_crypto::Sha256::new();
    h.update(b"fstp-assess/config-id\0");
    h.update(canonical.as_bytes());
    let digest = h.finish();
    let mut first = [0_u8; 16];
    for (d, s) in first.iter_mut().zip(digest.iter()) {
        *d = *s;
    }
    Ok(LlmConfigId::from_raw(u128::from_be_bytes(first)))
}
