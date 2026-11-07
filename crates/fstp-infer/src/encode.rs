//! The request encoder: the only module that builds a request body
//! (M7 design section 3.3, ADR-019).

use core::fmt;

use fstp_json::{Array, Decimal, Number, Object, Value};

use crate::data::DataPart;
use crate::instruction::Instruction;

/// The largest encoded request body, in bytes.
pub const MAX_REQUEST_BYTES: usize = 4 * 1024 * 1024;

/// The v1 output schema, sent as a request parameter, never as prompt text.
pub(crate) const FINDINGS_V1_SCHEMA: &str = include_str!("../schemas/v1/findings.json");

/// A model name from the tenant's inference record (P-21). It is tenant
/// configuration, never submission content.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ModelName(String);

impl ModelName {
    /// A model name of 1 to 128 bytes of ASCII letters, digits and
    /// `. _ - : / @ +`.
    ///
    /// # Errors
    ///
    /// Returns [`EncodeError::ModelName`] for any other text.
    pub fn new(name: &str) -> Result<ModelName, EncodeError> {
        let ok = !name.is_empty()
            && name.len() <= 128
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._-:/@+".contains(&b));
        if ok {
            Ok(ModelName(name.to_owned()))
        } else {
            Err(EncodeError::ModelName)
        }
    }

    /// The name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Decoding parameters, part of the `config_id` (I-11). No floats: the
/// temperature is held in thousandths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decoding {
    /// The most tokens of the reply.
    pub max_tokens: u32,
    /// The temperature in thousandths: 0 to 2000.
    pub temperature_milli: u16,
    /// The sampling seed.
    pub seed: u32,
}

/// A closed output schema, compiled in.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum OutputSchema {
    /// `schemas/v1/findings.json`.
    FindingsV1,
}

impl OutputSchema {
    /// The schema name sent with the request.
    pub const fn name(self) -> &'static str {
        match self {
            OutputSchema::FindingsV1 => "findings_v1",
        }
    }

    /// The schema text.
    pub const fn text(self) -> &'static str {
        match self {
            OutputSchema::FindingsV1 => FINDINGS_V1_SCHEMA,
        }
    }
}

/// One inference request before encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InferRequest {
    /// The model.
    pub model: ModelName,
    /// The decoding parameters.
    pub decoding: Decoding,
    /// The instruction: a pinned prompt and closed parameters.
    pub instruction: Instruction,
    /// The data parts, in order. At least one.
    pub data: Vec<DataPart>,
    /// The output schema, sent as a request parameter.
    pub schema: Option<OutputSchema>,
}

/// An encoded request body. Credentials are never part of it, so its
/// digest keys recordings (M7 design section 6).
#[derive(Clone, PartialEq, Eq)]
pub struct EncodedRequest {
    body: Vec<u8>,
}

impl fmt::Debug for EncodedRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EncodedRequest")
            .field("bytes", &self.body.len())
            .finish()
    }
}

impl EncodedRequest {
    /// The body bytes: canonical JSON (RFC 8785).
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// SHA-256 of the body.
    pub fn digest(&self) -> [u8; 32] {
        fstp_crypto::sha256(&self.body)
    }

    /// The digest in lowercase hex, the recording file stem.
    pub fn digest_hex(&self) -> String {
        hex(&self.digest())
    }
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

/// Why a request could not be encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EncodeError {
    /// The model name is not of the allowed form.
    ModelName,
    /// The request has no data part.
    NoData,
    /// The temperature is above 2000 thousandths.
    Temperature,
    /// The body would exceed [`MAX_REQUEST_BYTES`].
    TooLarge,
    /// A value had no canonical form.
    Canonical,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EncodeError::ModelName => "invalid model name",
            EncodeError::NoData => "no data part",
            EncodeError::Temperature => "temperature out of range",
            EncodeError::TooLarge => "request too large",
            EncodeError::Canonical => "no canonical form",
        };
        f.write_str(s)
    }
}

impl std::error::Error for EncodeError {}

/// Encodes `req` as one chat-completions request body.
///
/// # Errors
///
/// Returns an [`EncodeError`] when the request is out of bounds.
pub fn encode(req: &InferRequest) -> Result<EncodedRequest, EncodeError> {
    if req.data.is_empty() {
        return Err(EncodeError::NoData);
    }
    if req.decoding.temperature_milli > 2000 {
        return Err(EncodeError::Temperature);
    }

    // The data message: one JSON object whose parts hold each text as a
    // JSON string value. It is serialized on its own, then carried as the
    // string content of the user message.
    let parts: Array = req
        .data
        .iter()
        .map(|p| {
            let mut o = Object::new();
            o.insert("label", Value::from(p.label().as_str()));
            o.insert("text", Value::from(p.text().as_data()));
            Value::Object(o)
        })
        .collect();
    let mut data = Object::new();
    data.insert("parts", Value::Array(parts));
    let data_text = canonical(&Value::Object(data))?;

    let mut system = Object::new();
    system.insert("role", Value::from("system"));
    system.insert("content", Value::String(req.instruction.rendered()));
    let mut user = Object::new();
    user.insert("role", Value::from("user"));
    user.insert("content", Value::String(data_text));

    let mut body = Object::new();
    body.insert("model", Value::from(req.model.as_str()));
    body.insert(
        "messages",
        Value::Array(Array::from(vec![
            Value::Object(system),
            Value::Object(user),
        ])),
    );
    body.insert("max_tokens", integer(u64::from(req.decoding.max_tokens))?);
    body.insert(
        "temperature",
        Value::Number(Number::from_decimal(&Decimal::from_scaled_i128(
            i128::from(req.decoding.temperature_milli),
            3,
        ))),
    );
    body.insert("seed", integer(u64::from(req.decoding.seed))?);
    body.insert("stream", Value::Bool(false));
    if let Some(schema) = req.schema {
        let parsed = fstp_json::parse_str(schema.text()).map_err(|_| EncodeError::Canonical)?;
        let mut js = Object::new();
        js.insert("name", Value::from(schema.name()));
        js.insert("strict", Value::Bool(true));
        js.insert("schema", parsed);
        let mut rf = Object::new();
        rf.insert("type", Value::from("json_schema"));
        rf.insert("json_schema", Value::Object(js));
        body.insert("response_format", Value::Object(rf));
    }
    let text = canonical(&Value::Object(body))?;
    if text.len() > MAX_REQUEST_BYTES {
        return Err(EncodeError::TooLarge);
    }
    Ok(EncodedRequest {
        body: text.into_bytes(),
    })
}

fn canonical(v: &Value) -> Result<String, EncodeError> {
    fstp_json::to_canonical(v).map_err(|_| EncodeError::Canonical)
}

fn integer(n: u64) -> Result<Value, EncodeError> {
    Number::from_lexeme(&n.to_string())
        .map(Value::Number)
        .map_err(|_| EncodeError::Canonical)
}
