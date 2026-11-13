//! The body of a `KeyOp` record: one custody call of a chain's keystore,
//! with its request id (ADR-004 "Reconciliation", M3 design section 5.1).
//!
//! The keystore writes the body before the call (the start-up `unwrap`
//! of `S(e)` is the one exception). The custody backend logs the same
//! request id, so a reconciliation can match each backend usage entry
//! with its record (`fstp_custody::reconcile`).
//!
//! The body is the canonical JSON object
//!
//! ```text
//! {"call":<name>,"chain":<chain name>,"epoch":<u64>,"request":<32 lower hex>}
//! ```
//!
//! with the call names of [`KeyCall::name`] and the chain names of
//! [`Chain::name`]. [`decode`] takes exactly that spelling and no other,
//! so every accepted body re-encodes byte for byte. Its fuzz target is
//! `key_op_decode`.

use fstp_json::{Number, Object, Value};

use crate::hierarchy::{Chain, Epoch};

/// The most bytes [`decode`] reads. A body is under 160 bytes.
pub const MAX_KEY_OP_LEN: usize = 512;

/// A custody call, as the keystore names it in a `KeyOp` body.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KeyCall {
    /// `create_root`.
    CreateRoot,
    /// `wrap`.
    Wrap,
    /// `unwrap`.
    Unwrap,
    /// `destroy`.
    Destroy,
    /// `sign`.
    Sign,
}

impl KeyCall {
    /// Every call.
    pub const ALL: [KeyCall; 5] = [
        KeyCall::CreateRoot,
        KeyCall::Wrap,
        KeyCall::Unwrap,
        KeyCall::Destroy,
        KeyCall::Sign,
    ];

    /// The name in a `KeyOp` body.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            KeyCall::CreateRoot => "create_root",
            KeyCall::Wrap => "wrap",
            KeyCall::Unwrap => "unwrap",
            KeyCall::Destroy => "destroy",
            KeyCall::Sign => "sign",
        }
    }

    /// The call of a body name, if the name is known.
    #[must_use]
    pub fn from_name(name: &str) -> Option<KeyCall> {
        KeyCall::ALL.into_iter().find(|c| c.name() == name)
    }
}

/// One custody call of a keystore.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyOp {
    /// The call.
    pub call: KeyCall,
    /// The chain whose keystore made it.
    pub chain: Chain,
    /// The root epoch the call names.
    pub epoch: Epoch,
    /// The request id the call carries to custody.
    pub request: [u8; 16],
}

/// Why a `KeyOp` body was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyOpError {
    /// The body could not be encoded.
    Encode,
    /// The body is not the canonical form. It names the rule.
    Malformed(&'static str),
}

impl std::fmt::Display for KeyOpError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            KeyOpError::Encode => f.write_str("a KeyOp body could not be encoded"),
            KeyOpError::Malformed(rule) => write!(f, "a KeyOp body is malformed: {rule}"),
        }
    }
}

impl std::error::Error for KeyOpError {}

fn lower_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        for nibble in [b >> 4, b & 0x0f] {
            out.extend(char::from_digit(u32::from(nibble), 16));
        }
    }
    out
}

/// The value of a lower-case hex digit.
fn hex_digit(c: u8) -> Option<u8> {
    if c.is_ascii_uppercase() {
        return None;
    }
    char::from(c)
        .to_digit(16)
        .and_then(|d| u8::try_from(d).ok())
}

fn parse_request(text: &str) -> Option<[u8; 16]> {
    let bytes = text.as_bytes();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 16];
    for (slot, pair) in out.iter_mut().zip(bytes.chunks_exact(2)) {
        let (hi, lo) = (pair.first()?, pair.get(1)?);
        *slot = (hex_digit(*hi)? << 4) | hex_digit(*lo)?;
    }
    Some(out)
}

/// The canonical body of `op`.
///
/// # Errors
///
/// [`KeyOpError::Encode`] when the canonical writer refuses, which the
/// four fixed members never cause.
pub fn encode(op: &KeyOp) -> Result<Vec<u8>, KeyOpError> {
    let members = vec![
        ("call".to_owned(), Value::String(op.call.name().to_owned())),
        (
            "chain".to_owned(),
            Value::String(op.chain.name().to_owned()),
        ),
        ("epoch".to_owned(), Value::Number(Number::from(op.epoch.0))),
        ("request".to_owned(), Value::String(lower_hex(&op.request))),
    ];
    let obj = Object::from_members(members).map_err(|_| KeyOpError::Encode)?;
    fstp_json::to_canonical(&Value::Object(obj))
        .map(String::into_bytes)
        .map_err(|_| KeyOpError::Encode)
}

/// The `KeyOp` of a body in the canonical form of [`encode`].
///
/// # Errors
///
/// [`KeyOpError::Malformed`] for anything else: a body over
/// [`MAX_KEY_OP_LEN`], invalid JSON, another member set, an unknown call
/// or chain, an epoch that is no `u64`, a request id that is not 32 lower
/// hex digits, or any other spelling of the same object.
pub fn decode(body: &[u8]) -> Result<KeyOp, KeyOpError> {
    if body.len() > MAX_KEY_OP_LEN {
        return Err(KeyOpError::Malformed("too long"));
    }
    let v = fstp_json::parse(body).map_err(|_| KeyOpError::Malformed("not JSON"))?;
    let obj = v
        .as_object()
        .ok_or(KeyOpError::Malformed("not an object"))?;
    if obj.len() != 4 {
        return Err(KeyOpError::Malformed("not exactly four members"));
    }
    let text = |key: &'static str| {
        obj.get(key)
            .and_then(Value::as_str)
            .ok_or(KeyOpError::Malformed(key))
    };
    let call = KeyCall::from_name(text("call")?).ok_or(KeyOpError::Malformed("call"))?;
    let chain_name = text("chain")?;
    let chain = Chain::ALL
        .into_iter()
        .find(|c| c.name() == chain_name)
        .ok_or(KeyOpError::Malformed("chain"))?;
    let epoch = obj
        .get("epoch")
        .and_then(Value::as_u64)
        .ok_or(KeyOpError::Malformed("epoch"))?;
    let request = parse_request(text("request")?).ok_or(KeyOpError::Malformed("request"))?;
    let op = KeyOp {
        call,
        chain,
        epoch: Epoch(epoch),
        request,
    };
    if encode(&op)? != body {
        return Err(KeyOpError::Malformed("not the canonical spelling"));
    }
    Ok(op)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn op(call: KeyCall) -> KeyOp {
        KeyOp {
            call,
            chain: Chain::App,
            epoch: Epoch(7),
            request: [0xa5; 16],
        }
    }

    /// ADR-004 "Reconciliation": every call round-trips through its body,
    /// which carries the request id.
    #[test]
    fn adr004_key_op_body_round_trips_with_its_request_id() {
        for call in KeyCall::ALL {
            let body = encode(&op(call)).unwrap();
            assert_eq!(decode(&body), Ok(op(call)));
        }
        let body = encode(&op(KeyCall::CreateRoot)).unwrap();
        assert_eq!(
            String::from_utf8(body).unwrap(),
            "{\"call\":\"create_root\",\"chain\":\"app\",\"epoch\":7,\
             \"request\":\"a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5\"}"
        );
    }

    /// ADR-004 "Reconciliation": another spelling, an extra member, an
    /// unknown call or an upper-case request id is refused.
    #[test]
    fn adr004_key_op_body_takes_one_spelling_only() {
        let bad: [&[u8]; 6] = [
            b"{\"chain\":\"app\",\"call\":\"wrap\",\"epoch\":1,\"request\":\"00000000000000000000000000000000\"}",
            b"{\"call\":\"wrap\",\"chain\":\"app\",\"epoch\":1,\"extra\":1,\"request\":\"00000000000000000000000000000000\"}",
            b"{\"call\":\"rewrap\",\"chain\":\"app\",\"epoch\":1,\"request\":\"00000000000000000000000000000000\"}",
            b"{\"call\":\"wrap\",\"chain\":\"app\",\"epoch\":1,\"request\":\"0000000000000000000000000000000A\"}",
            b"{\"call\":\"wrap\",\"chain\":\"app\",\"epoch\":-1,\"request\":\"00000000000000000000000000000000\"}",
            b"{ \"call\":\"wrap\",\"chain\":\"app\",\"epoch\":1,\"request\":\"00000000000000000000000000000000\"}",
        ];
        for b in bad {
            assert!(decode(b).is_err(), "{}", String::from_utf8_lossy(b));
        }
    }
}
