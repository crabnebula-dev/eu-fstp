//! Codecs of auth records, commands, session cookies, tokens and operator
//! tickets (design sections 5.1 and 15, TH-26, H-05). Each decoder is
//! fuzzed.
//!
//! - **Tokens and cookies** are byte forms of constant length. A token is
//!   32 random bytes (ADR-008 "Constants"). A cookie value is the 16-byte
//!   cell id followed by the token (ADR-008 "Sessions", B11). Any text
//!   armour of a URL or a cookie header belongs to the route layer.
//! - **Records and commands** are RFC 8785 text, as the M2 envelope is
//!   (ADR-007). Every object has a `type` member and exactly its schema's
//!   members. Ids are canonical decimal strings, and byte strings are
//!   lowercase hexadecimal of their exact length. A decoder accepts only
//!   the canonical text, so every value has one spelling and every
//!   accepted input re-encodes byte for byte. A credential's public key
//!   is the hexadecimal of its canonical COSE bytes ([`cose_key_bytes`]),
//!   which `fstp_webauthn::parse_cose_key` must accept.
//! - **Operator tickets** are `case || staff_1 || staff_2 || signature`,
//!   with a composite signature of fixed length.
//!
//! Errors carry kinds and schema member names only, never input content
//! (R-NF-02). No decode path panics, and every allocation is bounded by
//! the input length or by a fixed limit.

use std::fmt;

use fstp_crypto::composite::SIGNATURE_LEN;
use fstp_crypto::constant_time_eq;
use fstp_domain::id::AccountId;
use fstp_json::{FromJson, FromJsonError, Object, ParseLimits, ToJson, Value};
use fstp_webauthn::CoseKey;

use crate::recovery::{OperatorTicket, RecoveryPath, StaffRef, TICKET_MESSAGE_LEN};
use crate::{AuthCommand, AuthRecord};

/// The length of a token (ADR-008 "Constants").
pub const TOKEN_LEN: usize = 32;
/// The length of a cell id.
pub const CELL_ID_LEN: usize = 16;
/// The length of a session cookie value: cell id, then token.
pub const COOKIE_LEN: usize = CELL_ID_LEN + TOKEN_LEN;
/// The length of an operator ticket: its signed part, then the composite
/// signature.
pub const TICKET_LEN: usize = TICKET_MESSAGE_LEN + SIGNATURE_LEN;
/// The longest credential id (WebAuthn Level 2 section 5.8.3).
pub const MAX_CREDENTIAL_LEN: usize = 1023;
/// The longest canonical COSE key that `fstp_webauthn::parse_cose_key`
/// admits: an RS256 key with a 1024-byte modulus and a 4-byte exponent.
/// The map head, labels, `kty` and `alg` take 12 bytes, and the two byte
/// string heads take 4 more.
pub const MAX_PUBLIC_KEY_LEN: usize = 1041;
/// The longest encoded record or command. A credential id of
/// [`MAX_CREDENTIAL_LEN`] bytes is 2046 hexadecimal characters, a key of
/// [`MAX_PUBLIC_KEY_LEN`] bytes is 2082, and the other members take less
/// than 400 bytes.
pub const MAX_ENCODED_LEN: usize = 8192;

/// Why bytes did not decode, or a value did not encode. No variant
/// carries input content.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodecError {
    /// The input has another length than the form's constant length.
    Length,
    /// The input is empty or longer than [`MAX_ENCODED_LEN`].
    Size,
    /// The input is not JSON within the codec's limits.
    Json,
    /// The input is JSON but not its RFC 8785 canonical text.
    NotCanonical,
    /// The value does not fit the schema. It names the schema member, or
    /// `type` for an unknown variant.
    Schema(&'static str),
    /// The cookie names another cell (B11).
    OtherCell,
}

/// A session cookie value: the cell id, then the token (ADR-008).
///
/// The W0 field names are kept, so callers written against the stub
/// still compile. `session` holds the cell id, and `tag` holds the token.
/// [`SessionCookie::cell`] and [`SessionCookie::token`] name them.
///
/// `Debug` prints the cell id and redacts the token. Equality compares the
/// token in constant time.
#[derive(Clone, Eq)]
pub struct SessionCookie {
    /// The cell id.
    pub session: [u8; 16],
    /// The token.
    pub tag: [u8; 32],
}

impl SessionCookie {
    /// The cookie of `cell` and `token`.
    pub const fn new(cell: [u8; 16], token: Token) -> SessionCookie {
        SessionCookie {
            session: cell,
            tag: token.0,
        }
    }

    /// The cell id.
    pub const fn cell(&self) -> [u8; 16] {
        self.session
    }

    /// The token.
    pub const fn token(&self) -> Token {
        Token(self.tag)
    }
}

impl PartialEq for SessionCookie {
    fn eq(&self, other: &SessionCookie) -> bool {
        let token = constant_time_eq(&self.tag, &other.tag);
        self.session == other.session && token
    }
}

impl fmt::Debug for SessionCookie {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCookie")
            .field("cell", &self.session)
            .field("token", &Token(self.tag))
            .finish()
    }
}

/// A one-time or session token, constant length.
///
/// `Debug` redacts the bytes, so a log line or a fuzz report never shows
/// a secret. Equality runs in constant time. A lookup should still use
/// the stored digest ([`crate::ceremony::token_digest`]), never the token.
#[derive(Clone, Copy, Eq)]
pub struct Token(pub [u8; 32]);

impl PartialEq for Token {
    fn eq(&self, other: &Token) -> bool {
        constant_time_eq(&self.0, &other.0)
    }
}

impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token(<redacted>)")
    }
}

/// Decodes a token: exactly 32 bytes. Fuzzed (`token_decode`).
pub fn decode_token(bytes: &[u8]) -> Result<Token, CodecError> {
    <[u8; TOKEN_LEN]>::try_from(bytes)
        .map(Token)
        .map_err(|_| CodecError::Length)
}

/// Encodes a token: its 32 bytes.
pub fn encode_token(t: &Token) -> [u8; TOKEN_LEN] {
    t.0
}

/// Decodes a session cookie value: exactly 48 bytes, the cell id then the
/// token. Fuzzed (`session_cookie_decode`).
pub fn decode_session_cookie(bytes: &[u8]) -> Result<SessionCookie, CodecError> {
    if bytes.len() != COOKIE_LEN {
        return Err(CodecError::Length);
    }
    let (cell, token) = bytes.split_at(CELL_ID_LEN);
    let cell = <[u8; CELL_ID_LEN]>::try_from(cell).map_err(|_| CodecError::Length)?;
    let token = <[u8; TOKEN_LEN]>::try_from(token).map_err(|_| CodecError::Length)?;
    Ok(SessionCookie {
        session: cell,
        tag: token,
    })
}

/// Decodes a session cookie value for the cell `cell`. Another cell's
/// cookie is refused before any lookup (B11).
pub fn decode_session_cookie_for(
    bytes: &[u8],
    cell: [u8; 16],
) -> Result<SessionCookie, CodecError> {
    let c = decode_session_cookie(bytes)?;
    if c.session != cell {
        return Err(CodecError::OtherCell);
    }
    Ok(c)
}

/// Encodes a session cookie value: the cell id, then the token.
pub fn encode_session_cookie(c: &SessionCookie) -> [u8; COOKIE_LEN] {
    let mut out = [0u8; COOKIE_LEN];
    let (cell, token) = out.split_at_mut(CELL_ID_LEN);
    cell.copy_from_slice(&c.session);
    token.copy_from_slice(&c.tag);
    out
}

// ---------------------------------------------------------------------------
// Operator tickets.

/// An operator ticket with its signature, not yet verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SignedTicket {
    /// The ticket.
    pub ticket: OperatorTicket,
    /// The composite signature over [`OperatorTicket::message`].
    pub signature: Vec<u8>,
}

/// Decodes an operator ticket: exactly [`TICKET_LEN`] bytes. The
/// signature is not checked here; [`crate::recovery::verify_ticket`]
/// checks it. Fuzzed (`operator_ticket_decode`).
pub fn decode_operator_ticket(bytes: &[u8]) -> Result<SignedTicket, CodecError> {
    if bytes.len() != TICKET_LEN {
        return Err(CodecError::Length);
    }
    let (message, signature) = bytes.split_at(TICKET_MESSAGE_LEN);
    let (case, rest) = message.split_at(16);
    let (s1, s2) = rest.split_at(16);
    let arr = |b: &[u8]| <[u8; 16]>::try_from(b).map_err(|_| CodecError::Length);
    Ok(SignedTicket {
        ticket: OperatorTicket {
            case: arr(case)?,
            staff_1: StaffRef(arr(s1)?),
            staff_2: StaffRef(arr(s2)?),
        },
        signature: signature.to_vec(),
    })
}

/// Encodes an operator ticket with its composite signature.
pub fn encode_operator_ticket(
    ticket: &OperatorTicket,
    signature: &[u8],
) -> Result<Vec<u8>, CodecError> {
    if signature.len() != SIGNATURE_LEN {
        return Err(CodecError::Length);
    }
    let mut out = Vec::with_capacity(TICKET_LEN);
    out.extend_from_slice(&ticket.message());
    out.extend_from_slice(signature);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Records and commands.

/// The member that names the variant.
const TAG: &str = "type";

type R<T> = Result<T, FromJsonError>;

/// The parse limits of a record or command: one flat object of strings
/// and booleans.
fn limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(MAX_ENCODED_LEN)
        .with_max_depth(1)
        .with_max_string_bytes(2 * MAX_PUBLIC_KEY_LEN)
        .with_max_number_len(1)
        .with_max_container_len(8)
        .with_max_nodes(9)
}

/// Lowercase hexadecimal.
fn hex(b: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(b.len().saturating_mul(2));
    for x in b {
        for nibble in [x >> 4, x & 0x0f] {
            if let Some(d) = DIGITS.get(usize::from(nibble)) {
                s.push(char::from(*d));
            }
        }
    }
    s
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => c.checked_sub(b'0'),
        b'a'..=b'f' => c.checked_sub(b'a').and_then(|v| v.checked_add(10)),
        _ => None,
    }
}

/// The bytes of lowercase hexadecimal `s`, or `None`.
fn unhex(s: &str) -> Option<Vec<u8>> {
    let b = s.as_bytes();
    if !b.len().is_multiple_of(2) {
        return None;
    }
    b.chunks_exact(2)
        .map(|pair| match pair {
            [hi, lo] => Some((nibble(*hi)? << 4) | nibble(*lo)?),
            _ => None,
        })
        .collect()
}

fn string<'a>(v: &'a Value, k: &'static str) -> R<&'a str> {
    v.as_str()
        .ok_or_else(|| FromJsonError::wrong_type("a string", v).at_field(k))
}

fn get<'a>(o: &'a Object, k: &'static str) -> R<&'a Value> {
    o.get(k)
        .ok_or_else(|| FromJsonError::new(fstp_json::FromJsonErrorKind::MissingField).at_field(k))
}

fn bytes_n<const N: usize>(o: &Object, k: &'static str) -> R<[u8; N]> {
    let s = string(get(o, k)?, k)?;
    unhex(s)
        .and_then(|b| <[u8; N]>::try_from(b.as_slice()).ok())
        .ok_or_else(|| FromJsonError::invalid("hexadecimal of the wrong form").at_field(k))
}

fn credential(o: &Object, k: &'static str) -> R<Vec<u8>> {
    let s = string(get(o, k)?, k)?;
    unhex(s)
        .filter(|b| !b.is_empty() && b.len() <= MAX_CREDENTIAL_LEN)
        .ok_or_else(|| FromJsonError::invalid("credential id of the wrong form").at_field(k))
}

fn account(o: &Object, k: &'static str) -> R<AccountId> {
    let s = string(get(o, k)?, k)?;
    let canonical =
        !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) && (s == "0" || !s.starts_with('0'));
    if !canonical {
        return Err(FromJsonError::invalid("id of the wrong form").at_field(k));
    }
    s.parse::<u128>()
        .map(AccountId::from_raw)
        .map_err(|_| FromJsonError::invalid("id out of range").at_field(k))
}

/// The CBOR major type bits of a negative integer.
const CBOR_NEGATIVE: u8 = 0x20;
/// The CBOR major type bits of a byte string.
const CBOR_BYTES: u8 = 0x40;
/// The CBOR major type bits of a map.
const CBOR_MAP: u8 = 0xa0;

/// Appends the shortest CBOR head of major type `major` and argument `v`.
fn cbor_head(out: &mut Vec<u8>, major: u8, v: usize) {
    if let Ok(small) = u8::try_from(v)
        && small < 24
    {
        out.push(major | small);
    } else if let Ok(one) = u8::try_from(v) {
        out.push(major | 24);
        out.push(one);
    } else if let Ok(two) = u16::try_from(v) {
        out.push(major | 25);
        out.extend_from_slice(&two.to_be_bytes());
    } else {
        let four = u32::try_from(v).unwrap_or(u32::MAX);
        out.push(major | 26);
        out.extend_from_slice(&four.to_be_bytes());
    }
}

/// Appends one CBOR byte string.
fn cbor_bytes(out: &mut Vec<u8>, b: &[u8]) {
    cbor_head(out, CBOR_BYTES, b.len());
    out.extend_from_slice(b);
}

/// The canonical COSE bytes of `k`: one CBOR map in the deterministic
/// order of RFC 8949 section 4.2.1, with labels 1, 3, -1, -2 and -3.
/// `fstp_webauthn::parse_cose_key` parses them back to `k`.
pub fn cose_key_bytes(k: &CoseKey) -> Vec<u8> {
    let mut out = Vec::new();
    match k {
        CoseKey::Es256 { x, y } => {
            cbor_head(&mut out, CBOR_MAP, 5);
            // kty 2 (EC2), alg -7 (ES256), crv 1 (P-256), x, y.
            out.extend_from_slice(&[0x01, 0x02, 0x03, CBOR_NEGATIVE | 6, CBOR_NEGATIVE, 0x01]);
            out.push(CBOR_NEGATIVE | 1);
            cbor_bytes(&mut out, x);
            out.push(CBOR_NEGATIVE | 2);
            cbor_bytes(&mut out, y);
        }
        CoseKey::Ed25519 { x } => {
            cbor_head(&mut out, CBOR_MAP, 4);
            // kty 1 (OKP), alg -8 (EdDSA), crv 6 (Ed25519), x.
            out.extend_from_slice(&[0x01, 0x01, 0x03, CBOR_NEGATIVE | 7, CBOR_NEGATIVE, 0x06]);
            out.push(CBOR_NEGATIVE | 1);
            cbor_bytes(&mut out, x);
        }
        CoseKey::Rs256 { n, e } => {
            cbor_head(&mut out, CBOR_MAP, 4);
            // kty 3 (RSA), alg -257 (RS256), n, e.
            out.extend_from_slice(&[0x01, 0x03, 0x03]);
            cbor_head(&mut out, CBOR_NEGATIVE, 256);
            out.push(CBOR_NEGATIVE);
            cbor_bytes(&mut out, n);
            out.push(CBOR_NEGATIVE | 1);
            cbor_bytes(&mut out, e);
        }
    }
    out
}

/// A COSE public key in lowercase hexadecimal of its canonical bytes. A
/// key `parse_cose_key` refuses, or one in another byte order, is refused.
fn public_key(o: &Object, k: &'static str) -> R<CoseKey> {
    let s = string(get(o, k)?, k)?;
    let bytes = unhex(s)
        .filter(|b| !b.is_empty() && b.len() <= MAX_PUBLIC_KEY_LEN)
        .ok_or_else(|| FromJsonError::invalid("public key of the wrong form").at_field(k))?;
    let key = fstp_webauthn::parse_cose_key(&bytes)
        .map_err(|_| FromJsonError::invalid("COSE key refused").at_field(k))?;
    if cose_key_bytes(&key) != bytes {
        return Err(FromJsonError::invalid("COSE key not in canonical form").at_field(k));
    }
    Ok(key)
}

fn boolean(o: &Object, k: &'static str) -> R<bool> {
    let v = get(o, k)?;
    v.as_bool()
        .ok_or_else(|| FromJsonError::wrong_type("a boolean", v).at_field(k))
}

const PATHS: [(RecoveryPath, &str); 4] = [
    (RecoveryPath::EmailThenPasskey, "EmailThenPasskey"),
    (RecoveryPath::SecondAdmin, "SecondAdmin"),
    (RecoveryPath::OperatorProcess, "OperatorProcess"),
    (RecoveryPath::HostConsole, "HostConsole"),
];

fn path_name(p: RecoveryPath) -> &'static str {
    PATHS
        .iter()
        .find(|(q, _)| *q == p)
        .map_or("EmailThenPasskey", |(_, n)| n)
}

fn path(o: &Object, k: &'static str) -> R<RecoveryPath> {
    let s = string(get(o, k)?, k)?;
    PATHS
        .iter()
        .find(|(_, n)| *n == s)
        .map(|(p, _)| *p)
        .ok_or_else(|| FromJsonError::invalid("unknown recovery path").at_field(k))
}

/// The object of `v` with exactly the members `names` plus `type`.
fn exactly<'a>(v: &'a Value, names: &[&'static str]) -> R<&'a Object> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::wrong_type("an object", v))?;
    let known = |k: &str| k == TAG || names.contains(&k);
    if o.keys().any(|k| !known(k)) {
        return Err(FromJsonError::new(
            fstp_json::FromJsonErrorKind::UnknownField,
        ));
    }
    for n in names {
        get(o, n)?;
    }
    Ok(o)
}

fn tag(v: &Value) -> R<&str> {
    let o = v
        .as_object()
        .ok_or_else(|| FromJsonError::wrong_type("an object", v))?;
    string(get(o, TAG)?, TAG)
}

/// A builder of one tagged object.
struct Obj(Object);

impl Obj {
    fn new(kind: &'static str) -> Obj {
        let mut o = Object::new();
        o.insert(TAG, Value::from(kind));
        Obj(o)
    }

    fn put(mut self, k: &'static str, v: Value) -> Obj {
        self.0.insert(k, v);
        self
    }

    fn bytes(self, k: &'static str, b: &[u8]) -> Obj {
        self.put(k, Value::from(hex(b)))
    }

    fn account(self, k: &'static str, a: AccountId) -> Obj {
        self.put(k, Value::from(a.raw().to_string()))
    }

    fn done(self) -> Value {
        Value::from(self.0)
    }
}

impl ToJson for AuthRecord {
    fn to_json(&self) -> Value {
        match self {
            AuthRecord::CredentialRegistered {
                account,
                credential,
                key,
                user_verified,
            } => Obj::new("CredentialRegistered")
                .account("account", *account)
                .bytes("credential", credential)
                .bytes("public_key", &cose_key_bytes(key))
                .put("user_verified", Value::from(*user_verified)),
            AuthRecord::StepUpGranted {
                id,
                action_digest,
                session,
            } => Obj::new("StepUpGranted")
                .bytes("id", id)
                .bytes("action_digest", action_digest)
                .bytes("session", session),
            AuthRecord::SessionEnded { session } => {
                Obj::new("SessionEnded").bytes("session", session)
            }
            AuthRecord::CredentialRevoked {
                account,
                credential,
            } => Obj::new("CredentialRevoked")
                .account("account", *account)
                .bytes("credential", credential),
            AuthRecord::CredentialSuspect {
                account,
                credential,
            } => Obj::new("CredentialSuspect")
                .account("account", *account)
                .bytes("credential", credential),
            AuthRecord::StepUpConsumed { id } => Obj::new("StepUpConsumed").bytes("id", id),
            AuthRecord::RecoveryRequested {
                case,
                account,
                path,
            } => Obj::new("RecoveryRequested")
                .bytes("case", case)
                .account("account", *account)
                .put("path", Value::from(path_name(*path))),
            AuthRecord::RecoveryEmailProven { case } => {
                Obj::new("RecoveryEmailProven").bytes("case", case)
            }
            AuthRecord::RecoveryApproved { case, approver } => Obj::new("RecoveryApproved")
                .bytes("case", case)
                .account("approver", *approver),
            AuthRecord::RecoveryCompleted {
                case,
                account,
                path,
                shown_to_tenant,
            } => Obj::new("RecoveryCompleted")
                .bytes("case", case)
                .account("account", *account)
                .put("path", Value::from(path_name(*path)))
                .put("shown_to_tenant", Value::from(*shown_to_tenant)),
            AuthRecord::InvitationIssued {
                invitation,
                account,
                token_digest,
                first_admin,
                split,
            } => Obj::new("InvitationIssued")
                .bytes("invitation", invitation)
                .account("account", *account)
                .bytes("token_digest", token_digest)
                .put("first_admin", Value::from(*first_admin))
                .put("split", Value::from(*split)),
            AuthRecord::InvitationConsumed { invitation } => {
                Obj::new("InvitationConsumed").bytes("invitation", invitation)
            }
            AuthRecord::FirstAdminEnrolled { account } => {
                Obj::new("FirstAdminEnrolled").account("account", *account)
            }
        }
        .done()
    }
}

impl FromJson for AuthRecord {
    fn from_json(v: &Value) -> R<AuthRecord> {
        let r = match tag(v)? {
            "CredentialRegistered" => {
                let o = exactly(v, &["account", "credential", "public_key", "user_verified"])?;
                AuthRecord::CredentialRegistered {
                    account: account(o, "account")?,
                    credential: credential(o, "credential")?,
                    key: public_key(o, "public_key")?,
                    user_verified: boolean(o, "user_verified")?,
                }
            }
            "StepUpGranted" => {
                let o = exactly(v, &["id", "action_digest", "session"])?;
                AuthRecord::StepUpGranted {
                    id: bytes_n(o, "id")?,
                    action_digest: bytes_n(o, "action_digest")?,
                    session: bytes_n(o, "session")?,
                }
            }
            "SessionEnded" => {
                let o = exactly(v, &["session"])?;
                AuthRecord::SessionEnded {
                    session: bytes_n(o, "session")?,
                }
            }
            "CredentialRevoked" => {
                let o = exactly(v, &["account", "credential"])?;
                AuthRecord::CredentialRevoked {
                    account: account(o, "account")?,
                    credential: credential(o, "credential")?,
                }
            }
            "CredentialSuspect" => {
                let o = exactly(v, &["account", "credential"])?;
                AuthRecord::CredentialSuspect {
                    account: account(o, "account")?,
                    credential: credential(o, "credential")?,
                }
            }
            "StepUpConsumed" => {
                let o = exactly(v, &["id"])?;
                AuthRecord::StepUpConsumed {
                    id: bytes_n(o, "id")?,
                }
            }
            "RecoveryRequested" => {
                let o = exactly(v, &["case", "account", "path"])?;
                AuthRecord::RecoveryRequested {
                    case: bytes_n(o, "case")?,
                    account: account(o, "account")?,
                    path: path(o, "path")?,
                }
            }
            "RecoveryEmailProven" => {
                let o = exactly(v, &["case"])?;
                AuthRecord::RecoveryEmailProven {
                    case: bytes_n(o, "case")?,
                }
            }
            "RecoveryApproved" => {
                let o = exactly(v, &["case", "approver"])?;
                AuthRecord::RecoveryApproved {
                    case: bytes_n(o, "case")?,
                    approver: account(o, "approver")?,
                }
            }
            "RecoveryCompleted" => {
                let o = exactly(v, &["case", "account", "path", "shown_to_tenant"])?;
                let path = path(o, "path")?;
                let shown_to_tenant = boolean(o, "shown_to_tenant")?;
                // The path fixes the member (`authentication.md`: the
                // operator path is "logged and shown to the tenant").
                if shown_to_tenant != path.shown_to_tenant() {
                    return Err(
                        FromJsonError::invalid("differs from the path").at_field("shown_to_tenant")
                    );
                }
                AuthRecord::RecoveryCompleted {
                    case: bytes_n(o, "case")?,
                    account: account(o, "account")?,
                    path,
                    shown_to_tenant,
                }
            }
            "InvitationIssued" => {
                let o = exactly(
                    v,
                    &[
                        "invitation",
                        "account",
                        "token_digest",
                        "first_admin",
                        "split",
                    ],
                )?;
                let first_admin = boolean(o, "first_admin")?;
                let split = boolean(o, "split")?;
                // Only the first admin's invitation is split (Q35).
                if split && !first_admin {
                    return Err(
                        FromJsonError::invalid("split without first admin").at_field("split")
                    );
                }
                AuthRecord::InvitationIssued {
                    invitation: bytes_n(o, "invitation")?,
                    account: account(o, "account")?,
                    token_digest: bytes_n(o, "token_digest")?,
                    first_admin,
                    split,
                }
            }
            "InvitationConsumed" => {
                let o = exactly(v, &["invitation"])?;
                AuthRecord::InvitationConsumed {
                    invitation: bytes_n(o, "invitation")?,
                }
            }
            "FirstAdminEnrolled" => {
                let o = exactly(v, &["account"])?;
                AuthRecord::FirstAdminEnrolled {
                    account: account(o, "account")?,
                }
            }
            _ => return Err(FromJsonError::invalid("unknown record type").at_field(TAG)),
        };
        Ok(r)
    }
}

impl ToJson for AuthCommand {
    fn to_json(&self) -> Value {
        match self {
            AuthCommand::RegisterCredential {
                account,
                credential,
            } => Obj::new("RegisterCredential")
                .account("account", *account)
                .bytes("credential", credential),
            AuthCommand::RevokeCredential {
                account,
                credential,
            } => Obj::new("RevokeCredential")
                .account("account", *account)
                .bytes("credential", credential),
            AuthCommand::GrantStepUp {
                session,
                action_digest,
            } => Obj::new("GrantStepUp")
                .bytes("session", session)
                .bytes("action_digest", action_digest),
            AuthCommand::EndSession { session } => Obj::new("EndSession").bytes("session", session),
            AuthCommand::RequestRecovery { case, account } => Obj::new("RequestRecovery")
                .bytes("case", case)
                .account("account", *account),
            AuthCommand::ProveRecoveryEmail { case } => {
                Obj::new("ProveRecoveryEmail").bytes("case", case)
            }
            AuthCommand::ApproveRecovery { case } => {
                Obj::new("ApproveRecovery").bytes("case", case)
            }
            AuthCommand::CompleteRecovery { case, credential } => Obj::new("CompleteRecovery")
                .bytes("case", case)
                .bytes("credential", credential),
        }
        .done()
    }
}

impl FromJson for AuthCommand {
    fn from_json(v: &Value) -> R<AuthCommand> {
        let c = match tag(v)? {
            "RegisterCredential" => {
                let o = exactly(v, &["account", "credential"])?;
                AuthCommand::RegisterCredential {
                    account: account(o, "account")?,
                    credential: credential(o, "credential")?,
                }
            }
            "RevokeCredential" => {
                let o = exactly(v, &["account", "credential"])?;
                AuthCommand::RevokeCredential {
                    account: account(o, "account")?,
                    credential: credential(o, "credential")?,
                }
            }
            "GrantStepUp" => {
                let o = exactly(v, &["session", "action_digest"])?;
                AuthCommand::GrantStepUp {
                    session: bytes_n(o, "session")?,
                    action_digest: bytes_n(o, "action_digest")?,
                }
            }
            "EndSession" => {
                let o = exactly(v, &["session"])?;
                AuthCommand::EndSession {
                    session: bytes_n(o, "session")?,
                }
            }
            "RequestRecovery" => {
                let o = exactly(v, &["case", "account"])?;
                AuthCommand::RequestRecovery {
                    case: bytes_n(o, "case")?,
                    account: account(o, "account")?,
                }
            }
            "ProveRecoveryEmail" => {
                let o = exactly(v, &["case"])?;
                AuthCommand::ProveRecoveryEmail {
                    case: bytes_n(o, "case")?,
                }
            }
            "ApproveRecovery" => {
                let o = exactly(v, &["case"])?;
                AuthCommand::ApproveRecovery {
                    case: bytes_n(o, "case")?,
                }
            }
            "CompleteRecovery" => {
                let o = exactly(v, &["case", "credential"])?;
                AuthCommand::CompleteRecovery {
                    case: bytes_n(o, "case")?,
                    credential: credential(o, "credential")?,
                }
            }
            _ => return Err(FromJsonError::invalid("unknown command type").at_field(TAG)),
        };
        Ok(c)
    }
}

/// The canonical text of `v`, with the encoder's bounds checked by
/// decoding it again: a value the decoder would refuse is not encoded.
fn encode<T: ToJson + FromJson + PartialEq>(x: &T) -> Result<Vec<u8>, CodecError> {
    let text = x.to_json().to_canonical().map_err(|_| CodecError::Json)?;
    let bytes = text.into_bytes();
    match decode::<T>(&bytes) {
        Ok(back) if back == *x => Ok(bytes),
        Ok(_) | Err(_) => Err(CodecError::Schema("value outside the schema")),
    }
}

/// Decodes the canonical text of a `T`.
fn decode<T: FromJson>(bytes: &[u8]) -> Result<T, CodecError> {
    if bytes.is_empty() || bytes.len() > MAX_ENCODED_LEN {
        return Err(CodecError::Size);
    }
    let v = fstp_json::parse_with(bytes, &limits()).map_err(|_| CodecError::Json)?;
    let canonical = v.to_canonical().map_err(|_| CodecError::NotCanonical)?;
    if canonical.as_bytes() != bytes {
        return Err(CodecError::NotCanonical);
    }
    T::from_json(&v).map_err(|e| {
        CodecError::Schema(match e.path().segments().first() {
            Some(fstp_json::Segment::Field(name)) => name,
            _ => "object",
        })
    })
}

/// Encodes an auth record as its RFC 8785 text.
pub fn encode_auth_record(r: &AuthRecord) -> Result<Vec<u8>, CodecError> {
    encode(r)
}

/// Decodes an auth record from its RFC 8785 text. Fuzzed
/// (`auth_record_decode`).
pub fn decode_auth_record(bytes: &[u8]) -> Result<AuthRecord, CodecError> {
    decode(bytes)
}

/// Encodes an auth command as its RFC 8785 text.
pub fn encode_auth_command(c: &AuthCommand) -> Result<Vec<u8>, CodecError> {
    encode(c)
}

/// Decodes an auth command from its RFC 8785 text. Fuzzed
/// (`auth_command_decode`).
pub fn decode_auth_command(bytes: &[u8]) -> Result<AuthCommand, CodecError> {
    decode(bytes)
}
