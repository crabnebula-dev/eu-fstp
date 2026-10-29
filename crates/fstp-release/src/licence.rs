//! Licence tokens, the licence key set, the refresh step, the licence
//! file and the licence state (design section 10.2, Q18, Q41).
//!
//! The formats are the W1g proposal:
//!
//! - token: `"FSTPLT01" || licence || kind || issued_at || refresh_after
//!   || not_after || signature`;
//! - key transition: `"FSTPKT01" || next_key || not_before || signature`;
//! - refresh response body: `"FSTPRR01" || flag || transition? || token`;
//! - licence file: an armour line, the token in padded base64 on one
//!   line, and a closing armour line.
//!
//! Each signature is Ed25519 over `context || 0x00 || body`, with a
//! context per format, so a body of one format never verifies as another.
//! Instants are big-endian UTC seconds.

pub use fstp_crypto::sig::Ed25519SigningKey;
use fstp_crypto::sig::{ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN};

use crate::ReleaseError;
use crate::wire;

/// A licence, by id.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LicenceId(pub [u8; 16]);

impl LicenceId {
    /// The id's path segment: 32 lowercase hex digits.
    #[must_use]
    pub fn hex(&self) -> String {
        wire::lower_hex(&self.0)
    }

    /// Reads back exactly what [`LicenceId::hex`] gives.
    #[must_use]
    pub fn from_hex(text: &[u8]) -> Option<LicenceId> {
        wire::parse_lower_hex::<16>(text).map(LicenceId)
    }
}

/// A licence kind. Closed. Every install, commercial or noncommercial,
/// holds a signed token (`self-hosted-services.md`, O-27).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum LicenceKind {
    /// A commercial licence. Code 1.
    Commercial,
    /// A noncommercial licence, issued on self-declared status (O-27).
    /// Code 2.
    Noncommercial,
}

impl LicenceKind {
    /// Every kind.
    pub const ALL: [LicenceKind; 2] = [LicenceKind::Commercial, LicenceKind::Noncommercial];

    /// The kind byte of a token.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            LicenceKind::Commercial => 1,
            LicenceKind::Noncommercial => 2,
        }
    }

    /// The kind of a kind byte.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<LicenceKind> {
        match code {
            1 => Some(LicenceKind::Commercial),
            2 => Some(LicenceKind::Noncommercial),
            _ => None,
        }
    }
}

/// The fields of a licence token. A decoder returns it only after the
/// signature verified under a pinned key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VerifiedToken {
    /// The licence.
    pub licence: LicenceId,
    /// The kind.
    pub kind: LicenceKind,
    /// UTC seconds.
    pub issued_at: i64,
    /// UTC seconds.
    pub refresh_after: i64,
    /// UTC seconds.
    pub not_after: i64,
}

/// An Ed25519 public key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Ed25519Public(pub [u8; ED25519_PUBLIC_KEY_LEN]);

// ---------------------------------------------------------------------------
// Tokens.

/// The first bytes of every token.
pub const TOKEN_MAGIC: [u8; 8] = *b"FSTPLT01";
/// The signature context of a token.
pub const TOKEN_CONTEXT: &[u8] = b"fstp-licence-token-v1";
/// The token body length: magic, licence, kind and three instants.
pub const TOKEN_BODY_LEN: usize = 8 + 16 + 1 + 3 * 8;
/// The token length: body and Ed25519 signature.
pub const TOKEN_LEN: usize = TOKEN_BODY_LEN + ED25519_SIGNATURE_LEN;

/// The token body of `t`.
fn token_body(t: &VerifiedToken) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOKEN_BODY_LEN);
    out.extend_from_slice(&TOKEN_MAGIC);
    out.extend_from_slice(&t.licence.0);
    out.push(t.kind.code());
    out.extend_from_slice(&t.issued_at.to_be_bytes());
    out.extend_from_slice(&t.refresh_after.to_be_bytes());
    out.extend_from_slice(&t.not_after.to_be_bytes());
    out
}

/// The signed token of `t`. The licence service issues tokens with it.
///
/// # Errors
///
/// Returns [`ReleaseError::Order`] unless `issued_at <= refresh_after <=
/// not_after`, so no token is issued that a cell would refuse. Returns
/// [`ReleaseError::Signing`] when signing fails.
pub fn sign_token(t: &VerifiedToken, key: &Ed25519SigningKey) -> Result<Vec<u8>, ReleaseError> {
    if !(t.issued_at <= t.refresh_after && t.refresh_after <= t.not_after) {
        return Err(ReleaseError::Order);
    }
    wire::sign(key, TOKEN_CONTEXT, token_body(t))
}

/// The body and signature of a token after its length and magic checks.
fn token_parts(bytes: &[u8]) -> Result<(&[u8], &[u8]), ReleaseError> {
    if bytes.len() != TOKEN_LEN {
        return Err(ReleaseError::Length);
    }
    let (body, signature) = bytes
        .split_at_checked(TOKEN_BODY_LEN)
        .ok_or(ReleaseError::Length)?;
    if body.get(..8) != Some(TOKEN_MAGIC.as_slice()) {
        return Err(ReleaseError::Magic);
    }
    Ok((body, signature))
}

/// The fields of a token body whose signature already verified.
fn token_fields(body: &[u8]) -> Result<VerifiedToken, ReleaseError> {
    let licence = wire::array::<16>(body, 8).ok_or(ReleaseError::Length)?;
    let kind = body
        .get(24)
        .copied()
        .and_then(LicenceKind::from_code)
        .ok_or(ReleaseError::Kind)?;
    let issued_at = wire::be_i64(body, 25).ok_or(ReleaseError::Length)?;
    let refresh_after = wire::be_i64(body, 33).ok_or(ReleaseError::Length)?;
    let not_after = wire::be_i64(body, 41).ok_or(ReleaseError::Length)?;
    if !(issued_at <= refresh_after && refresh_after <= not_after) {
        return Err(ReleaseError::Order);
    }
    Ok(VerifiedToken {
        licence: LicenceId(licence),
        kind,
        issued_at,
        refresh_after,
        not_after,
    })
}

/// A token verified under any of `keys`: length and magic, then the
/// signature, then the fields.
fn verify_token_under<'a>(
    bytes: &[u8],
    keys: impl IntoIterator<Item = &'a Ed25519Public>,
) -> Result<VerifiedToken, ReleaseError> {
    let (body, signature) = token_parts(bytes)?;
    if !keys
        .into_iter()
        .any(|k| wire::signed_by(&k.0, TOKEN_CONTEXT, body, signature))
    {
        return Err(ReleaseError::Signature);
    }
    token_fields(body)
}

/// Verifies a token's signature under `key` before any field is used.
/// Fuzzed (`licence_token_decode`).
///
/// The order is length, magic, signature, then the kind and the instant
/// order. So the refusal of a token that `key` did not sign never
/// depends on its fields.
///
/// # Errors
///
/// [`ReleaseError::Length`], [`ReleaseError::Magic`],
/// [`ReleaseError::Signature`], [`ReleaseError::Kind`] or
/// [`ReleaseError::Order`], in that order of checks.
pub fn verify_token(bytes: &[u8], key: &Ed25519Public) -> Result<VerifiedToken, ReleaseError> {
    verify_token_under(bytes, [key])
}

// ---------------------------------------------------------------------------
// The key set and its transitions.

/// The keys shipped with this release.
///
/// Empty in M3: the control-plane licence token key (ADR-004 "Licence
/// token key") does not exist yet. So an M3 cell verifies no token, and
/// its licence state stays [`LicenceState::Missing`], which blocks
/// nothing (Q18).
pub const SHIPPED_KEYS: [Ed25519Public; 0] = [];

/// The most keys a key set holds. Yearly rotation (ADR-004) reaches it
/// only after decades. [`KeySet::apply_transition`] refuses a transition
/// that would add a key past it, and [`apply_refresh`] then leaves the
/// transition out (see there).
pub const MAX_KEYS: usize = 32;

/// The Ed25519 public key encodings of the points of small order, with
/// bit 255 (the sign of x) cleared.
///
/// This is the table `fstp_crypto::composite` applies to the Ed25519
/// half of a composite public key. That check is private to
/// `fstp-crypto`, so the table is repeated here, and the crate test
/// `i39_small_order_table_matches_fstp_crypto` holds the two equal. It is
/// a table comparison, not a curve operation.
const ED25519_SMALL_ORDER: [[u8; ED25519_PUBLIC_KEY_LEN]; 7] = [
    // y = 0: the two points of order 4.
    [0; 32],
    // y = 1: the identity, of order 1.
    [
        0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0,
    ],
    // Order 8.
    [
        0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef, 0x98,
        0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88, 0x6d, 0x53,
        0xfc, 0x05,
    ],
    // Order 8.
    [
        0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10, 0x67,
        0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77, 0x92, 0xac,
        0x03, 0x7a,
    ],
    // y = p - 1: the point of order 2.
    [
        0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p, a non-canonical spelling of y = 0.
    [
        0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
    // y = p + 1, a non-canonical spelling of y = 1.
    [
        0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0x7f,
    ],
];

impl Ed25519Public {
    /// Whether the key encodes an Ed25519 point of small order, in any
    /// spelling: either sign bit, canonical or not. Such a key never
    /// joins a [`KeySet`], since signatures under it can be forged.
    #[must_use]
    pub fn is_small_order(&self) -> bool {
        let mut masked = self.0;
        if let Some(last) = masked.last_mut() {
            *last &= 0x7f;
        }
        ED25519_SMALL_ORDER.contains(&masked)
    }
}

/// A pinned key and the instant from which it is in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PinnedKey {
    /// The key.
    pub key: Ed25519Public,
    /// UTC seconds. A shipped key has `i64::MIN`.
    pub not_before: i64,
}

/// A key transition whose signature verified under a key in force.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyTransition {
    next_key: Ed25519Public,
    not_before: i64,
}

impl KeyTransition {
    /// The key the transition adds.
    #[must_use]
    pub const fn next_key(&self) -> Ed25519Public {
        self.next_key
    }

    /// UTC seconds from which the next key is in force.
    #[must_use]
    pub const fn not_before(&self) -> i64 {
        self.not_before
    }
}

/// The first bytes of every key transition.
pub const TRANSITION_MAGIC: [u8; 8] = *b"FSTPKT01";
/// The signature context of a key transition.
pub const TRANSITION_CONTEXT: &[u8] = b"fstp-licence-key-transition-v1";
/// The transition body length: magic, next key and `not_before`.
pub const TRANSITION_BODY_LEN: usize = 8 + ED25519_PUBLIC_KEY_LEN + 8;
/// The transition length: body and Ed25519 signature.
pub const TRANSITION_LEN: usize = TRANSITION_BODY_LEN + ED25519_SIGNATURE_LEN;

/// The signed transition that adds `next_key` from `not_before` on. The
/// control plane signs it with a current licence key.
///
/// # Errors
///
/// Returns [`ReleaseError::Signing`] when signing fails.
pub fn sign_transition(
    next_key: &Ed25519Public,
    not_before: i64,
    key: &Ed25519SigningKey,
) -> Result<Vec<u8>, ReleaseError> {
    let mut body = Vec::with_capacity(TRANSITION_BODY_LEN);
    body.extend_from_slice(&TRANSITION_MAGIC);
    body.extend_from_slice(&next_key.0);
    body.extend_from_slice(&not_before.to_be_bytes());
    wire::sign(key, TRANSITION_CONTEXT, body)
}

/// The licence key set a cell pins (design section 10.2). It starts from
/// the keys shipped with the release and changes only through accepted
/// transitions. It keeps join order and holds at most [`MAX_KEYS`] keys,
/// each once, none of small order.
///
/// A key joins a built set only through [`KeySet::apply_transition`] or
/// [`apply_refresh`], each of which verifies the transition under this
/// same set. So a transition verified under another set never adds a
/// key here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeySet {
    keys: Vec<PinnedKey>,
}

impl KeySet {
    /// A set of `keys` after the checks every set meets.
    fn checked(keys: Vec<PinnedKey>) -> Result<KeySet, ReleaseError> {
        if keys.len() > MAX_KEYS {
            return Err(ReleaseError::KeySetFull);
        }
        if keys.iter().any(|p| p.key.is_small_order()) {
            return Err(ReleaseError::WeakKey);
        }
        let mut seen: Vec<&Ed25519Public> = Vec::with_capacity(keys.len());
        for p in &keys {
            if seen.contains(&&p.key) {
                return Err(ReleaseError::DuplicateKey);
            }
            seen.push(&p.key);
        }
        Ok(KeySet { keys })
    }

    /// The set shipped with a release: every key in force from
    /// `i64::MIN`.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::KeySetFull`] past [`MAX_KEYS`] keys,
    /// [`ReleaseError::WeakKey`] for a key of small order and
    /// [`ReleaseError::DuplicateKey`] for a key named twice.
    pub fn shipped(keys: &[Ed25519Public]) -> Result<KeySet, ReleaseError> {
        if keys.len() > MAX_KEYS {
            return Err(ReleaseError::KeySetFull);
        }
        KeySet::checked(
            keys.iter()
                .map(|k| PinnedKey {
                    key: *k,
                    not_before: i64::MIN,
                })
                .collect(),
        )
    }

    /// A set restored from the cell's sealed store, in its stored order.
    /// The stored set has one spelling, so a key named twice is refused.
    ///
    /// # Errors
    ///
    /// As [`KeySet::shipped`].
    pub fn from_pinned(keys: &[PinnedKey]) -> Result<KeySet, ReleaseError> {
        if keys.len() > MAX_KEYS {
            return Err(ReleaseError::KeySetFull);
        }
        KeySet::checked(keys.to_vec())
    }

    /// Whether the set holds `key`.
    fn holds(&self, key: &Ed25519Public) -> bool {
        self.keys.iter().any(|p| p.key == *key)
    }

    /// The keys and their `not_before`, in join order.
    #[must_use]
    pub fn keys(&self) -> &[PinnedKey] {
        &self.keys
    }

    /// The keys in force at `now`: those whose `not_before <= now`.
    pub fn in_force(&self, now: i64) -> impl Iterator<Item = &Ed25519Public> {
        self.keys
            .iter()
            .filter(move |p| p.not_before <= now)
            .map(|p| &p.key)
    }

    /// Verifies a signed transition under the keys in force at `now`.
    /// Fuzzed (`key_transition_decode` over a pinned set, and
    /// `refresh_response_decode`).
    ///
    /// Reading (W1g): "signed by a current key" means a key in force at
    /// `now`. So a key announced for later signs no transition before its
    /// own `not_before`.
    ///
    /// After the signature, a next key of small order is refused, so no
    /// pinned key ever signs in a key whose signatures anyone can forge.
    /// The W1g reference has no such check. Real keys are never of small
    /// order, so the two agree on every transition a key holder signs.
    ///
    /// # Errors
    ///
    /// [`ReleaseError::Length`], [`ReleaseError::Magic`],
    /// [`ReleaseError::Signature`] or [`ReleaseError::WeakKey`], in that
    /// order of checks.
    pub fn verify_transition(&self, bytes: &[u8], now: i64) -> Result<KeyTransition, ReleaseError> {
        if bytes.len() != TRANSITION_LEN {
            return Err(ReleaseError::Length);
        }
        let (body, signature) = bytes
            .split_at_checked(TRANSITION_BODY_LEN)
            .ok_or(ReleaseError::Length)?;
        if body.get(..8) != Some(TRANSITION_MAGIC.as_slice()) {
            return Err(ReleaseError::Magic);
        }
        if !self
            .in_force(now)
            .any(|k| wire::signed_by(&k.0, TRANSITION_CONTEXT, body, signature))
        {
            return Err(ReleaseError::Signature);
        }
        let next_key =
            wire::array::<ED25519_PUBLIC_KEY_LEN>(body, 8).ok_or(ReleaseError::Length)?;
        let not_before = wire::be_i64(body, 40).ok_or(ReleaseError::Length)?;
        let next_key = Ed25519Public(next_key);
        if next_key.is_small_order() {
            return Err(ReleaseError::WeakKey);
        }
        Ok(KeyTransition {
            next_key,
            not_before,
        })
    }

    /// The set after `t` was accepted. Private, so a key joins only
    /// through a transition this same set verified.
    ///
    /// Reading (W1g): a key already in the set keeps its earlier
    /// `not_before`. So a replayed or later transition never delays a key
    /// in force, and a shipped key never loses force.
    ///
    /// # Errors
    ///
    /// Returns [`ReleaseError::KeySetFull`] when `t` adds a new key to a
    /// full set.
    fn with(&self, t: &KeyTransition) -> Result<KeySet, ReleaseError> {
        let mut next = self.clone();
        if !next.holds(&t.next_key) {
            if next.keys.len() >= MAX_KEYS {
                return Err(ReleaseError::KeySetFull);
            }
            next.keys.push(PinnedKey {
                key: t.next_key,
                not_before: t.not_before,
            });
        }
        Ok(next)
    }

    /// Verifies a signed transition at `now` and applies it. A refusal
    /// leaves the set unchanged.
    ///
    /// # Errors
    ///
    /// As [`KeySet::verify_transition`], then
    /// [`ReleaseError::KeySetFull`] when the transition adds a new key to
    /// a set of [`MAX_KEYS`] keys.
    pub fn apply_transition(
        &mut self,
        bytes: &[u8],
        now: i64,
    ) -> Result<KeyTransition, ReleaseError> {
        let t = self.verify_transition(bytes, now)?;
        *self = self.with(&t)?;
        Ok(t)
    }

    /// Verifies a token under the keys in force at `now`.
    ///
    /// # Errors
    ///
    /// As [`verify_token`].
    pub fn verify_token(&self, bytes: &[u8], now: i64) -> Result<VerifiedToken, ReleaseError> {
        verify_token_under(bytes, self.in_force(now))
    }
}

/// Decodes a licence key transition, accepted only when a key shipped
/// with this release signed it (I-39). Fuzzed (`key_transition_decode`).
///
/// A running cell uses [`KeySet::apply_transition`] over its stored set
/// instead. In M3 [`SHIPPED_KEYS`] is empty, so this refuses every
/// transition after the length and magic checks.
///
/// # Errors
///
/// As [`KeySet::verify_transition`].
pub fn decode_key_transition(bytes: &[u8]) -> Result<Ed25519Public, ReleaseError> {
    let shipped = KeySet::shipped(&SHIPPED_KEYS)?;
    shipped
        .verify_transition(bytes, i64::MIN)
        .map(|t| t.next_key())
}

// ---------------------------------------------------------------------------
// The refresh response.

/// The first bytes of every refresh response body.
pub const RESPONSE_MAGIC: [u8; 8] = *b"FSTPRR01";

/// The refresh response body: [`RESPONSE_MAGIC`], one byte that is 0
/// without a transition and 1 with one, the signed transition if any,
/// then the signed token. The licence service serves it as
/// `application/octet-stream`.
#[must_use]
pub fn refresh_response(transition: Option<&[u8]>, token: &[u8]) -> Vec<u8> {
    let extra = transition.map_or(0, <[u8]>::len);
    let mut out = Vec::with_capacity(9usize.saturating_add(extra).saturating_add(token.len()));
    out.extend_from_slice(&RESPONSE_MAGIC);
    match transition {
        None => out.push(0),
        Some(t) => {
            out.push(1);
            out.extend_from_slice(t);
        }
    }
    out.extend_from_slice(token);
    out
}

/// The transition, if any, and the token of a refresh response body. The
/// lengths are exact, so nothing else fits.
fn split_refresh_response(bytes: &[u8]) -> Option<(Option<&[u8]>, &[u8])> {
    let rest = bytes.strip_prefix(RESPONSE_MAGIC.as_slice())?;
    let (flag, rest) = rest.split_first()?;
    let (transition, token) = match flag {
        0 => (None, rest),
        1 => {
            let (t, token) = rest.split_at_checked(TRANSITION_LEN)?;
            (Some(t), token)
        }
        _ => return None,
    };
    (token.len() == TOKEN_LEN).then_some((transition, token))
}

/// What a cell stores after an accepted refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refreshed {
    /// The adopted token.
    pub token: VerifiedToken,
    /// The key set, with the transition's key if the response carried one.
    pub keys: KeySet,
}

/// Applies a refresh response body to the stored token and key set at
/// `now` (design section 10.2). Fuzzed (`refresh_response_decode`).
///
/// The order: the framing, then any transition under the keys in force
/// at `now`, then the token under the resulting set in force at `now`,
/// then the same licence, then not older than the stored token.
///
/// Reading (W1g): the response is all or nothing. A refused token also
/// drops the transition it came with. The service issues one token per
/// issue instant, so another token with the stored issue instant is
/// refused as stale, and the stored token itself is accepted again.
///
/// Reading (lane W2j, for Daniel): the W1g reference has no cap on the
/// key set. When the set already holds [`MAX_KEYS`] keys and a verified
/// transition names a new key, the transition is left out. The token is
/// then verified under the set as it stands. So a token signed by a key
/// already pinned still refreshes, and one signed only by the new key is
/// refused. The two agree on every set below the cap.
///
/// # Errors
///
/// [`ReleaseError::Framing`], any refusal of
/// [`KeySet::verify_transition`] or [`verify_token`],
/// [`ReleaseError::OtherLicence`] or [`ReleaseError::Stale`]. Nothing
/// changes on a refusal, since the inputs are borrowed.
pub fn apply_refresh(
    stored: &VerifiedToken,
    keys: &KeySet,
    response: &[u8],
    now: i64,
) -> Result<Refreshed, ReleaseError> {
    let (transition, token) = split_refresh_response(response).ok_or(ReleaseError::Framing)?;
    let next = match transition {
        None => keys.clone(),
        Some(t) => {
            let t = keys.verify_transition(t, now)?;
            match keys.with(&t) {
                Ok(next) => next,
                Err(ReleaseError::KeySetFull) => keys.clone(),
                Err(e) => return Err(e),
            }
        }
    };
    let token = next.verify_token(token, now)?;
    if token.licence != stored.licence {
        return Err(ReleaseError::OtherLicence);
    }
    let stale = token.issued_at < stored.issued_at
        || (token.issued_at == stored.issued_at && token != *stored);
    if stale {
        return Err(ReleaseError::Stale);
    }
    Ok(Refreshed { token, keys: next })
}

// ---------------------------------------------------------------------------
// The licence file (Q41).

/// The first line of a licence file.
pub const FILE_BEGIN: &str = "-----BEGIN FSTP LICENCE-----\n";
/// The last line of a licence file.
pub const FILE_END: &str = "-----END FSTP LICENCE-----\n";
/// The base64 length of a token.
const TOKEN_B64_LEN: usize = TOKEN_LEN.div_ceil(3) * 4;
/// The length of every licence file.
pub const FILE_LEN: usize = FILE_BEGIN.len() + TOKEN_B64_LEN + 1 + FILE_END.len();

/// The licence file of a signed token: the BEGIN line, the token in
/// standard padded base64 on one line, and the END line, each ending in
/// one line feed. The registration page hands it to the holder (Q41).
#[must_use]
pub fn licence_file(token: &[u8]) -> Vec<u8> {
    let mut out = String::with_capacity(FILE_LEN);
    out.push_str(FILE_BEGIN);
    out.push_str(&wire::base64(token));
    out.push('\n');
    out.push_str(FILE_END);
    out.into_bytes()
}

/// Decodes an imported licence file to its token bytes. Fuzzed
/// (`licence_file_import_decode`).
///
/// The file has one spelling, and its token has exactly [`TOKEN_LEN`]
/// bytes. So the length is checked first, and nothing larger is read.
/// The signature is checked next by [`verify_token`] or
/// [`KeySet::verify_token`].
///
/// # Errors
///
/// Returns [`ReleaseError::Length`] unless the file has [`FILE_LEN`]
/// bytes, and [`ReleaseError::Framing`] for any other spelling.
pub fn decode_licence_file(bytes: &[u8]) -> Result<Vec<u8>, ReleaseError> {
    if bytes.len() != FILE_LEN {
        return Err(ReleaseError::Length);
    }
    let line = bytes
        .strip_prefix(FILE_BEGIN.as_bytes())
        .and_then(|r| r.strip_suffix(FILE_END.as_bytes()))
        .and_then(|r| r.strip_suffix(b"\n".as_slice()))
        .ok_or(ReleaseError::Framing)?;
    let token = wire::unbase64(line).ok_or(ReleaseError::Framing)?;
    if token.len() != TOKEN_LEN {
        return Err(ReleaseError::Framing);
    }
    Ok(token)
}

/// Imports a licence file: decode, then verify under the keys in force
/// at `now` (Q41). The cell then stores the token sealed.
///
/// # Errors
///
/// As [`decode_licence_file`] and [`KeySet::verify_token`].
pub fn import_licence_file(
    bytes: &[u8],
    keys: &KeySet,
    now: i64,
) -> Result<VerifiedToken, ReleaseError> {
    let token = decode_licence_file(bytes)?;
    keys.verify_token(&token, now)
}

// ---------------------------------------------------------------------------
// Licence state.

/// One day in seconds.
pub const DAY_S: i64 = 86_400;

/// The licence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LicenceState {
    /// Valid until a time.
    Valid {
        /// UTC seconds.
        until: i64,
    },
    /// In the P-43 grace period.
    Grace {
        /// UTC seconds.
        since: i64,
        /// UTC seconds.
        ends: i64,
    },
    /// Expired.
    Expired {
        /// UTC seconds.
        since: i64,
    },
    /// No licence.
    Missing,
}

/// The licence state at `now`, with a grace period of `p43_days` (P-43).
///
/// Valid before `not_after`. In grace from `not_after` until
/// `not_after + p43_days` days, that end excluded. Expired from then on.
/// Missing without a token. Sums saturate, so a token near the end of
/// time never wraps into the past.
///
/// Reading (W1g): `self-hosted-services.md` says "a failed refresh starts
/// a grace period". A failed refresh changes no token, so the grace runs
/// from the token's `not_after`, and `last_ok` changes nothing.
///
/// # Errors
///
/// None. The `Result` stays so that callers keep one error path for
/// every operation of this crate.
pub fn licence_state(
    token: Option<&VerifiedToken>,
    last_ok: Option<i64>,
    now: i64,
    p43_days: u16,
) -> Result<LicenceState, ReleaseError> {
    let _ = last_ok;
    let Some(t) = token else {
        return Ok(LicenceState::Missing);
    };
    if now < t.not_after {
        return Ok(LicenceState::Valid { until: t.not_after });
    }
    let grace = i64::from(p43_days).saturating_mul(DAY_S);
    let ends = t.not_after.saturating_add(grace);
    if now < ends {
        Ok(LicenceState::Grace {
            since: t.not_after,
            ends,
        })
    } else {
        Ok(LicenceState::Expired { since: ends })
    }
}

// ---------------------------------------------------------------------------
// The gate.

/// What a licence check gates. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum GateKind {
    /// Evaluation commands. Protected (I-39).
    Evaluation,
    /// Payment commands. Protected (I-39).
    Payments,
    /// Outbox notifications. Protected (I-39).
    Notifications,
    /// The export entry point. Protected (I-39).
    Export,
    /// Programme and call setup.
    Setup,
    /// Applying an update.
    ApplyUpdate,
}

impl GateKind {
    /// Every row of the `permits` table.
    pub const ALL: [GateKind; 6] = [
        GateKind::Evaluation,
        GateKind::Payments,
        GateKind::Notifications,
        GateKind::Export,
        GateKind::Setup,
        GateKind::ApplyUpdate,
    ];

    /// Whether I-39 protects the row: no licence state may block it.
    #[must_use]
    pub const fn protected(self) -> bool {
        match self {
            GateKind::Evaluation
            | GateKind::Payments
            | GateKind::Notifications
            | GateKind::Export => true,
            GateKind::Setup | GateKind::ApplyUpdate => false,
        }
    }
}

/// Whether the state permits `kind`.
///
/// A protected row is permitted in every state (I-39). Every other row
/// is permitted in every state too in M3, since licence expiry blocks
/// nothing (Q18 interim, design section 17.2).
///
/// # Errors
///
/// None. The `Result` stays so that callers keep one error path for
/// every operation of this crate.
pub fn permits(state: LicenceState, kind: GateKind) -> Result<bool, ReleaseError> {
    let _ = state;
    let permitted = match kind {
        // I-39: never blocked, in any state.
        GateKind::Evaluation | GateKind::Payments | GateKind::Notifications | GateKind::Export => {
            true
        }
        // Q18 interim: licence expiry blocks nothing in M3.
        GateKind::Setup | GateKind::ApplyUpdate => true,
    };
    Ok(permitted)
}
