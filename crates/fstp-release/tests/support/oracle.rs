//! The test oracle of the `fstp-release` crate tests.
//!
//! It restates the W1g wire proposal of
//! `crates/fstp-celltest/src/reference/licence.rs` from design section 10,
//! so these tests and the cross-crate tests constrain the same bytes. The
//! crate tests cannot depend on `fstp-celltest`, which depends on this
//! crate. The oracle names no production item of `fstp-release`.
//!
//! One part is new here: the release metadata signature. The W1g
//! reference leaves it to the caller. This oracle proposes a composite
//! Ed25519 plus ML-DSA-65 signature over the metadata body with the
//! context [`METADATA_CONTEXT`] (ADR-010 encoding, accepted 2026-10-29).

#![allow(dead_code)]

use std::collections::BTreeSet;

use fstp_crypto::composite::CompositeSigningKey;
use fstp_crypto::sig::Ed25519SigningKey;

/// One day in seconds.
pub(crate) const DAY_S: i64 = 86_400;
/// P-43, the licence refresh grace period: 30 days.
pub(crate) const P43_DAYS: u16 = 30;
/// An instant near the M3 test clock, in UTC seconds.
pub(crate) const T0: i64 = 1_800_000_000;

/// The grace length of `p43_days` days in seconds.
pub(crate) const fn grace_len(p43_days: u16) -> i64 {
    (p43_days as i64).saturating_mul(DAY_S)
}

/// An Ed25519 key from a one-byte seed.
pub(crate) fn key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(&[seed; 32]).unwrap()
}

// ---------------------------------------------------------------------------
// Requests (design section 10.1).

/// A product version.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Version(pub(crate) u16, pub(crate) u16, pub(crate) u16);

impl Version {
    /// `major.minor.patch` in decimal without leading zeros.
    pub(crate) fn render(self) -> String {
        format!("{}.{}.{}", self.0, self.1, self.2)
    }
}

/// The lowercase hex of `bytes`.
pub(crate) fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The update check template.
pub(crate) fn update_request(host: &str, channel: &str, v: Version) -> Vec<u8> {
    format!(
        "GET /v1/updates/{channel}/{} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        v.render()
    )
    .into_bytes()
}

/// The licence refresh template.
pub(crate) fn licence_request(host: &str, licence: [u8; 16], v: Version) -> Vec<u8> {
    let body = format!("{{\"version\":\"{}\"}}", v.render());
    format!(
        "POST /v1/licences/{}/refresh HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        lower_hex(&licence),
        body.len()
    )
    .into_bytes()
}

/// The value of the second line of `request` when it is a `Host` header.
pub(crate) fn host_of(request: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    let mut lines = text.split("\r\n");
    lines.next()?;
    Some(lines.next()?.strip_prefix("Host: ")?.to_owned())
}

/// Whether `host` is a plain lowercase DNS name of two or more labels.
pub(crate) fn host_ok(host: &str) -> bool {
    let labels: Vec<&str> = host.split('.').collect();
    host.len() <= 253
        && labels.len() >= 2
        && labels.iter().all(|l| {
            let b = l.as_bytes();
            !b.is_empty()
                && b.len() <= 63
                && b.iter()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
                && b.first() != Some(&b'-')
                && b.last() != Some(&b'-')
        })
        && labels
            .last()
            .is_some_and(|t| t.bytes().any(|c| c.is_ascii_lowercase()))
}

// ---------------------------------------------------------------------------
// Tokens (design section 10.2).

/// A licence kind of the W1g proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Kind {
    /// Code 1.
    Commercial,
    /// Code 2 (O-27).
    Noncommercial,
}

impl Kind {
    /// Every kind.
    pub(crate) const ALL: [Kind; 2] = [Kind::Commercial, Kind::Noncommercial];

    /// The kind byte.
    pub(crate) const fn code(self) -> u8 {
        match self {
            Kind::Commercial => 1,
            Kind::Noncommercial => 2,
        }
    }
}

/// The fields of a licence token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Token {
    /// The licence id.
    pub(crate) licence: [u8; 16],
    /// The kind.
    pub(crate) kind: Kind,
    /// UTC seconds.
    pub(crate) issued_at: i64,
    /// UTC seconds.
    pub(crate) refresh_after: i64,
    /// UTC seconds.
    pub(crate) not_after: i64,
}

/// The token magic.
pub(crate) const TOKEN_MAGIC: [u8; 8] = *b"FSTPLT01";
/// The token signature context.
pub(crate) const TOKEN_CONTEXT: &[u8] = b"fstp-licence-token-v1";
/// The token body length.
pub(crate) const TOKEN_BODY_LEN: usize = 8 + 16 + 1 + 3 * 8;
/// The token length: body and Ed25519 signature.
pub(crate) const TOKEN_LEN: usize = TOKEN_BODY_LEN + 64;

/// The token body with a raw kind byte, so tests can write unknown kinds.
pub(crate) fn token_body_raw(t: &Token, kind: u8) -> Vec<u8> {
    let mut out = TOKEN_MAGIC.to_vec();
    out.extend_from_slice(&t.licence);
    out.push(kind);
    out.extend_from_slice(&t.issued_at.to_be_bytes());
    out.extend_from_slice(&t.refresh_after.to_be_bytes());
    out.extend_from_slice(&t.not_after.to_be_bytes());
    out
}

/// `body` signed under `context`: `body || Ed25519(context || 0x00 || body)`.
pub(crate) fn sign_body(key: &Ed25519SigningKey, context: &[u8], body: Vec<u8>) -> Vec<u8> {
    let mut msg = context.to_vec();
    msg.push(0);
    msg.extend_from_slice(&body);
    let sig = key.sign(&msg).unwrap();
    let mut out = body;
    out.extend_from_slice(&sig);
    out
}

/// The signed token.
pub(crate) fn sign_token(t: &Token, key: &Ed25519SigningKey) -> Vec<u8> {
    sign_body(key, TOKEN_CONTEXT, token_body_raw(t, t.kind.code()))
}

/// A token of ordered instants around [`T0`].
pub(crate) fn gen_token(g: &mut fstp_prop::Gen) -> Token {
    let mut licence = [0u8; 16];
    for b in &mut licence {
        *b = g.u8();
    }
    let issued_at = T0 + g.i64_in(-30 * DAY_S..=30 * DAY_S);
    let refresh_after = issued_at + g.i64_in(0..=14 * DAY_S);
    Token {
        licence,
        kind: *g.pick(&Kind::ALL),
        issued_at,
        refresh_after,
        not_after: refresh_after + g.i64_in(0..=14 * DAY_S),
    }
}

// ---------------------------------------------------------------------------
// Key set and transitions (design section 10.2).

/// A key transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Transition {
    /// The next key.
    pub(crate) next_key: [u8; 32],
    /// UTC seconds.
    pub(crate) not_before: i64,
}

/// The transition magic.
pub(crate) const TRANSITION_MAGIC: [u8; 8] = *b"FSTPKT01";
/// The transition signature context.
pub(crate) const TRANSITION_CONTEXT: &[u8] = b"fstp-licence-key-transition-v1";
/// The transition length: magic, key, `not_before` and signature.
pub(crate) const TRANSITION_LEN: usize = 8 + 32 + 8 + 64;

/// The signed transition.
pub(crate) fn sign_transition(t: &Transition, key: &Ed25519SigningKey) -> Vec<u8> {
    let mut body = TRANSITION_MAGIC.to_vec();
    body.extend_from_slice(&t.next_key);
    body.extend_from_slice(&t.not_before.to_be_bytes());
    sign_body(key, TRANSITION_CONTEXT, body)
}

/// A key set as a set of `(key, not_before)`. A shipped key has
/// `i64::MIN`.
pub(crate) type KeySet = BTreeSet<([u8; 32], i64)>;

/// The set shipped with a release.
pub(crate) fn shipped(keys: &[[u8; 32]]) -> KeySet {
    keys.iter().map(|k| (*k, i64::MIN)).collect()
}

/// The keys of `set` in force at `now`.
pub(crate) fn current(set: &KeySet, now: i64) -> Vec<[u8; 32]> {
    set.iter()
        .filter(|(_, nb)| *nb <= now)
        .map(|(k, _)| *k)
        .collect()
}

/// `set` after `t` was accepted. A key already present keeps its earlier
/// `not_before`.
pub(crate) fn with(set: &KeySet, t: &Transition) -> KeySet {
    let mut next = set.clone();
    if !next.iter().any(|(k, _)| *k == t.next_key) {
        next.insert((t.next_key, t.not_before));
    }
    next
}

// ---------------------------------------------------------------------------
// Refresh response (design section 10.2, W1g proposal).

/// The refresh response magic.
pub(crate) const RESPONSE_MAGIC: [u8; 8] = *b"FSTPRR01";

/// A refresh response body.
pub(crate) fn refresh_response(transition: Option<&[u8]>, token: &[u8]) -> Vec<u8> {
    let mut out = RESPONSE_MAGIC.to_vec();
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

/// Which of `keys` verifies `sig` over `context || 0x00 || body`.
fn signed_by(keys: &[[u8; 32]], context: &[u8], body: &[u8], sig: &[u8]) -> bool {
    let mut msg = context.to_vec();
    msg.push(0);
    msg.extend_from_slice(body);
    keys.iter()
        .any(|k| fstp_crypto::sig::ed25519_verify(k, &msg, sig).is_ok())
}

/// The oracle token check: exact length and magic, then the signature
/// under any of `keys`, then the kind and the instant order.
pub(crate) fn verify_token(bytes: &[u8], keys: &[[u8; 32]]) -> Option<Token> {
    if bytes.len() != TOKEN_LEN || bytes.get(..8) != Some(TOKEN_MAGIC.as_slice()) {
        return None;
    }
    let (body, sig) = bytes.split_at(TOKEN_BODY_LEN);
    if !signed_by(keys, TOKEN_CONTEXT, body, sig) {
        return None;
    }
    let kind = match body[24] {
        1 => Kind::Commercial,
        2 => Kind::Noncommercial,
        _ => return None,
    };
    let at = |i: usize| i64::from_be_bytes(body[i..i + 8].try_into().unwrap());
    let t = Token {
        licence: body[8..24].try_into().unwrap(),
        kind,
        issued_at: at(25),
        refresh_after: at(33),
        not_after: at(41),
    };
    (t.issued_at <= t.refresh_after && t.refresh_after <= t.not_after).then_some(t)
}

/// The oracle transition check under the keys of `set` in force at `now`.
pub(crate) fn verify_transition(bytes: &[u8], set: &KeySet, now: i64) -> Option<Transition> {
    if bytes.len() != TRANSITION_LEN || bytes.get(..8) != Some(TRANSITION_MAGIC.as_slice()) {
        return None;
    }
    let (body, sig) = bytes.split_at(TRANSITION_LEN - 64);
    if !signed_by(&current(set, now), TRANSITION_CONTEXT, body, sig) {
        return None;
    }
    Some(Transition {
        next_key: body[8..40].try_into().unwrap(),
        not_before: i64::from_be_bytes(body[40..48].try_into().unwrap()),
    })
}

/// The oracle refresh step (W1g `apply_refresh`): framing, then any
/// transition under the keys in force at `now`, then the token under the
/// resulting set in force at `now`, then same licence and not older. All
/// or nothing.
pub(crate) fn apply_refresh(
    stored: &Token,
    keys: &KeySet,
    response: &[u8],
    now: i64,
) -> Option<(Token, KeySet)> {
    let rest = response.strip_prefix(RESPONSE_MAGIC.as_slice())?;
    let (flag, rest) = rest.split_first()?;
    let (transition, token) = match flag {
        0 => (None, rest),
        1 => {
            let (t, token) = rest.split_at_checked(TRANSITION_LEN)?;
            (Some(t), token)
        }
        _ => return None,
    };
    if token.len() != TOKEN_LEN {
        return None;
    }
    let next = match transition {
        None => keys.clone(),
        Some(t) => with(keys, &verify_transition(t, keys, now)?),
    };
    let token = verify_token(token, &current(&next, now))?;
    if token.licence != stored.licence {
        return None;
    }
    let stale = token.issued_at < stored.issued_at
        || (token.issued_at == stored.issued_at && token != *stored);
    (!stale).then_some((token, next))
}

// ---------------------------------------------------------------------------
// Licence file (Q41).

/// The first line of a licence file.
pub(crate) const FILE_BEGIN: &str = "-----BEGIN FSTP LICENCE-----\n";
/// The last line of a licence file.
pub(crate) const FILE_END: &str = "-----END FSTP LICENCE-----\n";

/// The licence file of `token`.
pub(crate) fn licence_file(token: &[u8]) -> Vec<u8> {
    format!("{FILE_BEGIN}{}\n{FILE_END}", base64(token)).into_bytes()
}

/// Standard padded base64 (RFC 4648 section 4).
pub(crate) fn base64(bytes: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let b = [
            chunk.first().copied().unwrap_or(0),
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let n = u32::from(b[0]) << 16 | u32::from(b[1]) << 8 | u32::from(b[2]);
        for i in 0..4usize {
            if i <= chunk.len() {
                out.push(char::from(B64[((n >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Licence state (design section 10.2, P-43).

/// The oracle licence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum State {
    /// Valid until `not_after`.
    Valid {
        /// UTC seconds.
        until: i64,
    },
    /// In grace from `not_after`.
    Grace {
        /// UTC seconds.
        since: i64,
        /// UTC seconds.
        ends: i64,
    },
    /// Expired from the grace end.
    Expired {
        /// UTC seconds.
        since: i64,
    },
    /// No token.
    Missing,
}

/// The state of `token` at `now`. `last_ok` changes nothing (W1g
/// reading), and sums saturate.
pub(crate) fn licence_state(token: Option<&Token>, now: i64, p43_days: u16) -> State {
    let Some(t) = token else {
        return State::Missing;
    };
    if now < t.not_after {
        return State::Valid { until: t.not_after };
    }
    let ends = t.not_after.saturating_add(grace_len(p43_days));
    if now < ends {
        State::Grace {
            since: t.not_after,
            ends,
        }
    } else {
        State::Expired { since: ends }
    }
}

// ---------------------------------------------------------------------------
// Release metadata (design section 10.3).

/// The fields of release metadata (W1g proposal).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Metadata {
    /// The channel code: 1 is stable.
    pub(crate) channel: u8,
    /// The metadata version.
    pub(crate) seq: u64,
    /// The product version.
    pub(crate) version: Version,
    /// UTC seconds. Expired from this instant on.
    pub(crate) expires_at: i64,
    /// SHA-256 of the artifact.
    pub(crate) artifact_sha256: [u8; 32],
}

/// The metadata magic.
pub(crate) const METADATA_MAGIC: [u8; 8] = *b"FSTPRM01";
/// The metadata body length.
pub(crate) const METADATA_BODY_LEN: usize = 8 + 1 + 8 + 6 + 8 + 32;
/// The composite signature context this oracle proposes.
pub(crate) const METADATA_CONTEXT: &[u8] = b"fstp-release-metadata-v1";
/// The signed metadata length.
pub(crate) const METADATA_LEN: usize = METADATA_BODY_LEN + fstp_crypto::composite::SIGNATURE_LEN;

/// The metadata body.
pub(crate) fn metadata_body(m: &Metadata) -> Vec<u8> {
    let mut out = METADATA_MAGIC.to_vec();
    out.push(m.channel);
    out.extend_from_slice(&m.seq.to_be_bytes());
    out.extend_from_slice(&m.version.0.to_be_bytes());
    out.extend_from_slice(&m.version.1.to_be_bytes());
    out.extend_from_slice(&m.version.2.to_be_bytes());
    out.extend_from_slice(&m.expires_at.to_be_bytes());
    out.extend_from_slice(&m.artifact_sha256);
    out
}

/// Metadata signed by a composite key under [`METADATA_CONTEXT`].
pub(crate) fn sign_metadata(m: &Metadata, key: &CompositeSigningKey) -> Vec<u8> {
    let body = metadata_body(m);
    let sig = key.sign_with_context(&body, METADATA_CONTEXT).unwrap();
    let mut out = body;
    out.extend_from_slice(&sig.to_bytes());
    out
}

/// Metadata with any composite-length signature bytes.
pub(crate) fn metadata_with_sig(m: &Metadata, sig: &[u8]) -> Vec<u8> {
    let mut out = metadata_body(m);
    out.extend_from_slice(sig);
    out
}

/// Random metadata on the stable channel.
pub(crate) fn gen_metadata(g: &mut fstp_prop::Gen, seq: u64, expires_at: i64) -> Metadata {
    let mut sha = [0u8; 32];
    for b in &mut sha {
        *b = g.u8();
    }
    Metadata {
        channel: 1,
        seq,
        version: Version(g.u16_in(0..=3), g.u16(), g.u16()),
        expires_at,
        artifact_sha256: sha,
    }
}

/// Why the oracle store refuses metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum MetaRefusal {
    /// The signature did not verify.
    Unverifiable,
    /// `expires_at <= now`.
    Expired,
    /// The metadata version is below the highest accepted.
    Rollback,
    /// The same metadata version with another body.
    Conflict,
}

/// The oracle store: the highest accepted verified metadata.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MetaStore {
    /// The accepted metadata with the highest version.
    pub(crate) highest: Option<Metadata>,
}

impl MetaStore {
    /// The verdict on `m` at `now`, and the store after it.
    pub(crate) fn accept(
        &self,
        m: &Metadata,
        verified: bool,
        now: i64,
    ) -> Result<MetaStore, MetaRefusal> {
        if !verified {
            return Err(MetaRefusal::Unverifiable);
        }
        if m.expires_at <= now {
            return Err(MetaRefusal::Expired);
        }
        match self.highest {
            Some(h) if m.seq < h.seq => Err(MetaRefusal::Rollback),
            Some(h) if m.seq == h.seq && *m != h => Err(MetaRefusal::Conflict),
            Some(h) if m.seq == h.seq => Ok(*self),
            _ => Ok(MetaStore { highest: Some(*m) }),
        }
    }
}
