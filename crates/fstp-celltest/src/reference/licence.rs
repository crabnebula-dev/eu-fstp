//! The reference licence and update protocol (I-38, I-39, TH-32). Lane
//! W1g owns this file.
//!
//! The reference is written from design section 10,
//! `SPEC/03-architecture/self-hosted-services.md`, ADR-004 ("Licence token
//! key") and `SPEC/02-domain/policy-parameters.md` (P-43). It names no
//! production item of `fstp-release`, `fstp-release-svc` or `fstp-cell`.
//! It uses M2 types only as data and classifies command kinds by its own
//! table.
//!
//! It covers:
//!
//! - what a self-hosted cell may send to a CrabNebula host: the two
//!   request templates of design section 10.1, and a parser that accepts
//!   exactly their bytes ([`parse_request`]);
//! - the licence token, its file form for the first import (Q41), the key
//!   set and its transitions, and the refresh response that may carry one
//!   (design section 10.2);
//! - the licence state over the P-43 grace period, and the gate that
//!   never blocks evaluation, payments, notifications or export (I-39,
//!   Q18 interim: nothing is blocked);
//! - release metadata with rollback, expiry and conflict refusal over
//!   verified metadata only, and the M3 rule that nothing is installed or
//!   announced (design section 10.3, TH-32).
//!
//! Every function is pure and total. No function panics, and time sums
//! saturate, so an overflow never wraps into the past.
//!
//! Readings the sources leave open are marked "Reading" in the item that
//! takes them. Lane W1g reports each one to Daniel. The wire formats of
//! the token, the transition, the licence file and the metadata are not
//! fixed by the design. The formats here are the W1g proposal, which lane
//! W2j builds to.

use fstp_crypto::sig::{self, ED25519_PUBLIC_KEY_LEN, ED25519_SIGNATURE_LEN, Ed25519SigningKey};
use fstp_domain::CommandKind;

use crate::NotImplemented;

// ---------------------------------------------------------------------------
// Clock and parameters.

/// One day in seconds. The `fstp-release` stub counts time in UTC seconds.
///
/// Reading: design section 14.1 asks for ticks one microsecond around the
/// grace end. The stub API counts seconds, so the reference ticks one
/// second, the smallest step that API can express.
pub const DAY_S: i64 = 86_400;

/// P-43, the licence refresh grace period: 30 days (O-28).
pub const P43_DAYS: u16 = 30;

/// The length of a grace period of `p43_days` days, in seconds.
#[must_use]
pub const fn grace_len(p43_days: u16) -> i64 {
    (p43_days as i64).saturating_mul(DAY_S)
}

// ---------------------------------------------------------------------------
// What a cell sends (design section 10.1, I-38).

/// A product version, `major.minor.patch`. Closed: three decimals.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefVersion {
    /// The major number.
    pub major: u16,
    /// The minor number.
    pub minor: u16,
    /// The patch number.
    pub patch: u16,
}

impl RefVersion {
    /// `major.minor.patch` in decimal, without leading zeros.
    #[must_use]
    pub fn render(&self) -> String {
        format!("{}.{}.{}", self.major, self.minor, self.patch)
    }

    /// Reads back exactly what [`RefVersion::render`] gives.
    #[must_use]
    pub fn parse(text: &str) -> Option<RefVersion> {
        let mut parts = text.split('.');
        let major = parse_decimal_u16(parts.next()?)?;
        let minor = parse_decimal_u16(parts.next()?)?;
        let patch = parse_decimal_u16(parts.next()?)?;
        if parts.next().is_some() {
            return None;
        }
        Some(RefVersion {
            major,
            minor,
            patch,
        })
    }
}

/// An update channel. Closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefChannel {
    /// The stable channel.
    Stable,
}

impl RefChannel {
    /// Every channel.
    pub const ALL: [RefChannel; 1] = [RefChannel::Stable];

    /// The channel's path segment.
    ///
    /// Reading: design section 10.1 names the segment `{channel}` without
    /// a spelling. The reference uses the lowercase name.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            RefChannel::Stable => "stable",
        }
    }

    /// The channel's byte in signed metadata.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            RefChannel::Stable => 1,
        }
    }
}

/// A licence id: 16 random bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefLicenceId(pub [u8; 16]);

impl RefLicenceId {
    /// The id's path segment: 32 lowercase hex digits.
    ///
    /// Reading: design section 10.1 names the segment `{licence}` without
    /// a spelling. The reference uses lowercase hex, one spelling per id.
    #[must_use]
    pub fn hex(&self) -> String {
        crate::canary::lower_hex(&self.0)
    }
}

/// A call to a CrabNebula host. Closed: the two calls of design section
/// 10.1. A third call, such as registration, does not exist (Q41).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefCall {
    /// The update check: version and channel only.
    Update {
        /// The running version.
        version: RefVersion,
        /// The channel.
        channel: RefChannel,
    },
    /// The licence refresh: licence id and version only.
    Licence {
        /// The licence.
        licence: RefLicenceId,
        /// The running version.
        version: RefVersion,
    },
}

/// The hosts the two calls go to. Each is a fixed production constant.
///
/// Reading: design section 10.1 names no host. The tests read each host
/// from one production request and require the same host on every other
/// request of that call, so only version, channel and licence id vary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RefHosts {
    /// The update service host.
    pub update: String,
    /// The licence service host.
    pub licence: String,
}

/// The update check request: `GET /v1/updates/{channel}/{version}` with
/// the `Host` header only, and no body, cookies or `User-Agent`.
#[must_use]
pub fn update_request(host: &str, version: RefVersion, channel: RefChannel) -> Vec<u8> {
    format!(
        "GET /v1/updates/{}/{} HTTP/1.1\r\nHost: {host}\r\n\r\n",
        channel.label(),
        version.render()
    )
    .into_bytes()
}

/// The licence refresh body: `{"version":"x.y.z"}`, nothing else.
#[must_use]
pub fn refresh_body(version: RefVersion) -> String {
    format!("{{\"version\":\"{}\"}}", version.render())
}

/// The licence refresh request: `POST /v1/licences/{licence}/refresh`
/// with `Host`, `Content-Type` and `Content-Length`, in that order, and
/// the body of [`refresh_body`].
///
/// Reading: design section 10.1 names `Content-Type` without a value. The
/// body is JSON, so the reference sends `application/json`.
#[must_use]
pub fn licence_request(host: &str, licence: RefLicenceId, version: RefVersion) -> Vec<u8> {
    let body = refresh_body(version);
    format!(
        "POST /v1/licences/{}/refresh HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        licence.hex(),
        body.len()
    )
    .into_bytes()
}

/// The request bytes of `call`.
#[must_use]
pub fn request(call: &RefCall, hosts: &RefHosts) -> Vec<u8> {
    match *call {
        RefCall::Update { version, channel } => update_request(&hosts.update, version, channel),
        RefCall::Licence { licence, version } => licence_request(&hosts.licence, licence, version),
    }
}

/// Whether `host` is a DNS host name: two to 127 labels of lowercase
/// letters, digits and inner dashes, each 1 to 63 bytes, 253 bytes in all.
/// No port, user part, address literal or upper case.
#[must_use]
pub fn host_ok(host: &str) -> bool {
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    let mut labels = 0usize;
    for label in host.split('.') {
        labels = labels.saturating_add(1);
        let bytes = label.as_bytes();
        let inner_ok = bytes
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        let edges_ok =
            bytes.first().is_some_and(|b| *b != b'-') && bytes.last().is_some_and(|b| *b != b'-');
        if bytes.is_empty() || bytes.len() > 63 || !inner_ok || !edges_ok {
            return false;
        }
    }
    let top_ok = host
        .rsplit('.')
        .next()
        .is_some_and(|t| t.bytes().any(|b| b.is_ascii_lowercase()));
    labels >= 2 && top_ok
}

/// The value of the second line of `request` when it is a `Host` header.
#[must_use]
pub fn host_of(request: &[u8]) -> Option<String> {
    let text = std::str::from_utf8(request).ok()?;
    let mut lines = text.split("\r\n");
    lines.next()?;
    let host = lines.next()?.strip_prefix("Host: ")?;
    Some(host.to_owned())
}

/// Why a captured request is not one of the two templates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TemplateBreach {
    /// The bytes are not UTF-8.
    NotUtf8,
    /// The request line names no permitted method and path.
    RequestLine(String),
    /// A path segment is outside its closed grammar.
    Segment(String),
    /// The body is not exactly `{"version":"x.y.z"}`.
    Body,
    /// The bytes hold more or other than the template: an extra header, a
    /// changed header, a wrong host or trailing bytes.
    NotTheTemplate,
}

/// The call that `bytes` carries, if `bytes` is exactly the template of
/// that call under `hosts`. This is the permitted-fields predicate of the
/// I-38 test-plan row: only version, channel and licence id may vary.
///
/// # Errors
///
/// Returns the first [`TemplateBreach`] found.
pub fn parse_request(bytes: &[u8], hosts: &RefHosts) -> Result<RefCall, TemplateBreach> {
    let text = std::str::from_utf8(bytes).map_err(|_| TemplateBreach::NotUtf8)?;
    let (line, _) = text
        .split_once("\r\n")
        .ok_or_else(|| TemplateBreach::RequestLine(String::new()))?;
    let mut parts = line.split(' ');
    let (Some(method), Some(target), Some("HTTP/1.1"), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(TemplateBreach::RequestLine(line.to_owned()));
    };
    let call = match method {
        "GET" => {
            let rest = target
                .strip_prefix("/v1/updates/")
                .ok_or_else(|| TemplateBreach::RequestLine(line.to_owned()))?;
            let (channel, version) = rest
                .split_once('/')
                .ok_or_else(|| TemplateBreach::Segment(rest.to_owned()))?;
            let channel = RefChannel::ALL
                .into_iter()
                .find(|c| c.label() == channel)
                .ok_or_else(|| TemplateBreach::Segment(channel.to_owned()))?;
            let version = RefVersion::parse(version)
                .ok_or_else(|| TemplateBreach::Segment(version.to_owned()))?;
            RefCall::Update { version, channel }
        }
        "POST" => {
            let id = target
                .strip_prefix("/v1/licences/")
                .and_then(|r| r.strip_suffix("/refresh"))
                .ok_or_else(|| TemplateBreach::RequestLine(line.to_owned()))?;
            let licence = crate::canary::parse_lower_hex_16(id)
                .map(RefLicenceId)
                .ok_or_else(|| TemplateBreach::Segment(id.to_owned()))?;
            let (_, body) = text.split_once("\r\n\r\n").ok_or(TemplateBreach::Body)?;
            let version = body
                .strip_prefix("{\"version\":\"")
                .and_then(|r| r.strip_suffix("\"}"))
                .and_then(RefVersion::parse)
                .ok_or(TemplateBreach::Body)?;
            RefCall::Licence { licence, version }
        }
        _ => return Err(TemplateBreach::RequestLine(line.to_owned())),
    };
    if request(&call, hosts) == bytes {
        Ok(call)
    } else {
        Err(TemplateBreach::NotTheTemplate)
    }
}

/// The calls of one outbound stream, each exactly a template, back to
/// back. A stream joins every write of one connection, so a request
/// written in parts reads the same as one written at once.
///
/// # Errors
///
/// Names the first bytes that start no template.
pub fn split_requests(bytes: &[u8], hosts: &RefHosts) -> Result<Vec<RefCall>, String> {
    let mut calls = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let found = (1..=rest.len()).find_map(|end| {
            let head = rest.get(..end)?;
            parse_request(head, hosts).ok().map(|call| (call, end))
        });
        let Some((call, end)) = found else {
            return Err(format!(
                "the stream holds bytes outside the templates: {:?}",
                String::from_utf8_lossy(rest)
            ));
        };
        calls.push(call);
        rest = rest.get(end..).unwrap_or_default();
    }
    Ok(calls)
}

/// A decimal `u16` without sign, leading zeros or other characters.
fn parse_decimal_u16(text: &str) -> Option<u16> {
    if text.is_empty() || text.len() > 5 || (text.len() > 1 && text.starts_with('0')) {
        return None;
    }
    if !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u16>().ok()
}

// ---------------------------------------------------------------------------
// Licence tokens (design section 10.2, ADR-004 "Licence token key").

/// A licence kind. Closed. Every token is for a self-hosted install, so
/// the kind says which licence the install holds.
///
/// Reading: `self-hosted-services.md` says every install, "commercial or
/// noncommercial", holds a token, and O-27 issues noncommercial tokens
/// automatically. Q18 may treat the two differently (A for noncommercial
/// installs, B still open for commercial ones). So the kind byte has one
/// code per licence now, and a later Q18 answer needs no token format
/// change. Lane W1g proposes these codes to lane W2j and Daniel.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefKind {
    /// A commercial licence.
    Commercial,
    /// A noncommercial licence (O-27).
    Noncommercial,
}

impl RefKind {
    /// Every kind.
    pub const ALL: [RefKind; 2] = [RefKind::Commercial, RefKind::Noncommercial];

    /// The kind's byte in a token.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            RefKind::Commercial => 1,
            RefKind::Noncommercial => 2,
        }
    }

    /// The kind of a token byte.
    #[must_use]
    pub const fn from_code(b: u8) -> Option<RefKind> {
        match b {
            1 => Some(RefKind::Commercial),
            2 => Some(RefKind::Noncommercial),
            _ => None,
        }
    }
}

/// The fields of a licence token.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefToken {
    /// The licence.
    pub licence: RefLicenceId,
    /// The kind.
    pub kind: RefKind,
    /// UTC seconds.
    pub issued_at: i64,
    /// UTC seconds. The cell refreshes from this instant on.
    pub refresh_after: i64,
    /// UTC seconds. The token is valid before this instant.
    pub not_after: i64,
}

/// The first bytes of every token.
pub const TOKEN_MAGIC: [u8; 8] = *b"FSTPLT01";
/// The domain separation context of a token signature.
pub const TOKEN_CONTEXT: &[u8] = b"fstp-licence-token-v1";
/// The length of a token body: magic, licence, kind and three instants.
pub const TOKEN_BODY_LEN: usize = 8 + 16 + 1 + 3 * 8;
/// The length of a token: body and Ed25519 signature.
pub const TOKEN_LEN: usize = TOKEN_BODY_LEN + ED25519_SIGNATURE_LEN;

/// The token body: `"FSTPLT01" || licence (16) || kind (1) ||
/// issued_at || refresh_after || not_after`, each instant an `i64`
/// big-endian.
#[must_use]
pub fn token_body(t: &RefToken) -> Vec<u8> {
    let mut out = Vec::with_capacity(TOKEN_BODY_LEN);
    out.extend_from_slice(&TOKEN_MAGIC);
    out.extend_from_slice(&t.licence.0);
    out.push(t.kind.code());
    out.extend_from_slice(&t.issued_at.to_be_bytes());
    out.extend_from_slice(&t.refresh_after.to_be_bytes());
    out.extend_from_slice(&t.not_after.to_be_bytes());
    out
}

/// What an Ed25519 signature covers: `context || 0x00 || body`.
fn signed_message(context: &[u8], body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(context.len().saturating_add(body.len()).saturating_add(1));
    out.extend_from_slice(context);
    out.push(0);
    out.extend_from_slice(body);
    out
}

fn sign_with(
    key: &Ed25519SigningKey,
    context: &[u8],
    body: Vec<u8>,
) -> Result<Vec<u8>, NotImplemented> {
    let sig = key.sign(&signed_message(context, &body)).map_err(|_| {
        NotImplemented::new("fstp_celltest::reference::licence: Ed25519 signing failed")
    })?;
    let mut out = body;
    out.extend_from_slice(&sig);
    Ok(out)
}

/// The signed token bytes: body and signature.
///
/// # Errors
///
/// Refuses when signing fails, which only an internal failure causes.
pub fn sign_token(t: &RefToken, key: &Ed25519SigningKey) -> Result<Vec<u8>, NotImplemented> {
    sign_with(key, TOKEN_CONTEXT, token_body(t))
}

/// Why a token is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TokenRefusal {
    /// Not exactly [`TOKEN_LEN`] bytes.
    Length,
    /// The magic is wrong.
    Magic,
    /// No key of the set verifies the signature.
    Signature,
    /// The kind byte is unknown.
    Kind,
    /// The instants are not `issued_at <= refresh_after <= not_after`.
    Order,
}

/// Which of `pinned` verifies `signature` over `context || 0x00 || body`.
fn signer(pinned: &[[u8; 32]], context: &[u8], body: &[u8], signature: &[u8]) -> Option<[u8; 32]> {
    let msg = signed_message(context, body);
    pinned
        .iter()
        .find(|k| sig::ed25519_verify(k.as_slice(), &msg, signature).is_ok())
        .copied()
}

fn be_i64(bytes: &[u8], at: usize) -> Option<i64> {
    let end = at.checked_add(8)?;
    let chunk: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(i64::from_be_bytes(chunk))
}

fn be_u64(bytes: &[u8], at: usize) -> Option<u64> {
    let end = at.checked_add(8)?;
    let chunk: [u8; 8] = bytes.get(at..end)?.try_into().ok()?;
    Some(u64::from_be_bytes(chunk))
}

fn be_u16(bytes: &[u8], at: usize) -> Option<u16> {
    let end = at.checked_add(2)?;
    let chunk: [u8; 2] = bytes.get(at..end)?.try_into().ok()?;
    Some(u16::from_be_bytes(chunk))
}

/// Verifies a token under any key of `pinned`, then reads its fields.
/// The signature is checked before any field is used.
///
/// # Errors
///
/// Returns the [`TokenRefusal`]. Framing (length, magic) is checked
/// first, then the signature, then the fields.
pub fn verify_token(bytes: &[u8], pinned: &[[u8; 32]]) -> Result<RefToken, TokenRefusal> {
    if bytes.len() != TOKEN_LEN {
        return Err(TokenRefusal::Length);
    }
    let (body, signature) = bytes
        .split_at_checked(TOKEN_BODY_LEN)
        .ok_or(TokenRefusal::Length)?;
    if body.get(..8) != Some(TOKEN_MAGIC.as_slice()) {
        return Err(TokenRefusal::Magic);
    }
    signer(pinned, TOKEN_CONTEXT, body, signature).ok_or(TokenRefusal::Signature)?;
    let licence: [u8; 16] = body
        .get(8..24)
        .and_then(|s| s.try_into().ok())
        .ok_or(TokenRefusal::Length)?;
    let kind = body
        .get(24)
        .copied()
        .and_then(RefKind::from_code)
        .ok_or(TokenRefusal::Kind)?;
    let issued_at = be_i64(body, 25).ok_or(TokenRefusal::Length)?;
    let refresh_after = be_i64(body, 33).ok_or(TokenRefusal::Length)?;
    let not_after = be_i64(body, 41).ok_or(TokenRefusal::Length)?;
    if !(issued_at <= refresh_after && refresh_after <= not_after) {
        return Err(TokenRefusal::Order);
    }
    Ok(RefToken {
        licence: RefLicenceId(licence),
        kind,
        issued_at,
        refresh_after,
        not_after,
    })
}

// ---------------------------------------------------------------------------
// The licence key set and its transitions (design section 10.2).

/// One pinned licence key and the instant it may first be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefPinned {
    /// The Ed25519 public key.
    pub key: [u8; ED25519_PUBLIC_KEY_LEN],
    /// UTC seconds. A key shipped with the release has `i64::MIN`.
    pub not_before: i64,
}

/// The licence key set: the keys shipped with the release, plus every key
/// added by an accepted transition.
#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefKeySet {
    /// The keys, in the order they joined.
    pub keys: Vec<RefPinned>,
}

impl RefKeySet {
    /// The set shipped with a release.
    #[must_use]
    pub fn shipped(keys: &[[u8; 32]]) -> RefKeySet {
        RefKeySet {
            keys: keys
                .iter()
                .map(|k| RefPinned {
                    key: *k,
                    not_before: i64::MIN,
                })
                .collect(),
        }
    }

    /// The keys in force at `now`: those whose `not_before` has passed.
    #[must_use]
    pub fn current(&self, now: i64) -> Vec<[u8; 32]> {
        self.keys
            .iter()
            .filter(|p| p.not_before <= now)
            .map(|p| p.key)
            .collect()
    }

    /// The set as a set: each pinned key with its `not_before`, in key
    /// order. Join order is no part of the design section 10.2 behaviour,
    /// so comparisons of two key sets use this form.
    #[must_use]
    pub fn canonical(&self) -> std::collections::BTreeSet<RefPinned> {
        self.keys.iter().copied().collect()
    }

    /// The set after `t` was accepted. A key already in the set keeps its
    /// earlier `not_before`.
    #[must_use]
    pub fn with(&self, t: &RefTransition) -> RefKeySet {
        let mut next = self.clone();
        if !next.keys.iter().any(|p| p.key == t.next_key) {
            next.keys.push(RefPinned {
                key: t.next_key,
                not_before: t.not_before,
            });
        }
        next
    }
}

/// A key transition: the next key and the instant it may first be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefTransition {
    /// The next key.
    pub next_key: [u8; ED25519_PUBLIC_KEY_LEN],
    /// UTC seconds.
    pub not_before: i64,
}

/// The first bytes of every key transition.
pub const TRANSITION_MAGIC: [u8; 8] = *b"FSTPKT01";
/// The domain separation context of a transition signature.
pub const TRANSITION_CONTEXT: &[u8] = b"fstp-licence-key-transition-v1";
/// The length of a transition body: magic, next key and `not_before`.
pub const TRANSITION_BODY_LEN: usize = 8 + ED25519_PUBLIC_KEY_LEN + 8;
/// The length of a transition: body and Ed25519 signature.
pub const TRANSITION_LEN: usize = TRANSITION_BODY_LEN + ED25519_SIGNATURE_LEN;

/// The transition body: `"FSTPKT01" || next_key (32) || not_before`.
#[must_use]
pub fn transition_body(t: &RefTransition) -> Vec<u8> {
    let mut out = Vec::with_capacity(TRANSITION_BODY_LEN);
    out.extend_from_slice(&TRANSITION_MAGIC);
    out.extend_from_slice(&t.next_key);
    out.extend_from_slice(&t.not_before.to_be_bytes());
    out
}

/// The signed transition bytes.
///
/// # Errors
///
/// Refuses when signing fails.
pub fn sign_transition(
    t: &RefTransition,
    key: &Ed25519SigningKey,
) -> Result<Vec<u8>, NotImplemented> {
    sign_with(key, TRANSITION_CONTEXT, transition_body(t))
}

/// Why a transition is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum TransitionRefusal {
    /// Not exactly [`TRANSITION_LEN`] bytes.
    Length,
    /// The magic is wrong.
    Magic,
    /// No key in force verifies the signature.
    Signature,
}

/// Verifies a transition under a key of `set` in force at `now`. A token
/// or transition signed by a key outside the set is refused, so rotation
/// runs only through a pinned key (design section 10.2, TH-32).
///
/// Reading: "signed by a current key" means a key in force at `now`, so a
/// key announced for later cannot sign before its `not_before`.
///
/// # Errors
///
/// Returns the [`TransitionRefusal`].
pub fn verify_transition(
    bytes: &[u8],
    set: &RefKeySet,
    now: i64,
) -> Result<RefTransition, TransitionRefusal> {
    if bytes.len() != TRANSITION_LEN {
        return Err(TransitionRefusal::Length);
    }
    let (body, signature) = bytes
        .split_at_checked(TRANSITION_BODY_LEN)
        .ok_or(TransitionRefusal::Length)?;
    if body.get(..8) != Some(TRANSITION_MAGIC.as_slice()) {
        return Err(TransitionRefusal::Magic);
    }
    signer(&set.current(now), TRANSITION_CONTEXT, body, signature)
        .ok_or(TransitionRefusal::Signature)?;
    let next_key: [u8; 32] = body
        .get(8..40)
        .and_then(|s| s.try_into().ok())
        .ok_or(TransitionRefusal::Length)?;
    let not_before = be_i64(body, 40).ok_or(TransitionRefusal::Length)?;
    Ok(RefTransition {
        next_key,
        not_before,
    })
}

// ---------------------------------------------------------------------------
// The refresh response (design section 10.2).

/// The first bytes of every refresh response body.
pub const RESPONSE_MAGIC: [u8; 8] = *b"FSTPRR01";

/// The refresh response body: [`RESPONSE_MAGIC`], one byte that is 0
/// without a transition and 1 with one, the signed transition if any,
/// then the signed token.
///
/// Reading: design section 10.2 says the refresh response "may carry" a
/// key transition and fixes no form. The reference proposes this binary
/// body, served as `application/octet-stream`, with at most one
/// transition. Lane W2j builds `egress_response_decode` to it.
#[must_use]
pub fn refresh_response(transition: Option<&[u8]>, token: &[u8]) -> Vec<u8> {
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

/// The signed transition, if any, and the signed token of a refresh
/// response body. The lengths are exact, so nothing else fits.
#[must_use]
pub fn split_refresh_response(bytes: &[u8]) -> Option<(Option<&[u8]>, &[u8])> {
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

/// Why a refresh response is refused. A refused response changes
/// nothing: the stored token and the key set stay as they were.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RefreshRefusal {
    /// The body is not a [`refresh_response`].
    Framing,
    /// The transition it carries is refused.
    Transition(TransitionRefusal),
    /// The token it carries is refused.
    Token(TokenRefusal),
    /// The token is for another licence.
    OtherLicence,
    /// The token is older than the stored one, or differs from it at the
    /// same issue instant. A replay of T1 after T2 would shorten the
    /// licence.
    Stale,
}

/// The stored token and key set after an accepted refresh.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refreshed {
    /// The token now stored.
    pub token: RefToken,
    /// The key set now pinned.
    pub keys: RefKeySet,
}

/// Applies a refresh response to the stored token and key set at `now`.
///
/// The order is fixed. The framing is checked first. Then any transition
/// is verified under the keys in force at `now`, and joins the set. Then
/// the token is verified under the keys of that set in force at `now`. So
/// a token signed by a key announced in the same response verifies only
/// from that key's `not_before` on. Last, the token must be for the
/// stored licence and must not be older than the stored token.
///
/// Reading: the response is all or nothing. A refused token also drops
/// the transition it came with, so a response never half applies. A
/// token equal to the stored one is accepted and changes nothing. A
/// different token with the same `issued_at` is refused as
/// [`RefreshRefusal::Stale`], since the service issues one token per
/// instant.
///
/// # Errors
///
/// Returns the first [`RefreshRefusal`].
pub fn apply_refresh(
    stored: &RefToken,
    keys: &RefKeySet,
    response: &[u8],
    now: i64,
) -> Result<Refreshed, RefreshRefusal> {
    let (transition, token) = split_refresh_response(response).ok_or(RefreshRefusal::Framing)?;
    let next = match transition {
        None => keys.clone(),
        Some(t) => keys.with(&verify_transition(t, keys, now).map_err(RefreshRefusal::Transition)?),
    };
    let token = verify_token(token, &next.current(now)).map_err(RefreshRefusal::Token)?;
    if token.licence != stored.licence {
        return Err(RefreshRefusal::OtherLicence);
    }
    let stale = token.issued_at < stored.issued_at
        || (token.issued_at == stored.issued_at && token != *stored);
    if stale {
        return Err(RefreshRefusal::Stale);
    }
    Ok(Refreshed { token, keys: next })
}

// ---------------------------------------------------------------------------
// The licence file of the first import (Q41).

/// The first line of a licence file.
pub const FILE_BEGIN: &str = "-----BEGIN FSTP LICENCE-----\n";
/// The last line of a licence file.
pub const FILE_END: &str = "-----END FSTP LICENCE-----\n";

/// The licence file of `token`: [`FILE_BEGIN`], the token in standard
/// padded base64 on one line, a line feed and [`FILE_END`].
///
/// Reading: design section 10.2 calls it "a signed token file" without a
/// form. The reference proposes this one-line armour, which a holder can
/// paste from the registration page.
#[must_use]
pub fn licence_file(token: &[u8]) -> Vec<u8> {
    format!("{FILE_BEGIN}{}\n{FILE_END}", base64(token)).into_bytes()
}

/// The token bytes inside a licence file, if `file` is exactly the
/// [`licence_file`] of a [`TOKEN_LEN`]-byte token. The signature is not
/// checked here; [`verify_token`] checks it next.
#[must_use]
pub fn decode_licence_file(file: &[u8]) -> Option<Vec<u8>> {
    let text = std::str::from_utf8(file).ok()?;
    let inner = text.strip_prefix(FILE_BEGIN)?.strip_suffix(FILE_END)?;
    let line = inner.strip_suffix('\n')?;
    let token = unbase64(line)?;
    (token.len() == TOKEN_LEN && licence_file(&token) == file).then_some(token)
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Standard padded base64 (RFC 4648 section 4).
#[must_use]
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3).saturating_mul(4));
    for chunk in bytes.chunks(3) {
        let b0 = chunk.first().copied().unwrap_or(0);
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        let n = u32::from(b0) << 16 | u32::from(b1) << 8 | u32::from(b2);
        let sextets = [n >> 18, n >> 12, n >> 6, n];
        for (i, s) in sextets.iter().enumerate() {
            if i <= chunk.len() {
                if let Some(c) = B64.get((s & 0x3f) as usize) {
                    out.push(char::from(*c));
                }
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// Decodes what [`base64`] gives. Returns `None` for any other text.
#[must_use]
pub fn unbase64(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len().saturating_mul(3) / 4);
    let value = |c: u8| -> Option<u32> {
        B64.iter()
            .position(|b| *b == c)
            .and_then(|p| u32::try_from(p).ok())
    };
    for quad in bytes.chunks(4) {
        let mut n = 0u32;
        let mut pad = 0usize;
        for c in quad {
            n <<= 6;
            if *c == b'=' {
                pad = pad.saturating_add(1);
            } else if pad > 0 {
                return None;
            } else {
                n |= value(*c)?;
            }
        }
        let [_, a, b, c] = n.to_be_bytes();
        let take = 3usize.checked_sub(pad)?;
        out.extend_from_slice([a, b, c].get(..take)?);
    }
    (base64(&out) == text).then_some(out)
}

// ---------------------------------------------------------------------------
// Licence state (design section 10.2, P-43).

/// The licence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefState {
    /// Valid until an instant.
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
    /// No licence was imported.
    Missing,
}

/// The kind of a licence state.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StateKind {
    /// [`RefState::Valid`].
    Valid,
    /// [`RefState::Grace`].
    Grace,
    /// [`RefState::Expired`].
    Expired,
    /// [`RefState::Missing`].
    Missing,
}

impl StateKind {
    /// Every kind.
    pub const ALL: [StateKind; 4] = [
        StateKind::Valid,
        StateKind::Grace,
        StateKind::Expired,
        StateKind::Missing,
    ];
}

impl RefState {
    /// The kind of the state.
    #[must_use]
    pub const fn kind(&self) -> StateKind {
        match self {
            RefState::Valid { .. } => StateKind::Valid,
            RefState::Grace { .. } => StateKind::Grace,
            RefState::Expired { .. } => StateKind::Expired,
            RefState::Missing => StateKind::Missing,
        }
    }
}

/// The licence state at `now` of the verified `token`, with a grace
/// period of `p43_days` days.
///
/// - No token: [`RefState::Missing`].
/// - Before `not_after`: [`RefState::Valid`] until `not_after`.
/// - From `not_after` for P-43: [`RefState::Grace`].
/// - From the grace end on: [`RefState::Expired`] since the grace end.
///
/// Reading: `self-hosted-services.md` says "a failed refresh starts a
/// grace period". The cell refreshes from `refresh_after` on, and only a
/// failed refresh lets the token reach `not_after`, so the grace period
/// starts there. The state is read from the token alone. `last_ok` (the
/// last successful refresh) changes no state, because a successful
/// refresh replaces the token. A token issued after `now` (clock skew) is
/// still valid, so a skewed clock never makes a licence look worse.
#[must_use]
pub fn licence_state(
    token: Option<&RefToken>,
    last_ok: Option<i64>,
    now: i64,
    p43_days: u16,
) -> RefState {
    let _ = last_ok;
    let Some(t) = token else {
        return RefState::Missing;
    };
    if now < t.not_after {
        return RefState::Valid { until: t.not_after };
    }
    let ends = t.not_after.saturating_add(grace_len(p43_days));
    if now < ends {
        RefState::Grace {
            since: t.not_after,
            ends,
        }
    } else {
        RefState::Expired { since: ends }
    }
}

// ---------------------------------------------------------------------------
// What the licence gate may touch (I-39, Q18).

/// What a licence check could gate. The first four are the I-39 classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RefClass {
    /// Evaluation: every command of the call cycle and the roles that run
    /// it. I-39.
    Evaluation,
    /// Payments: the payment request and release commands. I-39.
    Payments,
    /// Notifications: outbox events. I-39.
    Notifications,
    /// Export: the export entry point. I-39.
    Export,
    /// Creating a programme and publishing a call: the only commands that
    /// Q18 option B would gate, after the P-43 grace period.
    Setup,
    /// Applying an update.
    ApplyUpdate,
}

impl RefClass {
    /// Every class.
    pub const ALL: [RefClass; 6] = [
        RefClass::Evaluation,
        RefClass::Payments,
        RefClass::Notifications,
        RefClass::Export,
        RefClass::Setup,
        RefClass::ApplyUpdate,
    ];

    /// Whether I-39 protects the class: no licence state and no service
    /// outage may block it.
    #[must_use]
    pub const fn protected(self) -> bool {
        matches!(
            self,
            RefClass::Evaluation | RefClass::Payments | RefClass::Notifications | RefClass::Export
        )
    }
}

/// The class of a command kind.
///
/// Reading: I-39 names evaluation, payments, notifications and export.
/// The strict reading counts every command as evaluation unless it is a
/// payment command or one of the two Q18 option B commands. So role
/// grants and ends, vault changes, negotiation, execution and amendments
/// are protected too, since blocking them would stall an open call.
#[must_use]
pub const fn class_of(kind: CommandKind) -> RefClass {
    match kind {
        CommandKind::CreateProgramme | CommandKind::PublishCall => RefClass::Setup,
        CommandKind::RequestPayment
        | CommandKind::AcceptLine
        | CommandKind::ApprovePayment
        | CommandKind::ReleasePayment
        | CommandKind::ConfirmPaid
        | CommandKind::WithdrawPaymentRequest
        | CommandKind::RequestPaymentChanges
        | CommandKind::RecordChecks
        | CommandKind::ClosePaymentRequest => RefClass::Payments,
        // M6 lane L6-API: a copy request is a notification (R-SB-04).
        CommandKind::RequestCopy => RefClass::Notifications,
        // M4 changes D2 and D5: the activation and the round commands are
        // not Q18 option B commands, so the strict reading protects them.
        // Lane L12-I37: the calibration consent commands follow the strict
        // reading too.
        // M9 lane P1: so do the public choice commands, since a withdrawal
        // must never be blocked (I-43).
        CommandKind::SetPublicChoice
        | CommandKind::WithdrawPublicChoice
        | CommandKind::RequestCalibrationConsent
        | CommandKind::GiveCalibrationConsent
        | CommandKind::RevokeCalibrationConsent
        | CommandKind::ActivateProgramme
        | CommandKind::OpenCutOffRound
        | CommandKind::CastBallot
        | CommandKind::DelegateVote
        | CommandKind::EditPolicy
        | CommandKind::DraftCall
        | CommandKind::EditCall
        | CommandKind::ApproveCallPublication
        | CommandKind::GrantRole
        | CommandKind::EndRole
        | CommandKind::EndScheduledRole
        | CommandKind::ReinstateBinding
        | CommandKind::VaultChanged
        | CommandKind::CreateDraft
        | CommandKind::AddTeamMember
        | CommandKind::AddGuardian
        | CommandKind::RecordPlanVersion
        | CommandKind::Submit
        | CommandKind::DeclareConflict
        | CommandKind::Assign
        | CommandKind::Unassign
        | CommandKind::ReadContent
        | CommandKind::RecordKnockOut
        | CommandKind::AdmitToStage1
        | CommandKind::RecordScore
        | CommandKind::CorrectScore
        | CommandKind::RecordRankingSummary
        | CommandKind::CloseStage1
        | CommandKind::AskQuestion
        | CommandKind::RecordNoQuestions
        | CommandKind::AnswerQuestions
        | CommandKind::SubmitRevision
        | CommandKind::RankAfterStage2
        | CommandKind::ExpireStage2
        | CommandKind::RecordCutOff
        | CommandKind::RecordIrcReview
        | CommandKind::DeclineAfterConcern
        | CommandKind::ReEnter
        | CommandKind::DetermineAmount
        | CommandKind::AcceptGrant
        | CommandKind::ApproveGrant
        | CommandKind::ContractFact
        | CommandKind::DeclineNegotiation
        | CommandKind::Withdraw
        | CommandKind::StartExecution
        | CommandKind::Complete
        | CommandKind::Terminate
        | CommandKind::RecordDeliverable
        | CommandKind::ProposeAmendment
        | CommandKind::RouteAmendment
        | CommandKind::ActivateAmendment
        | CommandKind::CloseMilestone => RefClass::Evaluation,
    }
}

/// Whether the licence gate lets `class` run in `state`.
///
/// Q18 interim (design section 17.2, "Licence expiry: blocks nothing"):
/// true for every class in every state. I-39 alone requires it for the
/// protected classes.
#[must_use]
pub const fn permits(state: RefState, class: RefClass) -> bool {
    let _ = (state, class);
    true
}

// ---------------------------------------------------------------------------
// Release metadata (design section 10.3, TH-32).

/// The fields of release metadata.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RefMetadata {
    /// The channel.
    pub channel: RefChannel,
    /// The metadata version, one counter per channel. Rollback is judged
    /// on it.
    pub seq: u64,
    /// The product version the metadata describes.
    pub version: RefVersion,
    /// UTC seconds. The metadata is expired from this instant on.
    pub expires_at: i64,
    /// SHA-256 of the artifact.
    pub artifact_sha256: [u8; 32],
}

/// The first bytes of release metadata.
pub const METADATA_MAGIC: [u8; 8] = *b"FSTPRM01";
/// The length of a metadata body: magic, channel, seq, version, expiry and
/// artifact digest.
pub const METADATA_BODY_LEN: usize = 8 + 1 + 8 + 6 + 8 + 32;
/// The length of the composite Ed25519 plus ML-DSA-65 signature.
pub const METADATA_SIG_LEN: usize = fstp_crypto::composite::SIGNATURE_LEN;
/// The length of signed metadata.
pub const METADATA_LEN: usize = METADATA_BODY_LEN + METADATA_SIG_LEN;

/// The metadata body: `"FSTPRM01" || channel (1) || seq (u64) || major,
/// minor, patch (u16 each) || expires_at (i64) || artifact SHA-256`, all
/// big-endian.
#[must_use]
pub fn metadata_body(m: &RefMetadata) -> Vec<u8> {
    let mut out = Vec::with_capacity(METADATA_BODY_LEN);
    out.extend_from_slice(&METADATA_MAGIC);
    out.push(m.channel.code());
    out.extend_from_slice(&m.seq.to_be_bytes());
    out.extend_from_slice(&m.version.major.to_be_bytes());
    out.extend_from_slice(&m.version.minor.to_be_bytes());
    out.extend_from_slice(&m.version.patch.to_be_bytes());
    out.extend_from_slice(&m.expires_at.to_be_bytes());
    out.extend_from_slice(&m.artifact_sha256);
    out
}

/// Signed metadata bytes: the body, then `signature`, which the caller
/// gives. In M3 no release key is certified by the release root (I-91),
/// so no signature can be verified, and tests pass any bytes of
/// [`METADATA_SIG_LEN`].
#[must_use]
pub fn metadata_bytes(m: &RefMetadata, signature: &[u8]) -> Vec<u8> {
    let mut out = metadata_body(m);
    out.extend_from_slice(signature);
    out
}

/// The fields of signed metadata bytes, by framing only. Tests use it to
/// read back what they built. No acceptance path reads fields this way:
/// [`MetadataStore::accept_with`] takes metadata only with its verdict.
#[must_use]
pub fn metadata_fields(bytes: &[u8]) -> Option<RefMetadata> {
    if bytes.len() != METADATA_LEN || bytes.get(..8) != Some(METADATA_MAGIC.as_slice()) {
        return None;
    }
    let channel = RefChannel::ALL
        .into_iter()
        .find(|c| bytes.get(8) == Some(&c.code()))?;
    let artifact_sha256: [u8; 32] = bytes.get(31..63)?.try_into().ok()?;
    Some(RefMetadata {
        channel,
        seq: be_u64(bytes, 9)?,
        version: RefVersion {
            major: be_u16(bytes, 17)?,
            minor: be_u16(bytes, 19)?,
            patch: be_u16(bytes, 21)?,
        },
        expires_at: be_i64(bytes, 23)?,
        artifact_sha256,
    })
}

/// Why metadata is refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum MetadataRefusal {
    /// The signature was not verified. Design section 15: the signature
    /// is checked before any field is used, so no field of unverified
    /// metadata is read, and it never moves the rollback floor.
    Unverifiable,
    /// The metadata expired at or before now.
    Expired,
    /// The metadata version is below the highest seen (TH-32 rollback).
    Rollback,
    /// The metadata version equals the highest seen but the body differs.
    /// One metadata version names one body, so a second body under it is
    /// a forgery or an equivocation.
    Conflict,
}

/// What a cell remembers of release metadata: the verified metadata with
/// the highest metadata version it has accepted, per channel (one
/// channel in M3).
///
/// Reading: design section 10.3 says the cell "stores the highest
/// metadata version it has seen". The reference stores the highest
/// version it has accepted after verification, with its whole body. In
/// M3 no metadata verifies (I-91 lands in M9), so the store stays empty
/// and the cell holds no rollback state until then. Lane W1g raises this
/// consequence with the lead and Daniel against design section 10.3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MetadataStore {
    /// The accepted metadata with the highest metadata version, if any.
    pub highest: Option<RefMetadata>,
}

impl MetadataStore {
    /// What an M3 cell does with metadata it receives: the signature
    /// verifies only when [`M3_METADATA_VERIFIABLE`], so never, and every
    /// metadata is refused as [`MetadataRefusal::Unverifiable`].
    ///
    /// # Errors
    ///
    /// Returns the [`MetadataRefusal`]; the store is then unchanged.
    pub fn accept(&self, m: &RefMetadata, now: i64) -> Result<MetadataStore, MetadataRefusal> {
        self.accept_with(m, M3_METADATA_VERIFIABLE, now)
    }

    /// Whether `m` is accepted at `now`, and the store after it.
    /// `verified` says whether its signature verified under a release key
    /// that the release root certifies (I-91).
    ///
    /// The order: unverified metadata is refused before any field is read
    /// (design section 15). Then expiry, then rollback, then conflict.
    ///
    /// Reading: "refuses older or expired metadata" (design section 10.3).
    /// Older means a metadata version below the highest accepted. The
    /// same metadata fetched again is accepted and changes nothing, and
    /// another body under the same version is refused as
    /// [`MetadataRefusal::Conflict`]. Expired means `expires_at <= now`.
    ///
    /// # Errors
    ///
    /// Returns the [`MetadataRefusal`]; the store is then unchanged.
    pub fn accept_with(
        &self,
        m: &RefMetadata,
        verified: bool,
        now: i64,
    ) -> Result<MetadataStore, MetadataRefusal> {
        if !verified {
            return Err(MetadataRefusal::Unverifiable);
        }
        if m.expires_at <= now {
            return Err(MetadataRefusal::Expired);
        }
        match self.highest {
            Some(h) if m.seq < h.seq => Err(MetadataRefusal::Rollback),
            Some(h) if m.seq == h.seq && *m != h => Err(MetadataRefusal::Conflict),
            Some(h) if m.seq == h.seq => Ok(*self),
            _ => Ok(MetadataStore { highest: Some(*m) }),
        }
    }
}

/// Whether release metadata can be verified in M3: never, until the
/// release root certification of I-91 lands in M9 (design section 10.3).
pub const M3_METADATA_VERIFIABLE: bool = false;

/// Whether an update to `target` may be applied on a cell that runs
/// `running`: verified metadata, a target strictly newer than the running
/// version, no call with a proposal in STAGE1, STAGE2, RANKED or
/// IRC_REVIEW, and no payment release in flight (`self-hosted-services.md`,
/// design section 10.3).
///
/// Reading: `self-hosted-services.md` says cells "reject rollbacks to
/// older versions". The metadata counter alone does not say that, since
/// newer metadata may describe an older product version. So the target
/// must also be newer than the running version, and the same version is
/// not applied again.
#[must_use]
pub fn may_apply(
    verified: bool,
    running: RefVersion,
    target: RefVersion,
    evaluation_window_open: bool,
    release_in_flight: bool,
) -> bool {
    verified && target > running && !evaluation_window_open && !release_in_flight
}

/// Whether the cell may tell a tenant admin that an update is available.
/// Only verified metadata may, so in M3 nothing does (design section
/// 10.3, TH-32).
#[must_use]
pub const fn announces_update(verified: bool, newer_than_running: bool) -> bool {
    verified && newer_than_running
}
