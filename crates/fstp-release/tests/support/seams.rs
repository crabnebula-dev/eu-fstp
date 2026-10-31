//! The production seams of the `fstp-release` crate tests.
//!
//! Each function here calls `fstp-release` and maps its answer onto the
//! oracle types. Lane W2j closed every seam below with a call into the
//! production API and changed nothing else in the tests. A stub refusal
//! is still named by [`stub_msg`], so a regression to a stub shows
//! `NotImplemented` first.

#![allow(dead_code)]

use fstp_release::ReleaseError;
use fstp_release::licence::{
    self as prod, Ed25519Public, GateKind, KeySet as ProdSet, LicenceId, LicenceKind, LicenceState,
    PinnedKey, VerifiedToken,
};
use fstp_release::metadata::{
    MetadataStore, ReleaseSigningKey, VerifiedMetadata, verify_metadata as prod_verify_metadata,
};

use crate::oracle::{
    self as o, KeySet, Kind, MetaRefusal, Metadata, State, Token, Transition, Version,
};

/// Closed by lane W2j: `LicenceKind` has `Commercial` (code 1) and
/// `Noncommercial` (code 2), the W1g token proposal (Q18, O-27).
pub(crate) const KIND_SEAM: &str = "fstp_release::licence::LicenceKind cannot say commercial or noncommercial (W1g token proposal; lane W2j)";

/// Closed by lane W2j: `GateKind::ALL` lists the six rows, and
/// `GateKind::protected` marks evaluation, payments, notifications and
/// export (design section 10.2).
pub(crate) const GATE_ROWS_SEAM: &str = "fstp_release::licence::GateKind has no protected rows and no list of its rows (design section 10.2; lane W2j)";

/// Closed by lane W2j: `fstp_release::licence::KeySet` (design section
/// 10.2).
pub(crate) const KEY_SET_SEAM: &str = "fstp_release::licence has no key set with transitions and not_before (design section 10.2; lane W2j)";

/// Closed by lane W2j: `fstp_release::licence::apply_refresh`.
pub(crate) const REFRESH_SEAM: &str = "fstp_release has no refresh step: no decoder of the refresh response body and no apply over the stored token and key set (design section 10.2; lane W2j)";

/// Closed by lane W2j: `fstp_release::metadata::verify_metadata` under a
/// `ReleaseSigningKey`, and `MetadataStore` (design section 10.3).
pub(crate) const METADATA_SEAM: &str = "fstp_release::metadata has no verifier under a test release key and no store of the highest metadata version (design section 10.3; lane W2j)";

/// Whether `e` is the W0 stub refusal.
pub(crate) fn is_stub(e: &ReleaseError) -> bool {
    matches!(e, ReleaseError::NotImplemented(_))
}

/// The stub refusal as a test message, if `e` is one.
pub(crate) fn stub_msg(e: &ReleaseError) -> Option<String> {
    match e {
        ReleaseError::NotImplemented(op) => Some(format!("{op} is NotImplemented")),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Tokens.

/// The production kind of an oracle kind.
pub(crate) const fn prod_kind(k: Kind) -> LicenceKind {
    match k {
        Kind::Commercial => LicenceKind::Commercial,
        Kind::Noncommercial => LicenceKind::Noncommercial,
    }
}

/// The oracle kind of a production kind.
///
/// # Errors
///
/// None since lane W2j closed [`KIND_SEAM`].
pub(crate) fn oracle_kind(k: LicenceKind) -> Result<Kind, String> {
    Ok(match k {
        LicenceKind::Commercial => Kind::Commercial,
        LicenceKind::Noncommercial => Kind::Noncommercial,
    })
}

/// The production token of an oracle token.
pub(crate) const fn prod_token(t: &Token) -> VerifiedToken {
    VerifiedToken {
        licence: LicenceId(t.licence),
        kind: prod_kind(t.kind),
        issued_at: t.issued_at,
        refresh_after: t.refresh_after,
        not_after: t.not_after,
    }
}

/// The oracle token of a production token.
///
/// # Errors
///
/// As [`oracle_kind`].
pub(crate) fn oracle_token(t: &VerifiedToken) -> Result<Token, String> {
    Ok(Token {
        licence: t.licence.0,
        kind: oracle_kind(t.kind)?,
        issued_at: t.issued_at,
        refresh_after: t.refresh_after,
        not_after: t.not_after,
    })
}

/// `verify_token` under `key`: the token, or the typed refusal.
///
/// # Errors
///
/// The stub refusal by name.
pub(crate) fn verify(bytes: &[u8], key: [u8; 32]) -> Result<Result<Token, ReleaseError>, String> {
    match prod::verify_token(bytes, &Ed25519Public(key)) {
        Ok(t) => Ok(Ok(oracle_token(&t)?)),
        Err(e) => match stub_msg(&e) {
            Some(m) => Err(m),
            None => Ok(Err(e)),
        },
    }
}

// ---------------------------------------------------------------------------
// State and gate.

/// The oracle state of a production state.
pub(crate) const fn oracle_state(s: LicenceState) -> State {
    match s {
        LicenceState::Valid { until } => State::Valid { until },
        LicenceState::Grace { since, ends } => State::Grace { since, ends },
        LicenceState::Expired { since } => State::Expired { since },
        LicenceState::Missing => State::Missing,
    }
}

/// The production state of an oracle state.
pub(crate) const fn prod_state(s: State) -> LicenceState {
    match s {
        State::Valid { until } => LicenceState::Valid { until },
        State::Grace { since, ends } => LicenceState::Grace { since, ends },
        State::Expired { since } => LicenceState::Expired { since },
        State::Missing => LicenceState::Missing,
    }
}

/// `licence_state` over oracle types.
///
/// # Errors
///
/// The stub refusal by name, or the typed refusal as text.
pub(crate) fn state(
    token: Option<&Token>,
    last_ok: Option<i64>,
    now: i64,
    p43_days: u16,
) -> Result<State, String> {
    let t = token.map(prod_token);
    prod::licence_state(t.as_ref(), last_ok, now, p43_days)
        .map(oracle_state)
        .map_err(|e| stub_msg(&e).unwrap_or_else(|| format!("licence_state refused: {e:?}")))
}

/// Every production gate row, with whether I-39 protects it.
///
/// # Errors
///
/// The stub refusal of `permits` by name.
pub(crate) fn gate_rows() -> Result<Vec<(GateKind, bool)>, String> {
    if let Err(e) = prod::permits(LicenceState::Missing, GateKind::ApplyUpdate)
        && let Some(m) = stub_msg(&e)
    {
        return Err(m);
    }
    Ok(GateKind::ALL.iter().map(|k| (*k, k.protected())).collect())
}

/// `permits` as a test verdict.
///
/// # Errors
///
/// The stub refusal by name, or the typed refusal as text.
pub(crate) fn permits(state: State, kind: GateKind) -> Result<bool, String> {
    prod::permits(prod_state(state), kind)
        .map_err(|e| stub_msg(&e).unwrap_or_else(|| format!("permits refused: {e:?}")))
}

// ---------------------------------------------------------------------------
// Key set.

/// The production set of an oracle set, in the oracle's order.
fn prod_set(keys: &KeySet) -> Result<ProdSet, String> {
    let pinned: Vec<PinnedKey> = keys
        .iter()
        .map(|(k, nb)| PinnedKey {
            key: Ed25519Public(*k),
            not_before: *nb,
        })
        .collect();
    ProdSet::from_pinned(&pinned).map_err(|e| format!("KeySet::from_pinned refused: {e:?}"))
}

/// The oracle set of a production set.
fn oracle_set(set: &ProdSet) -> KeySet {
    set.keys().iter().map(|p| (p.key.0, p.not_before)).collect()
}

/// Production's licence key set, over oracle types.
#[derive(Debug)]
pub(crate) struct ProdKeySet {
    set: ProdSet,
}

impl ProdKeySet {
    /// The set shipped with a release.
    ///
    /// # Errors
    ///
    /// The typed refusal of `KeySet::shipped` as text.
    pub(crate) fn shipped(keys: &[[u8; 32]]) -> Result<ProdKeySet, String> {
        let keys: Vec<Ed25519Public> = keys.iter().copied().map(Ed25519Public).collect();
        let set = ProdSet::shipped(&keys).map_err(|e| format!("KeySet::shipped refused: {e:?}"))?;
        Ok(ProdKeySet { set })
    }

    /// Applies a signed transition at `now`: the accepted transition, or
    /// `None` when it is refused and the set is unchanged.
    ///
    /// # Errors
    ///
    /// The stub refusal by name.
    pub(crate) fn apply_transition(
        &mut self,
        bytes: &[u8],
        now: i64,
    ) -> Result<Option<Transition>, String> {
        match self.set.apply_transition(bytes, now) {
            Ok(t) => Ok(Some(Transition {
                next_key: t.next_key().0,
                not_before: t.not_before(),
            })),
            Err(e) => stub_msg(&e).map_or(Ok(None), Err),
        }
    }

    /// The keys and their `not_before`.
    ///
    /// # Errors
    ///
    /// None.
    pub(crate) fn keys(&self) -> Result<KeySet, String> {
        Ok(oracle_set(&self.set))
    }

    /// The token, if a key in force at `now` verifies it.
    ///
    /// # Errors
    ///
    /// The stub refusal by name.
    pub(crate) fn verify(&self, token: &[u8], now: i64) -> Result<Option<Token>, String> {
        match self.set.verify_token(token, now) {
            Ok(t) => oracle_token(&t).map(Some),
            Err(e) => stub_msg(&e).map_or(Ok(None), Err),
        }
    }
}

// ---------------------------------------------------------------------------
// Refresh.

/// Production's refresh step: the stored token and key set after
/// `response` applied at `now`, or `None` when it is refused.
///
/// # Errors
///
/// The stub refusal by name.
pub(crate) fn apply_refresh(
    stored: &Token,
    keys: &KeySet,
    response: &[u8],
    now: i64,
) -> Result<Option<(Token, KeySet)>, String> {
    let set = prod_set(keys)?;
    match prod::apply_refresh(&prod_token(stored), &set, response, now) {
        Ok(done) => Ok(Some((oracle_token(&done.token)?, oracle_set(&done.keys)))),
        Err(e) => stub_msg(&e).map_or(Ok(None), Err),
    }
}

// ---------------------------------------------------------------------------
// Metadata.

/// The oracle metadata of verified production metadata.
fn oracle_metadata(m: &VerifiedMetadata) -> Metadata {
    let v = m.version();
    Metadata {
        channel: m.channel().code(),
        seq: m.seq(),
        version: Version(v.0, v.1, v.2),
        expires_at: m.expires_at(),
        artifact_sha256: m.artifact_sha256(),
    }
}

/// The production release key of composite public key bytes.
fn release_key(public_key: &[u8]) -> Result<ReleaseSigningKey, String> {
    ReleaseSigningKey::from_bytes(public_key)
        .map_err(|e| format!("ReleaseSigningKey::from_bytes refused the test key: {e:?}"))
}

/// Production's verification of signed metadata under the composite
/// release signing key `public_key`: the fields, or `None` when refused.
/// In M3 no release root certifies a key (I-91), so only tests call this
/// with a key of their own.
///
/// # Errors
///
/// The stub refusal by name, or a refused test key.
pub(crate) fn verify_metadata(bytes: &[u8], public_key: &[u8]) -> Result<Option<Metadata>, String> {
    let key = release_key(public_key)?;
    match prod_verify_metadata(bytes, &key) {
        Ok(m) => Ok(Some(oracle_metadata(&m))),
        Err(e) => stub_msg(&e).map_or(Ok(None), Err),
    }
}

/// Production's store of the highest accepted metadata version.
#[derive(Debug)]
pub(crate) struct ProdMetaStore {
    store: MetadataStore,
}

impl ProdMetaStore {
    /// An empty store.
    ///
    /// # Errors
    ///
    /// None.
    pub(crate) fn new() -> Result<ProdMetaStore, String> {
        Ok(ProdMetaStore {
            store: MetadataStore::new(),
        })
    }

    /// Verifies `bytes` under `public_key`, then accepts it at `now` or
    /// names the refusal. A refusal leaves the store unchanged.
    ///
    /// # Errors
    ///
    /// The stub refusal by name, a refused test key, or a refusal the
    /// oracle has no name for.
    pub(crate) fn accept(
        &mut self,
        bytes: &[u8],
        public_key: &[u8],
        now: i64,
    ) -> Result<Result<(), MetaRefusal>, String> {
        let key = release_key(public_key)?;
        match self.store.accept_signed(bytes, &key, now) {
            Ok(()) => Ok(Ok(())),
            Err(ReleaseError::Length | ReleaseError::Magic | ReleaseError::Signature) => {
                Ok(Err(MetaRefusal::Unverifiable))
            }
            Err(ReleaseError::Expired) => Ok(Err(MetaRefusal::Expired)),
            Err(ReleaseError::Rollback) => Ok(Err(MetaRefusal::Rollback)),
            Err(ReleaseError::Conflict) => Ok(Err(MetaRefusal::Conflict)),
            Err(e) => Err(stub_msg(&e).unwrap_or_else(|| format!("accept refused: {e:?}"))),
        }
    }
}

/// The oracle verdict on `bytes` signed by `public_key`: verified exactly
/// when the composite signature over the body under
/// [`o::METADATA_CONTEXT`] verifies and the framing is exact.
pub(crate) fn oracle_verified(bytes: &[u8], public_key: &[u8]) -> bool {
    bytes.len() == o::METADATA_LEN
        && bytes.get(..8) == Some(o::METADATA_MAGIC.as_slice())
        && bytes
            .split_at_checked(o::METADATA_BODY_LEN)
            .is_some_and(|(b, s)| {
                fstp_crypto::composite::verify_with_context(public_key, b, o::METADATA_CONTEXT, s)
                    .is_ok()
            })
}
