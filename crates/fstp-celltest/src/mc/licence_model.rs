//! M-LICENCE (design section 14.2, I-39). Lane W1g owns this file.
//!
//! The universe: one licence, imported from a file (Q41) or never
//! imported. Its first token T1 and a refreshed token T2. Refresh
//! outcomes: success (a response carrying T2), failure, and five kinds
//! of garbage (an error page, T2 signed by a key outside the pinned set,
//! T2 with one flipped byte, a replay of T1, and a validly signed token
//! for another licence). A reduced clock: issue, `refresh_after`, and each `not_after`
//! and grace end with one tick before and after. Activities: an
//! evaluation command (`RecordScore`), a payment command
//! (`ReleasePayment`), a setup command (`CreateProgramme`), an outbox
//! notification and the export entry point.
//!
//! The model runs over a [`LicenceBackend`]: [`Reference`],
//! [`Production`] (`fstp_release::licence`) or a [`Mutant`] with one
//! seeded defect. Every decision the model records comes from the
//! backend: the import, the refresh, the licence state and the gate. The properties judge them by the reference.
//!
//! The command classifier is the reference's [`r::class_of`]. No
//! production classifier exists, since no command path reaches
//! `fstp-release` (layering rule 6).

use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::CommandKind;
use fstp_mc::{Model, Property};
use fstp_release::ReleaseError;
use fstp_release::licence::{
    self as prod, Ed25519Public, GateKind, KeySet, LicenceId, LicenceKind, LicenceState, PinnedKey,
    VerifiedToken,
};

use crate::NotImplemented;
use crate::reference::licence::{
    self as r, DAY_S, P43_DAYS, RefClass, RefKeySet, RefKind, RefLicenceId, RefState, RefToken,
    RefTransition, StateKind,
};

// ---------------------------------------------------------------------------
// The universe.

/// The instant the first token is issued: UTC seconds.
pub const T0: i64 = 1_800_000_000;

/// The licence of the universe.
pub const LICENCE: RefLicenceId = RefLicenceId([0x4c; 16]);

/// The first token: issued at [`T0`], refresh after 7 days, valid for 14.
pub const T1: RefToken = RefToken {
    licence: LICENCE,
    kind: RefKind::Noncommercial,
    issued_at: T0,
    refresh_after: T0 + 7 * DAY_S,
    not_after: T0 + 14 * DAY_S,
};

/// The refreshed token: issued at T1's `refresh_after`, valid 14 days
/// past T1.
pub const T2: RefToken = RefToken {
    licence: LICENCE,
    kind: RefKind::Noncommercial,
    issued_at: T0 + 7 * DAY_S,
    refresh_after: T0 + 21 * DAY_S,
    not_after: T0 + 28 * DAY_S,
};

/// A token for another licence, issued and valid as T2 and signed by the
/// pinned key. A refresh must never adopt it.
pub const FOREIGN: RefToken = RefToken {
    licence: RefLicenceId([0x4d; 16]),
    ..T2
};

/// The grace end of T1 under P-43.
pub const G1: i64 = T1.not_after + r::grace_len(P43_DAYS);
/// The grace end of T2 under P-43.
pub const G2: i64 = T2.not_after + r::grace_len(P43_DAYS);

/// The reduced clock, in order: issue, `refresh_after`, and each
/// `not_after` and grace end with one tick before and after (design
/// section 14.1).
pub const INSTANTS: [i64; 14] = [
    T0,
    T1.refresh_after,
    T1.not_after - 1,
    T1.not_after,
    T1.not_after + 1,
    T2.not_after - 1,
    T2.not_after,
    T2.not_after + 1,
    G1 - 1,
    G1,
    G1 + 1,
    G2 - 1,
    G2,
    G2 + 1,
];

/// The instant at clock index `i`.
pub fn instant(i: u8) -> i64 {
    INSTANTS.get(usize::from(i)).copied().unwrap_or(T0)
}

/// The seed of the pinned licence key.
pub const PINNED_SEED: [u8; 32] = [0x11; 32];
/// The seed of a key outside the pinned set.
pub const UNPINNED_SEED: [u8; 32] = [0x99; 32];

/// The bytes the universe sends a backend.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fixtures {
    /// The pinned key set shipped with the release.
    pub pinned: Vec<[u8; 32]>,
    /// The licence file of T1, signed by the pinned key.
    pub file_t1: Vec<u8>,
    /// The refresh response: T2, signed by the pinned key, without a
    /// transition.
    pub refresh_t2: Vec<u8>,
    /// Garbage refresh responses: an error page, T2 signed by an unpinned
    /// key, T2 with one flipped byte, a replay of T1, and [`FOREIGN`].
    /// The replay changes nothing while T1 is stored, and it is refused
    /// as stale once T2 is.
    pub garbage: Vec<Vec<u8>>,
}

impl Fixtures {
    /// Builds the fixtures from the two seeds.
    ///
    /// # Errors
    ///
    /// Refuses when a key cannot be built or cannot sign.
    pub fn new() -> Result<Fixtures, NotImplemented> {
        let key = |seed: &[u8; 32]| {
            Ed25519SigningKey::from_seed(seed)
                .map_err(|_| NotImplemented::new("fstp_celltest::mc::licence_model: Ed25519 key"))
        };
        let pinned = key(&PINNED_SEED)?;
        let unpinned = key(&UNPINNED_SEED)?;
        let t1 = r::sign_token(&T1, &pinned)?;
        let t2 = r::sign_token(&T2, &pinned)?;
        let response = |token: &[u8]| r::refresh_response(None, token);
        let refresh_t2 = response(&t2);
        let mut flipped = refresh_t2.clone();
        // Byte 30 of the response is byte 21 of the token, in its licence.
        if let Some(b) = flipped.get_mut(30) {
            *b ^= 0x01;
        }
        Ok(Fixtures {
            pinned: vec![pinned.public_key()],
            file_t1: r::licence_file(&t1),
            refresh_t2,
            garbage: vec![
                b"<html><body>502 Bad Gateway</body></html>".to_vec(),
                response(&r::sign_token(&T2, &unpinned)?),
                flipped,
                response(&t1),
                response(&r::sign_token(&FOREIGN, &pinned)?),
            ],
        })
    }
}

/// An activity of a tenant during the run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Activity {
    /// A command of the given kind.
    Command(CommandKind),
    /// An outbox notification.
    Notify,
    /// The export entry point.
    Export,
}

impl Activity {
    /// The activities of the universe.
    pub const ALL: [Activity; 5] = [
        Activity::Command(CommandKind::RecordScore),
        Activity::Command(CommandKind::ReleasePayment),
        Activity::Command(CommandKind::CreateProgramme),
        Activity::Notify,
        Activity::Export,
    ];

    /// The activity's class.
    pub const fn class(self) -> RefClass {
        match self {
            Activity::Command(k) => r::class_of(k),
            Activity::Notify => RefClass::Notifications,
            Activity::Export => RefClass::Export,
        }
    }
}

// ---------------------------------------------------------------------------
// Backends.

/// The decisions M-LICENCE asks of a backend.
pub trait LicenceBackend {
    /// The verified token of an imported licence file, or `None` when the
    /// file or its token is refused.
    fn import(&self, file: &[u8], pinned: &[[u8; 32]]) -> Result<Option<RefToken>, NotImplemented>;

    /// The token stored after a refresh response applied to `stored`
    /// under `keys` at `now`, or `None` when the response is refused.
    fn refresh(
        &self,
        stored: &RefToken,
        keys: &RefKeySet,
        response: &[u8],
        now: i64,
    ) -> Result<Option<RefToken>, NotImplemented>;

    /// The licence state.
    fn state(
        &self,
        token: Option<&RefToken>,
        last_ok: Option<i64>,
        now: i64,
        p43_days: u16,
    ) -> Result<RefState, NotImplemented>;

    /// Whether the gate lets `class` run in `state`.
    fn permits(&self, state: RefState, class: RefClass) -> Result<bool, NotImplemented>;
}

/// The reference backend.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Reference;

impl LicenceBackend for Reference {
    fn import(&self, file: &[u8], pinned: &[[u8; 32]]) -> Result<Option<RefToken>, NotImplemented> {
        Ok(r::decode_licence_file(file).and_then(|t| r::verify_token(&t, pinned).ok()))
    }

    fn refresh(
        &self,
        stored: &RefToken,
        keys: &RefKeySet,
        response: &[u8],
        now: i64,
    ) -> Result<Option<RefToken>, NotImplemented> {
        Ok(r::apply_refresh(stored, keys, response, now)
            .ok()
            .map(|done| done.token))
    }

    fn state(
        &self,
        token: Option<&RefToken>,
        last_ok: Option<i64>,
        now: i64,
        p43_days: u16,
    ) -> Result<RefState, NotImplemented> {
        Ok(r::licence_state(token, last_ok, now, p43_days))
    }

    fn permits(&self, state: RefState, class: RefClass) -> Result<bool, NotImplemented> {
        Ok(r::permits(state, class))
    }
}

/// The seam that stood for a class without a production `GateKind` row.
///
/// Design section 10.2: "The `permits` table already marks evaluation,
/// payments, notifications and export as protected." Lane W2j closed it:
/// `GateKind` has a row for every [`RefClass`], mapped in [`prod_gate`].
pub const GATE_ROWS_SEAM: &str = "fstp_release::licence::GateKind has no row for this class (design section 10.2: the permits table marks evaluation, payments, notifications and export as protected; lane W2j)";

/// The seam that stood for a licence kind production could not express.
///
/// The reference proposes `Commercial` and `Noncommercial` ([`RefKind`]).
/// Lane W2j closed it: `LicenceKind` has both, mapped in [`prod_token`]
/// and [`ref_token`].
pub const KIND_SEAM: &str = "fstp_release::licence::LicenceKind cannot say commercial or noncommercial (W1g token format proposal, Q18, O-27; lane W2j)";

/// The seam that stood for the missing production key set.
///
/// Design section 10.2: the cell pins a key set, and a transition signed
/// by a current key adds the next key from its `not_before` on. Lane W2j
/// closed it with `fstp_release::licence::KeySet`, mapped in
/// [`ProdKeySet`].
pub const KEY_SET_SEAM: &str = "fstp_release::licence has no key set: decode_key_transition takes no pinned set or now and returns no not_before, and verify_token takes one key (design section 10.2; lane W2j)";

/// The seam that stood for the missing production refresh handler.
///
/// Design section 10.2: the refresh response carries a token and may
/// carry a key transition. Lane W2j closed it with
/// `fstp_release::licence::apply_refresh`, mapped in [`prod_refresh`].
pub const REFRESH_SEAM: &str = "fstp_release has no refresh handler: no decoder of the refresh response and no apply step over the stored token and key set (design section 10.2, W1g response proposal; lane W2j)";

/// The seam that stood for the missing stateful metadata acceptance.
///
/// Design section 10.3: "The cell stores the highest metadata version it
/// has seen and refuses older or expired metadata." Lane W2j closed it
/// with `fstp_release::metadata::MetadataStore`, which
/// `th_32_update.rs` compares with [`r::MetadataStore::accept_with`].
pub const METADATA_STORE_SEAM: &str = "fstp_release::metadata has no stateful acceptance of verified metadata: no store of the highest metadata version and no expiry check (design section 10.3; lane W2j)";

/// The seam that stands for the missing admin view of update checks.
///
/// Design section 10.3: the admin view shows only the last check time
/// and outcome, and never "update available" in M3. Lane W3a gives it an
/// API.
pub const ANNOUNCE_SEAM: &str = "the admin view of update checks has no API: nothing reads whether the cell announced an update (design section 10.3; lane W3a)";

/// Every seam this module names. A test that meets one shows it by name.
pub const SEAMS: [&str; 6] = [
    GATE_ROWS_SEAM,
    KIND_SEAM,
    KEY_SET_SEAM,
    REFRESH_SEAM,
    METADATA_STORE_SEAM,
    ANNOUNCE_SEAM,
];

/// `e` as a test message: a seam by its text, a stub as NotImplemented.
pub fn seam_or_stub(e: &NotImplemented) -> String {
    if SEAMS.contains(&e.operation) {
        e.operation.to_owned()
    } else {
        format!("{} is NotImplemented", e.operation)
    }
}

/// The production backend: `fstp_release::licence`.
///
/// The import tries each pinned key in turn through `verify_token`, which
/// is what `KeySet::verify_token` does over shipped keys.
#[derive(Clone, Copy, Debug)]
pub struct Production {
    _probe: (),
}

/// The operation a `fstp-release` stub names, or `None` for a typed
/// refusal.
#[allow(
    unreachable_patterns,
    reason = "lane W2j adds typed refusals to ReleaseError; until then NotImplemented is its only variant"
)]
pub fn release_stub(e: &ReleaseError) -> Option<&'static str> {
    match e {
        ReleaseError::NotImplemented(op) => Some(op),
        _ => None,
    }
}

/// The production token of a reference token.
pub const fn prod_token(t: &RefToken) -> VerifiedToken {
    VerifiedToken {
        licence: LicenceId(t.licence.0),
        kind: match t.kind {
            RefKind::Commercial => LicenceKind::Commercial,
            RefKind::Noncommercial => LicenceKind::Noncommercial,
        },
        issued_at: t.issued_at,
        refresh_after: t.refresh_after,
        not_after: t.not_after,
    }
}

/// The reference kind of a production kind.
///
/// # Errors
///
/// None since lane W2j closed [`KIND_SEAM`].
pub const fn ref_kind(k: LicenceKind) -> Result<RefKind, NotImplemented> {
    match k {
        LicenceKind::Commercial => Ok(RefKind::Commercial),
        LicenceKind::Noncommercial => Ok(RefKind::Noncommercial),
    }
}

/// The reference token of a production token.
///
/// # Errors
///
/// As [`ref_kind`].
pub fn ref_token(t: &VerifiedToken) -> Result<RefToken, NotImplemented> {
    Ok(RefToken {
        licence: RefLicenceId(t.licence.0),
        kind: ref_kind(t.kind)?,
        issued_at: t.issued_at,
        refresh_after: t.refresh_after,
        not_after: t.not_after,
    })
}

/// The production state of a reference state.
pub const fn prod_state(s: RefState) -> LicenceState {
    match s {
        RefState::Valid { until } => LicenceState::Valid { until },
        RefState::Grace { since, ends } => LicenceState::Grace { since, ends },
        RefState::Expired { since } => LicenceState::Expired { since },
        RefState::Missing => LicenceState::Missing,
    }
}

/// The reference state of a production state.
pub const fn ref_state(s: LicenceState) -> RefState {
    match s {
        LicenceState::Valid { until } => RefState::Valid { until },
        LicenceState::Grace { since, ends } => RefState::Grace { since, ends },
        LicenceState::Expired { since } => RefState::Expired { since },
        LicenceState::Missing => RefState::Missing,
    }
}

/// The reference class of a production gate row.
pub const fn ref_gate(k: GateKind) -> RefClass {
    match k {
        GateKind::Evaluation => RefClass::Evaluation,
        GateKind::Payments => RefClass::Payments,
        GateKind::Notifications => RefClass::Notifications,
        GateKind::Export => RefClass::Export,
        GateKind::Setup => RefClass::Setup,
        GateKind::ApplyUpdate => RefClass::ApplyUpdate,
    }
}

/// The production gate row of a class, if `GateKind` has one. Since lane
/// W2j closed [`GATE_ROWS_SEAM`], every class has one.
pub const fn prod_gate(c: RefClass) -> Option<GateKind> {
    match c {
        RefClass::Evaluation => Some(GateKind::Evaluation),
        RefClass::Payments => Some(GateKind::Payments),
        RefClass::Notifications => Some(GateKind::Notifications),
        RefClass::Export => Some(GateKind::Export),
        RefClass::Setup => Some(GateKind::Setup),
        RefClass::ApplyUpdate => Some(GateKind::ApplyUpdate),
    }
}

/// `fstp_release::licence::verify_token` under any key of `pinned`:
/// `Ok(None)` when every key refuses it with a typed error.
///
/// # Errors
///
/// Returns the stub's [`NotImplemented`].
pub fn prod_verify(token: &[u8], pinned: &[[u8; 32]]) -> Result<Option<RefToken>, NotImplemented> {
    for k in pinned {
        match prod::verify_token(token, &Ed25519Public(*k)) {
            Ok(t) => return ref_token(&t).map(Some),
            Err(e) => {
                if let Some(op) = release_stub(&e) {
                    return Err(NotImplemented::new(op));
                }
            }
        }
    }
    Ok(None)
}

/// `fstp_release::licence::permits` for `class`, through its gate row.
///
/// # Errors
///
/// Returns the stub's [`NotImplemented`], or [`GATE_ROWS_SEAM`] when the
/// class has no row.
pub fn prod_permits(state: RefState, class: RefClass) -> Result<bool, NotImplemented> {
    let Some(k) = prod_gate(class) else {
        // A stub `permits` names itself first, so the seam shows only
        // once `permits` answers.
        if let Err(e) = prod::permits(prod_state(state), GateKind::ApplyUpdate)
            && let Some(op) = release_stub(&e)
        {
            return Err(NotImplemented::new(op));
        }
        return Err(NotImplemented::new(GATE_ROWS_SEAM));
    };
    prod::permits(prod_state(state), k).map_err(|e| {
        NotImplemented::new(release_stub(&e).unwrap_or("fstp_release::licence::permits refused"))
    })
}

/// Production's refresh step: the stored token and key set after
/// `response` applied to `stored` under `keys` at `now`, or `None` when
/// the response is refused. The tests compare it with
/// [`r::apply_refresh`].
///
/// # Errors
///
/// Returns the stub's [`NotImplemented`], or a refusal to hold the set.
pub fn prod_refresh(
    stored: &RefToken,
    keys: &RefKeySet,
    response: &[u8],
    now: i64,
) -> Result<Option<r::Refreshed>, NotImplemented> {
    let set = prod_key_set(keys)?;
    match prod::apply_refresh(&prod_token(stored), &set, response, now) {
        Ok(done) => Ok(Some(r::Refreshed {
            token: ref_token(&done.token)?,
            keys: ref_key_set(&done.keys),
        })),
        Err(e) => match release_stub(&e) {
            Some(op) => Err(NotImplemented::new(op)),
            None => Ok(None),
        },
    }
}

/// The production key set of a reference key set, in its join order.
///
/// # Errors
///
/// Refuses a set larger than `fstp_release::licence::MAX_KEYS`.
fn prod_key_set(keys: &RefKeySet) -> Result<KeySet, NotImplemented> {
    let pinned: Vec<PinnedKey> = keys
        .keys
        .iter()
        .map(|p| PinnedKey {
            key: Ed25519Public(p.key),
            not_before: p.not_before,
        })
        .collect();
    KeySet::from_pinned(&pinned).map_err(|e| {
        NotImplemented::new(
            release_stub(&e).unwrap_or("fstp_release::licence::KeySet::from_pinned refused"),
        )
    })
}

/// The reference key set of a production key set, in its join order.
fn ref_key_set(set: &KeySet) -> RefKeySet {
    RefKeySet {
        keys: set
            .keys()
            .iter()
            .map(|p| r::RefPinned {
                key: p.key.0,
                not_before: p.not_before,
            })
            .collect(),
    }
}

/// Production's licence key set (design section 10.2): built from the
/// shipped keys, changed only by accepted transitions, and asked which
/// tokens verify at an instant. The tests compare it with [`RefKeySet`].
///
/// Lane W2j closed [`KEY_SET_SEAM`]: this wraps
/// `fstp_release::licence::KeySet`.
#[derive(Clone, Debug)]
pub struct ProdKeySet {
    set: KeySet,
}

impl ProdKeySet {
    /// The set shipped with a release.
    ///
    /// # Errors
    ///
    /// Returns the stub's [`NotImplemented`], or a refusal to hold the
    /// set.
    pub fn shipped(keys: &[[u8; 32]]) -> Result<ProdKeySet, NotImplemented> {
        let keys: Vec<Ed25519Public> = keys.iter().copied().map(Ed25519Public).collect();
        let set = KeySet::shipped(&keys).map_err(|e| {
            NotImplemented::new(
                release_stub(&e).unwrap_or("fstp_release::licence::KeySet::shipped refused"),
            )
        })?;
        Ok(ProdKeySet { set })
    }

    /// Applies a signed transition at `now`: the accepted transition, or
    /// `None` when it is refused and the set is unchanged.
    ///
    /// # Errors
    ///
    /// Returns the stub's [`NotImplemented`].
    pub fn apply_transition(
        &mut self,
        bytes: &[u8],
        now: i64,
    ) -> Result<Option<RefTransition>, NotImplemented> {
        match self.set.apply_transition(bytes, now) {
            Ok(t) => Ok(Some(RefTransition {
                next_key: t.next_key().0,
                not_before: t.not_before(),
            })),
            Err(e) => match release_stub(&e) {
                Some(op) => Err(NotImplemented::new(op)),
                None => Ok(None),
            },
        }
    }

    /// The keys of the set and their `not_before`, in any order. Callers
    /// compare [`RefKeySet::canonical`], so a sorted or hashed production
    /// set need not keep join order.
    ///
    /// # Errors
    ///
    /// None.
    pub fn keys(&self) -> Result<RefKeySet, NotImplemented> {
        Ok(ref_key_set(&self.set))
    }

    /// The token, if a key of the set in force at `now` verifies it.
    ///
    /// # Errors
    ///
    /// Returns the stub's [`NotImplemented`].
    pub fn verify(&self, token: &[u8], now: i64) -> Result<Option<RefToken>, NotImplemented> {
        match self.set.verify_token(token, now) {
            Ok(t) => ref_token(&t).map(Some),
            Err(e) => match release_stub(&e) {
                Some(op) => Err(NotImplemented::new(op)),
                None => Ok(None),
            },
        }
    }
}

impl Production {
    /// The production backend, once `licence_state` answers.
    ///
    /// # Errors
    ///
    /// Returns the stub's [`NotImplemented`].
    pub fn new() -> Result<Production, NotImplemented> {
        let p = Production { _probe: () };
        p.state(None, None, T0, P43_DAYS)?;
        Ok(p)
    }
}

impl LicenceBackend for Production {
    fn import(&self, file: &[u8], pinned: &[[u8; 32]]) -> Result<Option<RefToken>, NotImplemented> {
        match prod::decode_licence_file(file) {
            Ok(token) => prod_verify(&token, pinned),
            Err(e) => match release_stub(&e) {
                Some(op) => Err(NotImplemented::new(op)),
                None => Ok(None),
            },
        }
    }

    fn refresh(
        &self,
        stored: &RefToken,
        keys: &RefKeySet,
        response: &[u8],
        now: i64,
    ) -> Result<Option<RefToken>, NotImplemented> {
        Ok(prod_refresh(stored, keys, response, now)?.map(|done| done.token))
    }

    fn state(
        &self,
        token: Option<&RefToken>,
        last_ok: Option<i64>,
        now: i64,
        p43_days: u16,
    ) -> Result<RefState, NotImplemented> {
        let t = token.map(prod_token);
        prod::licence_state(t.as_ref(), last_ok, now, p43_days)
            .map(ref_state)
            .map_err(|e| {
                NotImplemented::new(
                    release_stub(&e).unwrap_or("fstp_release::licence::licence_state refused"),
                )
            })
    }

    fn permits(&self, state: RefState, class: RefClass) -> Result<bool, NotImplemented> {
        prod_permits(state, class)
    }
}

/// A defect a teeth test seeds into a backend (design section 14.2).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LicenceDefect {
    /// `permits` refuses `ReleasePayment` (the payments class) in every
    /// state but valid.
    GateOnReleasePayment,
    /// The grace period includes its end instant, one tick too long.
    GraceEndInclusive,
    /// A refresh adopts any validly signed token. It checks neither the
    /// licence id nor the token's age.
    RefreshSkipsLicenceAndAge,
}

/// `inner` with one seeded defect.
#[derive(Clone, Debug)]
pub struct Mutant<B> {
    inner: B,
    defect: LicenceDefect,
}

impl<B: LicenceBackend> Mutant<B> {
    /// `inner` with `defect`.
    pub fn new(inner: B, defect: LicenceDefect) -> Mutant<B> {
        Mutant { inner, defect }
    }
}

impl<B: LicenceBackend> LicenceBackend for Mutant<B> {
    fn import(&self, file: &[u8], pinned: &[[u8; 32]]) -> Result<Option<RefToken>, NotImplemented> {
        self.inner.import(file, pinned)
    }

    fn refresh(
        &self,
        stored: &RefToken,
        keys: &RefKeySet,
        response: &[u8],
        now: i64,
    ) -> Result<Option<RefToken>, NotImplemented> {
        if self.defect == LicenceDefect::RefreshSkipsLicenceAndAge {
            return Ok(r::split_refresh_response(response)
                .and_then(|(_, token)| r::verify_token(token, &keys.current(now)).ok()));
        }
        self.inner.refresh(stored, keys, response, now)
    }

    fn state(
        &self,
        token: Option<&RefToken>,
        last_ok: Option<i64>,
        now: i64,
        p43_days: u16,
    ) -> Result<RefState, NotImplemented> {
        let got = self.inner.state(token, last_ok, now, p43_days)?;
        if self.defect == LicenceDefect::GraceEndInclusive
            && let (RefState::Expired { since }, Some(t)) = (got, token)
            && since == now
        {
            return Ok(RefState::Grace {
                since: t.not_after,
                ends: since,
            });
        }
        Ok(got)
    }

    fn permits(&self, state: RefState, class: RefClass) -> Result<bool, NotImplemented> {
        let got = self.inner.permits(state, class)?;
        if self.defect == LicenceDefect::GateOnReleasePayment
            && class == RefClass::Payments
            && state.kind() != StateKind::Valid
        {
            return Ok(false);
        }
        Ok(got)
    }
}

// ---------------------------------------------------------------------------
// The model.

/// A refresh outcome.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Refresh {
    /// The service answers with a response carrying T2.
    Success,
    /// The service is down: refused, timed out, failed TLS or a slow body.
    Failure,
    /// The service answers with garbage number `i` of [`Fixtures::garbage`].
    Garbage(u8),
}

/// One decision of the gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Decision {
    /// The kind of the licence state the backend gave.
    pub kind: StateKind,
    /// The activity.
    pub activity: Activity,
    /// Whether the activity committed.
    pub admitted: bool,
}

/// The state of M-LICENCE.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct McState {
    /// The clock index into [`INSTANTS`].
    pub clock: u8,
    /// The stored verified token.
    pub token: Option<RefToken>,
    /// The last successful import or refresh.
    pub last_ok: Option<i64>,
    /// The last gate decision.
    pub last: Option<Decision>,
    /// Whether a garbage refresh replaced the token.
    pub adopted_garbage: bool,
    /// The first backend operation that answered `NotImplemented`.
    pub halt: Option<&'static str>,
}

impl McState {
    /// The instant now.
    pub fn now(&self) -> i64 {
        instant(self.clock)
    }
}

/// An action of M-LICENCE.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LicenceAction {
    /// One tick of the reduced clock.
    Tick,
    /// `fstp-cell licence import <file>` with T1's file.
    Import,
    /// A background refresh with an outcome.
    Refresh(Refresh),
    /// An activity of the tenant.
    Run(Activity),
}

/// M-LICENCE over a backend.
#[derive(Clone, Debug)]
pub struct LicenceModel<B> {
    backend: B,
    fixtures: Fixtures,
}

impl<B: LicenceBackend> LicenceModel<B> {
    /// The model over `backend`.
    ///
    /// # Errors
    ///
    /// Refuses when the fixtures cannot be signed.
    pub fn new(backend: B) -> Result<LicenceModel<B>, NotImplemented> {
        Ok(LicenceModel {
            backend,
            fixtures: Fixtures::new()?,
        })
    }

    /// The backend.
    pub fn backend(&self) -> &B {
        &self.backend
    }

    /// The fixtures.
    pub fn fixtures(&self) -> &Fixtures {
        &self.fixtures
    }
}

impl<B: LicenceBackend> Model for LicenceModel<B> {
    type State = McState;
    type Action = LicenceAction;

    fn init(&self) -> Vec<McState> {
        vec![McState {
            clock: 0,
            token: None,
            last_ok: None,
            last: None,
            adopted_garbage: false,
            halt: None,
        }]
    }

    fn actions(&self, s: &McState, out: &mut Vec<LicenceAction>) {
        if s.halt.is_some() {
            return;
        }
        out.push(LicenceAction::Tick);
        out.push(LicenceAction::Import);
        out.push(LicenceAction::Refresh(Refresh::Success));
        out.push(LicenceAction::Refresh(Refresh::Failure));
        for i in 0..self.fixtures.garbage.len() {
            if let Ok(i) = u8::try_from(i) {
                out.push(LicenceAction::Refresh(Refresh::Garbage(i)));
            }
        }
        for a in Activity::ALL {
            out.push(LicenceAction::Run(a));
        }
    }

    fn step(&self, s: &McState, a: &LicenceAction) -> Option<McState> {
        let mut next = s.clone();
        let pinned = &self.fixtures.pinned;
        let keys = RefKeySet::shipped(pinned);
        match *a {
            LicenceAction::Tick => {
                let c = s.clock.checked_add(1)?;
                if usize::from(c) >= INSTANTS.len() {
                    return None;
                }
                next.clock = c;
                next.last = None;
            }
            LicenceAction::Import => {
                if s.token.is_some() {
                    return None;
                }
                match self.backend.import(&self.fixtures.file_t1, pinned) {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => return None,
                    Ok(Some(t)) => {
                        next.token = Some(t);
                        next.last_ok = Some(s.now());
                    }
                }
            }
            LicenceAction::Refresh(Refresh::Failure) => {
                // Neither cell start nor any request waits for a refresh,
                // so a failed one changes nothing.
                s.token?;
                return None;
            }
            LicenceAction::Refresh(Refresh::Success) => {
                let stored = s.token?;
                if s.now() < T1.refresh_after {
                    return None;
                }
                match self
                    .backend
                    .refresh(&stored, &keys, &self.fixtures.refresh_t2, s.now())
                {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => return None,
                    Ok(Some(t)) => {
                        if s.token == Some(t) {
                            return None;
                        }
                        next.token = Some(t);
                        next.last_ok = Some(s.now());
                    }
                }
            }
            LicenceAction::Refresh(Refresh::Garbage(i)) => {
                let stored = s.token?;
                let bytes = self.fixtures.garbage.get(usize::from(i))?;
                match self.backend.refresh(&stored, &keys, bytes, s.now()) {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(None) => return None,
                    // The replay of the stored token changes nothing.
                    Ok(Some(t)) if t == stored => return None,
                    Ok(Some(t)) => {
                        next.token = Some(t);
                        next.adopted_garbage = true;
                    }
                }
            }
            LicenceAction::Run(activity) => {
                let decided = self
                    .backend
                    .state(s.token.as_ref(), s.last_ok, s.now(), P43_DAYS)
                    .and_then(|st| {
                        self.backend
                            .permits(st, activity.class())
                            .map(|admitted| Decision {
                                kind: st.kind(),
                                activity,
                                admitted,
                            })
                    });
                match decided {
                    Err(e) => next.halt = Some(e.operation),
                    Ok(d) => next.last = Some(d),
                }
            }
        }
        Some(next)
    }

    fn is_terminal(&self, s: &McState) -> bool {
        s.halt.is_some()
    }
}

// ---------------------------------------------------------------------------
// Properties.

/// The property ids of M-LICENCE.
pub mod ids {
    /// Every backend answer was given; a stub halts the run here only.
    pub const BACKEND_ANSWERS: &str = "backend-answers";
    /// I-39: no licence state blocks evaluation, payments, notifications
    /// or export.
    pub const I39: &str = "I-39";
    /// Q18 interim: no licence state blocks anything in M3.
    pub const Q18: &str = "Q18-blocks-nothing";
    /// Two-way: the licence state and every gate decision equal the
    /// reference's, in every state of the run.
    pub const TWO_WAY: &str = "two-way";
    /// A garbage refresh never replaces the token.
    pub const GARBAGE: &str = "garbage-never-adopted";
    /// Witness (design section 14.2): an expired state with an evaluation
    /// command committing.
    pub const W_EXPIRED_EVALUATION: &str = "witness-expired-evaluation-commits";
    /// Witness: a grace state with a payment release committing.
    pub const W_GRACE_PAYMENT: &str = "witness-grace-release-payment-commits";
    /// Witness: a missing licence with the export entry point running.
    pub const W_MISSING_EXPORT: &str = "witness-missing-export-runs";
    /// Witness: an expired state with a notification sent.
    pub const W_EXPIRED_NOTIFY: &str = "witness-expired-notification-sent";
    /// Witness: a refresh replaced T1 with T2.
    pub const W_REFRESHED: &str = "witness-refresh-adopted";
    /// Witness: the clock stands at T1's grace end with T1 stored.
    pub const W_GRACE_END: &str = "witness-at-grace-end";
}

/// The two-way check of one state: the stored token, the licence state
/// and the gate for every class.
///
/// The universe signs only T1, T2 and [`FOREIGN`] with a pinned key, and
/// a refresh must refuse [`FOREIGN`]. So the backend's import and refresh
/// may store no token but T1 and T2. A field misread by the backend shows
/// here, in the state that stores it.
fn two_way<B: LicenceBackend>(m: &LicenceModel<B>, s: &McState) -> Result<(), String> {
    if let Some(t) = s.token
        && t != T1
        && t != T2
    {
        return Err(format!(
            "two-way: the backend stored {t:?}, which is neither T1 nor T2"
        ));
    }
    let now = s.now();
    let want = r::licence_state(s.token.as_ref(), s.last_ok, now, P43_DAYS);
    let Ok(got) = m
        .backend()
        .state(s.token.as_ref(), s.last_ok, now, P43_DAYS)
    else {
        return Ok(());
    };
    if got != want {
        return Err(format!(
            "two-way: licence state at {now} with {:?} is {got:?}, reference {want:?}",
            s.token
        ));
    }
    for class in RefClass::ALL {
        let want = r::permits(got, class);
        if let Ok(admitted) = m.backend().permits(got, class)
            && admitted != want
        {
            return Err(format!(
                "two-way: permits({got:?}, {class:?}) is {admitted}, reference {want}"
            ));
        }
    }
    Ok(())
}

fn decided(s: &McState, kind: StateKind, activity: Activity) -> bool {
    s.last
        == Some(Decision {
            kind,
            activity,
            admitted: true,
        })
}

/// Every property of M-LICENCE.
pub fn properties<'a, B: LicenceBackend>(
    m: &'a LicenceModel<B>,
) -> Vec<Property<'a, LicenceModel<B>>> {
    vec![
        Property::always_with(ids::BACKEND_ANSWERS, |s: &McState| match s.halt {
            None => Ok(()),
            Some(op) => Err(format!("the backend did not answer: {op}")),
        }),
        Property::always_with(ids::I39, |s: &McState| match s.last {
            Some(d) if d.activity.class().protected() && !d.admitted => Err(format!(
                "I-39: {:?} ({:?}) was blocked in a {:?} licence state at {}",
                d.activity,
                d.activity.class(),
                d.kind,
                s.now()
            )),
            _ => Ok(()),
        }),
        Property::always_with(ids::Q18, |s: &McState| match s.last {
            Some(d) if !d.admitted => Err(format!(
                "Q18-blocks-nothing: {:?} was blocked in a {:?} licence state",
                d.activity, d.kind
            )),
            _ => Ok(()),
        }),
        Property::always_with(ids::TWO_WAY, move |s: &McState| two_way(m, s)),
        Property::always_with(ids::GARBAGE, |s: &McState| {
            if s.adopted_garbage {
                Err(format!(
                    "garbage-never-adopted: a garbage refresh stored {:?}",
                    s.token
                ))
            } else {
                Ok(())
            }
        }),
        Property::reachable(ids::W_EXPIRED_EVALUATION, |s: &McState| {
            decided(
                s,
                StateKind::Expired,
                Activity::Command(CommandKind::RecordScore),
            )
        }),
        Property::reachable(ids::W_GRACE_PAYMENT, |s: &McState| {
            decided(
                s,
                StateKind::Grace,
                Activity::Command(CommandKind::ReleasePayment),
            )
        }),
        Property::reachable(ids::W_MISSING_EXPORT, |s: &McState| {
            decided(s, StateKind::Missing, Activity::Export)
        }),
        Property::reachable(ids::W_EXPIRED_NOTIFY, |s: &McState| {
            decided(s, StateKind::Expired, Activity::Notify)
        }),
        Property::reachable(ids::W_REFRESHED, |s: &McState| s.token == Some(T2)),
        Property::reachable(ids::W_GRACE_END, |s: &McState| {
            s.token == Some(T1) && s.now() == G1
        }),
    ]
}
