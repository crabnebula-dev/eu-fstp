//! TH-32: a malicious or rolled-back update delivered to self-hosted
//! cells (T-UPDATE). M3 installs nothing and announces no update.
//! Metadata rollback and expired metadata are refused. Licence key
//! rotation runs only through a pinned key; that test is
//! `i39_licence_key_transition_accepted_only_when_signed_by_a_pinned_key`
//! (design sections 10.3 and 12).
//!
//! Lane W1g wrote these tests before the production code. They are red
//! until `fstp_release::metadata` (lane W2j) and the admin view (lane
//! W3a) land. The teeth run on the reference now.
//!
//! Each production claim has its own test. The rollback and expiry test
//! compares a stateful production acceptance of verified metadata with
//! [`MetadataStore::accept_with`] over sequences. The stub has no such
//! API, so the test names `METADATA_STORE_SEAM` and stays red until lane
//! W2j adds one. Until then TH-32 rollback refusal is shown on the
//! reference only, and lane W1g asks the lead to record that in the
//! design section 20 checklist. That nothing is installed, and that
//! unverifiable metadata is refused at decode, are separate tests, so
//! neither stands in for the rollback check.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::mc::licence_model::{ANNOUNCE_SEAM, METADATA_STORE_SEAM, release_stub};
use fstp_celltest::reference::licence::{
    self as r, DAY_S, MetadataRefusal, MetadataStore, RefChannel, RefMetadata, RefVersion,
};
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::Gen;

const NOW: i64 = 1_800_000_000;

/// The running version of the cell.
const RUNNING: RefVersion = RefVersion {
    major: 1,
    minor: 4,
    patch: 0,
};

fn gen_version(g: &mut Gen) -> RefVersion {
    RefVersion {
        major: g.u16_in(0..=3),
        minor: g.u16(),
        patch: g.u16(),
    }
}

fn gen_metadata(g: &mut Gen, seq: u64, expires_at: i64) -> RefMetadata {
    let mut sha = [0u8; 32];
    for b in &mut sha {
        *b = g.u8();
    }
    RefMetadata {
        channel: RefChannel::Stable,
        seq,
        version: gen_version(g),
        expires_at,
        artifact_sha256: sha,
    }
}

/// Signed metadata bytes with an arbitrary composite signature. No
/// signature can be verified in M3 (I-91 lands in M9).
fn signed(g: &mut Gen, m: &RefMetadata) -> Vec<u8> {
    let sig = g.bytes(r::METADATA_SIG_LEN..=r::METADATA_SIG_LEN);
    r::metadata_bytes(m, &sig)
}

/// The stub's name, if `e` is a stub refusal.
fn stub(e: &fstp_release::ReleaseError) -> Option<String> {
    release_stub(e).map(|op| format!("{op} is NotImplemented"))
}

/// Metadata of any kind the store judges: a rollback, an expired one, a
/// fresh one, or one for a newer product version.
fn gen_any_metadata(g: &mut Gen) -> RefMetadata {
    let seq = g.u64();
    let expires_at = NOW + g.i64_in(-30 * DAY_S..=30 * DAY_S);
    gen_metadata(g, seq, expires_at)
}

// ---------------------------------------------------------------------------
// The rollback floor over verified metadata.

/// One step of a metadata sequence: the signed bytes and the instant.
type Step = (Vec<u8>, i64);

/// Production's stateful acceptance of verified release metadata: from an
/// empty store, whether each step is accepted.
///
/// Gap ([`METADATA_STORE_SEAM`]): the stub has `decode_release_metadata`
/// and `may_apply` only, and no store. Lane W2j adds an acceptance API
/// over verified metadata, with a test release root so tests can verify.
/// Lane W1g then maps it here.
fn prod_accepts(steps: &[Step]) -> Result<Vec<bool>, String> {
    // A stub decoder names itself first, so the seam shows only once
    // `decode_release_metadata` answers.
    if let Some((bytes, _)) = steps.first()
        && let Err(e) = fstp_release::metadata::decode_release_metadata(bytes)
        && let Some(m) = stub(&e)
    {
        return Err(m);
    }
    Err(METADATA_STORE_SEAM.to_owned())
}

/// The TH-32 two-way property over a production acceptor: a sequence of
/// verified metadata, with rollbacks, expiries, refetches and a second
/// body under a seen version. Each step's verdict must equal
/// [`MetadataStore::accept_with`].
fn store_two_way(
    prod: impl Fn(&[Step]) -> Result<Vec<bool>, String>,
    g: &mut Gen,
) -> Result<(), String> {
    let mut store = MetadataStore::default();
    let mut now = NOW;
    let mut seen: Vec<RefMetadata> = Vec::new();
    let mut steps: Vec<Step> = Vec::new();
    let mut want = Vec::new();
    for _ in 0..g.usize_in(1..=6) {
        now += g.i64_in(0..=DAY_S);
        let m = match (seen.is_empty(), g.u8_in(0..=3)) {
            (false, 0) => *g.pick(seen.as_slice()),
            (false, 1) => {
                let mut m = *g.pick(seen.as_slice());
                m.artifact_sha256[0] ^= 1;
                m
            }
            _ => {
                let seq = g.u64_in(0..=8);
                let expires_at = now + g.i64_in(-2..=2);
                gen_metadata(g, seq, expires_at)
            }
        };
        let verdict = store.accept_with(&m, true, now);
        want.push(verdict.is_ok());
        if let Ok(next) = verdict {
            store = next;
        }
        seen.push(m);
        // A fixed signature: the steps stand for metadata that verified,
        // and random signature bytes would only slow the shrinker.
        steps.push((r::metadata_bytes(&m, &[0; r::METADATA_SIG_LEN]), now));
    }
    let got = prod(&steps)?;
    if got == want {
        Ok(())
    } else {
        Err(format!(
            "TH-32: production accepted {got:?}, the reference {want:?}, over {seen:?}"
        ))
    }
}

/// TH-32, design section 10.3 ("The cell stores the highest metadata
/// version it has seen and refuses older or expired metadata"): over
/// sequences of verified metadata, production accepts exactly what the
/// reference store accepts. It refuses a rollback below the highest
/// version accepted, expired metadata, and a second body under the same
/// version.
#[test]
fn th_32_t_update_rollback_and_expired_metadata_refused() {
    fstp_prop::check(
        "th_32_t_update_rollback_and_expired_metadata_refused",
        |g: &mut Gen| store_two_way(prod_accepts, g),
    );
}

/// TH-32 teeth: a production that accepts verified metadata by framing
/// and expiry alone, with no rollback floor, fails the two-way property.
#[test]
fn th_32_teeth_production_without_rollback_floor_is_caught() {
    let outcome = fstp_prop::run(
        "th_32_teeth_production_without_rollback_floor_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            store_two_way(
                |steps| {
                    Ok(steps
                        .iter()
                        .map(|(bytes, now)| {
                            r::metadata_fields(bytes).is_some_and(|m| m.expires_at > *now)
                        })
                        .collect())
                },
                g,
            )
        },
    );
    expect_prop_failure(&outcome, "TH-32").unwrap();
}

/// TH-32: the reference store passes the two-way property against
/// itself, so the teeth above fail on the seeded defect only.
#[test]
fn th_32_reference_store_two_way_holds() {
    fstp_prop::check("th_32_reference_store_two_way_holds", |g: &mut Gen| {
        store_two_way(
            |steps| {
                let mut store = MetadataStore::default();
                Ok(steps
                    .iter()
                    .map(|(bytes, now)| {
                        let Some(m) = r::metadata_fields(bytes) else {
                            return false;
                        };
                        match store.accept_with(&m, true, *now) {
                            Ok(next) => {
                                store = next;
                                true
                            }
                            Err(_) => false,
                        }
                    })
                    .collect())
            },
            g,
        )
    });
}

/// The TH-32 store property over an acceptor of verified metadata: run a
/// sequence through it and require that nothing it accepts is older
/// than the highest accepted, expired, or a second body under the
/// highest version.
fn store_holds(
    accept: impl Fn(&MetadataStore, &RefMetadata, i64) -> Result<MetadataStore, MetadataRefusal>,
    g: &mut Gen,
) -> Result<(), String> {
    let mut store = MetadataStore::default();
    let mut now = NOW;
    let steps = g.usize_in(1..=6);
    for _ in 0..steps {
        now += g.i64_in(0..=DAY_S);
        let seq = g.u64_in(0..=8);
        let expires_at = now + g.i64_in(-2..=2);
        let m = gen_metadata(g, seq, expires_at);
        if let Ok(next) = accept(&store, &m, now) {
            if let Some(h) = store.highest {
                if m.seq < h.seq {
                    return Err(format!("TH-32: metadata {seq} accepted after {}", h.seq));
                }
                if m.seq == h.seq && m != h {
                    return Err(format!(
                        "TH-32: a second body under metadata version {seq} accepted"
                    ));
                }
            }
            if m.expires_at <= now {
                return Err(format!(
                    "TH-32: metadata expired at {expires_at} accepted at {now}"
                ));
            }
            store = next;
        }
    }
    Ok(())
}

/// TH-32 teeth: a store that forgets the highest version accepted takes a
/// rollback, and the store property catches it.
#[test]
fn th_32_teeth_rollback_accepted_is_caught() {
    let outcome = fstp_prop::run(
        "th_32_teeth_rollback_accepted_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            store_holds(
                |_store, m, now| MetadataStore::default().accept_with(m, true, now),
                g,
            )
        },
    );
    expect_prop_failure(&outcome, "TH-32").unwrap();
}

/// TH-32 teeth: a store that ignores the expiry takes expired metadata,
/// and the store property catches it.
#[test]
fn th_32_teeth_expired_metadata_accepted_is_caught() {
    let outcome = fstp_prop::run(
        "th_32_teeth_expired_metadata_accepted_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            store_holds(
                |store, m, now| {
                    let fresh = RefMetadata {
                        expires_at: now.saturating_add(1),
                        ..*m
                    };
                    store.accept_with(&fresh, true, now)
                },
                g,
            )
        },
    );
    expect_prop_failure(&outcome, "TH-32").unwrap();
}

/// TH-32: the reference store passes the store property over verified
/// metadata, so the teeth above fail on the seeded defect only.
#[test]
fn th_32_reference_store_refuses_rollback_and_expiry() {
    fstp_prop::check(
        "th_32_reference_store_refuses_rollback_and_expiry",
        |g: &mut Gen| store_holds(|store, m, now| store.accept_with(m, true, now), g),
    );
}

/// TH-32, design section 15 ("signature checked before use"): metadata
/// that cannot be verified never moves the reference rollback floor. A
/// forged response with any metadata version, `u64::MAX` among them,
/// leaves the store empty, and genuine verified metadata is then
/// accepted.
#[test]
fn th_32_reference_unverified_metadata_never_moves_the_floor() {
    fstp_prop::check(
        "th_32_reference_unverified_metadata_never_moves_the_floor",
        |g: &mut Gen| {
            let store = MetadataStore::default();
            for _ in 0..g.usize_in(1..=4) {
                let seq = if g.bool() { u64::MAX } else { g.u64() };
                let m = gen_metadata(g, seq, NOW + DAY_S);
                let verdict = store.accept(&m, NOW);
                if verdict != Err(MetadataRefusal::Unverifiable) {
                    return Err(format!(
                        "TH-32: unverified metadata {m:?} was judged {verdict:?}"
                    ));
                }
            }
            let genuine = gen_metadata(g, 0, NOW + DAY_S);
            match store.accept_with(&genuine, true, NOW) {
                Ok(_) => Ok(()),
                Err(e) => Err(format!(
                    "TH-32: genuine metadata refused as {e:?} after unverified metadata"
                )),
            }
        },
    );
}

// ---------------------------------------------------------------------------
// Signature first, nothing installed, nothing announced.

/// TH-32, design sections 10.3 and 15: `decode_release_metadata` checks
/// the signature before any field is used. In M3 no release key is
/// certified by the release root (I-91 lands in M9), so production
/// refuses every metadata at decode, with a typed error.
///
/// Reading: the stub's decoder takes bytes only and says "signature
/// first". With no certified key nothing verifies, so nothing decodes.
#[test]
fn th_32_t_update_unverifiable_metadata_refused_at_decode() {
    fstp_prop::check(
        "th_32_t_update_unverifiable_metadata_refused_at_decode",
        |g: &mut Gen| {
            let m = gen_any_metadata(g);
            match fstp_release::metadata::decode_release_metadata(&signed(g, &m)) {
                Ok(meta) => Err(format!(
                    "TH-32: unverifiable metadata {m:?} decoded as {meta:?}"
                )),
                Err(e) => stub(&e).map_or(Ok(()), Err),
            }
        },
    );
}

/// TH-32, design section 10.3: M3 installs nothing. Whatever production
/// decodes, `may_apply` is false for it.
#[test]
fn th_32_t_update_m3_installs_nothing() {
    fstp_prop::check("th_32_t_update_m3_installs_nothing", |g: &mut Gen| {
        let m = gen_any_metadata(g);
        match fstp_release::metadata::decode_release_metadata(&signed(g, &m)) {
            Err(e) => stub(&e).map_or(Ok(()), Err),
            Ok(meta) => match fstp_release::metadata::may_apply(&meta) {
                Ok(false) => Ok(()),
                Ok(true) => Err(format!("TH-32: M3 would install {m:?}")),
                Err(e) => Err(stub(&e).unwrap_or_else(|| format!("may_apply refused: {e:?}"))),
            },
        }
    });
}

/// Whether the cell announces an update to a tenant admin after an
/// update check that fetched `bytes`.
///
/// Gap ([`ANNOUNCE_SEAM`]): the admin view of lane W3a has no API.
fn prod_announces(bytes: &[u8]) -> Result<bool, String> {
    if let Err(e) = fstp_release::metadata::decode_release_metadata(bytes)
        && let Some(m) = stub(&e)
    {
        return Err(m);
    }
    Err(ANNOUNCE_SEAM.to_owned())
}

/// TH-32, design section 10.3: metadata cannot be verified until the
/// release root certification of I-91 lands in M9. So the cell never
/// tells a tenant admin that an update is available, even for fresh
/// metadata of a newer version.
#[test]
fn th_32_t_update_no_notice_from_unverifiable_metadata() {
    fstp_prop::check(
        "th_32_t_update_no_notice_from_unverifiable_metadata",
        |g: &mut Gen| {
            let seq = g.u64();
            let expires_at = NOW + g.i64_in(1..=30 * DAY_S);
            let mut m = gen_metadata(g, seq, expires_at);
            m.version = RefVersion {
                major: RUNNING.major + g.u16_in(0..=2),
                minor: RUNNING.minor + 1,
                patch: g.u16(),
            };
            let bytes = signed(g, &m);
            if prod_announces(&bytes)? {
                Err(format!(
                    "TH-32: the cell announced unverifiable metadata {m:?}"
                ))
            } else {
                Ok(())
            }
        },
    );
}

// ---------------------------------------------------------------------------
// The reference.

/// TH-32, design section 10.3: in M3 the reference never applies an
/// update, to any target, in or out of an evaluation window, with or
/// without a payment release in flight.
#[test]
fn th_32_reference_m3_installs_nothing() {
    fstp_prop::check("th_32_reference_m3_installs_nothing", |g: &mut Gen| {
        let target = gen_version(g);
        let (window, release) = (g.bool(), g.bool());
        if r::may_apply(r::M3_METADATA_VERIFIABLE, RUNNING, target, window, release) {
            Err(format!("TH-32: M3 would apply {target:?}"))
        } else {
            Ok(())
        }
    });
}

/// TH-32, `self-hosted-services.md` ("reject rollbacks to older
/// versions"): with verified metadata, outside an evaluation window and
/// with no release in flight, the reference applies a target only when
/// it is strictly newer than the running version.
#[test]
fn th_32_reference_may_apply_refuses_older_or_same_version() {
    fstp_prop::check(
        "th_32_reference_may_apply_refuses_older_or_same_version",
        |g: &mut Gen| {
            let target = if g.bool() { RUNNING } else { gen_version(g) };
            let applied = r::may_apply(true, RUNNING, target, false, false);
            if applied == (target > RUNNING) {
                Ok(())
            } else {
                Err(format!(
                    "TH-32: may_apply is {applied} for {target:?} over {RUNNING:?}"
                ))
            }
        },
    );
}
