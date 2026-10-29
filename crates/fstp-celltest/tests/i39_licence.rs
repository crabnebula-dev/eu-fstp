//! I-39: unavailability of the update or licence service never blocks
//! evaluation, payments, notifications or export (design sections 10.2
//! and 14.4, T-LICENCE-OUTAGE, TH-33). Q18 interim: licence expiry
//! blocks nothing in M3.
//!
//! Lane W1g wrote these tests before the production code. Each compares
//! production against `fstp_celltest::reference::licence`. They are red
//! until `fstp_release::licence` (lane W2j) and the self-hosted cell
//! runtime (lanes W3a and W3b) land. The layering test and the teeth run
//! now. The model runs of M-LICENCE are in `i39_m_licence.rs`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::path::Path;
use std::process::Command;

use fstp_celltest::egress::{Direction, Endpoint, Peer};
use fstp_celltest::mc::licence_model::{
    Activity, ProdKeySet, prod_permits, prod_refresh, prod_token, prod_verify, ref_state,
    release_stub, seam_or_stub,
};
use fstp_celltest::reference::licence::{
    self as r, DAY_S, P43_DAYS, RefClass, RefKeySet, RefKind, RefLicenceId, RefState, RefToken,
    RefTransition, RefreshRefusal, TokenRefusal, TransitionRefusal,
};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_domain::CommandKind;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

// ---------------------------------------------------------------------------
// Helpers.

const T0: i64 = 1_800_000_000;

fn key(seed: u8) -> Ed25519SigningKey {
    Ed25519SigningKey::from_seed(&[seed; 32]).unwrap()
}

/// Any licence state, with instants around `T0`.
fn gen_state(g: &mut Gen) -> RefState {
    let at = |g: &mut Gen| T0 + g.i64_in(-60 * DAY_S..=60 * DAY_S);
    match g.u8_in(0..=3) {
        0 => RefState::Valid { until: at(g) },
        1 => {
            let since = at(g);
            RefState::Grace {
                since,
                ends: since + r::grace_len(P43_DAYS),
            }
        }
        2 => RefState::Expired { since: at(g) },
        _ => RefState::Missing,
    }
}

/// Any subject of the gate: a command of any kind, a notification or the
/// export entry point.
fn gen_activity(g: &mut Gen) -> Activity {
    match g.u8_in(0..=5) {
        0 => Activity::Notify,
        1 => Activity::Export,
        _ => Activity::Command(*g.pick(&CommandKind::ALL)),
    }
}

fn gen_token(g: &mut Gen) -> RefToken {
    let mut id = [0u8; 16];
    for b in &mut id {
        *b = g.u8();
    }
    let issued_at = T0 + g.i64_in(-30 * DAY_S..=30 * DAY_S);
    let refresh_after = issued_at + g.i64_in(0..=14 * DAY_S);
    RefToken {
        licence: RefLicenceId(id),
        kind: *g.pick(&RefKind::ALL),
        issued_at,
        refresh_after,
        not_after: refresh_after + g.i64_in(0..=14 * DAY_S),
    }
}

fn ni(e: fstp_celltest::NotImplemented) -> String {
    seam_or_stub(&e)
}

/// The production licence state, with a stub refusal named.
fn prod_state(token: Option<&RefToken>, now: i64) -> Result<RefState, String> {
    let t = token.map(prod_token);
    fstp_release::licence::licence_state(t.as_ref(), None, now, P43_DAYS)
        .map(ref_state)
        .map_err(|e| match release_stub(&e) {
            Some(op) => format!("{op} is NotImplemented"),
            None => format!("licence_state refused: {e:?}"),
        })
}

/// An instant on either side of `at`, at it, or anywhere in 90 days.
fn around(g: &mut Gen, at: i64) -> i64 {
    match g.u8_in(0..=3) {
        0 => at - 1,
        1 => at,
        2 => at + 1,
        _ => T0 + g.i64_in(-DAY_S..=90 * DAY_S),
    }
}

// ---------------------------------------------------------------------------
// The gate.

/// I-39, design section 14.4: for every command kind, the outbox and the
/// export entry point, in every licence state, the production gate lets
/// every protected activity run. A later change to a protected row of the
/// `permits` table fails here.
#[test]
fn i39_licence_states_never_block_protected_commands() {
    fstp_prop::check(
        "i39_licence_states_never_block_protected_commands",
        |g: &mut Gen| {
            let activity = gen_activity(g);
            let class = activity.class();
            if !class.protected() {
                return Ok(());
            }
            let state = gen_state(g);
            let admitted = prod_permits(state, class).map_err(ni)?;
            prop_assert!(
                admitted,
                "I-39: {activity:?} ({class:?}) is blocked in licence state {state:?}"
            );
            Ok(())
        },
    );
}

/// Q18 interim (design section 17.2): in M3 licence expiry blocks nothing.
/// The production gate permits every class, protected or not, in every
/// licence state.
#[test]
fn i39_q18_licence_expiry_blocks_nothing_in_m3() {
    fstp_prop::check(
        "i39_q18_licence_expiry_blocks_nothing_in_m3",
        |g: &mut Gen| {
            let class = *g.pick(&RefClass::ALL);
            let state = gen_state(g);
            let admitted = prod_permits(state, class).map_err(ni)?;
            prop_assert_eq!(admitted, r::permits(state, class), "{class:?} in {state:?}");
            Ok(())
        },
    );
}

/// I-39, P-43, design section 14.1 "Reduced clock": the production
/// licence state equals the reference at `not_after` and at the grace end,
/// one tick before and after each, and anywhere else.
#[test]
fn i39_licence_state_matches_reference() {
    fstp_prop::check("i39_licence_state_matches_reference", |g: &mut Gen| {
        let token = g.option(gen_token);
        let last_ok = g.option(|g| T0 + g.i64_in(-60 * DAY_S..=60 * DAY_S));
        let p43 = *g.pick(&[P43_DAYS, 0, 1, u16::MAX]);
        let now = match token {
            Some(t) if g.bool() => {
                let edge = if g.bool() {
                    t.not_after
                } else {
                    t.not_after.saturating_add(r::grace_len(p43))
                };
                edge + g.i64_in(-1..=1)
            }
            _ => T0 + g.i64_in(-120 * DAY_S..=120 * DAY_S),
        };
        let want = r::licence_state(token.as_ref(), last_ok, now, p43);
        let t = token.as_ref().map(prod_token);
        let got =
            fstp_release::licence::licence_state(t.as_ref(), last_ok, now, p43).map_err(|e| {
                match release_stub(&e) {
                    Some(op) => format!("{op} is NotImplemented"),
                    None => format!("licence_state refused: {e:?}"),
                }
            })?;
        prop_assert_eq!(
            ref_state(got),
            want,
            "{token:?}, last_ok {last_ok:?}, now {now}, P-43 {p43}"
        );
        Ok(())
    });
}

/// I-39, design section 15 ("signature checked before use"): production
/// token verification equals the reference for tokens signed by the
/// pinned key, by a key outside the set, and with one flipped byte, so a
/// forged token never changes the licence state.
#[test]
fn i39_verify_token_matches_reference() {
    let pinned = key(0x11);
    let other = key(0x99);
    let set = [pinned.public_key()];
    fstp_prop::check("i39_verify_token_matches_reference", |g: &mut Gen| {
        let t = gen_token(g);
        let signer = if g.bool() { &pinned } else { &other };
        let mut bytes = r::sign_token(&t, signer).map_err(|e| e.to_string())?;
        if g.bool() {
            let i = g.usize_in(0..=bytes.len() - 1);
            bytes[i] ^= 1u8 << g.u8_in(0..=7);
        }
        if g.bool() {
            bytes.truncate(g.usize_in(0..=bytes.len()));
        }
        let want = r::verify_token(&bytes, &set).ok();
        let got = prod_verify(&bytes, &set).map_err(ni)?;
        prop_assert_eq!(got, want);
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// Key rotation (design section 10.2, ADR-004 "Licence token key", TH-32).

/// I-39, TH-32 ("licence key rotation only through a pinned key"),
/// design section 10.2: a key transition is accepted only when a key of
/// the pinned set in force at `now` signs it. Production then names the
/// same next key and `not_before`, and holds the same key set. A second
/// transition, signed by the next key or a key outside the set, runs at
/// instants on either side of the next key's `not_before`, since a key
/// announced for later cannot sign before then.
#[test]
fn i39_licence_key_transition_accepted_only_when_signed_by_a_pinned_key() {
    let shipped = key(0x11);
    let next = key(0x22);
    let third = key(0x33);
    let outsider = key(0x99);
    fstp_prop::check(
        "i39_licence_key_transition_accepted_only_when_signed_by_a_pinned_key",
        |g: &mut Gen| {
            let pinned = [shipped.public_key()];
            let mut want_set = RefKeySet::shipped(&pinned);
            let mut prod = ProdKeySet::shipped(&pinned).map_err(ni)?;
            let not_before = T0 + g.i64_in(-DAY_S..=30 * DAY_S);
            let first = RefTransition {
                next_key: if g.bool() {
                    next.public_key()
                } else {
                    outsider.public_key()
                },
                not_before,
            };
            let second = RefTransition {
                next_key: third.public_key(),
                not_before: not_before + g.i64_in(0..=DAY_S),
            };
            let steps = [
                (first, *g.pick(&[&shipped, &next, &outsider]), T0),
                (second, *g.pick(&[&next, &outsider]), around(g, not_before)),
            ];
            for (t, signer, now) in steps {
                let mut bytes = r::sign_transition(&t, signer).map_err(|e| e.to_string())?;
                if g.u8_in(0..=3) == 0 {
                    let i = g.usize_in(0..=bytes.len() - 1);
                    bytes[i] ^= 1;
                }
                let want = r::verify_transition(&bytes, &want_set, now).ok();
                let got = prod.apply_transition(&bytes, now).map_err(ni)?;
                prop_assert_eq!(got, want, "{t:?} at {now} over {want_set:?}");
                if let Some(accepted) = want {
                    want_set = want_set.with(&accepted);
                }
                prop_assert_eq!(
                    prod.keys().map_err(ni)?.canonical(),
                    want_set.canonical(),
                    "after {t:?}"
                );
            }
            Ok(())
        },
    );
}

/// I-39, design section 10.2: through a rotation, accepted or refused,
/// production's key set verifies exactly the tokens the reference set
/// verifies at instants on either side of the next key's `not_before`.
/// Tokens are signed by the new key, the shipped key or a key outside
/// the set. Whatever the outcome, and a refused token can leave the
/// licence missing or expired, production never blocks a protected
/// activity.
#[test]
fn i39_rotation_never_blocks_protected_commands() {
    let shipped = key(0x11);
    let next = key(0x22);
    let outsider = key(0x99);
    fstp_prop::check(
        "i39_rotation_never_blocks_protected_commands",
        |g: &mut Gen| {
            let pinned = [shipped.public_key()];
            let mut want_set = RefKeySet::shipped(&pinned);
            let mut prod = ProdKeySet::shipped(&pinned).map_err(ni)?;
            let t = RefTransition {
                next_key: next.public_key(),
                not_before: T0 + g.i64_in(0..=DAY_S),
            };
            let transition_signer = if g.bool() { &shipped } else { &outsider };
            let bytes = r::sign_transition(&t, transition_signer).map_err(|e| e.to_string())?;
            let want_t = r::verify_transition(&bytes, &want_set, T0).ok();
            let got_t = prod.apply_transition(&bytes, T0).map_err(ni)?;
            prop_assert_eq!(got_t, want_t);
            if let Some(accepted) = want_t {
                want_set = want_set.with(&accepted);
            }
            let now = around(g, t.not_before);
            let token_signer = *g.pick(&[&shipped, &next, &outsider]);
            let token = r::sign_token(&gen_token(g), token_signer).map_err(|e| e.to_string())?;
            let want = r::verify_token(&token, &want_set.current(now)).ok();
            let got = prod.verify(&token, now).map_err(ni)?;
            prop_assert_eq!(got, want, "at {now} over {want_set:?}");
            let state = prod_state(got.as_ref(), now)?;
            for class in RefClass::ALL.into_iter().filter(|c| c.protected()) {
                let admitted = prod_permits(state, class).map_err(ni)?;
                prop_assert!(
                    admitted,
                    "I-39: {class:?} blocked in {state:?} after rotation"
                );
            }
            Ok(())
        },
    );
}

// ---------------------------------------------------------------------------
// The refresh response (design section 10.2).

/// A refresh response of one of the kinds a service, an attacker or a
/// fault can send: with or without a transition, its token signed by the
/// shipped key, the announced key or an outsider, a replay or a token
/// for another licence, and sometimes one flipped byte.
fn gen_response(
    g: &mut Gen,
    stored: &RefToken,
    keys: (&Ed25519SigningKey, &Ed25519SigningKey, &Ed25519SigningKey),
    t: &RefTransition,
) -> Result<Vec<u8>, String> {
    let (shipped, next, outsider) = keys;
    let transition = if g.bool() {
        let signer = if g.bool() { shipped } else { outsider };
        Some(r::sign_transition(t, signer).map_err(|e| e.to_string())?)
    } else {
        None
    };
    let mut token = gen_token(g);
    match g.u8_in(0..=3) {
        0 => token = *stored,
        1 => token.licence = RefLicenceId([0x4d; 16]),
        2 => token.licence = stored.licence,
        _ => {
            token.licence = stored.licence;
            token.issued_at = stored.issued_at + g.i64_in(-DAY_S..=DAY_S);
            token.refresh_after = token.refresh_after.max(token.issued_at);
            token.not_after = token.not_after.max(token.refresh_after);
        }
    }
    let signer = *g.pick(&[shipped, next, outsider]);
    let token = r::sign_token(&token, signer).map_err(|e| e.to_string())?;
    let mut bytes = r::refresh_response(transition.as_deref(), &token);
    if g.u8_in(0..=4) == 0 {
        let i = g.usize_in(0..=bytes.len() - 1);
        bytes[i] ^= 1u8 << g.u8_in(0..=7);
    }
    Ok(bytes)
}

/// I-39, design sections 10.2 and 15 ("signature checked before use"):
/// the production refresh step equals [`r::apply_refresh`]. It verifies
/// any transition first, then the token under the keys in force at `now`.
/// It refuses a token for another licence and a token older than the
/// stored one. A refused response changes neither the token nor the set.
#[test]
fn i39_refresh_response_matches_reference() {
    let shipped = key(0x11);
    let next = key(0x22);
    let outsider = key(0x99);
    fstp_prop::check("i39_refresh_response_matches_reference", |g: &mut Gen| {
        let mut stored = gen_token(g);
        stored.licence = RefLicenceId([0x4c; 16]);
        let keys = RefKeySet::shipped(&[shipped.public_key()]);
        let t = RefTransition {
            next_key: next.public_key(),
            not_before: T0 + g.i64_in(0..=DAY_S),
        };
        let response = gen_response(g, &stored, (&shipped, &next, &outsider), &t)?;
        let now = around(g, t.not_before);
        let want = r::apply_refresh(&stored, &keys, &response, now).ok();
        let got = prod_refresh(&stored, &keys, &response, now).map_err(ni)?;
        prop_assert_eq!(got, want, "at {now}");
        Ok(())
    });
}

/// The rotation property over an acceptor of transitions.
fn rotation_holds(
    accept: impl Fn(&[u8], &RefKeySet, i64) -> Option<RefTransition>,
    g: &mut Gen,
) -> Result<(), String> {
    let shipped = key(0x11);
    let outsider = key(0x99);
    let set = RefKeySet::shipped(&[shipped.public_key()]);
    let t = RefTransition {
        next_key: outsider.public_key(),
        not_before: T0,
    };
    let signer = if g.bool() { &shipped } else { &outsider };
    let bytes = r::sign_transition(&t, signer).map_err(|e| e.to_string())?;
    let accepted = accept(&bytes, &set, T0).is_some();
    let by_pinned = std::ptr::eq(signer, &shipped);
    if accepted && !by_pinned {
        return Err(
            "I-39-pinned: a transition signed outside the pinned set was accepted".to_owned(),
        );
    }
    Ok(())
}

/// I-39 teeth, TH-32: an acceptor that checks the signature against the
/// transition's own next key, and not the pinned set, fails the rotation
/// property.
#[test]
fn i39_teeth_unpinned_key_transition_is_caught() {
    let outcome = fstp_prop::run(
        "i39_teeth_unpinned_key_transition_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| {
            rotation_holds(
                |bytes, _set, now| {
                    let claimed = bytes.get(8..40)?.try_into().ok()?;
                    r::verify_transition(bytes, &RefKeySet::shipped(&[claimed]), now).ok()
                },
                g,
            )
        },
    );
    expect_prop_failure(&outcome, "I-39-pinned").unwrap();
}

/// I-39: the reference acceptor passes the rotation property, so the teeth
/// above fail on the seeded defect only.
#[test]
fn i39_reference_rotation_holds() {
    fstp_prop::check("i39_reference_rotation_holds", |g: &mut Gen| {
        rotation_holds(
            |bytes, set, now| r::verify_transition(bytes, set, now).ok(),
            g,
        )
    });
}

// ---------------------------------------------------------------------------
// Layering (design section 2.4 rule 6).

/// Every workspace crate that reaches `fstp-release` through normal or
/// build edges, read from `cargo tree --invert`.
fn release_dependents() -> BTreeSet<String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..").join("..");
    let out = Command::new(env!("CARGO"))
        .args([
            "tree",
            "--locked",
            "--workspace",
            "--invert",
            "fstp-release",
            "--edges",
            "normal,build",
            "--prefix",
            "none",
            "--format",
            "{p}",
        ])
        .arg("--manifest-path")
        .arg(root.join("Cargo.toml"))
        .output()
        .expect("cargo tree runs");
    assert!(
        out.status.success(),
        "cargo tree failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split_whitespace().next())
        .filter(|n| *n != "fstp-release")
        .map(str::to_owned)
        .collect()
}

/// I-39, design section 2.4 rule 6: only `fstp-cell` and
/// `fstp-release-svc`, and the test-only `fstp-celltest`, reach
/// `fstp-release`. So no command-path crate (`fstp-cell-core`,
/// `fstp-engine`, `fstp-domain`, `fstp-pgstore`, `fstp-vault`,
/// `fstp-backup`) can consult the licence. The same rule runs in
/// `tools/deps-check`.
#[test]
fn i39_no_command_path_reaches_release_crate() {
    let dependents = release_dependents();
    assert!(
        dependents.contains("fstp-cell"),
        "the dependency graph lost the edge fstp-cell -> fstp-release: {dependents:?}"
    );
    let allowed = ["fstp-cell", "fstp-release-svc", "fstp-celltest"];
    let offenders: Vec<&String> = dependents
        .iter()
        .filter(|d| !allowed.contains(&d.as_str()))
        .collect();
    assert!(
        offenders.is_empty(),
        "I-39: these crates reach fstp-release, so a command path could depend on the licence: {offenders:?}"
    );
}

// ---------------------------------------------------------------------------
// Services down (T-LICENCE-OUTAGE).

/// What a fault leaves in the plaintext egress log above TLS.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Trace {
    /// The request is written and the faulty answer comes back.
    RequestAndAnswer,
    /// The request is written and no answer comes back.
    RequestOnly,
    /// The connection fails below TLS, so nothing reaches the recorder.
    BelowTls,
}

/// How the CrabNebula services fail in one run of
/// `i39_cycle_completes_with_services_down` (design section 14.4), and
/// what each fault leaves in the egress log.
const SERVICE_FAULTS: [(&str, Trace); 8] = [
    ("refused", Trace::BelowTls),
    ("timed-out", Trace::RequestOnly),
    ("failed-tls", Trace::BelowTls),
    ("garbage", Trace::RequestAndAnswer),
    ("slow-body", Trace::RequestAndAnswer),
    ("expired-token", Trace::RequestAndAnswer),
    ("bad-signature", Trace::RequestAndAnswer),
    ("clock-skew", Trace::RequestAndAnswer),
];

/// The gap that stands for faults below TLS. The egress recorder keeps
/// the bytes of successful reads and writes above TLS only. A refused
/// connection or a failed handshake leaves nothing, so no test can show
/// that the cell met such a fault.
const ATTEMPT_SEAM: &str = "the egress recorder keeps no record of a connection attempt that fails below TLS, so a refused or failed-TLS attempt cannot be shown (design section 14.3; lead, harness)";

/// Whether the captures since `from` show a CrabNebula attempt by cell 0
/// that met a fault with `trace`.
fn met_fault(world: &World, from: usize, trace: Trace) -> Result<(), String> {
    let new: Vec<_> = world
        .egress()
        .captures()
        .into_iter()
        .skip(from)
        .filter(|c| c.route.to == Peer::CrabNebula && c.route.from == Endpoint::cell(0))
        .collect();
    let sent = new.iter().any(|c| c.direction == Direction::Outbound);
    let answered = new.iter().any(|c| c.direction == Direction::Inbound);
    match trace {
        Trace::BelowTls => Err(ATTEMPT_SEAM.to_owned()),
        Trace::RequestOnly if sent && !answered => Ok(()),
        Trace::RequestAndAnswer if sent && answered => Ok(()),
        _ => Err(format!(
            "no CrabNebula attempt met the fault: request sent {sent}, answer read {answered}, expected {trace:?}"
        )),
    }
}

/// I-39, design section 14.4 and G18: with both services failing in each
/// way, a self-hosted cell runs the M2 catalogue to GRANTED and through
/// the payment commands, enqueues outbox events and calls the export
/// entry point stub. M5, M6 and M9 rerun it with real legs (Q33). Each
/// run must show a refresh or update check by the cell that met the
/// fault, so a no-op fault step cannot pass.
///
/// Gap: `CycleScript` names steps by text, and lane W3b defines the step
/// vocabulary. `services-down:<fault>` and the step names here are the
/// W1g proposal. Faults below TLS wait for [`ATTEMPT_SEAM`].
#[test]
fn i39_cycle_completes_with_services_down() {
    let world = World::start(WorldSpec {
        cells: 1,
        mode: DbMode::Dedicated,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: true,
        process_mode: false,
    })
    .unwrap_or_else(|e| panic!("a self-hosted world with one cell: {e}"));
    let failed: Vec<(&str, String)> = SERVICE_FAULTS
        .iter()
        .filter_map(|(fault, trace)| {
            let steps = [
                format!("services-down:{fault}"),
                "restart".to_owned(),
                "licence-refresh".to_owned(),
                "update-check".to_owned(),
                "catalogue-to-granted".to_owned(),
                "payment-commands".to_owned(),
                "enqueue-outbox".to_owned(),
                "export-entry-point".to_owned(),
            ];
            let script = CycleScript {
                steps: steps.to_vec(),
            };
            let from = world.egress().captures().len();
            let outcome = world
                .run_cycle(0, &script)
                .result
                .map_err(|e| e.to_string())
                .and_then(|()| met_fault(&world, from, *trace));
            outcome.err().map(|e| (*fault, e))
        })
        .collect();
    assert!(
        failed.is_empty(),
        "I-39: the cycle did not complete with the services down, or met no fault: {failed:?}"
    );
}

// ---------------------------------------------------------------------------
// The reference.

/// P-43, design section 14.1: the reference is in grace one tick before
/// the grace end and expired at it, and valid one tick before
/// `not_after`. A self-test of the reduced-clock edges the model uses.
#[test]
fn i39_reference_licence_state_edges() {
    let t = RefToken {
        licence: RefLicenceId([1; 16]),
        kind: RefKind::Noncommercial,
        issued_at: T0,
        refresh_after: T0 + 7 * DAY_S,
        not_after: T0 + 14 * DAY_S,
    };
    let ends = t.not_after + r::grace_len(P43_DAYS);
    let at = |now| r::licence_state(Some(&t), None, now, P43_DAYS);
    assert_eq!(
        [
            at(t.not_after - 1),
            at(t.not_after),
            at(ends - 1),
            at(ends),
            at(ends + 1)
        ],
        [
            RefState::Valid { until: t.not_after },
            RefState::Grace {
                since: t.not_after,
                ends
            },
            RefState::Grace {
                since: t.not_after,
                ends
            },
            RefState::Expired { since: ends },
            RefState::Expired { since: ends },
        ]
    );
}

/// I-39: the reference classifier puts every payment kind in the payments
/// class and only the two Q18 option B kinds outside the protected
/// classes.
#[test]
fn i39_reference_classifier_protects_all_but_setup() {
    let unprotected: Vec<CommandKind> = CommandKind::ALL
        .into_iter()
        .filter(|k| !r::class_of(*k).protected())
        .collect();
    assert_eq!(
        unprotected,
        vec![CommandKind::CreateProgramme, CommandKind::PublishCall]
    );
}

/// I-39, design section 10.2: a self-test of the reference refresh order
/// and checks. A token signed by a key announced in the same response
/// verifies from the key's `not_before` on and not one tick before. A
/// transition signed outside the set is refused with its token. A
/// validly signed token for another licence and a replay of an older
/// token are refused, and the stored token fetched again changes
/// nothing.
#[test]
fn i39_reference_refresh_order_and_checks() {
    let shipped = key(0x11);
    let next = key(0x22);
    let outsider = key(0x99);
    let keys = RefKeySet::shipped(&[shipped.public_key()]);
    let t1 = RefToken {
        licence: RefLicenceId([0x4c; 16]),
        kind: RefKind::Commercial,
        issued_at: T0,
        refresh_after: T0 + 7 * DAY_S,
        not_after: T0 + 14 * DAY_S,
    };
    let t2 = RefToken {
        issued_at: T0 + 7 * DAY_S,
        refresh_after: T0 + 21 * DAY_S,
        not_after: T0 + 28 * DAY_S,
        ..t1
    };
    let nb = T0 + 7 * DAY_S;
    let t = RefTransition {
        next_key: next.public_key(),
        not_before: nb,
    };
    let signed_t = r::sign_transition(&t, &shipped).unwrap();
    let forged_t = r::sign_transition(&t, &outsider).unwrap();
    let t2_next = r::sign_token(&t2, &next).unwrap();
    let t2_shipped = r::sign_token(&t2, &shipped).unwrap();
    let t1_shipped = r::sign_token(&t1, &shipped).unwrap();
    let foreign = r::sign_token(
        &RefToken {
            licence: RefLicenceId([0x4d; 16]),
            ..t2
        },
        &shipped,
    )
    .unwrap();
    let apply = |stored: &RefToken, transition: Option<&[u8]>, token: &[u8], now| {
        r::apply_refresh(stored, &keys, &r::refresh_response(transition, token), now)
    };
    let rotated = keys.with(&t);
    assert_eq!(
        [
            apply(&t1, Some(&signed_t), &t2_next, nb - 1),
            apply(&t1, Some(&signed_t), &t2_next, nb),
            apply(&t1, Some(&forged_t), &t2_shipped, nb),
            apply(&t1, None, &foreign, nb),
            apply(&t2, None, &t1_shipped, nb),
            apply(&t1, None, &t1_shipped, nb),
            r::apply_refresh(&t1, &keys, &t2_shipped, nb),
        ],
        [
            Err(RefreshRefusal::Token(TokenRefusal::Signature)),
            Ok(r::Refreshed {
                token: t2,
                keys: rotated,
            }),
            Err(RefreshRefusal::Transition(TransitionRefusal::Signature)),
            Err(RefreshRefusal::OtherLicence),
            Err(RefreshRefusal::Stale),
            Ok(r::Refreshed {
                token: t1,
                keys: keys.clone(),
            }),
            Err(RefreshRefusal::Framing),
        ]
    );
}
