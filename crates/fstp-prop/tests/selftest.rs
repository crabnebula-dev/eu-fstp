//! Self-tests of the property harness (M1 exit criterion "harnesses self-tested").
//!
//! Each test runs the harness on a property with a known answer and checks the
//! outcome exactly: the minimal counterexample, the replay, the bounds, the
//! shrink budget and the discard limit.

// Helpers and fixtures here sit outside #[test] functions, where the workspace
// test exemptions (clippy.toml) do not reach. Panics, indexing and arithmetic
// in this file report test failures, which is their purpose.
#![allow(
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::Cell;
use std::collections::VecDeque;

use fstp_prop::{
    Config, Failure, FailureKind, Gen, Outcome, StateMachine, check_with, commands_for,
    format_replay, parse_replay, prop_assert, prop_assert_eq, run, run_machine, seed_for_name,
};

fn failure(outcome: Outcome) -> Failure {
    match outcome {
        Outcome::Failed(f) => f,
        Outcome::Passed { cases } => panic!("expected a failure, passed {cases} cases"),
    }
}

fn shortlex_le(a: &[u64], b: &[u64]) -> bool {
    a.len() < b.len() || (a.len() == b.len() && a <= b)
}

// 1. Known-false properties shrink to the exact minimal counterexample.

/// `x < 1000` over all `u64` shrinks to exactly 1000.
#[test]
fn selftest_shrinks_u64_below_1000_to_1000() {
    let f = failure(run("u64_below_1000", Config::default(), |g| {
        let x = g.u64();
        g.note("x", &x);
        prop_assert!(x < 1000);
        Ok(())
    }));
    assert_eq!(f.kind, FailureKind::Counterexample);
    assert_eq!(f.choices, vec![1000]);
    assert_eq!(f.notes, vec!["x = 1000".to_owned()]);
    assert!(f.message.contains("x < 1000"), "{}", f.message);
}

/// `len < 3` shrinks to a vector of exactly three zeros.
#[test]
fn selftest_shrinks_vec_len_below_3_to_three_zeros() {
    let f = failure(run("vec_len_below_3", Config::default(), |g| {
        let v = g.vec(0..=50, |g| g.u64());
        g.note("v", &v);
        prop_assert!(v.len() < 3);
        Ok(())
    }));
    assert_eq!(f.notes, vec!["v = [0, 0, 0]".to_owned()]);
    // Three continue flags with zero elements; the trailing stop flag and zero are trimmed.
    assert_eq!(f.choices, vec![1, 0, 1, 0, 1]);
}

/// `sum <= 100` over `Vec<u8>` shrinks to the one-element vector `[101]`.
///
/// This is the shortlex-minimal counterexample. No vector of length 0 can
/// exceed 100. Among vectors of length 1, 101 is the smallest byte that does.
/// The choice sequence is a continue flag followed by 101. Reaching it from a
/// multi-element failure needs the pair pass that moves value between choices.
#[test]
fn selftest_shrinks_byte_sum_to_single_101() {
    for i in 0..20u64 {
        let cfg = Config::default().with_seed(seed_for_name("byte_sum") ^ i);
        let f = failure(run("byte_sum", cfg, |g| {
            let v = g.bytes(0..=64);
            g.note("v", &v);
            let sum: u64 = v.iter().map(|&b| u64::from(b)).sum();
            prop_assert!(sum <= 100);
            Ok(())
        }));
        assert_eq!(f.notes, vec!["v = [101]".to_owned()], "seed variant {i}");
        assert_eq!(f.choices, vec![1, 101], "seed variant {i}");
    }
}

/// `a <= b + 10` shrinks to exactly `(11, 0)`.
#[test]
fn selftest_shrinks_pair_to_11_0() {
    let f = failure(run("pair_gap", Config::default(), |g| {
        let pair = (g.u64(), g.u64());
        g.note("pair", &pair);
        prop_assert!(u128::from(pair.0) <= u128::from(pair.1) + 10);
        Ok(())
    }));
    assert_eq!(f.notes, vec!["pair = (11, 0)".to_owned()]);
    assert_eq!(f.choices, vec![11]);
}

/// A string containing a specific character shrinks to that one character.
#[test]
fn selftest_shrinks_string_to_single_char() {
    let f = failure(run("ascii_no_x", Config::default().with_cases(5000), |g| {
        let s = g.ascii_string(0..=40);
        g.note("s", &s);
        prop_assert!(!s.contains('x'));
        Ok(())
    }));
    assert_eq!(f.notes, vec!["s = \"x\"".to_owned()]);
    assert_eq!(f.choices.len(), 2);

    let f = failure(run(
        "unicode_no_euro",
        Config::default().with_cases(5000),
        |g| {
            let s = g.string(0..=40);
            g.note("s", &s);
            prop_assert!(!s.contains('\u{20AC}'));
            Ok(())
        },
    ));
    assert_eq!(f.notes, vec!["s = \"\u{20AC}\"".to_owned()]);
    assert_eq!(f.choices, vec![1, 0x20AC]);
}

/// A composed generator shrinks with no shrinking code of its own.
#[test]
fn selftest_composed_generator_shrinks() {
    #[derive(Debug)]
    #[allow(dead_code)]
    struct Order {
        id: u32,
        lines: Vec<(u8, u16)>,
        note: Option<String>,
    }
    let gen_order = |g: &mut Gen| Order {
        id: g.u32(),
        lines: g.vec(0..=10, |g| (g.u8_in(1..=50), g.u16())),
        note: g.option(|g| g.ascii_string(0..=8)),
    };
    let f = failure(run("composed_order", Config::default(), |g| {
        let order = gen_order(g);
        g.note("order", &order);
        let total: u32 = order.lines.iter().map(|&(q, _)| u32::from(q)).sum();
        prop_assert!(total < 60);
        Ok(())
    }));
    assert_eq!(
        f.notes,
        vec!["order = Order { id: 0, lines: [(10, 0), (50, 0)], note: None }".to_owned()]
    );
}

// 2. True properties pass for 10,000 cases.

#[test]
fn selftest_true_properties_pass_10000_cases() {
    let cfg = Config::default().with_cases(10_000);
    let outcomes = [
        run("reverse_twice", cfg.clone(), |g| {
            let v = g.vec(0..=20, |g| g.i64());
            let mut w = v.clone();
            w.reverse();
            w.reverse();
            prop_assert_eq!(w, v);
            Ok(())
        }),
        run("sort_orders_and_keeps_length", cfg.clone(), |g| {
            let v = g.bytes(0..=40);
            let mut w = v.clone();
            w.sort_unstable();
            prop_assert_eq!(w.len(), v.len());
            prop_assert!(w.windows(2).all(|p| p[0] <= p[1]));
            Ok(())
        }),
        run("string_lengths_in_range", cfg.clone(), |g| {
            let s = g.string(2..=9);
            let n = s.chars().count();
            prop_assert!((2..=9).contains(&n), "{} chars", n);
            let a = g.ascii_string(0..=5);
            prop_assert!(a.is_ascii() && a.len() <= 5);
            Ok(())
        }),
        run("pick_and_weighted", cfg.clone(), |g| {
            let items = [10, 20, 30];
            prop_assert!(items.contains(g.pick(&items)));
            let i = g.weighted(&[0, 3, 0, 1]);
            prop_assert!(i == 1 || i == 3, "picked zero-weight index {}", i);
            Ok(())
        }),
        run("shuffle_is_a_permutation", cfg.clone(), |g| {
            let v = g.vec(0..=12, |g| g.u8());
            let mut w = v.clone();
            g.shuffle(&mut w);
            let (mut a, mut b) = (v.clone(), w.clone());
            a.sort_unstable();
            b.sort_unstable();
            prop_assert_eq!(a, b);
            Ok(())
        }),
        run("wrapping_add_commutes", cfg, |g| {
            let (a, b) = (g.u32(), g.u32());
            prop_assert_eq!(a.wrapping_add(b), b.wrapping_add(a));
            Ok(())
        }),
    ];
    for outcome in outcomes {
        assert_eq!(outcome, Outcome::Passed { cases: 10_000 });
    }
}

// 3. Determinism.

fn determinism_case(name: &str, cfg: Config) -> Outcome {
    run(name, cfg, |g| {
        let v = g.vec(0..=30, |g| g.u16());
        g.note("v", &v);
        prop_assert!(v.iter().map(|&x| u64::from(x)).sum::<u64>() < 5000);
        Ok(())
    })
}

#[test]
fn selftest_same_seed_same_outcome_and_choices() {
    let a = failure(determinism_case("determinism", Config::default()));
    let b = failure(determinism_case("determinism", Config::default()));
    assert_eq!(a, b);
    assert_eq!(a.seed, seed_for_name("determinism"));
    // An explicit seed gives the same search under any name.
    let c = failure(determinism_case(
        "other_name",
        Config::default().with_seed(a.seed),
    ));
    assert_eq!(c.original_choices, a.original_choices);
    assert_eq!(c.choices, a.choices);
    assert_eq!(c.shrink_steps, a.shrink_steps);
}

#[test]
fn selftest_different_names_different_seeds() {
    let names = [
        "a",
        "b",
        "determinism",
        "determinism2",
        "prop_x",
        "prop_y",
        "",
    ];
    for (i, x) in names.iter().enumerate() {
        for y in names.iter().skip(i + 1) {
            assert_ne!(seed_for_name(x), seed_for_name(y), "{x} vs {y}");
        }
    }
    // The hash is stable: these values must never change between builds.
    // They are FNV-1a followed by one SplitMix64 step, computed independently.
    assert_eq!(seed_for_name("a"), 0x5f29_c2aa_dd9b_8527);
    assert_eq!(seed_for_name(""), 0xc381_7c01_6ba4_ff30);
    assert_eq!(seed_for_name("determinism"), 0xe35e_fdc6_1e29_dc60);
    let a = failure(determinism_case("name_one", Config::default()));
    let b = failure(determinism_case("name_two", Config::default()));
    assert_ne!(a.seed, b.seed);
}

// 4. Panics are failures with their message, and they shrink.

#[test]
fn selftest_panicking_property_fails_and_shrinks() {
    let f = failure(run("panics_at_500", Config::default(), |g| {
        let x = g.u32();
        if x >= 500 {
            panic!("too big: {x}");
        }
        Ok(())
    }));
    assert_eq!(f.kind, FailureKind::Counterexample);
    assert_eq!(f.choices, vec![500]);
    assert!(f.message.contains("too big: 500"), "{}", f.message);
    assert!(f.message.contains("selftest.rs"), "{}", f.message);

    let f = failure(run("index_panic", Config::default(), |g| {
        let v = g.bytes(0..=10);
        let i = g.usize_in(0..=10);
        let _ = v[i];
        Ok(())
    }));
    assert!(f.message.contains("index out of bounds"), "{}", f.message);
    assert_eq!(f.choices, Vec::<u64>::new());
}

// 5. Replay reproduces a reported failure exactly.

#[test]
fn selftest_replay_reproduces_failure() {
    let prop = |g: &mut Gen| {
        let v = g.vec(1..=20, |g| g.i32());
        g.note("v", &v);
        prop_assert!(v.iter().all(|&x| x > -1000), "negative element in {:?}", v);
        Ok(())
    };
    let f = failure(run("replayable", Config::default(), prop));
    let text = format_replay(&f.choices);
    assert!(
        f.report().contains(&format!("FSTP_PROP_REPLAY='{text}'")),
        "{}",
        f.report()
    );
    let parsed = parse_replay(&text).unwrap();
    assert_eq!(parsed, f.choices);

    let replayed = failure(run(
        "replayable",
        Config::default().with_replay(parsed.clone()),
        prop,
    ));
    assert_eq!(replayed.kind, FailureKind::Counterexample);
    assert_eq!(replayed.choices, f.choices);
    assert_eq!(replayed.message, f.message);
    assert_eq!(replayed.notes, f.notes);
    assert_eq!(replayed.shrink_steps, 0);

    // The environment path parses the same value.
    let cfg = Config::default()
        .try_with_vars(|k| (k == "FSTP_PROP_REPLAY").then(|| text.clone()))
        .unwrap();
    assert_eq!(cfg.replay, Some(parsed));

    // Replaying the original, unshrunk sequence also reproduces the failure.
    let original = failure(run(
        "replayable",
        Config::default().with_replay(f.original_choices.clone()),
        prop,
    ));
    assert_eq!(original.choices, f.original_choices);

    // A replay that passes reports one passing case.
    assert_eq!(
        run("replayable", Config::default().with_replay(vec![1]), prop),
        Outcome::Passed { cases: 1 }
    );
}

// 6. Range generators stay in bounds and hit both bounds.

#[test]
fn selftest_range_generators_stay_in_bounds() {
    let outcome = run(
        "ranges_in_bounds",
        Config::default().with_cases(10_000),
        |g| {
            let (a, b) = (g.u64(), g.u64());
            let (lo, hi) = (a.min(b), a.max(b));
            let x = g.u64_in(lo..=hi);
            prop_assert!(lo <= x && x <= hi, "{} not in {}..={}", x, lo, hi);

            let (a, b) = (g.i64(), g.i64());
            let (lo, hi) = (a.min(b), a.max(b));
            let x = g.i64_in(lo..=hi);
            prop_assert!(lo <= x && x <= hi, "{} not in {}..={}", x, lo, hi);

            let (a, b) = (g.i32(), g.i32());
            let (lo, hi) = (a.min(b), a.max(b));
            let x = g.i32_in(lo..=hi);
            prop_assert!(lo <= x && x <= hi);

            let (a, b) = (g.u8(), g.u8());
            let (lo, hi) = (a.min(b), a.max(b));
            let x = g.u8_in(lo..=hi);
            prop_assert!(lo <= x && x <= hi);

            let (a, b) = (g.usize_in(0..=1000), g.usize_in(0..=1000));
            let (lo, hi) = (a.min(b), a.max(b));
            let v = g.vec(lo..=hi, |g| g.bool());
            prop_assert!(lo <= v.len() && v.len() <= hi);
            Ok(())
        },
    );
    assert_eq!(outcome, Outcome::Passed { cases: 10_000 });
}

/// For random ranges, both bounds appear within 200 cases.
#[test]
fn selftest_range_generators_hit_both_bounds() {
    const BUDGET: u32 = 200;
    let outcome = run("bounds_are_hit", Config::default().with_cases(300), |g| {
        let (a, b) = (g.i64(), g.i64());
        let (lo, hi) = (a.min(b), a.max(b));
        let (hit_lo, hit_hi) = (Cell::new(false), Cell::new(false));
        let inner = run("bounds_inner", Config::default().with_cases(BUDGET), |g| {
            let x = g.i64_in(lo..=hi);
            hit_lo.set(hit_lo.get() || x == lo);
            hit_hi.set(hit_hi.get() || x == hi);
            Ok(())
        });
        prop_assert_eq!(inner, Outcome::Passed { cases: BUDGET });
        prop_assert!(
            hit_lo.get() && hit_hi.get(),
            "range {}..={} missed a bound",
            lo,
            hi
        );

        let (a, b) = (g.u64(), g.u64());
        let (lo, hi) = (a.min(b), a.max(b));
        let (hit_lo, hit_hi) = (Cell::new(false), Cell::new(false));
        let _ = run(
            "bounds_inner_u64",
            Config::default().with_cases(BUDGET),
            |g| {
                let x = g.u64_in(lo..=hi);
                hit_lo.set(hit_lo.get() || x == lo);
                hit_hi.set(hit_hi.get() || x == hi);
                Ok(())
            },
        );
        prop_assert!(
            hit_lo.get() && hit_hi.get(),
            "range {}..={} missed a bound",
            lo,
            hi
        );

        let (a, b) = (g.usize_in(0..=500), g.usize_in(0..=500));
        let (lo, hi) = (a.min(b), a.max(b));
        let (hit_lo, hit_hi) = (Cell::new(false), Cell::new(false));
        let _ = run(
            "bounds_inner_len",
            Config::default().with_cases(BUDGET),
            |g| {
                let n = g.bytes(lo..=hi).len();
                hit_lo.set(hit_lo.get() || n == lo);
                hit_hi.set(hit_hi.get() || n == hi);
                Ok(())
            },
        );
        prop_assert!(
            hit_lo.get() && hit_hi.get(),
            "length range {}..={} missed a bound",
            lo,
            hi
        );
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 300 });
}

// 7. Shrinking respects its budget and never grows the failing sequence.

#[test]
fn selftest_shrinking_respects_budget_and_never_grows() {
    let outcome = run("shrink_budget", Config::default().with_cases(100), |g| {
        let budget = g.u32_in(0..=300);
        let threshold = g.u64_in(0..=2000);
        let inner = run(
            "shrink_budget_inner",
            Config::default().with_max_shrink_steps(budget),
            |g| {
                let v = g.vec(0..=40, |g| g.u16());
                let sum: u64 = v.iter().map(|&x| u64::from(x)).sum();
                prop_assert!(v.len() < 4 || sum < threshold);
                Ok(())
            },
        );
        let f = match inner {
            Outcome::Failed(f) => f,
            Outcome::Passed { .. } => return Ok(()),
        };
        prop_assert!(
            f.shrink_steps <= budget,
            "{} steps > budget {}",
            f.shrink_steps,
            budget
        );
        prop_assert!(
            shortlex_le(&f.choices, &f.original_choices),
            "grew from {:?} to {:?}",
            f.original_choices,
            f.choices
        );
        prop_assert_eq!(f.kind, FailureKind::Counterexample);
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 100 });

    // A zero budget reports the original failing sequence.
    let f = failure(run(
        "no_shrinking",
        Config::default().with_max_shrink_steps(0),
        |g| {
            let x = g.u64();
            prop_assert!(x < 10);
            Ok(())
        },
    ));
    assert_eq!(f.shrink_steps, 0);
    assert_eq!(f.choices, f.original_choices);
}

// 8. Stateful testing finds a seeded bug in a bounded queue.

const CAPACITY: usize = 3;

/// A ring-buffer queue with an off-by-one capacity check: a push into a full
/// queue succeeds and overwrites the oldest element.
struct BrokenQueue {
    buf: [u8; CAPACITY],
    head: usize,
    len: usize,
}

impl BrokenQueue {
    fn push(&mut self, v: u8) -> Result<(), u8> {
        if self.len > CAPACITY {
            return Err(v);
        }
        let tail = (self.head + self.len) % CAPACITY;
        self.buf[tail] = v;
        if self.len == CAPACITY {
            self.head = (self.head + 1) % CAPACITY;
        } else {
            self.len += 1;
        }
        Ok(())
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let v = self.buf[self.head];
        self.head = (self.head + 1) % CAPACITY;
        self.len -= 1;
        Some(v)
    }
}

#[derive(Clone, Debug, PartialEq)]
enum QCmd {
    Push(u8),
    Pop,
    Len,
}

#[derive(Debug, PartialEq)]
enum QOut {
    Pushed(Result<(), u8>),
    Popped(Option<u8>),
    Len(usize),
}

struct QueueMachine;

impl StateMachine for QueueMachine {
    type Model = VecDeque<u8>;
    type Sut = BrokenQueue;
    type Command = QCmd;
    type Output = QOut;

    fn init_model(&self) -> VecDeque<u8> {
        VecDeque::new()
    }

    fn init_sut(&self) -> BrokenQueue {
        BrokenQueue {
            buf: [0; CAPACITY],
            head: 0,
            len: 0,
        }
    }

    fn command(&self, g: &mut Gen, _model: &VecDeque<u8>) -> QCmd {
        match g.weighted(&[3, 2, 1]) {
            0 => QCmd::Push(g.u8()),
            1 => QCmd::Pop,
            _ => QCmd::Len,
        }
    }

    fn run(&self, sut: &mut BrokenQueue, cmd: &QCmd) -> QOut {
        match cmd {
            QCmd::Push(v) => QOut::Pushed(sut.push(*v)),
            QCmd::Pop => QOut::Popped(sut.pop()),
            QCmd::Len => QOut::Len(sut.len),
        }
    }

    fn next_state(&self, model: &mut VecDeque<u8>, cmd: &QCmd) {
        match cmd {
            QCmd::Push(v) if model.len() < CAPACITY => model.push_back(*v),
            QCmd::Pop => {
                model.pop_front();
            }
            _ => {}
        }
    }

    fn postcondition(&self, model: &VecDeque<u8>, cmd: &QCmd, out: &QOut) -> Result<(), String> {
        let expected = match cmd {
            QCmd::Push(v) if model.len() >= CAPACITY => QOut::Pushed(Err(*v)),
            QCmd::Push(_) => QOut::Pushed(Ok(())),
            QCmd::Pop => QOut::Popped(model.front().copied()),
            QCmd::Len => QOut::Len(model.len()),
        };
        if *out == expected {
            Ok(())
        } else {
            Err(format!("expected {expected:?}"))
        }
    }
}

/// The minimal failing sequence fills the queue and pushes once more:
/// exactly `CAPACITY + 1` pushes of 0. Checked for 25 seeds.
#[test]
fn selftest_state_machine_finds_broken_queue() {
    for i in 0..25u64 {
        let cfg = Config::default().with_seed(seed_for_name("broken_queue") ^ i);
        let f = failure(run_machine("broken_queue", cfg, &QueueMachine));
        assert_eq!(f.kind, FailureKind::Counterexample);
        let commands = commands_for(&QueueMachine, &f.choices);
        assert_eq!(
            commands.len(),
            CAPACITY + 1,
            "seed variant {i}: {commands:?}"
        );
        assert_eq!(
            commands,
            vec![QCmd::Push(0); CAPACITY + 1],
            "seed variant {i}"
        );
    }
    let f = failure(run_machine(
        "broken_queue",
        Config::default(),
        &QueueMachine,
    ));
    assert_eq!(f.notes.len(), CAPACITY + 1);
    assert_eq!(f.notes[CAPACITY], format!("step {}: Push(0)", CAPACITY + 1));
    let report = f.report();
    assert!(report.contains("step 4: Push(0)"), "{report}");
    assert!(
        report.contains("postcondition failed at step 4"),
        "{report}"
    );
}

/// A correct queue passes the same machine.
#[test]
fn selftest_state_machine_passes_correct_model() {
    struct Fixed;
    impl StateMachine for Fixed {
        type Model = VecDeque<u8>;
        type Sut = VecDeque<u8>;
        type Command = QCmd;
        type Output = QOut;
        fn init_model(&self) -> VecDeque<u8> {
            VecDeque::new()
        }
        fn init_sut(&self) -> VecDeque<u8> {
            VecDeque::new()
        }
        fn command(&self, g: &mut Gen, m: &VecDeque<u8>) -> QCmd {
            QueueMachine.command(g, m)
        }
        fn run(&self, sut: &mut VecDeque<u8>, cmd: &QCmd) -> QOut {
            match cmd {
                QCmd::Push(v) if sut.len() >= CAPACITY => QOut::Pushed(Err(*v)),
                QCmd::Push(v) => {
                    sut.push_back(*v);
                    QOut::Pushed(Ok(()))
                }
                QCmd::Pop => QOut::Popped(sut.pop_front()),
                QCmd::Len => QOut::Len(sut.len()),
            }
        }
        fn next_state(&self, m: &mut VecDeque<u8>, cmd: &QCmd) {
            QueueMachine.next_state(m, cmd);
        }
        fn postcondition(&self, m: &VecDeque<u8>, c: &QCmd, o: &QOut) -> Result<(), String> {
            QueueMachine.postcondition(m, c, o)
        }
        fn invariant(&self, m: &VecDeque<u8>, s: &VecDeque<u8>) -> Result<(), String> {
            if m == s {
                Ok(())
            } else {
                Err("diverged".to_owned())
            }
        }
    }
    let outcome = run_machine("fixed_queue", Config::default().with_cases(2000), &Fixed);
    assert_eq!(outcome, Outcome::Passed { cases: 2000 });
}

// 9. Excessive discards fail the run.

#[test]
fn selftest_excessive_discards_fail() {
    let f = failure(run(
        "always_rejects",
        Config::default().with_cases(50),
        |g| {
            let _ = g.u8();
            g.assume(false);
            Ok(())
        },
    ));
    assert_eq!(f.kind, FailureKind::TooManyDiscards);
    assert_eq!(f.cases_passed, 0);
    assert_eq!(f.cases_discarded, 50 * fstp_prop::MAX_DISCARD_RATIO + 1);
    assert!(f.message.contains("discarded"), "{}", f.message);

    // Cases that exceed max_choices are discards, not failures.
    let f = failure(run(
        "always_overruns",
        Config::default().with_cases(20).with_max_choices(4),
        |g| {
            let v = g.bytes(10..=12);
            prop_assert!(v.len() > 100, "never reached");
            Ok(())
        },
    ));
    assert_eq!(f.kind, FailureKind::TooManyDiscards);
    assert!(
        f.message.contains("exceeded max_choices = 4"),
        "{}",
        f.message
    );

    // A moderate discard rate still passes.
    let outcome = run("half_rejected", Config::default().with_cases(500), |g| {
        let x = g.u32();
        g.assume(x % 2 == 0);
        prop_assert!(x % 2 == 0);
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 500 });

    // A replay that is discarded is a failure, not a pass.
    let f = failure(run(
        "replay_rejected",
        Config::default().with_replay(vec![]),
        |g| g.reject(),
    ));
    assert_eq!(f.kind, FailureKind::ReplayDiscarded);
}

// Reporting and configuration.

#[test]
fn selftest_check_panics_with_full_report() {
    let result = std::panic::catch_unwind(|| {
        check_with("reported", Config::default(), |g| {
            let x = g.u16();
            g.note("x", &x);
            prop_assert!(x < 300, "x is {}", x);
            Ok(())
        });
    });
    let payload = result.expect_err("check must panic on failure");
    let report = payload
        .downcast_ref::<String>()
        .cloned()
        .unwrap_or_default();
    for needle in [
        "property `reported` failed (counterexample found)",
        "seed: 0x",
        "cases passed before failure:",
        "shrink steps:",
        "x is 300",
        "x = 300",
        "minimal choice sequence: '12c'",
        "FSTP_PROP_REPLAY='12c' cargo test ",
        " --test selftest -- --exact selftest_check_panics_with_full_report\n",
        "selftest.rs",
    ] {
        assert!(report.contains(needle), "missing {needle:?} in:\n{report}");
    }
    // Under cargo test, the command also selects the package.
    if std::env::var("CARGO_PKG_NAME").as_deref() == Ok("fstp-prop") {
        let needle = "FSTP_PROP_REPLAY='12c' cargo test -p fstp-prop --test selftest -- --exact \
                      selftest_check_panics_with_full_report\n";
        assert!(report.contains(needle), "missing {needle:?} in:\n{report}");
    }
    assert!(!report.contains("<TEST>"), "{report}");
}

#[test]
fn selftest_env_overrides_parse_strictly() {
    let vars = |pairs: &'static [(&'static str, &'static str)]| {
        move |k: &str| {
            pairs
                .iter()
                .find(|(name, _)| *name == k)
                .map(|(_, v)| (*v).to_owned())
        }
    };
    let cfg = Config::default()
        .try_with_vars(vars(&[
            ("FSTP_PROP_CASES", "77"),
            ("FSTP_PROP_SEED", "0xff"),
            ("FSTP_PROP_REPLAY", "3e8,0,1"),
        ]))
        .unwrap();
    assert_eq!(cfg.cases, 77);
    assert_eq!(cfg.seed, Some(255));
    assert_eq!(cfg.replay, Some(vec![1000, 0, 1]));
    let cfg = Config::default()
        .try_with_vars(vars(&[("FSTP_PROP_SEED", "12345")]))
        .unwrap();
    assert_eq!(cfg.seed, Some(12345));
    assert_eq!(cfg.cases, 256);
    assert_eq!(
        Config::default()
            .try_with_vars(vars(&[("FSTP_PROP_REPLAY", "")]))
            .unwrap()
            .replay,
        Some(vec![])
    );
    for bad in [
        &[("FSTP_PROP_CASES", "0")][..],
        &[("FSTP_PROP_CASES", "many")][..],
        &[("FSTP_PROP_SEED", "0xzz")][..],
        &[("FSTP_PROP_REPLAY", "3E8")][..],
    ] {
        let err = Config::default().try_with_vars(vars(bad)).unwrap_err();
        assert_eq!(err.var, bad[0].0);
        assert!(!err.to_string().is_empty());
    }
}

/// A property that fails only on its first run is reported as flaky, not passed.
#[test]
fn selftest_flaky_property_is_reported() {
    let runs = Cell::new(0u32);
    let f = failure(run("flaky", Config::default(), |g| {
        let _ = g.u8();
        runs.set(runs.get() + 1);
        prop_assert!(runs.get() > 1, "first run");
        Ok(())
    }));
    assert_eq!(f.kind, FailureKind::Flaky);
    assert!(f.message.contains("first run"), "{}", f.message);
}

/// Generator misuse ends the case as a failure with a clear message.
#[test]
fn selftest_generator_misuse_is_a_failure() {
    let f = failure(run("pick_empty", Config::default(), |g| {
        let empty: [u8; 0] = [];
        let _ = g.pick(&empty);
        Ok(())
    }));
    assert!(f.message.contains("empty slice"), "{}", f.message);
    let f = failure(run("weighted_zero", Config::default(), |g| {
        let _ = g.weighted(&[0, 0]);
        Ok(())
    }));
    assert!(f.message.contains("non-zero weight"), "{}", f.message);
    #[allow(clippy::reversed_empty_ranges)]
    let f = failure(run("empty_range", Config::default(), |g| {
        let _ = g.u8_in(5..=4);
        Ok(())
    }));
    assert!(f.message.contains("empty integer range"), "{}", f.message);

    // A property that catches the unwind itself still fails or discards.
    let f = failure(run("caught_misuse", Config::default(), |g| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let empty: [u8; 0] = [];
            let _ = g.pick(&empty);
        }));
        Ok(())
    }));
    assert!(f.message.contains("empty slice"), "{}", f.message);
    let f = failure(run("caught_reject", Config::default().with_cases(5), |g| {
        let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| g.reject()));
        Ok(())
    }));
    assert_eq!(f.kind, FailureKind::TooManyDiscards);
}

/// A shuffle that must keep the order shrinks to one swap of the first two
/// items. Its choice sequence `[1]` is shortlex smaller than any other
/// non-identity shuffle, such as `[0, 0, 0, 1]` for the last two items.
#[test]
fn selftest_shuffle_shrinks_to_first_swap() {
    let f = failure(run("shuffle_keeps_order", Config::default(), |g| {
        let mut v: Vec<u8> = (0..5).collect();
        g.shuffle(&mut v);
        g.note("v", &v);
        prop_assert!(v.windows(2).all(|p| p[0] < p[1]));
        Ok(())
    }));
    assert_eq!(f.notes, vec!["v = [1, 0, 2, 3, 4]".to_owned()]);
    assert_eq!(f.choices, vec![1]);
}
