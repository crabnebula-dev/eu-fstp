//! Regression tests for the M1 review findings on the property harness.
//!
//! Each test is named after the finding it guards. The harness runs every
//! invariant property (`07-test-plan/test-plan.md`), so a gap here would let
//! an invariant test pass without checking anything.

// Helpers and fixtures here sit outside #[test] functions, where the workspace
// test exemptions (clippy.toml) do not reach. Panics, unwraps, indexing and
// arithmetic in this file report test failures, which is their purpose.
#![allow(
    clippy::panic,
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects
)]

use std::cell::{Cell, RefCell};
use std::path::PathBuf;
use std::process::{Command, Output};

use fstp_prop::{
    Config, ENV_CASES, ENV_REPLAY, ENV_REPLAY_FILE, ENV_SEED, Failure, FailureKind, Gen,
    MAX_REPLAY_ENV_LEN, Outcome, StateMachine, check_with, commands_for, format_replay,
    prop_assert, run, run_machine,
};

fn failure(outcome: Outcome) -> Failure {
    match outcome {
        Outcome::Failed(f) => f,
        Outcome::Passed { cases } => panic!("expected a failure, passed {cases} cases"),
    }
}

/// Returns the text of a panic payload.
fn payload_text(payload: &(dyn std::any::Any + Send)) -> String {
    if let Some(s) = payload.downcast_ref::<String>() {
        s.clone()
    } else if let Some(s) = payload.downcast_ref::<&str>() {
        (*s).to_owned()
    } else {
        String::new()
    }
}

// ---------------------------------------------------------------------------
// prop-wide-length-hole

/// Collection lengths in the middle of a wide range occur. A property that
/// fails only there must not pass.
#[test]
fn review_prop_wide_length_hole() {
    let f = failure(run(
        "len_mid_of_4096",
        Config::default().with_max_shrink_steps(50),
        |g| {
            let v = g.bytes(0..=4096);
            g.note("len", &v.len());
            prop_assert!(v.len() < 1024 || v.len() == 4096, "len {}", v.len());
            Ok(())
        },
    ));
    assert_eq!(f.kind, FailureKind::Counterexample);
    let len: usize = f.notes[0].trim_start_matches("len = ").parse().unwrap();
    assert!((1024..4096).contains(&len), "{len}");

    let f = failure(run(
        "len_of_100k",
        Config::default().with_max_shrink_steps(50),
        |g| {
            let v = g.vec(0..=100_000, |_| ());
            prop_assert!(v.len() < 1024, "len {}", v.len());
            Ok(())
        },
    ));
    assert_eq!(f.kind, FailureKind::Counterexample);

    // Within the default case count, each eighth of 0..=4096 occurs.
    let buckets = RefCell::new([0u32; 8]);
    let outcome = run("len_buckets", Config::default(), |g| {
        let n = g.bytes(0..=4096).len();
        buckets.borrow_mut()[(n * 8 / 4097).min(7)] += 1;
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 256 });
    assert!(buckets.borrow().iter().all(|&b| b > 0), "{buckets:?}");
}

// ---------------------------------------------------------------------------
// prop-selftest-statemachine-gap

#[derive(Clone, Debug, PartialEq)]
enum CounterCmd {
    Inc,
    Dec,
}

/// A counter whose system under test skips 3: incrementing 2 gives 4.
/// Commands return nothing, so only the invariant can see the bug.
struct SkipsThree {
    /// The system under test starts here; the model starts at 0.
    sut_start: u8,
}

impl StateMachine for SkipsThree {
    type Model = u8;
    type Sut = u8;
    type Command = CounterCmd;
    type Output = ();

    fn init_model(&self) -> u8 {
        0
    }

    fn init_sut(&self) -> u8 {
        self.sut_start
    }

    fn command(&self, g: &mut Gen, _: &u8) -> CounterCmd {
        if g.bool() {
            CounterCmd::Dec
        } else {
            CounterCmd::Inc
        }
    }

    fn run(&self, sut: &mut u8, cmd: &CounterCmd) {
        *sut = match cmd {
            CounterCmd::Inc if *sut == 2 => 4,
            CounterCmd::Inc => sut.saturating_add(1),
            CounterCmd::Dec => sut.saturating_sub(1),
        };
    }

    fn next_state(&self, model: &mut u8, cmd: &CounterCmd) {
        *model = match cmd {
            CounterCmd::Inc => model.saturating_add(1),
            CounterCmd::Dec => model.saturating_sub(1),
        };
    }

    fn invariant(&self, model: &u8, sut: &u8) -> Result<(), String> {
        if model == sut {
            Ok(())
        } else {
            Err(format!("model {model}, sut {sut}"))
        }
    }
}

/// An invariant that breaks after the third increment is reported with the
/// exact minimal sequence and message, for several seeds.
#[test]
fn review_prop_selftest_statemachine_gap_invariant_after_step() {
    let machine = SkipsThree { sut_start: 0 };
    for i in 0..10u64 {
        let cfg = Config::default().with_seed(0x1234 ^ i);
        let f = failure(run_machine("skips_three", cfg, &machine));
        assert_eq!(f.kind, FailureKind::Counterexample, "seed variant {i}");
        assert_eq!(
            f.message, "invariant failed after step 3 (Inc): model 3, sut 4",
            "seed variant {i}"
        );
        assert_eq!(f.choices, vec![1, 0, 1, 0, 1], "seed variant {i}");
        assert_eq!(
            commands_for(&machine, &f.choices),
            vec![CounterCmd::Inc; 3],
            "seed variant {i}"
        );
        assert_eq!(f.notes, ["step 1: Inc", "step 2: Inc", "step 3: Inc"]);
    }
}

/// An invariant that fails in the initial state is reported before any
/// command runs, with the empty sequence.
#[test]
fn review_prop_selftest_statemachine_gap_invariant_before_first_command() {
    let machine = SkipsThree { sut_start: 1 };
    let f = failure(run_machine("bad_start", Config::default(), &machine));
    assert_eq!(f.kind, FailureKind::Counterexample);
    assert_eq!(
        f.message,
        "invariant failed before the first command: model 0, sut 1"
    );
    assert_eq!(f.choices, Vec::<u64>::new());
    assert!(f.notes.is_empty(), "{:?}", f.notes);
}

#[derive(Clone, Debug, PartialEq)]
enum StackCmd {
    Push(u8),
    Pop,
}

/// A stack whose generator emits `Pop` even when the model is empty. The
/// precondition must skip those, because popping an empty system under test
/// panics.
#[derive(Default)]
struct GuardedStack {
    /// Number of generated commands the precondition rejected.
    rejected: Cell<u32>,
}

impl StateMachine for GuardedStack {
    type Model = Vec<u8>;
    type Sut = Vec<u8>;
    type Command = StackCmd;
    type Output = Option<u8>;

    fn init_model(&self) -> Vec<u8> {
        Vec::new()
    }

    fn init_sut(&self) -> Vec<u8> {
        Vec::new()
    }

    fn command(&self, g: &mut Gen, _: &Vec<u8>) -> StackCmd {
        if g.bool() {
            StackCmd::Pop
        } else {
            StackCmd::Push(g.u8())
        }
    }

    fn precondition(&self, model: &Vec<u8>, cmd: &StackCmd) -> bool {
        let ok = *cmd != StackCmd::Pop || !model.is_empty();
        if !ok {
            self.rejected.set(self.rejected.get() + 1);
        }
        ok
    }

    fn run(&self, sut: &mut Vec<u8>, cmd: &StackCmd) -> Option<u8> {
        match cmd {
            StackCmd::Push(v) => {
                sut.push(*v);
                None
            }
            StackCmd::Pop => match sut.pop() {
                Some(v) => Some(v),
                None => panic!("pop on an empty stack"),
            },
        }
    }

    fn next_state(&self, model: &mut Vec<u8>, cmd: &StackCmd) {
        match cmd {
            StackCmd::Push(v) => model.push(*v),
            StackCmd::Pop => {
                model.pop();
            }
        }
    }

    fn postcondition(
        &self,
        model: &Vec<u8>,
        cmd: &StackCmd,
        out: &Option<u8>,
    ) -> Result<(), String> {
        let want = match cmd {
            StackCmd::Push(_) => None,
            StackCmd::Pop => model.last().copied(),
        };
        if *out == want {
            Ok(())
        } else {
            Err(format!("expected {want:?}"))
        }
    }

    fn invariant(&self, model: &Vec<u8>, sut: &Vec<u8>) -> Result<(), String> {
        if model == sut {
            Ok(())
        } else {
            Err("diverged".to_owned())
        }
    }
}

/// Commands that fail the precondition are skipped: the run passes although
/// running them would panic, and `commands_for` leaves them out.
#[test]
fn review_prop_selftest_statemachine_gap_precondition_skips() {
    let machine = GuardedStack::default();
    let outcome = run_machine(
        "guarded_stack",
        Config::default().with_cases(2000),
        &machine,
    );
    assert_eq!(outcome, Outcome::Passed { cases: 2000 });
    assert!(
        machine.rejected.get() > 0,
        "the generator never needed the precondition"
    );

    // Flag, Pop (rejected on the empty model), flag, Push(5), flag, Pop.
    let commands = commands_for(&machine, &[1, 1, 1, 0, 5, 1, 1]);
    assert_eq!(commands, vec![StackCmd::Push(5), StackCmd::Pop]);
}

// ---------------------------------------------------------------------------
// prop-selftest-env-gap

/// Name of the child test that `review_prop_selftest_env_gap` runs.
const ENV_CHILD: &str = "env_child_check_with";
/// Prefix of the line the child prints with the values it drew.
const ENV_CHILD_LINE: &str = "env-child values: ";

/// A property that records every `u64` it draws and always passes.
fn record_values(values: &RefCell<Vec<u64>>) -> impl Fn(&mut Gen) -> Result<(), String> + '_ {
    move |g| {
        values.borrow_mut().push(g.u64());
        Ok(())
    }
}

/// Runs the child test in a fresh process of this test binary, with the
/// `FSTP_PROP_*` variables cleared and then set to `vars`.
fn run_child(vars: &[(&str, &str)]) -> Output {
    let exe = std::env::current_exe().unwrap();
    let mut cmd = Command::new(exe);
    cmd.args([
        "--exact",
        ENV_CHILD,
        "--ignored",
        "--nocapture",
        "--test-threads=1",
    ]);
    for var in [ENV_CASES, ENV_SEED, ENV_REPLAY, ENV_REPLAY_FILE] {
        cmd.env_remove(var);
    }
    for (k, v) in vars {
        cmd.env(k, v);
    }
    cmd.output().unwrap()
}

/// Returns the child's stdout and stderr together.
fn child_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

/// Returns the values a successful child drew.
fn child_values(out: &Output) -> Vec<u64> {
    let text = child_text(out);
    assert!(out.status.success(), "child failed:\n{text}");
    let line = text
        .lines()
        .find_map(|l| l.split_once(ENV_CHILD_LINE).map(|(_, rest)| rest))
        .unwrap_or_else(|| panic!("no values line in:\n{text}"));
    let inner = line.trim().trim_start_matches('[').trim_end_matches(']');
    if inner.is_empty() {
        return Vec::new();
    }
    inner.split(", ").map(|v| v.parse().unwrap()).collect()
}

/// The child half of `review_prop_selftest_env_gap`: a check that reads the
/// real process environment.
#[test]
#[ignore = "run in a subprocess by review_prop_selftest_env_gap"]
fn env_child_check_with() {
    let values = RefCell::new(Vec::new());
    check_with("env_child", Config::default(), record_values(&values));
    println!("{ENV_CHILD_LINE}{:?}", values.borrow());
}

/// `check_with` applies `FSTP_PROP_CASES`, `FSTP_PROP_SEED`,
/// `FSTP_PROP_REPLAY` and `FSTP_PROP_REPLAY_FILE` from the real process
/// environment, and panics on a malformed value. Setting variables in this
/// process would need `unsafe`, so a child process runs the check.
#[test]
fn review_prop_selftest_env_gap() {
    // Seed and case count.
    let values = child_values(&run_child(&[(ENV_CASES, "7"), (ENV_SEED, "0x5eed")]));
    let expected = RefCell::new(Vec::new());
    let cfg = Config::default().with_cases(7).with_seed(0x5eed);
    assert_eq!(
        run("env_child", cfg, record_values(&expected)),
        Outcome::Passed { cases: 7 }
    );
    assert_eq!(values, *expected.borrow());
    let unseeded = RefCell::new(Vec::new());
    let _ = run(
        "env_child",
        Config::default().with_cases(7),
        record_values(&unseeded),
    );
    assert_ne!(values, *unseeded.borrow(), "the seed made no difference");

    // Without variables, the defaults apply.
    assert_eq!(child_values(&run_child(&[])).len(), 256);

    // Replay from the variable.
    let out = run_child(&[(ENV_REPLAY, "2a")]);
    assert_eq!(child_values(&out), vec![42]);
    assert!(child_text(&out).contains("passed the replayed case"));

    // Replay from a file.
    let path = scratch_file("env-gap-replay.txt");
    std::fs::write(&path, "2a\n").unwrap();
    let path_text = path.display().to_string();
    let values = child_values(&run_child(&[(ENV_REPLAY_FILE, &path_text)]));
    assert_eq!(values, vec![42]);

    // A malformed or conflicting value makes the check panic before any case runs.
    let both = [(ENV_REPLAY, "1"), (ENV_REPLAY_FILE, path_text.as_str())];
    let missing = scratch_file("env-gap-missing.txt").display().to_string();
    let cases: [(&[(&str, &str)], &str); 7] = [
        (&[(ENV_CASES, "many")], ENV_CASES),
        (&[(ENV_CASES, "0")], ENV_CASES),
        (&[(ENV_SEED, "0xzz")], ENV_SEED),
        (&[(ENV_REPLAY, "3E8")], ENV_REPLAY),
        (&[(ENV_REPLAY, "1,,2")], ENV_REPLAY),
        (&both, ENV_REPLAY_FILE),
        (&[(ENV_REPLAY_FILE, missing.as_str())], ENV_REPLAY_FILE),
    ];
    for (vars, var) in cases {
        let out = run_child(vars);
        let text = child_text(&out);
        assert!(!out.status.success(), "{vars:?} passed:\n{text}");
        assert!(
            text.contains(&format!("invalid {var}=")),
            "{vars:?}:\n{text}"
        );
        assert!(!text.contains(ENV_CHILD_LINE), "{vars:?}:\n{text}");
    }
    let _ = std::fs::remove_file(&path);
}

/// Returns a path next to the test binary for a file this test writes.
fn scratch_file(name: &str) -> PathBuf {
    let exe = std::env::current_exe().unwrap();
    let dir = exe.parent().unwrap();
    dir.join(format!("fstp-prop-review-{}-{name}", std::process::id()))
}

// ---------------------------------------------------------------------------
// prop-replay-cmd-thread-name

/// A property that fails for `x >= 7`.
fn below_seven(g: &mut Gen) -> Result<(), String> {
    let x = g.u8();
    prop_assert!(x < 7);
    Ok(())
}

/// A check on a thread that is not a libtest thread never prints a command
/// that filters on that thread's name. The command holds a placeholder that
/// the shell rejects, and the report points at the check's location.
#[test]
fn review_prop_replay_cmd_thread_name() {
    let handle = std::thread::Builder::new()
        .name("tokio-runtime-worker".to_owned())
        .spawn(|| run("worker_prop", Config::default(), below_seven))
        .unwrap();
    let f = failure(handle.join().unwrap());
    assert_eq!(f.test_name, None);
    assert_eq!(f.thread_name.as_deref(), Some("tokio-runtime-worker"));
    let cmd = f.replay_command();
    assert!(cmd.ends_with(" -- --exact <TEST>"), "{cmd}");
    assert!(cmd.contains(" --test review "), "{cmd}");
    let report = f.report();
    assert!(!report.contains("--exact tokio-runtime-worker"), "{report}");
    assert!(
        report.contains(&format!(
            "<TEST> is the path of the test function that calls the check at {}",
            f.location
        )),
        "{report}"
    );
    assert!(f.location.contains("tests/review.rs"), "{report}");
    assert!(
        report.contains(
            "The check ran on thread `tokio-runtime-worker`, which is not a libtest test thread."
        ),
        "{report}"
    );

    // An unnamed thread.
    let f = failure(
        std::thread::spawn(|| run("unnamed_prop", Config::default(), below_seven))
            .join()
            .unwrap(),
    );
    assert_eq!(f.test_name, None);
    assert!(f.report().contains("The check ran on an unnamed thread"));

    // The check's panic on a worker thread carries the same report.
    let handle = std::thread::Builder::new()
        .name("worker-1".to_owned())
        .spawn(|| check_with("worker_check", Config::default(), below_seven))
        .unwrap();
    let report = payload_text(handle.join().unwrap_err().as_ref());
    assert!(report.contains("--exact <TEST>"), "{report}");

    // On the libtest thread, the command names this test, its target and,
    // under cargo test, its package.
    let f = failure(run("on_test_thread", Config::default(), below_seven));
    assert_eq!(
        f.test_name.as_deref(),
        Some("review_prop_replay_cmd_thread_name")
    );
    let mut want = vec!["--test".to_owned(), "review".to_owned()];
    if let Ok(pkg) = std::env::var("CARGO_PKG_NAME") {
        want.splice(0..0, ["-p".to_owned(), pkg]);
    }
    assert_eq!(f.cargo_args, want);
    assert!(
        f.replay_command()
            .ends_with(" --test review -- --exact review_prop_replay_cmd_thread_name"),
        "{}",
        f.replay_command()
    );
}

// ---------------------------------------------------------------------------
// prop-selftest-generator-gap

/// `bool` and `option` produce both values in random cases and shrink to
/// the non-default value with one choice. The first case uses the simplest
/// value of every generator. A case may draw exactly `max_choices` choices.
///
/// Before the fix, `bool` returned `true` in every random case. Only the
/// simplest first case gave `false`.
#[test]
fn review_prop_selftest_generator_gap() {
    // Counts of false, true, None and Some over the random cases.
    let counts = RefCell::new([0u32; 4]);
    let case = Cell::new(0u32);
    let outcome = run("bool_and_option", Config::default().with_cases(200), |g| {
        let b = g.bool();
        let o = g.option(|g| g.u8());
        case.set(case.get() + 1);
        if case.get() > 1 {
            let mut c = counts.borrow_mut();
            c[usize::from(b)] += 1;
            c[2 + usize::from(o.is_some())] += 1;
        }
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 200 });
    let c = *counts.borrow();
    assert!(c.iter().all(|&n| n >= 20), "false, true, None, Some: {c:?}");

    let f = failure(run("bool_true", Config::default(), |g| {
        prop_assert!(!g.bool());
        Ok(())
    }));
    assert_eq!(f.choices, vec![1]);
    let f = failure(run("option_some", Config::default(), |g| {
        prop_assert!(g.option(|g| g.u8()).is_none());
        Ok(())
    }));
    assert_eq!(f.choices, vec![1]);

    // The first case: every generator at its simplest value.
    type Simplest = (
        bool,
        u8,
        i32,
        u64,
        i64,
        Option<u8>,
        Vec<u16>,
        char,
        char,
        String,
        u8,
        usize,
    );
    let first: RefCell<Option<Simplest>> = RefCell::new(None);
    let outcome = run("simplest_first", Config::default().with_cases(1), |g| {
        let snapshot = (
            g.bool(),
            g.u8(),
            g.i32(),
            g.u64_in(5..=9),
            g.i64_in(-9..=-5),
            g.option(|g| g.u8()),
            g.vec(2..=5, |g| g.u16()),
            g.ascii_char(),
            g.char(),
            g.string(0..=5),
            *g.pick(&[7, 8, 9]),
            g.weighted(&[0, 3, 1]),
        );
        first.borrow_mut().get_or_insert(snapshot);
        Ok(())
    });
    assert_eq!(outcome, Outcome::Passed { cases: 1 });
    let want: Simplest = (
        false,
        0,
        0,
        5,
        -5,
        None,
        vec![0, 0],
        'a',
        'a',
        String::new(),
        7,
        1,
    );
    assert_eq!(first.into_inner(), Some(want));

    // Exactly max_choices choices pass; one more is discarded.
    let draw = |n: usize| {
        move |g: &mut Gen| {
            for _ in 0..n {
                let _ = g.u8();
            }
            Ok(())
        }
    };
    let cfg = Config::default().with_max_choices(5).with_cases(20);
    assert_eq!(
        run("exact_budget", cfg.clone(), draw(5)),
        Outcome::Passed { cases: 20 }
    );
    let f = failure(run("over_budget", cfg.clone(), draw(6)));
    assert_eq!(f.kind, FailureKind::TooManyDiscards);
    assert!(
        f.message.contains("exceeded max_choices = 5"),
        "{}",
        f.message
    );
    let replay = cfg.with_replay(vec![1; 6]);
    assert_eq!(
        run("exact_budget_replay", replay.clone(), draw(5)),
        Outcome::Passed { cases: 1 }
    );
    let f = failure(run("over_budget_replay", replay, draw(6)));
    assert_eq!(f.kind, FailureKind::ReplayDiscarded);
}

// ---------------------------------------------------------------------------
// prop-zero-cases-pass

/// `cases = 0` never passes, even for a property that always fails. The run
/// reports `FailureKind::InvalidConfig` and the property never runs.
#[test]
fn review_prop_zero_cases_pass() {
    let ran = Cell::new(0u32);
    let f = failure(run("zero_cases", Config::default().with_cases(0), |_| {
        ran.set(ran.get() + 1);
        Err("always fails".to_owned())
    }));
    assert_eq!(f.kind, FailureKind::InvalidConfig);
    assert_eq!(ran.get(), 0);
    assert!(f.message.contains("Config::cases is 0"), "{}", f.message);
    let report = f.report();
    assert!(
        report.contains("failed (invalid configuration)"),
        "{report}"
    );
    assert!(!report.contains("replay:"), "{report}");

    // A replay configuration with zero cases is rejected as well.
    let cfg = Config::default().with_cases(0).with_replay(vec![]);
    assert_eq!(
        failure(run("zero_cases_replay", cfg, |_| Ok(()))).kind,
        FailureKind::InvalidConfig
    );
    let outcome = run_machine(
        "zero_cases_machine",
        Config::default().with_cases(0),
        &GuardedStack::default(),
    );
    assert_eq!(failure(outcome).kind, FailureKind::InvalidConfig);

    // check_with panics. FSTP_PROP_CASES would override the zero, so this
    // part needs the variable unset.
    if std::env::var_os(ENV_CASES).is_none() {
        let result = std::panic::catch_unwind(|| {
            check_with("zero_cases_check", Config::default().with_cases(0), |_| {
                Ok(())
            });
        });
        let report = payload_text(result.unwrap_err().as_ref());
        assert!(report.contains("invalid configuration"), "{report}");
    }
}

// ---------------------------------------------------------------------------
// prop-panic-message-misattributed

/// A property that catches an expected panic and then re-raises a real
/// failure with `resume_unwind` reports the real failure.
#[test]
fn review_prop_panic_message_misattributed() {
    let f = failure(run("resume_unwind", Config::default(), |g| {
        let x = g.u8();
        let _ = std::panic::catch_unwind(|| panic!("expected inner panic"));
        if x > 5 {
            std::panic::resume_unwind(Box::new(format!("real failure {x}")));
        }
        Ok(())
    }));
    assert_eq!(f.choices, vec![6]);
    assert_eq!(f.message, "panicked: real failure 6");

    // A panic in a scoped thread loses its own message to std::thread::scope.
    // The report says so instead of presenting the scope's message alone.
    let f = failure(run(
        "scoped_thread",
        Config::default().with_max_shrink_steps(0),
        |g| {
            let x = g.u32();
            std::thread::scope(|s| {
                s.spawn(|| assert!(x < 100, "x too big {x}"));
            });
            Ok(())
        },
    ));
    assert!(
        f.message.contains("a scoped thread panicked"),
        "{}",
        f.message
    );
    assert!(
        f.message
            .contains("A thread that the property spawned panicked"),
        "{}",
        f.message
    );
}

// ---------------------------------------------------------------------------
// prop-replay-e2big

/// A property whose replayed case draws 5000 maximal choices, which format
/// to about 85 KB, and always fails.
fn long_case(g: &mut Gen) -> Result<(), String> {
    let v = g.vec(5000..=5000, |g| g.u64());
    prop_assert!(v.is_empty());
    Ok(())
}

/// A minimal sequence too long for one environment string is replayed
/// through `FSTP_PROP_REPLAY_FILE`. The check functions write the file, and
/// the printed command stays short.
#[test]
fn review_prop_replay_e2big() {
    let long = Config::default().with_replay(vec![u64::MAX; 5000]);
    let mut f = failure(run("long_replay", long.clone(), long_case));
    assert_eq!(f.choices.len(), 5000);
    assert!(format_replay(&f.choices).len() > MAX_REPLAY_ENV_LEN);

    // Before a file exists, the command names the file variable with a
    // placeholder, never the long environment string.
    assert!(f.needs_replay_file());
    let cmd = f.replay_command();
    assert!(
        cmd.starts_with("FSTP_PROP_REPLAY_FILE=<FILE> cargo test"),
        "{cmd}"
    );
    assert!(cmd.len() < 1024, "{} bytes", cmd.len());
    assert!(
        f.report()
            .contains("<FILE> is a file that holds the minimal choice sequence")
    );

    // Writing the file switches the command to its path.
    let path = f.write_replay_file().unwrap();
    assert!(!f.needs_replay_file());
    let cmd = f.replay_command();
    let prefix = format!("FSTP_PROP_REPLAY_FILE='{}' cargo test", path.display());
    assert!(cmd.starts_with(&prefix), "{cmd}");
    assert!(f.report().contains("5000 choices, written to"));

    // The environment path reads the file back, and the replay reproduces
    // the failure.
    let path_text = path.display().to_string();
    let cfg = Config::default()
        .try_with_vars(|k| (k == ENV_REPLAY_FILE).then(|| path_text.clone()))
        .unwrap();
    assert_eq!(cfg.replay.as_ref(), Some(&f.choices));
    assert_eq!(
        failure(run("long_replay", cfg, long_case)).choices,
        f.choices
    );
    let err = Config::default()
        .try_with_vars(|k| match k {
            ENV_REPLAY => Some("1".to_owned()),
            ENV_REPLAY_FILE => Some(path_text.clone()),
            _ => None,
        })
        .unwrap_err();
    assert_eq!(err.var, ENV_REPLAY_FILE);

    // check_with writes the file itself and prints a short report.
    if std::env::var_os(ENV_REPLAY).is_none() && std::env::var_os(ENV_REPLAY_FILE).is_none() {
        let result = std::panic::catch_unwind(|| check_with("long_replay", long, long_case));
        let report = payload_text(result.unwrap_err().as_ref());
        assert!(report.contains(&format!("replay: {prefix}")), "{report}");
        assert!(report.len() < 4096, "report of {} bytes", report.len());
    }
    let _ = std::fs::remove_file(&path);
}
