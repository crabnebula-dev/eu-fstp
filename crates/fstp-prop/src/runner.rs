//! Configuration, the search loop and failure reports.

use core::fmt;
use core::fmt::Write as _;
use std::ffi::OsStr;
use std::io::Read as _;
use std::panic::Location;
use std::path::{Component, Path, PathBuf};

use crate::exec::{Silence, Status, execute};
use crate::generator::{Gen, Invalid, Recording};
use crate::replay::{ReplayLimits, format_replay, parse_replay, parse_replay_with};
use crate::rng::{Rng, splitmix64};
use crate::shrink::Shrinker;

/// Default number of valid cases per property.
pub const DEFAULT_CASES: u32 = 256;
/// Default budget of property runs for shrinking one failure.
pub const DEFAULT_MAX_SHRINK_STEPS: u32 = 10_000;
/// Default maximum number of choices one case may draw.
pub const DEFAULT_MAX_CHOICES: usize = 65_536;
/// A run fails when discarded cases exceed this multiple of the requested
/// case count (with a minimum of one case).
pub const MAX_DISCARD_RATIO: u64 = 10;

/// Environment variable that overrides [`Config::cases`].
pub const ENV_CASES: &str = "FSTP_PROP_CASES";
/// Environment variable that overrides [`Config::seed`]. Decimal or `0x` hex.
pub const ENV_SEED: &str = "FSTP_PROP_SEED";
/// Environment variable that sets [`Config::replay`], in the format of
/// [`format_replay`]. An empty value replays the empty sequence.
pub const ENV_REPLAY: &str = "FSTP_PROP_REPLAY";
/// Environment variable that names a file holding [`Config::replay`], in the
/// format of [`format_replay`]. It is the alternative to [`ENV_REPLAY`] for
/// sequences longer than [`MAX_REPLAY_ENV_LEN`]. Set only one of the two.
pub const ENV_REPLAY_FILE: &str = "FSTP_PROP_REPLAY_FILE";
/// Longest formatted choice sequence that a replay command passes in
/// [`ENV_REPLAY`]. Linux limits one environment string to 128 KiB, so longer
/// sequences go through a file and [`ENV_REPLAY_FILE`] instead.
pub const MAX_REPLAY_ENV_LEN: usize = 64 * 1024;

/// Bytes of surrounding whitespace allowed in a replay file on top of
/// [`ReplayLimits::max_input_len`].
const REPLAY_FILE_SLACK: usize = 4096;
/// Placeholder for the test path in a replay command when it is unknown.
const TEST_PLACEHOLDER: &str = "<TEST>";
/// Placeholder for the replay file in a replay command when none was written.
const FILE_PLACEHOLDER: &str = "<FILE>";

/// Settings for one property run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    /// Number of valid (not discarded) cases to run. The first case uses the
    /// simplest value of every generator; the rest are random.
    ///
    /// It must be at least 1. A run with `cases = 0` would pass without
    /// testing anything, so it fails with [`FailureKind::InvalidConfig`].
    pub cases: u32,
    /// Seed for random generation. `None` derives it from the property name
    /// with [`seed_for_name`], so runs are deterministic by default.
    pub seed: Option<u64>,
    /// Maximum number of property runs spent shrinking one failure.
    pub max_shrink_steps: u32,
    /// Maximum number of choices one case may draw. A case that draws more is
    /// discarded, not failed.
    pub max_choices: usize,
    /// When set, run only this choice sequence once and report the result.
    pub replay: Option<Vec<u64>>,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            cases: DEFAULT_CASES,
            seed: None,
            max_shrink_steps: DEFAULT_MAX_SHRINK_STEPS,
            max_choices: DEFAULT_MAX_CHOICES,
            replay: None,
        }
    }
}

/// A malformed `FSTP_PROP_*` environment variable.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError {
    /// The variable name.
    pub var: &'static str,
    /// The value that failed to parse.
    pub value: String,
    /// Why it failed.
    pub reason: String,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid {}={:?}: {}", self.var, self.value, self.reason)
    }
}

impl std::error::Error for ConfigError {}

impl Config {
    /// Returns the default configuration with environment overrides applied.
    ///
    /// # Panics
    ///
    /// Panics with a clear message when an `FSTP_PROP_*` variable is set but
    /// malformed. Ignoring it could turn a requested replay into a silent pass.
    #[track_caller]
    pub fn from_env() -> Config {
        Config::default().with_env()
    }

    /// Applies the `FSTP_PROP_*` variables on top of `self`. See
    /// [`Config::try_with_vars`].
    ///
    /// # Panics
    ///
    /// Panics when a variable is set but malformed, like [`Config::from_env`].
    #[track_caller]
    pub fn with_env(self) -> Config {
        let lookup = |key: &str| std::env::var_os(key).map(|v| v.to_string_lossy().into_owned());
        match self.try_with_vars(lookup) {
            Ok(cfg) => cfg,
            Err(e) => report_and_panic(&format!("fstp-prop: {e}")),
        }
    }

    /// Applies overrides read through `lookup`, which maps a variable name to
    /// its value. A set variable must be well formed. Never panics.
    ///
    /// The variables are [`ENV_CASES`], [`ENV_SEED`], [`ENV_REPLAY`] and
    /// [`ENV_REPLAY_FILE`]. Setting both replay variables is an error. The
    /// replay file is read here, bounded by the default [`ReplayLimits`].
    pub fn try_with_vars(
        mut self,
        lookup: impl Fn(&str) -> Option<String>,
    ) -> Result<Config, ConfigError> {
        let error = |var: &'static str, value: &str, reason: String| ConfigError {
            var,
            value: value.to_owned(),
            reason,
        };
        if let Some(v) = lookup(ENV_CASES) {
            match v.trim().parse::<u32>() {
                Ok(0) => return Err(error(ENV_CASES, &v, "must be at least 1".to_owned())),
                Ok(n) => self.cases = n,
                Err(e) => return Err(error(ENV_CASES, &v, e.to_string())),
            }
        }
        if let Some(v) = lookup(ENV_SEED) {
            let t = v.trim();
            let parsed = match t.strip_prefix("0x").or_else(|| t.strip_prefix("0X")) {
                Some(hex) => u64::from_str_radix(hex, 16),
                None => t.parse::<u64>(),
            };
            match parsed {
                Ok(seed) => self.seed = Some(seed),
                Err(e) => return Err(error(ENV_SEED, &v, e.to_string())),
            }
        }
        match (lookup(ENV_REPLAY), lookup(ENV_REPLAY_FILE)) {
            (Some(_), Some(path)) => {
                return Err(error(
                    ENV_REPLAY_FILE,
                    &path,
                    format!("set only one of {ENV_REPLAY} and {ENV_REPLAY_FILE}"),
                ));
            }
            (Some(v), None) => match parse_replay(&v) {
                Ok(seq) => self.replay = Some(seq),
                Err(e) => return Err(error(ENV_REPLAY, &v, e.to_string())),
            },
            (None, Some(path)) => match read_replay_file(Path::new(&path)) {
                Ok(seq) => self.replay = Some(seq),
                Err(reason) => return Err(error(ENV_REPLAY_FILE, &path, reason)),
            },
            (None, None) => {}
        }
        Ok(self)
    }

    /// Returns `self` with [`Config::cases`] set.
    pub fn with_cases(mut self, cases: u32) -> Config {
        self.cases = cases;
        self
    }

    /// Returns `self` with [`Config::seed`] set.
    pub fn with_seed(mut self, seed: u64) -> Config {
        self.seed = Some(seed);
        self
    }

    /// Returns `self` with [`Config::max_shrink_steps`] set.
    pub fn with_max_shrink_steps(mut self, steps: u32) -> Config {
        self.max_shrink_steps = steps;
        self
    }

    /// Returns `self` with [`Config::max_choices`] set.
    pub fn with_max_choices(mut self, max_choices: usize) -> Config {
        self.max_choices = max_choices;
        self
    }

    /// Returns `self` with [`Config::replay`] set.
    pub fn with_replay(mut self, choices: Vec<u64>) -> Config {
        self.replay = Some(choices);
        self
    }
}

/// Reads and parses a replay file with the default [`ReplayLimits`].
fn read_replay_file(path: &Path) -> Result<Vec<u64>, String> {
    let limits = ReplayLimits::default();
    let cap = limits.max_input_len.saturating_add(REPLAY_FILE_SLACK);
    let file = std::fs::File::open(path).map_err(|e| format!("cannot open: {e}"))?;
    let mut bytes = Vec::new();
    file.take(u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read: {e}"))?;
    if bytes.len() > cap {
        return Err(format!("the file is larger than {cap} bytes"));
    }
    parse_replay_with(&bytes, &limits).map_err(|e| e.to_string())
}

/// Derives the default seed from a property name with a stable hash
/// (FNV-1a followed by a SplitMix64 step). It does not change between runs,
/// platforms or compiler versions.
pub fn seed_for_name(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    splitmix64(&mut h)
}

/// The result of a property run.
// A run builds one Outcome and moves it a few times, so the size of the
// Failed variant costs nothing measurable. Boxing it would change the
// public contract that other crates match on.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Every case passed.
    Passed {
        /// Number of valid cases that ran.
        cases: u32,
    },
    /// The run failed. See [`Failure::kind`].
    Failed(Failure),
}

impl Outcome {
    /// Returns whether the run passed.
    pub fn is_passed(&self) -> bool {
        matches!(self, Outcome::Passed { .. })
    }

    /// Returns the failure, if the run failed.
    pub fn failure(&self) -> Option<&Failure> {
        match self {
            Outcome::Passed { .. } => None,
            Outcome::Failed(f) => Some(f),
        }
    }
}

/// What kind of failure a run reported.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum FailureKind {
    /// The property failed, and the minimal case fails again when replayed.
    Counterexample,
    /// The property failed during the search, but the minimal case passed when
    /// replayed. The property is not deterministic.
    Flaky,
    /// Too many cases were discarded by [`Gen::assume`], [`Gen::reject`] or
    /// `max_choices`. A run never passes with too few valid cases.
    TooManyDiscards,
    /// The replayed choice sequence was discarded instead of passing or failing.
    ReplayDiscarded,
    /// The configuration cannot give a meaningful run, so nothing ran.
    ///
    /// `cases = 0` is the case today: such a run would pass without testing
    /// anything. [`run`] returns this failure and the check functions panic
    /// with its report, so a zero case count never passes.
    InvalidConfig,
}

/// A failed run, with everything needed to understand and replay it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Failure {
    /// Seed used for random generation.
    pub seed: u64,
    /// The minimal failing choice sequence, with trailing zeros trimmed.
    /// Empty for discard failures.
    pub choices: Vec<u64>,
    /// The failure message of the minimal case. For a panic, it holds the
    /// panic message and location.
    pub message: String,
    /// Notes recorded by the final run of the minimal case.
    pub notes: Vec<String>,
    /// Property runs spent shrinking.
    pub shrink_steps: u32,
    /// The property name.
    pub name: String,
    /// What kind of failure this is.
    pub kind: FailureKind,
    /// Source location of the call that ran the property.
    pub location: String,
    /// Path of the libtest test that ran the property, used in the replay
    /// command. `None` when the thread that ran it is not a libtest thread.
    pub test_name: Option<String>,
    /// Name of the thread that ran the property, if it has one.
    pub thread_name: Option<String>,
    /// `cargo test` arguments that select the package and the test target of
    /// the check, when they are known. Used in the replay command.
    pub cargo_args: Vec<String>,
    /// File that holds the minimal choice sequence for [`ENV_REPLAY_FILE`].
    /// The check functions write it when the sequence is longer than
    /// [`MAX_REPLAY_ENV_LEN`]. See [`Failure::write_replay_file`].
    pub replay_file: Option<PathBuf>,
    /// The failing choice sequence before shrinking.
    pub original_choices: Vec<u64>,
    /// Number of shrink candidates that replaced the current smallest case.
    pub accepted_shrinks: u32,
    /// Valid cases that passed before the failure.
    pub cases_passed: u32,
    /// Cases discarded before the failure.
    pub cases_discarded: u64,
}

impl Failure {
    /// Returns the shell command that replays the minimal case.
    ///
    /// The command filters `cargo test` to the exact test that failed. When
    /// that test is unknown, the command holds the placeholder `<TEST>`. A
    /// sequence longer than [`MAX_REPLAY_ENV_LEN`] goes through
    /// [`ENV_REPLAY_FILE`], with the placeholder `<FILE>` until
    /// [`Failure::replay_file`] is set. A placeholder makes the shell fail
    /// loudly, so the command never silently runs zero tests.
    pub fn replay_command(&self) -> String {
        let seq = format_replay(&self.choices);
        let var = match &self.replay_file {
            Some(path) => format!("{ENV_REPLAY_FILE}={}", shell_quote(&path.to_string_lossy())),
            None if seq.len() > MAX_REPLAY_ENV_LEN => {
                format!("{ENV_REPLAY_FILE}={FILE_PLACEHOLDER}")
            }
            None => format!("{ENV_REPLAY}='{seq}'"),
        };
        let mut cmd = format!("{var} cargo test");
        for arg in &self.cargo_args {
            cmd.push(' ');
            cmd.push_str(arg);
        }
        cmd.push_str(" -- --exact ");
        cmd.push_str(self.test_name.as_deref().unwrap_or(TEST_PLACEHOLDER));
        cmd
    }

    /// Returns whether the minimal sequence needs a replay file: it is too
    /// long for [`ENV_REPLAY`] and no file holds it yet.
    pub fn needs_replay_file(&self) -> bool {
        self.replay_file.is_none()
            && self.kind.has_replay()
            && format_replay(&self.choices).len() > MAX_REPLAY_ENV_LEN
    }

    /// Writes the minimal choice sequence to a file for [`ENV_REPLAY_FILE`]
    /// and records its path in [`Failure::replay_file`].
    ///
    /// The file goes to a `fstp-prop-replay` directory next to the test
    /// binary. A binary in a `deps` directory, as under `cargo test`, puts
    /// it one level up, in `target/<profile>/fstp-prop-replay/`. The name
    /// derives from the property name and the sequence, so a rerun of the
    /// same failure overwrites the same file.
    pub fn write_replay_file(&mut self) -> std::io::Result<PathBuf> {
        let exe = std::env::current_exe()?;
        let mut dir = exe
            .parent()
            .ok_or_else(|| std::io::Error::other("the test binary has no parent directory"))?;
        if dir.file_name() == Some(OsStr::new("deps"))
            && let Some(up) = dir.parent()
        {
            dir = up;
        }
        let dir = dir.join("fstp-prop-replay");
        std::fs::create_dir_all(&dir)?;
        let mut text = format_replay(&self.choices);
        let file = format!(
            "{}-{:016x}.txt",
            file_stem(&self.name),
            fnv1a(text.as_bytes())
        );
        text.push('\n');
        let path = dir.join(file);
        std::fs::write(&path, text)?;
        self.replay_file = Some(path.clone());
        Ok(path)
    }

    /// Returns the human-readable failure report.
    pub fn report(&self) -> String {
        let mut s = String::new();
        let what = match self.kind {
            FailureKind::Counterexample => "counterexample found",
            FailureKind::Flaky => "flaky: the minimal case passed when replayed",
            FailureKind::TooManyDiscards => "too many discarded cases",
            FailureKind::ReplayDiscarded => "replayed case was discarded",
            FailureKind::InvalidConfig => "invalid configuration",
        };
        let _ = writeln!(s, "fstp-prop: property `{}` failed ({what})", self.name);
        let _ = writeln!(s, "  defined at: {}", self.location);
        let _ = writeln!(s, "  seed: {:#018x}", self.seed);
        let _ = writeln!(s, "  cases passed before failure: {}", self.cases_passed);
        let _ = writeln!(s, "  cases discarded: {}", self.cases_discarded);
        if matches!(self.kind, FailureKind::Counterexample | FailureKind::Flaky) {
            let _ = writeln!(
                s,
                "  shrink steps: {} ({} accepted; {} -> {} choices)",
                self.shrink_steps,
                self.accepted_shrinks,
                self.original_choices.len(),
                self.choices.len()
            );
        }
        let _ = writeln!(s, "  message:");
        for line in self.message.lines() {
            let _ = writeln!(s, "    {line}");
        }
        if !self.notes.is_empty() {
            let _ = writeln!(s, "  notes from the minimal run:");
            for note in &self.notes {
                for line in note.lines() {
                    let _ = writeln!(s, "    {line}");
                }
            }
        }
        if self.kind.has_replay() {
            match &self.replay_file {
                Some(path) => {
                    let _ = writeln!(
                        s,
                        "  minimal choice sequence: {} choices, written to {}",
                        self.choices.len(),
                        path.display()
                    );
                }
                None => {
                    let _ = writeln!(
                        s,
                        "  minimal choice sequence: '{}'",
                        format_replay(&self.choices)
                    );
                }
            }
            let cmd = self.replay_command();
            let _ = writeln!(s, "  replay: {cmd}");
            if cmd.contains(FILE_PLACEHOLDER) {
                let _ = writeln!(
                    s,
                    "    {FILE_PLACEHOLDER} is a file that holds the minimal choice sequence above. \
                     The sequence is too long for {ENV_REPLAY}."
                );
            }
            if self.test_name.is_none() {
                let _ = writeln!(
                    s,
                    "    {TEST_PLACEHOLDER} is the path of the test function that calls the check at {}.",
                    self.location
                );
                let thread = match &self.thread_name {
                    Some(name) => format!("thread `{name}`"),
                    None => "an unnamed thread".to_owned(),
                };
                let _ = writeln!(
                    s,
                    "    The check ran on {thread}, which is not a libtest test thread."
                );
            }
        }
        s
    }
}

impl FailureKind {
    /// Returns whether a failure of this kind has a choice sequence to replay.
    fn has_replay(self) -> bool {
        matches!(
            self,
            FailureKind::Counterexample | FailureKind::Flaky | FailureKind::ReplayDiscarded
        )
    }
}

/// Quotes `s` for a POSIX shell.
fn shell_quote(s: &str) -> String {
    format!("'{}'", s.replace('\'', "'\\''"))
}

/// Returns a file name stem made of the safe characters of `name`.
fn file_stem(name: &str) -> String {
    let stem: String = name
        .chars()
        .take(80)
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if stem.is_empty() {
        "property".to_owned()
    } else {
        stem
    }
}

/// FNV-1a over `bytes`.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0100_0000_01b3);
    }
    h
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.report())
    }
}

/// The single panic site of the harness.
///
/// A property check reports failure by panicking, the way `assert!` does, so
/// the test runner marks the test as failed and prints the report. This is the
/// harness's purpose, so `clippy::panic` is allowed here and nowhere else.
#[allow(clippy::panic)]
#[track_caller]
pub(crate) fn report_and_panic(report: &str) -> ! {
    panic!("{report}")
}

/// Panics with the report of a failed check. A minimal sequence that is too
/// long for [`ENV_REPLAY`] is first written to a replay file.
#[track_caller]
pub(crate) fn fail_check(mut failure: Failure) -> ! {
    if failure.needs_replay_file()
        && let Err(e) = failure.write_replay_file()
    {
        eprintln!("fstp-prop: cannot write the replay file: {e}");
    }
    report_and_panic(&failure.report())
}

/// Checks a property with [`Config::from_env`] and panics with a report on failure.
///
/// # Panics
///
/// Panics with the failure report when the property fails, and when an
/// `FSTP_PROP_*` variable is malformed.
#[track_caller]
pub fn check<F>(name: &str, prop: F)
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    check_with(name, Config::default(), prop);
}

/// Checks a property with `cfg` and panics with a report on failure.
///
/// Environment overrides (`FSTP_PROP_CASES`, `FSTP_PROP_SEED`,
/// `FSTP_PROP_REPLAY`) apply on top of `cfg`, so the replay command in a report
/// works for every check. Use [`run`] to ignore the environment.
///
/// # Panics
///
/// Panics with the failure report when the property fails, and when an
/// `FSTP_PROP_*` variable is malformed.
#[track_caller]
pub fn check_with<F>(name: &str, cfg: Config, prop: F)
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    let cfg = cfg.with_env();
    match run_at(name, &cfg, &prop, Location::caller()) {
        Outcome::Failed(failure) => fail_check(failure),
        Outcome::Passed { .. } if cfg.replay.is_some() => {
            eprintln!("fstp-prop: property `{name}` passed the replayed case");
        }
        Outcome::Passed { .. } => {}
    }
}

/// Runs a property with exactly `cfg` and returns the outcome. Never panics,
/// and ignores the environment.
#[track_caller]
pub fn run<F>(name: &str, cfg: Config, prop: F) -> Outcome
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    run_at(name, &cfg, &prop, Location::caller())
}

/// Facts shared by every failure of one run.
struct RunInfo {
    name: String,
    location: &'static Location<'static>,
    seed: u64,
}

impl RunInfo {
    fn failure(&self, kind: FailureKind, message: String) -> Failure {
        let thread = std::thread::current();
        let thread_name = thread.name().map(str::to_owned);
        Failure {
            seed: self.seed,
            choices: Vec::new(),
            message,
            notes: Vec::new(),
            shrink_steps: 0,
            name: self.name.clone(),
            kind,
            location: self.location.to_string(),
            test_name: thread_name.clone().filter(|n| is_test_path(n)),
            thread_name,
            cargo_args: cargo_args(self.location.file()),
            replay_file: None,
            original_choices: Vec::new(),
            accepted_shrinks: 0,
            cases_passed: 0,
            cases_discarded: 0,
        }
    }
}

/// Returns whether a thread name is a libtest test path.
///
/// libtest runs each test on a thread named after the test path, such as
/// `tests::parses_empty`. A name that is not a Rust path, such as
/// `tokio-runtime-worker` or a merged doctest name, belongs to some other
/// thread. A worker thread whose name happens to be a Rust path, other than
/// `main`, is taken for a test thread.
fn is_test_path(name: &str) -> bool {
    name != "main" && name.split("::").all(is_identifier)
}

/// Returns whether `s` is a Rust identifier, raw identifiers included.
fn is_identifier(s: &str) -> bool {
    let s = s.strip_prefix("r#").unwrap_or(s);
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c == '_' || c.is_alphabetic() => {}
        _ => return false,
    }
    s != "_" && chars.all(|c| c == '_' || c.is_alphanumeric())
}

/// Returns `cargo test` arguments that select the package and test target of
/// a check called from `file`.
///
/// The package comes from `CARGO_PKG_NAME`, which `cargo test` sets for the
/// test process. The test target is the file stem when `file` is the root of
/// an integration test, `tests/<name>.rs` or `tests/<name>/main.rs`.
fn cargo_args(file: &str) -> Vec<String> {
    let mut args = Vec::new();
    if let Ok(pkg) = std::env::var("CARGO_PKG_NAME")
        && !pkg.is_empty()
        && pkg
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        args.push("-p".to_owned());
        args.push(pkg);
    }
    if let Some(target) = test_target(Path::new(file)) {
        args.push("--test".to_owned());
        args.push(target);
    }
    args
}

/// Returns the integration test target whose root file is `file`.
fn test_target(file: &Path) -> Option<String> {
    let parts: Vec<&str> = file
        .components()
        .filter_map(|c| match c {
            Component::Normal(part) => part.to_str(),
            _ => None,
        })
        .collect();
    let name = match parts.as_slice() {
        [rest @ .., "tests", root] if rest.last() != Some(&"src") => root.strip_suffix(".rs")?,
        [rest @ .., "tests", dir, "main.rs"] if rest.last() != Some(&"src") => dir,
        _ => return None,
    };
    let valid = !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    valid.then(|| name.to_owned())
}

/// Runs the search for one property. Shared by every public entry point.
pub(crate) fn run_at<F>(
    name: &str,
    cfg: &Config,
    prop: &F,
    location: &'static Location<'static>,
) -> Outcome
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    let _quiet = Silence::begin();
    let info = RunInfo {
        name: name.to_owned(),
        location,
        seed: cfg.seed.unwrap_or_else(|| seed_for_name(name)),
    };
    if cfg.cases == 0 {
        let message = "Config::cases is 0, so the run would pass without testing anything. \
                       Set it to at least 1.";
        return Outcome::Failed(info.failure(FailureKind::InvalidConfig, message.to_owned()));
    }
    if let Some(prefix) = &cfg.replay {
        return replay_once(&info, cfg, prop, prefix);
    }
    let mut master = Rng::new(info.seed);
    let mut passed: u32 = 0;
    let mut discarded: u64 = 0;
    let mut overruns: u64 = 0;
    let limit = u64::from(cfg.cases.max(1)).saturating_mul(MAX_DISCARD_RATIO);
    let mut simplest_first = true;
    while passed < cfg.cases {
        // The first case replays the empty sequence: every value at its simplest.
        let mut g = if simplest_first {
            simplest_first = false;
            Gen::replay(Vec::new(), cfg.max_choices)
        } else {
            Gen::random(Rng::new(master.next_u64()), cfg.max_choices)
        };
        match execute(prop, &mut g) {
            Status::Pass => passed = passed.saturating_add(1),
            Status::Invalid(why) => {
                discarded = discarded.saturating_add(1);
                if why == Invalid::Overrun {
                    overruns = overruns.saturating_add(1);
                }
                if discarded > limit {
                    let message = format!(
                        "discarded {discarded} cases ({overruns} exceeded max_choices = {}, the rest \
                         by Gen::assume or Gen::reject) with only {passed} of {} valid cases. \
                         The limit is {MAX_DISCARD_RATIO} discards per requested case. \
                         Loosen the preconditions or generate valid inputs directly.",
                        cfg.max_choices, cfg.cases
                    );
                    let mut f = info.failure(FailureKind::TooManyDiscards, message);
                    f.cases_passed = passed;
                    f.cases_discarded = discarded;
                    return Outcome::Failed(f);
                }
            }
            Status::Fail(message) => {
                let rec = g.into_recording();
                let mut f = shrink_failure(&info, cfg, prop, rec, message);
                f.cases_passed = passed;
                f.cases_discarded = discarded;
                return Outcome::Failed(f);
            }
        }
    }
    Outcome::Passed { cases: passed }
}

/// Shrinks a failing sequence, then replays the result once with notes on.
fn shrink_failure<F>(
    info: &RunInfo,
    cfg: &Config,
    prop: &F,
    original: Recording,
    first_message: String,
) -> Failure
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    let mut shrinker = Shrinker::new(
        prop,
        cfg.max_choices,
        cfg.max_shrink_steps,
        original.choices.clone(),
        original.spans,
        first_message,
    );
    shrinker.shrink();
    let mut g = Gen::replay(shrinker.best.clone(), cfg.max_choices).collecting_notes();
    let status = execute(prop, &mut g);
    let rec = g.into_recording();
    let (kind, message) = match status {
        Status::Fail(message) => (FailureKind::Counterexample, message),
        Status::Pass => (
            FailureKind::Flaky,
            format!(
                "the minimal case passed when replayed, so the property depends on more than its \
                 generated input. The last failure seen while searching was:\n{}",
                shrinker.message
            ),
        ),
        Status::Invalid(_) => (
            FailureKind::Flaky,
            format!(
                "the minimal case was discarded when replayed, so the property depends on more \
                 than its generated input. The last failure seen while searching was:\n{}",
                shrinker.message
            ),
        ),
    };
    let mut f = info.failure(kind, message);
    f.choices = shrinker.best;
    f.notes = rec.notes;
    f.shrink_steps = shrinker.steps;
    f.accepted_shrinks = shrinker.accepted;
    f.original_choices = original.choices;
    f
}

/// Runs a single replayed sequence with notes on.
fn replay_once<F>(info: &RunInfo, cfg: &Config, prop: &F, prefix: &[u64]) -> Outcome
where
    F: Fn(&mut Gen) -> Result<(), String>,
{
    let mut g = Gen::replay(prefix.to_vec(), cfg.max_choices).collecting_notes();
    let status = execute(prop, &mut g);
    let rec = g.into_recording();
    let (kind, message) = match status {
        Status::Pass => return Outcome::Passed { cases: 1 },
        Status::Fail(message) => (FailureKind::Counterexample, message),
        Status::Invalid(why) => (
            FailureKind::ReplayDiscarded,
            match why {
                Invalid::Assume => {
                    "the replayed case was discarded by Gen::assume or Gen::reject".to_owned()
                }
                Invalid::Overrun => format!(
                    "the replayed case drew more than max_choices = {} choices",
                    cfg.max_choices
                ),
            },
        ),
    };
    let mut f = info.failure(kind, message);
    f.choices = rec.choices;
    f.notes = rec.notes;
    f.original_choices = prefix.to_vec();
    Outcome::Failed(f)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_paths_are_rust_paths() {
        for name in ["foo", "tests::foo", "a::b::c_1", "r#type::x", "_private"] {
            assert!(is_test_path(name), "{name}");
        }
        for name in [
            "main",
            "",
            "tokio-runtime-worker",
            "worker 1",
            "src/lib.rs - (line 5)",
            "a::",
            "::a",
            "1abc",
            "_",
            "a::b-c",
        ] {
            assert!(!is_test_path(name), "{name}");
        }
    }

    #[test]
    fn test_target_comes_from_integration_test_roots() {
        let t = |f: &str| test_target(Path::new(f));
        assert_eq!(
            t("crates/fstp-prop/tests/review.rs").as_deref(),
            Some("review")
        );
        assert_eq!(t("tests/selftest.rs").as_deref(), Some("selftest"));
        assert_eq!(
            t("/abs/crate/tests/multi/main.rs").as_deref(),
            Some("multi")
        );
        assert_eq!(t("tests/foo-bar.rs").as_deref(), Some("foo-bar"));
        assert_eq!(t("crates/x/tests/common/mod.rs"), None);
        assert_eq!(t("crates/x/src/lib.rs"), None);
        assert_eq!(t("crates/x/src/tests/foo.rs"), None);
        assert_eq!(t("crates/x/src/tests.rs"), None);
        assert_eq!(t("tests/odd name.rs"), None);
    }

    #[test]
    fn report_helpers() {
        assert_eq!(shell_quote("a'b c"), "'a'\\''b c'");
        assert_eq!(file_stem("a b/c-d_e"), "a_b_c-d_e");
        assert_eq!(file_stem(""), "property");
    }
}
