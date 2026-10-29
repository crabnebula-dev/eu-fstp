//! SIGTERM drains a running cell through `fstp_rt::Shutdown` (ADR-002
//! review note of 2026-10-28, M3 design sections 2.3 and 19 row W3a).
//!
//! Lane W3a (agent two, test author) wrote these tests before `main`.
//! Each process test starts a child process that runs a cell and sends it
//! a real signal with the system `kill` command. The child is this test
//! binary, started again with [`CHILD_ENV`] set and filtered to
//! [`adr002_cell_child_process_entry`]. The child runs the cell through
//! [`serve_until_terminated`], whose events reach standard error through
//! `fstp_obs`. It reports its own progress as `fstp-cell-child:` lines on
//! standard output.
//!
//! The production agent replaced the seam bodies with calls into
//! `fstp_cell::engine` and `fstp_cell::engine::serve` and left the
//! assertions alone. A child whose cell does not run reports `refused`,
//! and the parent fails with the reason.
//!
//! Registration installs process-wide handlers that stay in place, so a
//! cell that listens for signals runs only in a child, never in the test
//! runner itself.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(
    clippy::disallowed_methods,
    reason = "test harness: the child reports progress to its parent on stdout"
)]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread;
use std::time::{Duration, Instant};

use std::future::Future;

use fstp_cell::engine::serve::ServeOptions;
use fstp_cell::engine::{CellEngine, EngineError, Unanchored, VaultClient};
use fstp_cell_core::driver::{Done, ExecError, VaultFault};
use fstp_cell_core::gate::{self, Action, Admitted};
use fstp_cell_core::{
    CellCommand, CellRecord, CellState, KeyCommand, SystemTask, system_command_id,
};
use fstp_domain::id::VaultEpoch;
use fstp_domain::oracle::{Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::{AsyncRecordStore, MemStore, Seq};
use fstp_obs::{LogEvent, Signal, encode_log};
use fstp_rt::signal::Signals;
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime, Shutdown};

/// Names the scenario a child process runs.
const CHILD_ENV: &str = "FSTP_CELL_SIGNAL_CHILD";
/// Prefix of every progress line of the child.
const PREFIX: &str = "fstp-cell-child: ";
/// Name of the child entry test, for `--exact`.
const CHILD_TEST: &str = "adr002_cell_child_process_entry";
/// How long the parent waits for any one step of the child.
const STEP_TIMEOUT: Duration = Duration::from_secs(60);

/// What the child's cell does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scenario {
    /// Serves and waits for a termination signal.
    Idle,
    /// Serves, and once started submits one erasure-runner key command
    /// whose vault answer takes 500 ms. Reports `submitted` before the
    /// vault answers, then `result ok <head>` or `result err <error>`.
    InFlight,
}

/// The cell id of these tests.
const CELL: [u8; 16] = [0xC5; 16];

/// The in-memory store of the child's cell.
type Store = Unanchored<MemStore<CellRecord>>;

/// A vault at the genesis epoch whose epoch answer waits `delay`. Before
/// it waits it sends `submitted` to `progress`, once, so the parent knows
/// the command is in flight.
struct SlowVault {
    rt: TokioRuntime,
    delay: Duration,
    progress: Option<std::sync::Mutex<Option<Sender<String>>>>,
}

impl VaultClient for SlowVault {
    fn epoch(&self) -> impl Future<Output = Result<VaultEpoch, VaultFault>> + Send {
        let tell = self.progress.as_ref().and_then(|m| {
            m.lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .take()
        });
        let sleep = self.rt.sleep(self.delay);
        async move {
            if let Some(tx) = tell {
                let _ = tx.send("submitted".to_owned());
            }
            sleep.await;
            Ok(VaultEpoch::GENESIS)
        }
    }

    fn ask(
        &self,
        _queries: &[Query],
        _reaction_for: Option<VaultEpoch>,
        _at: Timestamp,
    ) -> impl Future<Output = Result<Answers, VaultFault>> + Send {
        std::future::ready(Ok(Answers::new()))
    }

    fn ack(
        &self,
        _epoch: VaultEpoch,
        _seq: Seq,
        _link: [u8; 32],
    ) -> impl Future<Output = Result<(), VaultFault>> + Send {
        std::future::ready(Ok(()))
    }
}

/// The erasure runner's key command `{"n":1}` under a system id.
fn key_command() -> Admitted {
    let s = CellState::genesis();
    gate::admit_system(
        &s,
        Action::Command(CellCommand::Key(KeyCommand::RecordKeyOp {
            op: b"{\"n\":1}".to_vec(),
        })),
        SystemTask::ErasureRunner,
        system_command_id(*b"sigterm1"),
        s.now_floor(),
    )
    .unwrap()
}

/// Seam: runs one cell over in-memory parts on its one `TokioRuntime`. It
/// takes termination signals through `fstp_rt::signal::Signals`, logs
/// `Started` once it serves, and triggers `Shutdown` on a signal. It
/// returns once the drain ends. `report` writes a progress line.
fn serve_until_terminated(scenario: Scenario, report: &dyn Fn(&str)) -> Result<(), &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let term = rt
        .listen_termination()
        .map_err(|_| "no termination handlers")?;
    let (tx, rx) = channel::<String>();
    let in_flight = scenario == Scenario::InFlight;
    let vault = SlowVault {
        rt: rt.clone(),
        delay: Duration::from_millis(500),
        progress: in_flight.then(|| std::sync::Mutex::new(Some(tx.clone()))),
    };
    let rt2 = rt.clone();
    let served = rt.spawn(async move {
        let store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let rt3 = rt2.clone();
        let on_started = move |engine: &CellEngine, shutdown: &Shutdown| {
            if in_flight {
                let engine = engine.clone();
                let signal = shutdown.signal();
                let tx = tx.clone();
                drop(rt3.spawn(async move {
                    let line = match engine.execute(key_command()).await {
                        Ok(done) => format!("result ok {}", done.head.raw()),
                        Err(e) => format!("result err {e:?}"),
                    };
                    let _ = tx.send(line);
                    drop(signal);
                }));
            }
            drop(tx);
        };
        let opts = ServeOptions {
            drain: Duration::from_secs(20),
            queue: 8,
        };
        fstp_cell::engine::serve::serve_until_terminated(&rt2, term, store, vault, opts, on_started)
            .await
            .map(|_| ())
            .map_err(|_| "the cell did not serve")
    });
    // Every progress line goes through `report` on this thread, until the
    // senders are gone.
    for line in rx {
        report(&line);
    }
    rt.block_on(served).map_err(|_| "the serving task failed")?
}

/// Seam: starts a cell over in-memory parts in this process, without
/// signal handlers, triggers its `Shutdown`, then submits one
/// erasure-runner key command. Returns what the command got and the
/// number of ledger entries once the drain ends.
fn submit_after_shutdown() -> Result<(Late, u64), &'static str> {
    let rt = TokioRuntime::new_multi_thread(2).map_err(|_| "no runtime")?;
    let rt2 = rt.clone();
    rt.block_on(async move {
        let store: Store = Unanchored::open(MemStore::new(), CELL)
            .await
            .map_err(|_| "the store did not open")?;
        let shutdown = Shutdown::new();
        let vault = SlowVault {
            rt: rt2.clone(),
            delay: Duration::ZERO,
            progress: None,
        };
        let (engine, task) = CellEngine::start(&rt2, store, vault, &shutdown, 8)
            .await
            .map_err(|_| "the engine did not start")?;
        shutdown.trigger();
        let late = match engine.execute(key_command()).await {
            Err(EngineError::ShuttingDown) => Late::RefusedShuttingDown,
            Err(EngineError::Exec(e)) => Late::Ran(Err(e)),
            Ok(d) => Late::Ran(Ok(d)),
            Err(EngineError::Stopped) => return Err("the engine task stopped"),
        };
        if fstp_rt::timeout(&rt2, Duration::from_secs(20), shutdown.drained())
            .await
            .is_err()
        {
            return Err("the engine did not drain");
        }
        drop(engine);
        let store = task.await.map_err(|_| "the engine task failed")?;
        let head = AsyncRecordStore::head(&store)
            .await
            .map_err(|_| "the store head failed")?;
        Ok((late, head.raw()))
    })
}

/// What a command submitted after the shutdown trigger gets.
#[derive(Debug)]
#[allow(
    dead_code,
    reason = "only the seam builds it, once the production path exists"
)]
enum Late {
    /// The engine ran it.
    Ran(Result<Done, ExecError>),
    /// The engine refused it because the cell is shutting down.
    RefusedShuttingDown,
}

// ---------------------------------------------------------------- child side

fn emit(event: &str) {
    let mut out = std::io::stdout().lock();
    let _ = out
        .write_all(format!("{PREFIX}{event}\n").as_bytes())
        .and_then(|()| out.flush());
}

/// Child-process entry point for the signal tests of this file.
///
/// It does nothing in a normal test run. When [`CHILD_ENV`] is set, it
/// runs the named scenario in this process. The parent tests make the
/// assertions.
#[test]
fn adr002_cell_child_process_entry() {
    let scenario = match std::env::var(CHILD_ENV).as_deref() {
        Ok("idle") => Scenario::Idle,
        Ok("in-flight") => Scenario::InFlight,
        _ => return,
    };
    match serve_until_terminated(scenario, &emit) {
        Ok(()) => emit("exit"),
        Err(e) => emit(&format!("refused {e}")),
    }
}

// --------------------------------------------------------------- parent side

/// A line from the child: a progress line, or an `fstp_obs` log event.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Line {
    Progress(String),
    Log(String),
}

struct Spawned {
    child: Child,
    lines: Receiver<Line>,
    transcript: Vec<Line>,
}

fn forward(stream: impl std::io::Read + Send + 'static, tx: Sender<Line>, progress: bool) {
    thread::spawn(move || {
        for line in BufReader::new(stream).lines() {
            let Ok(line) = line else { return };
            let item = if progress {
                // libtest may print "test <name> ... " on the same line.
                match line.find(PREFIX) {
                    Some(at) => Line::Progress(line[at + PREFIX.len()..].to_owned()),
                    None => continue,
                }
            } else if line.starts_with("{\"event\":") {
                Line::Log(line)
            } else {
                continue;
            };
            if tx.send(item).is_err() {
                return;
            }
        }
    });
}

fn spawn_child(scenario: &str) -> Spawned {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, scenario)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let (tx, lines) = channel();
    forward(child.stdout.take().unwrap(), tx.clone(), true);
    forward(child.stderr.take().unwrap(), tx, false);
    Spawned {
        child,
        lines,
        transcript: Vec::new(),
    }
}

/// The log line of `event`, without its newline.
fn log_line(event: &LogEvent) -> String {
    encode_log(event).unwrap().trim_end().to_owned()
}

impl Spawned {
    /// Reads lines until `want` arrives. Panics with the transcript when
    /// the child refuses, exits or stalls first.
    fn expect(&mut self, want: &Line) {
        let deadline = Instant::now() + STEP_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(line) => {
                    let refused = matches!(&line, Line::Progress(p) if p.starts_with("refused "));
                    let done = &line == want;
                    self.transcript.push(line);
                    if refused {
                        let status = self.wait();
                        panic!(
                            "the child's cell did not run: {:?} (status {status:?})",
                            self.transcript
                        );
                    }
                    if done {
                        return;
                    }
                }
                Err(RecvTimeoutError::Timeout) => {
                    let _ = self.child.kill();
                    panic!("child stalled before {want:?}: {:?}", self.transcript);
                }
                Err(RecvTimeoutError::Disconnected) => {
                    let status = self.wait();
                    panic!(
                        "child closed its streams before {want:?}: {:?}, status {status:?}",
                        self.transcript
                    );
                }
            }
        }
    }

    fn send_signal(&self, name: &str) {
        let status = Command::new("kill")
            .arg(format!("-{name}"))
            .arg(self.child.id().to_string())
            .status()
            .unwrap();
        assert!(status.success(), "kill -{name} failed: {status:?}");
    }

    /// Waits for the child to exit, killing it after [`STEP_TIMEOUT`].
    fn wait(&mut self) -> ExitStatus {
        let deadline = Instant::now() + STEP_TIMEOUT;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            if Instant::now() >= deadline {
                let _ = self.child.kill();
                return self.child.wait().unwrap();
            }
            thread::sleep(Duration::from_millis(10));
        }
    }

    /// Waits for exit and returns the status with every line, in order of
    /// arrival.
    fn finish(mut self) -> (ExitStatus, Vec<Line>) {
        let status = self.wait();
        while let Ok(line) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.transcript.push(line);
        }
        (status, self.transcript)
    }
}

/// The log events of `lines`, in order.
fn logs(lines: &[Line]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| match l {
            Line::Log(s) => Some(s.clone()),
            Line::Progress(_) => None,
        })
        .collect()
}

/// Whether the log holds a signal report, the shutdown start and a
/// completed drain, in that order after `Started`, and no drain timeout.
fn drained_after_sigterm(lines: &[Line]) -> bool {
    let logs = logs(lines);
    let want = [
        log_line(&LogEvent::Started),
        log_line(&LogEvent::SignalReceived {
            signal: Signal::Terminate,
        }),
        log_line(&LogEvent::ShuttingDown),
    ];
    let mut from = 0;
    for w in &want {
        match logs[from..].iter().position(|l| l == w) {
            Some(i) => from += i + 1,
            None => return false,
        }
    }
    let drained = logs[from..]
        .iter()
        .any(|l| l.starts_with("{\"event\":\"drained\""));
    let timed_out = logs
        .iter()
        .any(|l| l.starts_with("{\"event\":\"drain_timed_out\""));
    drained && !timed_out
}

/// ADR-002 review note of 2026-10-28, design section 2.3: SIGTERM to a
/// running cell triggers its `Shutdown`. The cell logs the signal, drains,
/// and exits with status 0 rather than dying by the signal.
#[test]
fn adr002_cell_sigterm_drains_through_shutdown_and_exits_cleanly() {
    let mut child = spawn_child("idle");
    child.expect(&Line::Log(log_line(&LogEvent::Started)));
    child.send_signal("TERM");
    let (status, lines) = child.finish();
    assert!(
        status.success()
            && drained_after_sigterm(&lines)
            && lines.contains(&Line::Progress("exit".to_owned())),
        "status {status:?}, transcript {lines:?}"
    );
}

/// ADR-002, ADR-007, design sections 2.3 and 5.2: a command in flight
/// when SIGTERM arrives finishes and commits before the cell exits, and
/// the drain completes within its deadline.
#[test]
fn adr002_cell_sigterm_finishes_the_in_flight_command_before_exit() {
    let mut child = spawn_child("in-flight");
    child.expect(&Line::Progress("submitted".to_owned()));
    child.send_signal("TERM");
    let (status, lines) = child.finish();
    let committed = lines.contains(&Line::Progress("result ok 1".to_owned()));
    assert!(
        status.success() && committed && drained_after_sigterm(&lines),
        "status {status:?}, transcript {lines:?}"
    );
}

/// ADR-002, design section 5.2: once `Shutdown` is triggered, the engine
/// takes no new command. A command submitted after the trigger is refused
/// as shutting down and appends nothing.
#[test]
fn adr002_cell_refuses_new_commands_once_shutdown_is_triggered() {
    let (late, entries) = submit_after_shutdown().unwrap_or_else(|e| panic!("{e}"));
    assert!(
        matches!(late, Late::RefusedShuttingDown) && entries == 0,
        "late command {late:?}, ledger entries {entries}"
    );
}

/// The drain predicate itself: it needs `Started`, the signal report,
/// `ShuttingDown` and a drain, in order, and refuses a drain timeout.
#[test]
fn adr002_drain_predicate_needs_the_events_in_order() {
    let started = Line::Log(log_line(&LogEvent::Started));
    let signal = Line::Log(log_line(&LogEvent::SignalReceived {
        signal: Signal::Terminate,
    }));
    let down = Line::Log(log_line(&LogEvent::ShuttingDown));
    let drained = Line::Log(log_line(&LogEvent::Drained {
        elapsed: Duration::from_millis(3),
    }));
    let timeout = Line::Log(log_line(&LogEvent::DrainTimedOut { remaining: 1 }));
    let good = vec![
        started.clone(),
        signal.clone(),
        down.clone(),
        drained.clone(),
    ];
    let swapped = vec![
        started.clone(),
        down.clone(),
        signal.clone(),
        drained.clone(),
    ];
    let timed_out = vec![started, signal, down, timeout, drained];
    let ok = drained_after_sigterm(&good)
        && !drained_after_sigterm(&swapped)
        && !drained_after_sigterm(&timed_out);
    assert!(ok, "the drain predicate is wrong");
}
