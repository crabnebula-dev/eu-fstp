//! Termination signals drain through the existing `Shutdown` (ADR-002 review
//! note of 2026-10-28, M3 design section 19 row W2l).
//!
//! Each test starts a child process that uses `fstp-rt` and sends it a real
//! signal with the system `kill` command. The child is this test binary,
//! started again with `FSTP_RT_SIGNAL_CHILD` set and filtered to
//! [`adr002_signal_child_process_entry`]. The child reports its progress as
//! `fstp-rt-child:` lines on stdout, and the parent checks the transcript and
//! the exit status.
//!
//! The child takes its signals from its one runtime through
//! `fstp_rt::signal::Signals` (ADR-002: each binary uses exactly one
//! runtime). It holds one `ShutdownSignal` participant that needs time to
//! finish, so a clean exit proves the drain waited for it.
//!
//! Registration installs process-wide handlers that stay in place, so every
//! test that registers runs in a child and never in the test runner itself.

#![cfg(unix)]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]
#![allow(
    clippy::disallowed_methods,
    reason = "test harness: the child reports progress to its parent on stdout"
)]

use std::io::{BufRead, BufReader, Read, Write};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{Receiver, RecvTimeoutError, channel};
use std::thread;
use std::time::{Duration, Instant};

use fstp_rt::signal::{Signals, Termination, TerminationListener};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{Runtime, Shutdown};

/// Names the scenario a child process runs.
const CHILD_ENV: &str = "FSTP_RT_SIGNAL_CHILD";
/// Prefix of every line the child reports.
const PREFIX: &str = "fstp-rt-child: ";
/// Name of the child entry test, for `--exact`.
const CHILD_TEST: &str = "adr002_signal_child_process_entry";
/// How long the participant works after it is notified.
const PARTICIPANT_WORK: Duration = Duration::from_millis(150);
/// Drain deadline inside the child. Far above the participant's work.
const DRAIN_DEADLINE: Duration = Duration::from_secs(10);
/// How long the parent waits for any one step of the child.
const STEP_TIMEOUT: Duration = Duration::from_secs(30);

// ---------------------------------------------------------------- child side

fn emit(event: &str) {
    let mut out = std::io::stdout().lock();
    out.write_all(PREFIX.as_bytes()).unwrap();
    out.write_all(event.as_bytes()).unwrap();
    out.write_all(b"\n").unwrap();
    out.flush().unwrap();
}

fn termination_name(t: Termination) -> &'static str {
    match t {
        Termination::Terminate => "Terminate",
        Termination::Interrupt => "Interrupt",
    }
}

/// Runs one child scenario.
///
/// `wait_for_go` makes the child block on a line from stdin after it reports
/// `ready`, before it first polls the listener. The parent sends the signal
/// in that window, so the test sees whether registration happened at
/// `listen_termination` time.
fn child_main(wait_for_go: bool) {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let rt2 = rt.clone();
    rt.block_on(async move {
        let mut listener = match rt2.listen_termination() {
            Ok(l) => l,
            Err(e) => {
                emit(&format!("refused {e:?}"));
                return;
            }
        };
        let shutdown = Shutdown::new();
        let participant = shutdown.signal();
        let worker_rt = rt2.clone();
        let _worker = rt2.spawn(async move {
            participant.notified().await;
            emit("participant-notified");
            worker_rt.sleep(PARTICIPANT_WORK).await;
            emit("participant-drained");
            drop(participant);
        });
        emit("ready");
        if wait_for_go {
            let go = rt2
                .spawn_blocking(|| {
                    let mut line = String::new();
                    std::io::stdin().lock().read_line(&mut line).map(|_| line)
                })
                .await
                .unwrap()
                .unwrap();
            emit(&format!("go {}", go.trim()));
        }
        let which = listener.recv().await;
        emit(&format!("terminated {}", termination_name(which)));
        match shutdown.shutdown(&rt2, DRAIN_DEADLINE).await {
            Ok(()) => emit("drained"),
            Err(t) => emit(&format!("drain-timeout {}", t.remaining)),
        }
        emit("exit");
    });
}

/// Registers the listener on the test thread, outside every task and every
/// runtime thread, then waits for the signal inside the runtime.
fn child_outside_a_task() {
    let rt = TokioRuntime::new_current_thread().unwrap();
    let mut listener = match rt.listen_termination() {
        Ok(l) => l,
        Err(e) => {
            emit(&format!("refused {e:?}"));
            return;
        }
    };
    emit("ready");
    let which = rt.block_on(async move { listener.recv().await });
    emit(&format!("terminated {}", termination_name(which)));
    emit("exit");
}

/// Child-process entry point for the signal tests of this file.
///
/// It does nothing in a normal test run. When [`CHILD_ENV`] is set, it runs
/// the named scenario in this process. The parent tests below make the
/// assertions.
#[test]
fn adr002_signal_child_process_entry() {
    match std::env::var(CHILD_ENV).as_deref() {
        Ok("drain") => child_main(false),
        Ok("queued") => child_main(true),
        Ok("outside") => child_outside_a_task(),
        _ => {}
    }
}

// --------------------------------------------------------------- parent side

struct Spawned {
    child: Child,
    lines: Receiver<String>,
    stderr: thread::JoinHandle<String>,
    transcript: Vec<String>,
}

fn spawn_child(scenario: &str) -> Spawned {
    let exe = std::env::current_exe().unwrap();
    let mut child = Command::new(exe)
        .args(["--exact", CHILD_TEST, "--nocapture", "--test-threads=1"])
        .env(CHILD_ENV, scenario)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut stderr = child.stderr.take().unwrap();
    let (tx, lines) = channel();
    thread::spawn(move || {
        for line in BufReader::new(stdout).lines() {
            let Ok(line) = line else { return };
            // libtest may print "test <name> ... " on the same line first.
            if let Some(at) = line.find(PREFIX) {
                let event = &line[at + PREFIX.len()..];
                if tx.send(event.to_owned()).is_err() {
                    return;
                }
            }
        }
    });
    let stderr = thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });
    Spawned {
        child,
        lines,
        stderr,
        transcript: Vec::new(),
    }
}

impl Spawned {
    /// Reads events until `want` arrives. Panics with the transcript when the
    /// child refuses, exits or stalls first.
    fn expect_event(&mut self, want: &str) {
        let deadline = Instant::now() + STEP_TIMEOUT;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                Ok(event) => {
                    let refused = event.starts_with("refused ");
                    let done = event == want;
                    self.transcript.push(event);
                    if refused {
                        let status = self.wait();
                        panic!(
                            "fstp-rt refused to set up termination signals \
                             (transcript {:?}, child {status:?})",
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
                        "child closed stdout before {want:?}: transcript {:?}, \
                         status {status:?}",
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

    /// Lets a `queued` child go on. A child that already died closed its
    /// stdin, so a write error is left for the transcript check to report.
    fn send_go(&mut self) {
        if let Some(stdin) = self.child.stdin.as_mut() {
            let _ = stdin.write_all(b"go\n").and_then(|()| stdin.flush());
        }
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

    /// Waits for exit and returns the status with every event, in order.
    fn finish(mut self) -> (ExitStatus, Vec<String>, String) {
        let status = self.wait();
        while let Ok(event) = self.lines.recv_timeout(Duration::from_secs(5)) {
            self.transcript.push(event);
        }
        let stderr = self.stderr.join().unwrap_or_default();
        (status, self.transcript, stderr)
    }
}

/// The transcript of a clean drain after `which`.
fn clean_drain(which: &str, go: bool) -> Vec<String> {
    let mut v = vec!["ready".to_owned()];
    if go {
        v.push("go go".to_owned());
    }
    v.extend([
        format!("terminated {which}"),
        "participant-notified".to_owned(),
        "participant-drained".to_owned(),
        "drained".to_owned(),
        "exit".to_owned(),
    ]);
    v
}

/// ADR-002 review note of 2026-10-28 (M3 design section 19, W2l): SIGTERM
/// to a process that uses `fstp-rt` triggers the existing `Shutdown`. The
/// participant is notified and finishes its work, the drain completes, and
/// the process exits with status 0 rather than dying by the signal.
#[test]
fn adr002_sigterm_drains_through_shutdown_and_exits_cleanly() {
    let mut child = spawn_child("drain");
    child.expect_event("ready");
    child.send_signal("TERM");
    let (status, transcript, stderr) = child.finish();
    assert!(
        status.success() && transcript == clean_drain("Terminate", false),
        "status {status:?}, transcript {transcript:?}, stderr:\n{stderr}"
    );
}

/// ADR-002 review note of 2026-10-28: SIGINT from a terminal drains the same
/// way and is reported as `Termination::Interrupt`.
#[test]
fn adr002_sigint_drains_through_shutdown_and_exits_cleanly() {
    let mut child = spawn_child("drain");
    child.expect_event("ready");
    child.send_signal("INT");
    let (status, transcript, stderr) = child.finish();
    assert!(
        status.success() && transcript == clean_drain("Interrupt", false),
        "status {status:?}, transcript {transcript:?}, stderr:\n{stderr}"
    );
}

/// ADR-002 review note of 2026-10-28: the handler is in place once
/// `listen_termination` returns. A SIGTERM that arrives before the listener
/// is first polled neither kills the process nor gets lost.
#[test]
fn adr002_sigterm_before_first_recv_is_queued_not_fatal() {
    let mut child = spawn_child("queued");
    child.expect_event("ready");
    child.send_signal("TERM");
    // Give the signal time to land before the child polls its listener.
    thread::sleep(Duration::from_millis(200));
    child.send_go();
    let (status, transcript, stderr) = child.finish();
    assert!(
        status.success() && transcript == clean_drain("Terminate", true),
        "status {status:?}, transcript {transcript:?}, stderr:\n{stderr}"
    );
}

/// ADR-002 review note of 2026-10-28: registration works from outside the
/// runtime's own threads, because it enters the runtime's handle. The check
/// runs in a child process, since the handlers it installs stay in place for
/// the life of the process and would swallow SIGTERM and SIGINT here.
#[test]
fn adr002_listen_termination_outside_a_task() {
    let mut child = spawn_child("outside");
    child.expect_event("ready");
    child.send_signal("TERM");
    let (status, transcript, stderr) = child.finish();
    let want = ["ready", "terminated Terminate", "exit"];
    assert!(
        status.success() && transcript == want,
        "status {status:?}, transcript {transcript:?}, stderr:\n{stderr}"
    );
}
