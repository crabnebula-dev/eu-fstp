//! Process mode of the test world (design section 14.1, lane
//! m3/custody-decisions).
//!
//! A world started with `process_mode` runs its cells and vaults in a
//! process of their own, `fstp-world-host`, and each cell's custody in
//! another, `fstp-custody-sim --serve`. The test process keeps neither.
//! The cells reach their custody through the production client
//! `fstp_custody::keyd::KeydCustody`, so no root byte enters the host
//! process (I-80). Each custody process reports its roots and the seal
//! keys it wrapped to a file only the test reads
//! ([`crate::custody_sim::report`]), so the I-80 scans know what to look
//! for, and the Linux memory scans read the host process by its PID.
//!
//! Interim, pending Daniel: one host process runs every cell and vault of
//! the world, beside the test world's own parts (the edge, the witness,
//! the relays and the cycle's clients). Design section 14.1 asks for the
//! real `fstp-cell` and `fstp-vault` binaries, but `fstp_cell::run` still
//! refuses (its configuration names no logins, custody or keys), and the
//! world drives each cell through in-process handles (its clock, store
//! fault point, keystore and mail). A clean memory scan of the host
//! process thus covers every cell and vault process the world would have.
//!
//! # Protocol
//!
//! The test starts the host with `--cells <n> --mode shared|dedicated
//! --self-hosted 0|1` and one `--custody <socket>` per cell, in cell
//! order. The host answers on standard output with lines that start with
//! [`LINE_PREFIX`] and hold one JSON value each, written and read with
//! `fstp-json`. Any other line is the world's own output and is passed on
//! to standard error. The host first sends `{"ready":null}` or
//! `{"ready":"<why not>"}`. For each request `{"cycle":<cell>,
//! "steps":[...]}` on its standard input it sends the egress the world
//! recorded since the last request (`capture`, `handshake` and `attempt`
//! lines), then `{"result":null}` or `{"result":"<why not>"}`. When its
//! standard input closes, it stops the world and exits.

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, ChildStdout, Command, Stdio};
use std::sync::{Mutex, PoisonError};

use fstp_json::{Object, ParseLimits, Value};

use crate::NotImplemented;
use crate::custody_sim::report;
use crate::egress::{
    Attempt, AttemptOutcome, Capture, Component, Direction, EgressLog, Endpoint, Handshake, Peer,
    Route,
};
use crate::scan::Needle;
use crate::world::{CycleScript, DbMode, VaultLayout, WorldError, WorldSpec};

/// The start of every protocol line of the host.
pub const LINE_PREFIX: &str = "fstp-world-host ";

/// The longest capture a host line may carry, in bytes.
const MAX_CAPTURE: usize = 16 << 20;

fn fail(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("process mode: {what}: {e}"))
}

/// The path of the test binary `name` that Cargo built beside the running
/// executable: in its directory, or one up from a test's `deps`.
///
/// # Errors
///
/// Fails when no such file exists.
pub fn bin_path(name: &str) -> Result<PathBuf, WorldError> {
    let exe = std::env::current_exe().map_err(|e| fail("the running executable", &e))?;
    let dir = exe
        .parent()
        .ok_or_else(|| fail("the running executable", &"it has no directory"))?;
    [Some(dir), dir.parent()]
        .into_iter()
        .flatten()
        .map(|d| d.join(name))
        .find(|p| p.is_file())
        .ok_or_else(|| {
            fail(
                name,
                &"not built beside this executable; build the fstp-celltest binaries",
            )
        })
}

/// A short private directory for sockets and reports. A Unix socket path
/// must stay short, so it sits right under the system temporary
/// directory.
fn private_dir() -> Result<PathBuf, WorldError> {
    use std::os::unix::fs::DirBuilderExt as _;
    let tag = fstp_crypto::random_array::<6>().map_err(|e| fail("a directory name", &e))?;
    let dir = std::env::temp_dir().join(format!("fstp-pm-{}", crate::canary::lower_hex(&tag)));
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|e| fail("the process mode directory", &e))?;
    Ok(dir)
}

/// Reads lines from `out` until one ends with `want`, passing other
/// output on to standard error. Fails at end of file.
fn read_until(
    out: &mut impl std::io::BufRead,
    what: &str,
    want: impl Fn(&str) -> bool,
) -> Result<String, WorldError> {
    loop {
        let mut line = String::new();
        let n = out.read_line(&mut line).map_err(|e| fail(what, &e))?;
        if n == 0 {
            return Err(fail(what, &"the process ended"));
        }
        let line = line.trim_end_matches('\n');
        if want(line) {
            return Ok(line.to_owned());
        }
        #[allow(
            clippy::disallowed_macros,
            reason = "test-only: pass the child's output on"
        )]
        {
            eprintln!("{line}");
        }
    }
}

// ---------------------------------------------------------------------------
// The custody process of one cell.

/// One `fstp-custody-sim --serve` process: a cell's custody in process
/// mode. Dropping it closes its standard input, so it removes its socket
/// and exits.
pub struct SimProcess {
    child: Child,
    stdin: Option<ChildStdin>,
    socket: PathBuf,
    report: PathBuf,
}

impl std::fmt::Debug for SimProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimProcess")
            .field("pid", &self.child.id())
            .field("socket", &self.socket)
            .finish_non_exhaustive()
    }
}

impl SimProcess {
    /// Starts the custody process of cell index `cell_index`, with its
    /// socket and report in `dir`, and waits until it listens.
    ///
    /// # Errors
    ///
    /// Fails when the binary is missing or does not start.
    pub fn spawn(cell_index: u8, dir: &Path) -> Result<SimProcess, WorldError> {
        let socket = dir.join(format!("c{cell_index}.sock"));
        let report = dir.join(format!("c{cell_index}.report"));
        let mut child = Command::new(bin_path("fstp-custody-sim")?)
            .arg("--cell-index")
            .arg(cell_index.to_string())
            .arg("--serve")
            .arg(&socket)
            .arg("--report")
            .arg(&report)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| fail("the custody process", &e))?;
        let stdin = child.stdin.take();
        let mut sim = SimProcess {
            child,
            stdin,
            socket,
            report,
        };
        let stdout = sim
            .child
            .stdout
            .take()
            .ok_or_else(|| fail("the custody process", &"no standard output"))?;
        read_until(&mut BufReader::new(stdout), "the custody process", |l| {
            l == "ready"
        })?;
        Ok(sim)
    }

    /// The socket it serves.
    #[must_use]
    pub fn socket(&self) -> &Path {
        &self.socket
    }

    /// Its process id.
    #[must_use]
    pub fn pid(&self) -> u32 {
        self.child.id()
    }

    /// Everything it reported so far.
    ///
    /// # Errors
    ///
    /// Fails when the report cannot be read or breaks its format.
    pub fn records(&self) -> Result<Vec<report::Record>, WorldError> {
        let bytes = std::fs::read(&self.report).or_else(|e| match e.kind() {
            std::io::ErrorKind::NotFound => Ok(Vec::new()),
            _ => Err(fail("the custody report", &e)),
        })?;
        report::decode(&bytes).map_err(|e| fail("the custody report", &e))
    }
}

impl Drop for SimProcess {
    fn drop(&mut self) {
        drop(self.stdin.take());
        let _ = self.child.wait();
    }
}

// ---------------------------------------------------------------------------
// The host process, seen from the test.

struct HostIo {
    stdin: ChildStdin,
    stdout: BufReader<ChildStdout>,
}

/// The processes of a world in process mode: the host and one custody
/// process per cell. Dropping it stops the host first, then custody, and
/// removes their directory.
pub(crate) struct WorldHost {
    child: Child,
    io: Mutex<Option<HostIo>>,
    sims: Vec<SimProcess>,
    dir: PathBuf,
}

impl std::fmt::Debug for WorldHost {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WorldHost")
            .field("pid", &self.child.id())
            .field("sims", &self.sims)
            .finish_non_exhaustive()
    }
}

impl WorldHost {
    /// Starts the custody processes and the host of `spec`, and waits
    /// until the host's world started.
    pub(crate) fn start(spec: &WorldSpec) -> Result<WorldHost, WorldError> {
        let dir = private_dir()?;
        let started = WorldHost::start_in(spec, &dir);
        if started.is_err() {
            let _ = std::fs::remove_dir_all(&dir);
        }
        started
    }

    fn start_in(spec: &WorldSpec, dir: &Path) -> Result<WorldHost, WorldError> {
        let sims = (0..spec.cells)
            .map(|i| SimProcess::spawn(i, dir))
            .collect::<Result<Vec<_>, _>>()?;
        let mut cmd = Command::new(bin_path("fstp-world-host")?);
        cmd.arg("--cells")
            .arg(spec.cells.to_string())
            .arg("--mode")
            .arg(match spec.mode {
                DbMode::Shared => "shared",
                DbMode::Dedicated => "dedicated",
            })
            .arg("--self-hosted")
            .arg(if spec.self_hosted { "1" } else { "0" });
        for s in &sims {
            cmd.arg("--custody").arg(s.socket());
        }
        // The host's edge takes a free port: the test's own edge may hold
        // the one the environment names.
        let mut child = cmd
            .env_remove(crate::world::EDGE_PORT_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| fail("the world host", &e))?;
        let io = match (child.stdin.take(), child.stdout.take()) {
            (Some(stdin), Some(stdout)) => HostIo {
                stdin,
                stdout: BufReader::new(stdout),
            },
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(fail("the world host", &"no pipes"));
            }
        };
        let mut host = WorldHost {
            child,
            io: Mutex::new(Some(io)),
            sims,
            dir: dir.to_path_buf(),
        };
        let ready = host.read_message("the world host start")?;
        match ready.get("ready") {
            Some(Value::Null) => Ok(host),
            Some(Value::String(why)) => {
                let why = why.clone();
                host.stop();
                Err(WorldError::Store(format!(
                    "process mode: the host world: {why}"
                )))
            }
            _ => {
                host.stop();
                Err(fail("the world host start", &"an unexpected line"))
            }
        }
    }

    fn read_message(&self, what: &str) -> Result<Value, WorldError> {
        let mut io = self.io.lock().unwrap_or_else(PoisonError::into_inner);
        let io = io.as_mut().ok_or_else(|| fail(what, &"the host stopped"))?;
        read_line(&mut io.stdout, what)
    }

    /// The host's process id: the process that runs every cell and vault
    /// of the world.
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }

    /// The custody process of cell `cell`.
    pub(crate) fn custody(&self, cell: u8) -> Option<&SimProcess> {
        self.sims.get(usize::from(cell))
    }

    /// The number of cells.
    pub(crate) fn cells(&self) -> usize {
        self.sims.len()
    }

    /// Runs `script` on cell `cell` in the host and records the egress
    /// the host saw meanwhile in `egress`.
    pub(crate) fn run_cycle(
        &self,
        cell: u8,
        script: &CycleScript,
        egress: &EgressLog,
    ) -> Result<(), NotImplemented> {
        const LOST: &str = "fstp_celltest::world_host: the world host did not answer";
        let mut request = Object::new();
        request.insert("cycle", Value::from(cell));
        request.insert(
            "steps",
            Value::from(
                script
                    .steps
                    .iter()
                    .map(|s| Value::from(s.as_str()))
                    .collect::<Vec<_>>(),
            ),
        );
        let mut guard = self.io.lock().unwrap_or_else(PoisonError::into_inner);
        let io = guard.as_mut().ok_or(NotImplemented::new(LOST))?;
        let line = format!("{}\n", Value::from(request).to_compact());
        io.stdin
            .write_all(line.as_bytes())
            .and_then(|()| io.stdin.flush())
            .map_err(|_| NotImplemented::new(LOST))?;
        loop {
            let msg =
                read_line(&mut io.stdout, "a cycle").map_err(|_| NotImplemented::new(LOST))?;
            if let Some(result) = msg.get("result") {
                return match result {
                    Value::Null => Ok(()),
                    // The world's refusals name static text. The host's
                    // text crosses as a string, so it is kept for the
                    // life of the test process.
                    Value::String(why) => {
                        Err(NotImplemented::new(Box::leak(why.clone().into_boxed_str())))
                    }
                    _ => Err(NotImplemented::new(LOST)),
                };
            }
            replay(&msg, egress).map_err(|_| NotImplemented::new(LOST))?;
        }
    }

    /// One needle per root that any cell's custody created, destroyed
    /// roots included.
    pub(crate) fn root_needles(&self) -> Result<Vec<Needle>, WorldError> {
        let mut out = Vec::new();
        for (i, sim) in self.sims.iter().enumerate() {
            for (n, r) in report::roots(&sim.records()?).into_iter().enumerate() {
                out.push(Needle {
                    label: format!("cell {i} root {n} ({:?} epoch {})", r.chain, r.epoch),
                    bytes: r.bytes.to_vec(),
                });
            }
        }
        Ok(out)
    }

    /// One needle per seal key that a cell's custody wrapped under a root
    /// of `chains`, only those of destroyed roots when `destroyed_only`.
    pub(crate) fn seal_needles(
        &self,
        chains: &[fstp_custody::Chain],
        destroyed_only: bool,
    ) -> Result<Vec<Needle>, WorldError> {
        let mut out = Vec::new();
        for (i, sim) in self.sims.iter().enumerate() {
            let records = sim.records()?;
            for (r, destroyed) in report::seal_keys(&records) {
                if chains.contains(&r.chain) && (destroyed || !destroyed_only) {
                    out.push(Needle {
                        label: format!(
                            "cell {i} seal key ({:?} epoch {}, destroyed {destroyed})",
                            r.chain, r.epoch
                        ),
                        bytes: r.bytes.to_vec(),
                    });
                }
            }
        }
        Ok(out)
    }

    fn stop(&mut self) {
        let io = self
            .io
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        drop(io);
        let _ = self.child.wait();
    }
}

impl Drop for WorldHost {
    fn drop(&mut self) {
        // The host stops its world before custody goes, so the cells
        // never see their custody vanish while they run.
        self.stop();
        self.sims.clear();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The limits of a host line: a capture may be large.
fn line_limits() -> ParseLimits {
    ParseLimits {
        max_input_bytes: MAX_CAPTURE.saturating_mul(2).saturating_add(4096),
        max_string_bytes: MAX_CAPTURE.saturating_mul(2),
        ..ParseLimits::default()
    }
}

/// Reads the next protocol line and decodes its JSON object.
fn read_line(out: &mut impl std::io::BufRead, what: &str) -> Result<Value, WorldError> {
    let line = read_until(out, what, |l| l.starts_with(LINE_PREFIX))?;
    let json = line.get(LINE_PREFIX.len()..).unwrap_or("");
    let value =
        fstp_json::parse_with(json.as_bytes(), &line_limits()).map_err(|e| fail(what, &e))?;
    if value.as_object().is_none() {
        return Err(fail(what, &"a line that is not an object"));
    }
    Ok(value)
}

// ---------------------------------------------------------------------------
// Egress across the process boundary.

const COMPONENTS: [Component; 6] = [
    Component::Cell,
    Component::Vault,
    Component::ControlPlane,
    Component::Witness,
    Component::Edge,
    Component::Backup,
];

const OUTCOMES: [(AttemptOutcome, &str); 3] = [
    (AttemptOutcome::Refused, "refused"),
    (AttemptOutcome::HandshakeFailed, "handshake-failed"),
    (AttemptOutcome::Connected, "connected"),
];

fn opt_cell(cell: Option<u8>) -> Value {
    cell.map_or(Value::Null, Value::from)
}

fn route_value(r: &Route) -> Value {
    let mut o = Object::new();
    o.insert("from", Value::from(r.from.component.label()));
    o.insert("from_cell", opt_cell(r.from.cell));
    o.insert("to", Value::from(r.to.label()));
    o.insert("to_cell", opt_cell(r.to_cell));
    Value::from(o)
}

fn capture_value(c: &Capture) -> Value {
    let mut o = Object::new();
    o.insert("route", route_value(&c.route));
    o.insert(
        "dir",
        Value::from(match c.direction {
            Direction::Outbound => "out",
            Direction::Inbound => "in",
        }),
    );
    o.insert("conn", Value::from(c.connection));
    o.insert("bytes", Value::from(crate::canary::lower_hex(&c.bytes)));
    let mut line = Object::new();
    line.insert("capture", Value::from(o));
    Value::from(line)
}

fn handshake_value(h: &Handshake) -> Value {
    let mut o = Object::new();
    o.insert("route", route_value(&h.route));
    o.insert("conn", Value::from(h.connection));
    o.insert("verified", Value::from(h.client_certificate_verified));
    let mut line = Object::new();
    line.insert("handshake", Value::from(o));
    Value::from(line)
}

fn attempt_value(a: &Attempt) -> Value {
    let mut o = Object::new();
    o.insert("route", route_value(&a.route));
    let outcome = OUTCOMES
        .iter()
        .find(|(k, _)| *k == a.outcome)
        .map_or("", |(_, n)| n);
    o.insert("outcome", Value::from(outcome));
    let mut line = Object::new();
    line.insert("attempt", Value::from(o));
    Value::from(line)
}

/// The refusal of a host line that breaks the protocol.
const BAD_LINE: &str = "fstp_celltest::world_host: a host line breaks the protocol";

fn bad() -> NotImplemented {
    NotImplemented::new(BAD_LINE)
}

fn get_cell(o: &Value, key: &str) -> Result<Option<u8>, NotImplemented> {
    match o.get(key) {
        Some(Value::Null) => Ok(None),
        Some(v) => v
            .as_u64()
            .and_then(|n| u8::try_from(n).ok())
            .map(Some)
            .ok_or_else(bad),
        None => Err(bad()),
    }
}

fn route_of(v: &Value) -> Result<Route, NotImplemented> {
    let from = v.get("from").and_then(Value::as_str).ok_or_else(bad)?;
    let component = COMPONENTS
        .into_iter()
        .find(|c| c.label() == from)
        .ok_or_else(bad)?;
    let to = v.get("to").and_then(Value::as_str).ok_or_else(bad)?;
    let peer = Peer::ALL
        .into_iter()
        .find(|p| p.label() == to)
        .ok_or_else(bad)?;
    Ok(Route::new(
        Endpoint {
            component,
            cell: get_cell(v, "from_cell")?,
        },
        peer,
        get_cell(v, "to_cell")?,
    ))
}

/// Records one egress line of the host in `egress`.
fn replay(msg: &Value, egress: &EgressLog) -> Result<(), NotImplemented> {
    let route = |v: &Value| v.get("route").ok_or_else(bad).and_then(route_of);
    let conn = |v: &Value| v.get("conn").and_then(Value::as_u64).ok_or_else(bad);
    if let Some(c) = msg.get("capture") {
        let direction = match c.get("dir").and_then(Value::as_str) {
            Some("out") => Direction::Outbound,
            Some("in") => Direction::Inbound,
            _ => return Err(bad()),
        };
        let bytes = c
            .get("bytes")
            .and_then(Value::as_str)
            .and_then(|h| fstp_cell::http::body::hex_vec(h, MAX_CAPTURE))
            .ok_or_else(bad)?;
        egress.record(route(c)?, direction, conn(c)?, &bytes);
        return Ok(());
    }
    if let Some(h) = msg.get("handshake") {
        let verified = h.get("verified").and_then(Value::as_bool).ok_or_else(bad)?;
        egress.record_handshake(Handshake {
            route: route(h)?,
            connection: conn(h)?,
            client_certificate_verified: verified,
        });
        return Ok(());
    }
    if let Some(a) = msg.get("attempt") {
        let name = a.get("outcome").and_then(Value::as_str).ok_or_else(bad)?;
        let outcome = OUTCOMES
            .iter()
            .find(|(_, n)| *n == name)
            .map(|(k, _)| *k)
            .ok_or_else(bad)?;
        egress.record_attempt(Attempt {
            route: route(a)?,
            outcome,
        });
        return Ok(());
    }
    Err(bad())
}

// ---------------------------------------------------------------------------
// The host process itself.

/// What the host is asked to run.
#[derive(Debug, Default)]
struct HostArgs {
    cells: u8,
    dedicated: bool,
    self_hosted: bool,
    custody: Vec<PathBuf>,
}

fn parse_host_args(args: &[String]) -> Result<HostArgs, String> {
    let mut out = HostArgs::default();
    let mut it = args.iter();
    while let Some(flag) = it.next() {
        let value = it.next().ok_or("a flag lacks its value")?;
        match (flag.as_str(), value.as_str()) {
            ("--cells", n) => out.cells = n.parse().map_err(|_| "bad --cells")?,
            ("--mode", "shared") => out.dedicated = false,
            ("--mode", "dedicated") => out.dedicated = true,
            ("--self-hosted", "0") => out.self_hosted = false,
            ("--self-hosted", "1") => out.self_hosted = true,
            ("--custody", path) => out.custody.push(path.into()),
            _ => return Err(format!("unknown flag or value: {flag}")),
        }
    }
    if out.custody.len() != usize::from(out.cells) {
        return Err("one --custody per cell".to_owned());
    }
    Ok(out)
}

/// Writes one protocol line.
fn send(out: &mut impl std::io::Write, value: Value) -> Result<(), String> {
    let line = format!("{LINE_PREFIX}{}\n", value.to_compact());
    out.write_all(line.as_bytes())
        .and_then(|()| out.flush())
        .map_err(|e| format!("standard output: {e}"))
}

fn tagged(key: &str, value: Value) -> Value {
    let mut o = Object::new();
    o.insert(key, value);
    Value::from(o)
}

/// The `fstp-world-host` process: it starts the world its arguments
/// name, with each cell's custody on its socket, and serves cycle
/// requests until its standard input closes ([module docs](self)).
///
/// # Errors
///
/// Fails on bad arguments, a failed write, or a request that breaks the
/// protocol.
pub fn host_main() -> Result<(), String> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let args = parse_host_args(&args)?;
    let mut stdout = std::io::stdout();
    let spec = WorldSpec {
        cells: args.cells,
        mode: if args.dedicated {
            DbMode::Dedicated
        } else {
            DbMode::Shared
        },
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: args.self_hosted,
        process_mode: false,
    };
    let world = match crate::world::World::start_hosted(spec, &args.custody) {
        Ok(w) => {
            send(&mut stdout, tagged("ready", Value::Null))?;
            w
        }
        Err(e) => {
            send(&mut stdout, tagged("ready", Value::from(e.to_string())))?;
            return Ok(());
        }
    };
    let (mut captures, mut handshakes, mut attempts) = (0usize, 0usize, 0usize);
    let stdin = std::io::stdin();
    for line in stdin.lock().lines() {
        let line = line.map_err(|e| format!("standard input: {e}"))?;
        let request = fstp_json::parse(line.as_bytes()).map_err(|e| format!("a request: {e}"))?;
        let cell = request
            .get("cycle")
            .and_then(Value::as_u64)
            .and_then(|n| u8::try_from(n).ok())
            .ok_or("a request names no cell")?;
        let steps = request
            .get("steps")
            .and_then(Value::as_array)
            .ok_or("a request names no steps")?
            .iter()
            .map(|s| {
                s.as_str()
                    .map(str::to_owned)
                    .ok_or("a step is not a string")
            })
            .collect::<Result<Vec<_>, _>>()?;
        let result = world.run_cycle(cell, &CycleScript { steps }).result;
        let egress = world.egress();
        let all = egress.captures();
        for c in all.iter().skip(captures) {
            send(&mut stdout, capture_value(c))?;
        }
        captures = all.len();
        let all = egress.handshakes();
        for h in all.iter().skip(handshakes) {
            send(&mut stdout, handshake_value(h))?;
        }
        handshakes = all.len();
        let all = egress.attempts();
        for a in all.iter().skip(attempts) {
            send(&mut stdout, attempt_value(a))?;
        }
        attempts = all.len();
        let result = match result {
            Ok(()) => Value::Null,
            Err(e) => Value::from(e.operation),
        };
        send(&mut stdout, tagged("result", result))?;
    }
    drop(world);
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    /// I-19 harness: every egress record the host sends is recorded the
    /// same in the test's log, routes and bytes included.
    #[test]
    fn i19_harness_host_egress_lines_round_trip() {
        let route = Route::new(Endpoint::cell(1), Peer::Vault, Some(1));
        let shared = Route::new(Endpoint::shared(Component::Edge), Peer::Witness, None);
        let capture = Capture {
            route,
            direction: Direction::Inbound,
            connection: 7,
            bytes: b"synthetic bytes".to_vec(),
        };
        let handshake = Handshake {
            route: shared,
            connection: 3,
            client_certificate_verified: true,
        };
        let attempt = Attempt {
            route,
            outcome: AttemptOutcome::HandshakeFailed,
        };
        let log = EgressLog::new();
        for v in [
            capture_value(&capture),
            handshake_value(&handshake),
            attempt_value(&attempt),
        ] {
            let text = v.to_compact();
            replay(&fstp_json::parse(text.as_bytes()).unwrap(), &log).unwrap();
        }
        assert_eq!(log.captures(), vec![capture]);
        assert_eq!(log.handshakes(), vec![handshake]);
        assert_eq!(log.attempts(), vec![attempt]);
        assert!(replay(&tagged("other", Value::Null), &log).is_err());
    }
}
