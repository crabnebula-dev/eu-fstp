//! The sent mail of the demo cell (M6 design section 8, lane L6-DEMO).
//!
//! The cell runs the real timeline engine, the real dispatcher worker and
//! the real SMTP client against the test sink, which listens on loopback
//! with implicit TLS (`fstp_api_testkit::smtp_sink`). The path:
//!
//! 1. A mirror of the cell's ledger folds the engine's entries into a
//!    `fstp_cell_core::CellState`, one entry at a time, as the cell's own
//!    timeline task reads its state.
//! 2. `fstp_timeline::plan` schedules and cancels events, and
//!    `fstp_timeline::firing` fires each due event with the bodies of its
//!    messages. The mirror folds the firing, so an event fires once.
//!    The System commands of the sweep kinds run in `crate::pump` on the
//!    real engine, so the mirror never issues one (its firing is cancelled
//!    once the engine's entry reaches the mirror).
//! 3. The message of each body is composed with `fstp_mail::compose`. It
//!    holds ids, times and a link only (I-27, R-NF-02).
//! 4. `fstp_dispatch::Worker` sends it with the attempt protocol of I-25
//!    and I-26 through `SmtpTransport` to the sink, over an in-memory
//!    delivery log (`MemDelivery`).
//!
//! The demo page lists the result per person and in one table, and shows
//! each raw message as escaped text. Two buttons arm a one-shot sink
//! fault: a 451 refusal and a dropped connection after DATA.
//!
//! Test only: this module lives in `fstp-e2e-cell` and never ships.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fstp_api_core::port::AsyncEngine;
use fstp_api_testkit::smtp_sink::{Fault, SinkConfig, SmtpSink};
use fstp_cell_core::timeline::{Recipient, TimelineCommand};
use fstp_cell_core::{CellCommand, CellRecord, CellState, RouteInputs, SystemCtx, SystemTask};
use fstp_dispatch::store::MemDelivery;
use fstp_dispatch::{
    DigestKey, LoadError, Outcome, Prepared, SmtpTransport, Source, Transport, Worker, prepare,
};
use fstp_domain::oracle::Answers;
use fstp_domain::time::Timestamp;
use fstp_http::{Method, Request, Response, StatusCode};
use fstp_ledger::{Entry, Seq};
use fstp_mail::{DisplayName, MailConfig, Mailbox, Origin};
use fstp_rt::tokio::TokioRuntime;
use fstp_timeline::message::MessageSpec;

use crate::{Inner, Site, wire};

/// The sender of the demo cell's mail.
const SENDER: &str = "noreply@fstp.demo.test";
/// The address a copy request names, as the sealed address stands in for.
const COPY_ADDRESS: &str = "requested-copy@e2e.invalid";
/// Most steps one tick gives the worker.
const MAX_STEPS: usize = 400;

type Staged = <SmtpTransport<TokioRuntime> as Transport>::Staged;

/// One message the cell composed, with what the demo page shows.
struct Item {
    outbox: [u8; 16],
    to: String,
    to_account: Option<fstp_domain::id::AccountId>,
    template: String,
    event: [u8; 32],
}

/// The mirror, the delivery log and the worker of one cell state.
struct Mail {
    /// Which cell state this mirror follows (`Arc` address).
    inner: usize,
    state: CellState,
    entries: Vec<Entry<CellRecord>>,
    seen: usize,
    broken: Option<String>,
    /// Engine entries the cell's fold refused.
    skipped: Vec<String>,
    raw: BTreeMap<[u8; 16], Vec<u8>>,
    items: Vec<Item>,
    log: MemDelivery,
    worker: Worker<Staged>,
    /// How many sink messages belonged to earlier cell states.
    base: usize,
}

struct Raw<'a>(&'a BTreeMap<[u8; 16], Vec<u8>>);

impl Source for Raw<'_> {
    async fn load(&mut self, outbox: [u8; 16]) -> Result<Prepared, LoadError> {
        let raw = self.0.get(&outbox).ok_or(LoadError::Unusable)?;
        prepare(raw, SENDER).map_err(|_| LoadError::Unusable)
    }
}

/// The running demo mail: the sink, the runtime and the mirror.
pub(crate) struct MailDemo {
    rt: TokioRuntime,
    sink: SmtpSink,
    mail: Mutex<Option<Mail>>,
}

static DEMO: OnceLock<Arc<MailDemo>> = OnceLock::new();

fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn wall_micros() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_micros()).unwrap_or(i64::MAX))
}

/// Starts the sink and the tick thread over `sites`.
pub(crate) fn start(rt: &TokioRuntime, sites: Vec<Arc<Site>>) -> Result<(), String> {
    let sink = rt
        .block_on(SmtpSink::start(rt, SinkConfig::default()))
        .map_err(|e| format!("the mail sink: {e}"))?;
    let demo = Arc::new(MailDemo {
        rt: rt.clone(),
        sink,
        mail: Mutex::new(None),
    });
    let _ = DEMO.set(Arc::clone(&demo));
    let _ = std::thread::Builder::new()
        .name("demo-mail".to_owned())
        .spawn(move || {
            loop {
                for s in &sites {
                    demo.tick(s);
                }
                std::thread::sleep(Duration::from_millis(700));
            }
        });
    Ok(())
}

fn fresh(inner: &Arc<Inner>, base: usize) -> Mail {
    Mail {
        inner: Arc::as_ptr(inner) as usize,
        state: CellState::genesis(),
        entries: Vec::new(),
        seen: 0,
        broken: None,
        skipped: Vec::new(),
        raw: BTreeMap::new(),
        items: Vec::new(),
        log: MemDelivery::new(std::iter::empty()),
        worker: Worker::new(*b"fstp:demo:worker", DigestKey::new([0x5a; 32])),
        base,
    }
}

impl Mail {
    /// Folds `record` into the mirror at `at` under `command`.
    fn append(&mut self, at: i64, command: [u8; 16], record: CellRecord) -> Result<(), String> {
        let at = at.max(self.entries.last().map_or(0, |e| e.at));
        let seq = Seq::from_raw(self.state.head().raw().saturating_add(1));
        let e = match self.entries.first() {
            // An entry is built only by a store, so a new one takes the
            // envelope of the first and its own fields.
            Some(first) => {
                let mut e = first.clone();
                e.seq = seq;
                e.at = at;
                e.command = command;
                e.record = record;
                e
            }
            None => return Err("the mirror holds no first entry".to_owned()),
        };
        fstp_cell_core::apply(&mut self.state, &e).map_err(|e| format!("{e:?}"))?;
        self.entries.push(e);
        Ok(())
    }

    /// Takes the engine entries the mirror has not seen.
    fn sync(&mut self, inner: &Inner) -> Result<(), String> {
        let Some(ledger) = inner.ports.engine.ledger() else {
            return Ok(());
        };
        for e in ledger.into_iter().skip(self.seen) {
            if self.entries.is_empty() {
                let first = e.map_record(CellRecord::Engine);
                let mut first = first;
                first.seq = Seq::from_raw(1);
                fstp_cell_core::apply(&mut self.state, &first).map_err(|e| format!("{e:?}"))?;
                self.entries.push(first);
            } else {
                let shown: String = format!("{:?}", e.record).chars().take(160).collect();
                // The fake engine folds entries that the cell's fold refuses, such
                // as a Guide published from an out-of-band spec. The mirror
                // follows mail only, so it skips such an entry and says so.
                if let Err(why) = self.append(e.at, e.command, CellRecord::Engine(e.record)) {
                    self.skipped.push(format!("entry {} ({shown}): {why}", self.seen));
                }
            }
            self.seen = self.seen.saturating_add(1);
        }
        Ok(())
    }

    /// Runs `cmd` as the timeline task and folds its records.
    fn run(
        &mut self,
        cmd: TimelineCommand,
        bodies: Vec<fstp_cell_core::timeline::MessageBody>,
        now: Timestamp,
    ) -> Result<(), String> {
        let id = fstp_timeline::command_id(&cmd);
        let cmd = CellCommand::Timeline(cmd);
        let x = SystemCtx {
            task: SystemTask::Timeline,
            at: now.micros(),
        };
        let inputs = RouteInputs::none().with_outbox(bodies);
        let batch = fstp_cell_core::decide_system_with_inputs(
            &self.state,
            &cmd,
            &x,
            id,
            &inputs,
            &Answers::new(),
        )
        .map_err(|e| format!("{e:?}"))?;
        for r in batch {
            self.append(now.micros(), id, r)?;
        }
        Ok(())
    }

    /// The plan and every due firing at `now`. Returns the new bodies.
    fn timeline(&mut self, now: Timestamp) -> Result<Vec<fstp_cell_core::timeline::MessageBody>, String> {
        let mut out = Vec::new();
        for chunk in fstp_timeline::plan(&self.state, now).chunks(fstp_timeline::PLAN_CHUNK) {
            self.run(
                TimelineCommand::Plan {
                    records: chunk.to_vec(),
                },
                Vec::new(),
                now,
            )?;
        }
        for event in fstp_timeline::due_events(self.state.timeline(), now) {
            if let Some(f) = fstp_timeline::firing(&self.state, &event, now) {
                self.run(f.command, f.bodies.clone(), now)?;
                out.extend(f.bodies);
            }
        }
        Ok(out)
    }
}

impl MailDemo {
    /// One tick for `site`: mirror, timeline, compose, dispatch.
    fn tick(&self, site: &Site) {
        let inner = site.inner();
        let mut guard = lock(&self.mail);
        let now_inner = Arc::as_ptr(&inner) as usize;
        if guard.as_ref().is_none_or(|m| m.inner != now_inner) {
            let base = self.sink.messages().len();
            *guard = Some(fresh(&inner, base));
        }
        let Some(m) = guard.as_mut() else { return };
        if m.broken.is_some() {
            return;
        }
        if let Err(e) = self.step(site, &inner, m) {
            m.broken = Some(e);
        }
    }

    fn step(&self, site: &Site, inner: &Inner, m: &mut Mail) -> Result<(), String> {
        m.sync(inner)?;
        if m.entries.is_empty() {
            return Ok(());
        }
        let now = inner.ports.clock.read();
        let bodies = m.timeline(now)?;
        let cfg = MailConfig {
            origin: Origin::new(&site.info.origin).map_err(|e| format!("{e:?}"))?,
            from: Mailbox::new(SENDER).map_err(|e| format!("{e:?}"))?,
            from_name: DisplayName::new("FSTP demo").ok(),
            dkim: Vec::new(),
        };
        for b in bodies {
            let spec = MessageSpec::decode(&b.body).map_err(|e| format!("{e:?}"))?;
            let (to, account) = match spec.to {
                Recipient::Account(a) => (
                    crate::lock(&inner.auth)
                        .email_of(a)
                        .map_or_else(|| format!("account-{}@e2e.invalid", a.raw()), str::to_owned),
                    Some(a),
                ),
                Recipient::Address(_) => (COPY_ADDRESS.to_owned(), None),
            };
            let mailbox = Mailbox::new(&to).map_err(|e| format!("{e:?}"))?;
            let raw = spec.compose(&cfg, &mailbox).map_err(|e| format!("{e:?}"))?;
            m.log.add_message(b.outbox);
            m.items.push(Item {
                outbox: b.outbox,
                to,
                to_account: account,
                template: format!("{}/{}", fstp_timeline::template_code(spec.template), spec.version),
                event: spec.event,
            });
            m.raw.insert(b.outbox, raw);
        }
        let pending: Vec<[u8; 16]> = m
            .items
            .iter()
            .map(|i| i.outbox)
            .filter(|o| !m.log.is_settled(o))
            .collect();
        if pending.is_empty() {
            return Ok(());
        }
        let client = self.sink.client().map_err(|e| e.to_string())?;
        let addr = self.sink.addr();
        let mut transport = SmtpTransport::new(
            self.rt.clone(),
            client,
            &addr.ip().to_string(),
            addr.port(),
        );
        let raw = m.raw.clone();
        let mut source = Raw(&raw);
        let now_us = wall_micros();
        let Mail { worker, log, .. } = m;
        self.rt.block_on(async {
            for _ in 0..MAX_STEPS {
                let out = worker
                    .step(log, &mut source, &mut transport, &pending, now_us)
                    .await;
                if matches!(out, Outcome::Idle | Outcome::StoreFault { .. }) && worker.is_idle() {
                    break;
                }
            }
        });
        Ok(())
    }
}

/// `s` escaped for HTML text.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn phase_of(m: &Mail, o: &[u8; 16]) -> String {
    m.log
        .head(o)
        .map_or_else(|| "QUEUED".to_owned(), |r| format!("{:?}", r.phase).to_uppercase())
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// The sink message of `item`, by its event id and address.
fn sink_index(demo: &MailDemo, item: &Item) -> Option<usize> {
    demo.sink.messages().iter().position(|s| {
        let text = String::from_utf8_lossy(&s.data);
        text.contains(&hex(&item.event)) && s.to.iter().any(|t| *t == item.to)
    })
}

fn subject_of(data: &[u8]) -> String {
    fstp_mail::parse(data)
        .ok()
        .and_then(|p| p.header("Subject").map(str::to_owned))
        .unwrap_or_default()
}

/// The mail rows of the demo page for `email`, or every row when `None`.
fn rows(email: Option<&str>) -> String {
    let Some(demo) = DEMO.get() else {
        return String::new();
    };
    let guard = lock(&demo.mail);
    let Some(m) = guard.as_ref() else {
        return String::new();
    };
    let mut out = String::new();
    for i in &m.items {
        if email.is_some_and(|e| e != i.to) {
            continue;
        }
        let phase = phase_of(m, &i.outbox);
        let (when, link, subject) = match sink_index(demo, i) {
            Some(n) => {
                let s = demo.sink.messages();
                let msg = s.get(n);
                (
                    msg.map_or(0, |x| x.at_unix_ms),
                    format!("<a href=\"/demo/mail/{n}\" target=\"_blank\" rel=\"noopener\">raw message</a>"),
                    msg.map(|x| subject_of(&x.data)).unwrap_or_default(),
                )
            }
            None => (0, String::new(), String::new()),
        };
        let who = i
            .to_account
            .and_then(crate::scenario::persona_label)
            .unwrap_or(&i.to);
        out.push_str(&format!(
            "<li data-demo-mail data-phase=\"{p}\">{subject} to {who}, template {t}, event {e}, delivery <strong>{p}</strong>, sink time {when} ms {link}</li>\n",
            p = esc(&phase),
            subject = esc(&subject),
            who = esc(who),
            t = esc(&i.template),
            e = esc(&hex(&i.event[..6])),
            link = link,
        ));
    }
    out
}

/// The mail list of one person for the front door.
pub(crate) fn person_html(email: &str) -> String {
    let r = rows(Some(email));
    if r.is_empty() {
        return String::new();
    }
    format!("<ul class=\"person-mail\">\n{r}</ul>\n")
}

/// The mail section of the front door: every message, and the fault buttons.
pub(crate) fn section_html() -> String {
    let all = rows(None);
    let status = DEMO
        .get()
        .map(|d| lock(&d.mail).as_ref().and_then(|m| m.broken.clone()))
        .unwrap_or(None);
    let stats = DEMO
        .get()
        .and_then(|d| lock(&d.mail).as_ref().map(|m| format!("{} ledger entries followed ({} skipped), {} messages composed", m.seen, m.skipped.len(), m.items.len())))
        .unwrap_or_default();
    let note = status.map_or_else(String::new, |e| {
        format!("<p role=\"alert\">The mail mirror stopped: {}</p>\n", esc(&e))
    });
    let body = if all.is_empty() {
        "<p>No dispatcher mail yet. Outcome notices, copy requests and corrigenda appear here.</p>\n".to_owned()
    } else {
        format!("<ul id=\"demo-mail\">\n{all}</ul>\n")
    };
    format!(
        "<h2>Mail through the dispatcher</h2>\n<p>The real timeline task and dispatcher send to the test sink over TLS. A message holds ids, times and a link only (I-27).</p>\n<p class=\"muted\" id=\"demo-mail-status\">{stats}</p>\n{note}{body}<p>Sink faults, once each: <a href=\"/demo/mail/fault?kind=refuse451\">Refuse the next message (451)</a> | <a href=\"/demo/mail/fault?kind=drop\">Drop the connection after DATA</a> | <a href=\"/demo/mail/fault?kind=lose_reply\">Accept, then lose the reply</a></p>\n"
    )
}

/// The `/demo/mail...` routes: a raw message, and the fault buttons.
pub(crate) fn route(req: &Request) -> Option<Response> {
    let path = req.target.path();
    let rest = path.strip_prefix("/demo/mail/")?;
    let demo = DEMO.get()?;
    if rest == "fault" {
        let fault = match wire::query_param(req, "kind").as_deref() {
            Some("refuse451") => Fault::Refuse(451),
            Some("drop") => Fault::Drop,
            Some("lose_reply") => Fault::LoseReply,
            _ => return Some(wire::bad("kind")),
        };
        demo.sink.set_fault(Some(fault));
        let mut r = Response::new(StatusCode::SEE_OTHER);
        let _ = r.headers.try_insert("location", "/demo");
        return Some(r);
    }
    if req.method != Method::GET {
        return Some(wire::not_found());
    }
    let n: usize = rest.parse().ok()?;
    let all = demo.sink.messages();
    let msg = all.get(n)?;
    let text = esc(&String::from_utf8_lossy(&msg.data));
    let html = format!(
        "<!doctype html>\n<html lang=\"en\"><head><meta charset=\"utf-8\"><title>Raw message {n}</title></head><body><main><h1>Raw message {n}</h1>\n<p>From {from} to {to}. An attached PDF is named, never shown here.</p>\n<pre id=\"raw-message\">{text}</pre></main></body></html>\n",
        from = esc(&msg.from),
        to = esc(&msg.to.join(", ")),
    );
    let mut r = Response::with_body(StatusCode::OK, "text/html; charset=utf-8", html.into_bytes());
    let _ = r.headers.try_insert("cache-control", "no-store");
    let _ = r.headers.try_insert("content-security-policy", "default-src 'none'; frame-ancestors 'none'");
    Some(r)
}
