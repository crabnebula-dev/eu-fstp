//! `fstp-devstack-relay <mail dir>`: the mail relay and the fake resolver
//! of the devstack (ADR-026 record of lane L20). Development only: it
//! never ships, and every value is synthetic.
//!
//! - The test SMTP sink of this crate on loopback, with implicit TLS from
//!   the `fstp-tls` test CA and the sink's synthetic credential. Rule A9
//!   keeps the sink in this crate, so the devstack runs it as this
//!   separate process.
//! - A fake DNS resolver on loopback (ADR-026 record of lane L18,
//!   "Loopback resolver"). It answers every TXT question over TCP with one
//!   record of the asked kind: DMARC under `_dmarc.`, DKIM under
//!   `._domainkey.`, SPF otherwise. So any sending domain passes the
//!   Domains and email step.
//! - Each accepted message is written byte for byte to
//!   `<mail dir>/<n>.eml`, so a developer can open the links it carries.
//!
//! It prints `relay <address>`, `resolver <address>`, `mail-dir <path>`,
//! `user <name>`, `password <secret>` and then `ready`, one per line. It
//! serves until its standard input closes, so it ends with the process
//! that started it.

#![allow(
    clippy::disallowed_macros,
    clippy::disallowed_methods,
    reason = "R-NF-02 print ban: test-only code that never ships, so it may print"
)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

use fstp_api_testkit::smtp_sink::{SinkConfig, SmtpSink};
use fstp_rt::tokio::TokioRuntime;

/// The DKIM record the resolver serves. The key is synthetic.
const DKIM: &str = "v=DKIM1; k=ed25519; p=c3ludGhldGljLWtleQ";

/// The one TXT record of `name` (module documentation).
fn record_of(name: &str) -> &'static str {
    if name.starts_with("_dmarc.") {
        "v=DMARC1; p=reject"
    } else if name.contains("._domainkey.") {
        DKIM
    } else {
        "v=spf1 -all"
    }
}

/// Answers one DNS question over TCP (RFC 7766) on `s`: the question
/// copied, and one TXT answer whose name points to the question's.
fn answer_one(s: &mut TcpStream) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut len = [0u8; 2];
    s.read_exact(&mut len)?;
    let mut q = vec![0u8; usize::from(u16::from_be_bytes(len))];
    s.read_exact(&mut q)?;
    let mut at = 12usize;
    let mut labels = Vec::new();
    while let Some(&n) = q.get(at) {
        at = at.saturating_add(1);
        if n == 0 {
            break;
        }
        let end = at.saturating_add(usize::from(n));
        labels.push(String::from_utf8_lossy(q.get(at..end).unwrap_or(&[])).to_lowercase());
        at = end;
    }
    let question = q.get(12..at.saturating_add(4)).unwrap_or(&[]).to_vec();
    let record = record_of(&labels.join("."));
    let Ok(n) = u8::try_from(record.len()) else {
        return Ok(());
    };
    let mut m = Vec::new();
    m.extend_from_slice(q.get(..2).unwrap_or(&[0, 0]));
    m.extend_from_slice(&0x8180u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&1u16.to_be_bytes());
    m.extend_from_slice(&[0, 0, 0, 0]);
    m.extend_from_slice(&question);
    m.extend_from_slice(&[0xc0, 0x0c, 0, 16, 0, 1, 0, 0, 0, 60]);
    m.extend_from_slice(&u16::from(n).saturating_add(1).to_be_bytes());
    m.push(n);
    m.extend_from_slice(record.as_bytes());
    let Ok(total) = u16::try_from(m.len()) else {
        return Ok(());
    };
    let mut out = total.to_be_bytes().to_vec();
    out.extend_from_slice(&m);
    s.write_all(&out)
}

/// Starts the fake resolver on a loopback port.
fn resolver() -> std::io::Result<SocketAddr> {
    let l = TcpListener::bind("127.0.0.1:0")?;
    let addr = l.local_addr()?;
    std::thread::spawn(move || {
        for mut s in l.incoming().flatten() {
            let _ = answer_one(&mut s);
        }
    });
    Ok(addr)
}

/// Writes each new message of `sink` to `dir`, until the process ends.
fn keep_mail(sink: fstp_api_testkit::smtp_sink::SinkHandle, dir: PathBuf) {
    std::thread::spawn(move || {
        let mut written = 0usize;
        loop {
            let all = sink.messages();
            for m in all.iter().skip(written) {
                // Written beside, then renamed, so a reader never sees half.
                let tmp = dir.join(format!(".{:04}.eml.tmp", m.seq));
                if std::fs::write(&tmp, &m.data).is_ok() {
                    let _ = std::fs::rename(&tmp, dir.join(format!("{:04}.eml", m.seq)));
                }
            }
            written = all.len();
            std::thread::sleep(Duration::from_millis(200));
        }
    });
}

fn run(dir: &Path) -> Result<(), String> {
    std::fs::create_dir_all(dir).map_err(|e| format!("the mail directory: {e}"))?;
    let rt = TokioRuntime::new_multi_thread(1).map_err(|e| format!("no runtime: {e}"))?;
    let cfg = SinkConfig::default();
    let sink = rt
        .block_on(SmtpSink::start(&rt, cfg.clone()))
        .map_err(|e| format!("the sink: {e}"))?;
    let dns = resolver().map_err(|e| format!("the resolver: {e}"))?;
    keep_mail(sink.handle().clone(), dir.to_owned());
    // Standard output is line buffered, so each line leaves at once.
    print!(
        "relay {}\nresolver {dns}\nmail-dir {}\nuser {}\npassword {}\nready\n",
        sink.addr(),
        dir.display(),
        cfg.username,
        cfg.password,
    );
    // Serve until standard input closes.
    let mut sink_stdin = Vec::new();
    let _ = std::io::stdin().read_to_end(&mut sink_stdin);
    drop(sink);
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let [dir] = args.as_slice() else {
        eprintln!("usage: fstp-devstack-relay <mail dir>");
        return ExitCode::from(2);
    };
    match run(Path::new(dir)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("fstp-devstack-relay: {e}");
            ExitCode::FAILURE
        }
    }
}
