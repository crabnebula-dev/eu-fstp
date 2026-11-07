//! R-LA-01, R-LA-02, R-LA-07 and I-10 through the real `fstp-assessor`
//! process: jobs and results on its queue socket, against a scripted
//! inference endpoint and a scripted retrieval proxy on 127.0.0.1.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing)]

mod common;

use std::io::{BufRead, BufReader, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr};
use std::os::fd::OwnedFd;
use std::os::unix::net::UnixStream;
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use fstp_http::{Request, Response, Server, ServerConfig, ServerHandle, StatusCode, handler_fn};
use fstp_infer::{Protocol, SyntheticModel};
use fstp_json::Value;
use fstp_retrieve::{Outcome, Refusal, Retrieved, SourceUrl, url_param};
use fstp_rt::tokio::TokioRuntime;

type Seen = Arc<Mutex<Vec<Vec<u8>>>>;

/// The scripted inference endpoint: answers as the synthetic model would
/// and keeps each request body. It insists on the bearer credential.
async fn inference(rt: &TokioRuntime, seen: &Seen) -> ServerHandle<TokioRuntime> {
    let seen = seen.clone();
    let h = handler_fn(move |req: Request| {
        let seen = seen.clone();
        async move {
            let ok = req.path() == "/v1/chat/completions"
                && req.headers.get("authorization").map(|v| v.as_bytes())
                    == Some(b"Bearer synthetic-key".as_slice());
            if !ok {
                return Response::new(StatusCode::UNAUTHORIZED);
            }
            seen.lock().unwrap().push(req.body.clone());
            match SyntheticModel.answer(&req.body) {
                Ok(b) => Response::with_body(StatusCode::OK, "application/json", b),
                Err(_) => Response::new(StatusCode::BAD_REQUEST),
            }
        }
    });
    Server::new(rt.clone(), ServerConfig::default(), h)
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap()
}

/// The scripted retrieval proxy: `GET /v1/retrieve?url=` with a fixed
/// README for `repo.test` and a refusal for anything else.
async fn retrieval(rt: &TokioRuntime, seen: &Seen) -> ServerHandle<TokioRuntime> {
    let seen = seen.clone();
    let h = handler_fn(move |req: Request| {
        let url = req.query().and_then(url_param).unwrap_or_default();
        seen.lock().unwrap().push(url.clone().into_bytes());
        async move {
            let outcome = match SourceUrl::parse(&url) {
                Ok(u) if u.host() == "repo.test" => Outcome::Retrieved(Retrieved {
                    chain: vec![u],
                    text: fstp_findings::UntrustedText::new(
                        "Tool README. Maintained by Acme since 2019.".to_owned(),
                    ),
                    truncated: false,
                }),
                _ => Outcome::Refused(Refusal::HostNotAllowed),
            };
            Response::with_body(
                StatusCode::OK,
                "application/json",
                fstp_json::to_compact(&outcome.to_json()).into_bytes(),
            )
        }
    });
    Server::new(rt.clone(), ServerConfig::default(), h)
        .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .unwrap()
}

/// Runs the binary on `input` and returns its result lines. The queue is
/// one Unix socket passed as the child's stdin, as the cell spawns it.
fn run(args: &[String], input: &[u8]) -> Vec<Value> {
    let (ours, theirs) = UnixStream::pair().unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_fstp-assessor"))
        .args(args)
        .env("FSTP_ASSESSOR_KEY", "synthetic-key")
        .stdin(Stdio::from(OwnedFd::from(theirs)))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut writer = ours.try_clone().unwrap();
    let input = input.to_vec();
    let feed = std::thread::spawn(move || {
        writer.write_all(&input).unwrap();
        writer.shutdown(Shutdown::Write).unwrap();
    });
    let lines: Vec<Value> = BufReader::new(ours)
        .lines()
        .map(|l| fstp_json::parse(l.unwrap().as_bytes()).unwrap())
        .collect();
    feed.join().unwrap();
    assert!(child.wait().unwrap().success());
    lines
}

fn s<'a>(v: &'a Value, k: &str) -> &'a str {
    v.get(k).and_then(Value::as_str).unwrap_or("")
}

/// R-LA-01, R-LA-02, R-LA-07: one job runs end to end through the
/// process and yields exactly one result line. The line carries findings
/// with evidence pointers, the raw replies for the sealed trace and the
/// retrieval log with each source's class (TH-12).
#[test]
fn r_la_01_job_runs_end_to_end_and_yields_one_result_line() {
    let rt = TokioRuntime::new_multi_thread(2).unwrap();
    let infer_seen: Seen = Arc::default();
    let retr_seen: Seen = Arc::default();
    let (inf, ret) = rt.block_on(async {
        (
            inference(&rt, &infer_seen).await,
            retrieval(&rt, &retr_seen).await,
        )
    });
    let args = vec![
        "--inference".to_owned(),
        format!(
            "chat:http://127.0.0.1:{}/v1/chat/completions",
            inf.local_addr().port()
        ),
        "--retrieval".to_owned(),
        format!("http://127.0.0.1:{}", ret.local_addr().port()),
    ];
    let mut job = common::job(Protocol::ChatCompletions, common::NARRATIVE);
    job.sources.push(fstp_assessor::SourceLine {
        url: SourceUrl::parse("https://blocked.test/x").unwrap(),
        text: fstp_domain::id::TextId::from_raw(102),
    });
    let mut input = job.to_line();
    input.push(b'\n');
    let lines = run(&args, &input);
    assert_eq!(lines.len(), 1, "one job, one result line");
    let r = &lines[0];
    assert_eq!(s(r, "job"), "4242");
    assert_eq!(s(r, "status"), "done");
    let findings = r.get("findings").unwrap().as_array().unwrap();
    assert!(!findings.is_empty());
    for f in findings.iter() {
        assert!(!f.get("evidence").unwrap().as_array().unwrap().is_empty());
        assert!(f.get("score").is_none() && f.get("decision").is_none());
    }
    let replies = r.get("replies").unwrap().as_array().unwrap();
    // Completeness, two criteria, claims, verify and integrity.
    assert_eq!(replies.len(), 6);
    assert_eq!(infer_seen.lock().unwrap().len(), 6);
    let log = r.get("retrievals").unwrap().as_array().unwrap();
    assert_eq!(log.len(), 3);
    assert_eq!(s(&log[0], "class"), "applicant_controlled");
    assert_eq!(s(&log[1], "refusal"), "host_not_allowed");
    assert_eq!(s(&log[2], "refusal"), "host_not_allowed");
    assert_eq!(retr_seen.lock().unwrap().len(), 3);
    // The retrieved README reached stage 6 as data, under its class.
    let verify = infer_seen
        .lock()
        .unwrap()
        .iter()
        .map(|b| common::data_of(b))
        .find(|d| d.contains("Tool README"))
        .unwrap();
    assert!(verify.contains("source_applicant"));
    rt.block_on(async {
        let _ = inf.shutdown(Duration::from_secs(1)).await;
        let _ = ret.shutdown(Duration::from_secs(1)).await;
    });
}

/// I-10, TH-26: a malformed or oversized line yields a refusal line and
/// the process goes on with the next job. A provider failure leaves the
/// job pending (R-NF-10). Nothing but result lines reaches stdout.
#[test]
fn i10_queue_refuses_bad_lines_and_keeps_serving() {
    let job = common::job(Protocol::Anthropic, common::NARRATIVE);
    let mut input = b"{\"job\":\"1\",\"score\":9}\n".to_vec();
    input.extend(vec![b'x'; fstp_assessor::MAX_LINE_BYTES + 1]);
    input.push(b'\n');
    input.extend(job.to_line());
    input.push(b'\n');
    let lines = run(&["--inference".to_owned(), "synthetic".to_owned()], &input);
    assert_eq!(lines.len(), 3);
    assert_eq!(s(&lines[0], "status"), "refused");
    assert_eq!(s(&lines[1], "status"), "refused");
    assert_eq!(s(&lines[1], "error"), "line_too_long");
    assert_eq!(s(&lines[2], "status"), "done");
    assert_eq!(s(&lines[2], "job"), "4242");
    // No retrieval proxy configured: every source is refused as
    // unavailable, and the job still completes.
    let log = lines[2].get("retrievals").unwrap().as_array().unwrap();
    assert!(
        log.iter()
            .all(|e| s(e, "refusal") == "retrieval_unavailable")
    );

    // An unreachable endpoint leaves the job pending.
    let lines = run(
        &[
            "--inference".to_owned(),
            "anthropic:http://127.0.0.1:9/v1/messages".to_owned(),
        ],
        &{
            let mut l = job.to_line();
            l.push(b'\n');
            l
        },
    );
    assert_eq!(lines.len(), 1);
    assert_eq!(s(&lines[0], "status"), "pending");
    assert_eq!(s(&lines[0], "error"), "infer");
}
