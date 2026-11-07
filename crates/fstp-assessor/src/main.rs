//! `fstp-assessor`: the assessor child process (M7 design section 3.1).
//!
//! ```text
//! fstp-assessor --inference synthetic|replay:<dir>|anthropic:<url>|chat:<url>
//!               [--inference-ca <pem file>] [--retrieval <http url>]
//! ```
//!
//! The queue is one Unix stream socket, passed as the child's stdin:
//! jobs come in on it and result lines go back on it. Standard output is
//! not used, because R-NF-02 keeps it for `fstp_obs` metrics in shipped
//! crates. The cell spawns the child with one end of
//! `std::os::unix::net::UnixStream::pair()` as stdin.
//!
//! The credential of an HTTP endpoint comes from `FSTP_ASSESSOR_KEY`.
//! The process writes nothing to standard error. A failure shows only in
//! its exit status: 2 for usage, 3 for the runtime, 4 for an endpoint and
//! 5 for the queue.

use std::io::Write;
use std::os::fd::AsFd;
use std::process::ExitCode;

use fstp_assessor::{
    Assessor, Inference, InferenceMode, Line, LineReader, MAX_LINE_BYTES, ProxyClient, QueueError,
    refused, result_bytes,
};
use fstp_rt::tokio::TokioRuntime;

struct Args {
    inference: InferenceMode,
    anchors: Option<String>,
    retrieval: Option<String>,
}

fn args() -> Option<Args> {
    let mut inference = None;
    let mut anchors = None;
    let mut retrieval = None;
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next()?;
        match flag.as_str() {
            "--inference" => inference = Some(InferenceMode::parse(&value)?),
            "--inference-ca" => anchors = Some(value),
            "--retrieval" => retrieval = Some(value),
            _ => return None,
        }
    }
    Some(Args {
        inference: inference?,
        anchors,
        retrieval,
    })
}

fn main() -> ExitCode {
    let Some(args) = args() else {
        return ExitCode::from(2);
    };
    let Ok(rt) = TokioRuntime::new_current_thread() else {
        return ExitCode::from(3);
    };
    let anchors = match &args.anchors {
        Some(path) => match std::fs::read(path) {
            Ok(pem) => Some(pem),
            Err(_) => return ExitCode::from(4),
        },
        None => None,
    };
    let key = std::env::var_os("FSTP_ASSESSOR_KEY").map(|k| k.into_encoded_bytes());
    let Ok(inference) = Inference::new(rt.clone(), &args.inference, key, anchors.as_deref()) else {
        return ExitCode::from(4);
    };
    let retrieval = match &args.retrieval {
        Some(base) => match ProxyClient::new(rt.clone(), base) {
            Ok(c) => Some(c),
            Err(_) => return ExitCode::from(4),
        },
        None => None,
    };
    let assessor = Assessor {
        inference,
        retrieval,
        protocol: args.inference.protocol(),
    };
    let stdin = std::io::stdin();
    // The queue socket, written through its own descriptor.
    let Ok(fd) = stdin.as_fd().try_clone_to_owned() else {
        return ExitCode::from(5);
    };
    let mut out = std::fs::File::from(fd);
    let mut reader = LineReader::new(stdin.lock(), MAX_LINE_BYTES);
    let mut n: u64 = 0;
    loop {
        n = n.saturating_add(1);
        let result = match reader.next_line() {
            Ok(Line::Eof) => return ExitCode::SUCCESS,
            Ok(Line::TooLong) => refused(n, QueueError::TooLong),
            Ok(Line::Line(bytes)) => rt.block_on(assessor.handle_line(n, &bytes)),
            Err(_) => return ExitCode::from(5),
        };
        let mut bytes = result_bytes(&result);
        bytes.push(b'\n');
        if out.write_all(&bytes).and_then(|()| out.flush()).is_err() {
            return ExitCode::from(5);
        }
    }
}
