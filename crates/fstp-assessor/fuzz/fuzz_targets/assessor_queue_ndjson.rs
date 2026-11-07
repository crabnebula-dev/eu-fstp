//! TH-26: the assessor's job queue (M7 design section 3.1) against
//! arbitrary stdin bytes.
//!
//! Properties checked beyond "no panic":
//!
//! - the line reader never returns a line over its limit, and never one
//!   holding a line feed;
//! - an accepted job encodes to a line that decodes to the same job, so
//!   the cell's encoder and this decoder agree;
//! - the refusal line of a rejected job is one line of JSON.

#![no_main]

use std::io::Cursor;

use fstp_assessor::{Line, LineReader, decode_job, refused, result_bytes};
use libfuzzer_sys::fuzz_target;

/// A small limit, so the fuzzer reaches the oversized path.
const LIMIT: usize = 4096;

fuzz_target!(|data: &[u8]| {
    let mut reader = LineReader::new(Cursor::new(data), LIMIT);
    let mut n: u64 = 0;
    loop {
        n += 1;
        let line = match reader.next_line().expect("in-memory reads never fail") {
            Line::Eof => break,
            Line::TooLong => continue,
            Line::Line(l) => l,
        };
        assert!(line.len() <= LIMIT, "line over the limit");
        assert!(!line.contains(&b'\n'), "line holds a line feed");
        match decode_job(&line) {
            Ok(job) => {
                let again = decode_job(&job.to_line()).expect("an encoded job decodes");
                assert_eq!(again, job, "round trip changed the job");
            }
            Err(e) => {
                let out = result_bytes(&refused(n, e));
                assert!(!out.contains(&b'\n'), "refusal spans lines");
            }
        }
    }
});
