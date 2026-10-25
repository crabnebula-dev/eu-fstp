//! Behaviour of the scripted transport and the bounded poll helper.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll, Waker};

use fstp_rt::future::{block_on, poll_bounded};
use fstp_rt::scripted::{FUZZ_CONTROL_LEN, MAX_RECORDED_WRITES, ScriptedStream};
use fstp_rt::{AsyncRead, AsyncWrite, IoExt};

#[test]
fn replays_script_in_chunks_then_eof() {
    let script: Vec<u8> = (0u8..=200).collect();
    let mut s = ScriptedStream::new(script.clone()).with_read_chunk(7);
    let mut out = Vec::new();
    block_on(async {
        let mut buf = [0u8; 64];
        loop {
            let n = s.read(&mut buf).await.unwrap();
            assert!(n <= 7);
            if n == 0 {
                break;
            }
            out.extend_from_slice(&buf[..n]);
        }
    });
    assert_eq!(out, script);
    assert_eq!(s.remaining(), 0);
}

#[test]
fn records_writes_with_chunk_limit_and_cap() {
    let mut s = ScriptedStream::new(Vec::new()).with_write_chunk(5);
    block_on(async {
        assert_eq!(s.write(b"abcdefgh").await.unwrap(), 5);
        s.write_all(b"ijklmnop").await.unwrap();
        s.flush().await.unwrap();
        s.shutdown().await.unwrap();
        let err = s.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
    });
    assert_eq!(s.written(), b"abcdeijklmnop");
    assert_eq!(s.written_total(), 13);
    assert!(s.is_shut_down());

    let mut big = ScriptedStream::new(Vec::new());
    let chunk = vec![1u8; 300_000];
    block_on(async {
        for _ in 0..5 {
            big.write_all(&chunk).await.unwrap();
        }
    });
    assert_eq!(big.written().len(), MAX_RECORDED_WRITES);
    assert_eq!(big.written_total(), 1_500_000);
}

#[test]
fn pending_pattern_never_repeats_and_self_wakes() {
    let mut s = ScriptedStream::new(vec![9u8; 100]).with_pending_pattern(0xFF);
    let flag = std::sync::Arc::new(Flag(std::sync::atomic::AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut buf = [0u8; 10];
    let mut pendings = 0;
    let mut reads = 0;
    let mut last_pending = false;
    while reads < 10 {
        match Pin::new(&mut s).poll_read(&mut cx, &mut buf) {
            Poll::Pending => {
                assert!(!last_pending, "two Pending results in a row");
                assert!(flag.0.swap(false, std::sync::atomic::Ordering::SeqCst));
                last_pending = true;
                pendings += 1;
            }
            Poll::Ready(r) => {
                r.unwrap();
                last_pending = false;
                reads += 1;
            }
        }
    }
    assert_eq!(pendings, 10);
}

struct Flag(std::sync::atomic::AtomicBool);

impl std::task::Wake for Flag {
    fn wake(self: std::sync::Arc<Self>) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

#[test]
fn fuzz_input_decoding() {
    // Short inputs are accepted.
    for len in 0..FUZZ_CONTROL_LEN {
        let s = ScriptedStream::from_fuzz_input(&vec![0u8; len]);
        assert_eq!(s.remaining(), 0);
    }
    // Control byte 0 limits reads to one byte; 255 means unlimited.
    let mut s = ScriptedStream::from_fuzz_input(&[0, 0, 0, 1, 2, 3]);
    let mut buf = [0u8; 8];
    assert_eq!(block_on(s.read(&mut buf)).unwrap(), 1);
    let mut s = ScriptedStream::from_fuzz_input(&[255, 0, 255, 1, 2, 3]);
    assert_eq!(block_on(s.read(&mut buf)).unwrap(), 3);
    assert_eq!(block_on(s.write(&[0u8; 1000])).unwrap(), 1000);
}

#[test]
fn poll_bounded_detects_non_termination() {
    assert_eq!(poll_bounded(async { 5 }, 1), Some(5));
    assert_eq!(poll_bounded(std::future::pending::<()>(), 1000), None);
    // A future that needs a few polls completes within budget.
    let mut s = ScriptedStream::new(vec![1, 2, 3]).with_pending_pattern(0b0101_0101);
    let fut = async move {
        let mut out = Vec::new();
        s.read_to_end(&mut out, 10).await.unwrap();
        out
    };
    assert_eq!(poll_bounded(fut, 100), Some(vec![1, 2, 3]));
    assert_eq!(poll_bounded(Never, 0), None);
}

struct Never;

impl Future for Never {
    type Output = ();

    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        Poll::Pending
    }
}

#[test]
fn empty_buffers_are_noops() {
    let mut s = ScriptedStream::new(vec![1]).with_pending_pattern(0xFF);
    let mut cx = Context::from_waker(Waker::noop());
    assert!(matches!(
        Pin::new(&mut s).poll_read(&mut cx, &mut []),
        Poll::Ready(Ok(0))
    ));
    assert!(matches!(
        Pin::new(&mut s).poll_write(&mut cx, &[]),
        Poll::Ready(Ok(0))
    ));
}
