//! Semantics of the in-memory duplex transport and the `IoExt` helpers.
//!
//! The interleaving tests run reader and writer tasks under a deterministic
//! scheduler that picks the next ready task with a seeded PRNG. A task that
//! returns `Pending` without arranging a wake-up leaves no ready task while
//! work remains, which the scheduler reports as a lost wake-up.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::cell::RefCell;
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};

use fstp_rt::duplex::{DuplexStream, duplex};
use fstp_rt::future::block_on;
use fstp_rt::{AsyncRead, AsyncWrite, IoExt};

/// Deterministic xorshift generator. Not cryptographic.
#[derive(Clone)]
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }

    fn range(&mut self, lo: usize, hi: usize) -> usize {
        lo + self.below(hi - lo + 1)
    }
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    (0..len).map(|_| rng.next() as u8).collect()
}

struct Flag(AtomicBool);

impl Wake for Flag {
    fn wake(self: Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.store(true, Ordering::SeqCst);
    }
}

type Task = Pin<Box<dyn Future<Output = ()>>>;

/// Runs tasks to completion, choosing among ready tasks with `rng`.
///
/// Panics on a lost wake-up or when the step budget runs out.
fn run_interleaved(mut tasks: Vec<Task>, rng: &mut Rng, max_steps: usize) {
    let flags: Vec<Arc<Flag>> = tasks
        .iter()
        .map(|_| Arc::new(Flag(AtomicBool::new(true))))
        .collect();
    let wakers: Vec<Waker> = flags.iter().map(|f| Waker::from(f.clone())).collect();
    let mut done = vec![false; tasks.len()];
    for _ in 0..max_steps {
        let ready: Vec<usize> = (0..tasks.len())
            .filter(|&i| !done[i] && flags[i].0.load(Ordering::SeqCst))
            .collect();
        if ready.is_empty() {
            assert!(
                done.iter().all(|d| *d),
                "lost wake-up: tasks pending with no wake-up scheduled"
            );
            return;
        }
        let i = ready[rng.below(ready.len())];
        flags[i].0.store(false, Ordering::SeqCst);
        let mut cx = Context::from_waker(&wakers[i]);
        if tasks[i].as_mut().poll(&mut cx).is_ready() {
            done[i] = true;
        }
    }
    panic!("step budget exhausted");
}

/// Writes `data` in random chunk sizes, then shuts down the write direction.
async fn write_chunked(mut io: DuplexStream, data: Rc<Vec<u8>>, mut rng: Rng) -> DuplexStream {
    let mut pos = 0;
    while pos < data.len() {
        let n = rng.range(1, 97).min(data.len() - pos);
        let accepted = io.write(&data[pos..pos + n]).await.unwrap();
        assert!(accepted >= 1 && accepted <= n);
        pos += accepted;
    }
    io.shutdown().await.unwrap();
    io
}

/// Reads until end of stream with random buffer sizes.
async fn read_chunked(
    mut io: DuplexStream,
    out: Rc<RefCell<Vec<u8>>>,
    mut rng: Rng,
) -> DuplexStream {
    let mut buf = [0u8; 128];
    loop {
        let n = rng.range(1, buf.len());
        let got = io.read(&mut buf[..n]).await.unwrap();
        if got == 0 {
            break;
        }
        assert!(got <= n);
        out.borrow_mut().extend_from_slice(&buf[..got]);
    }
    io
}

#[test]
fn bidirectional_transfer_under_many_interleavings() {
    for seed in 0..400u64 {
        let mut rng = Rng::new(seed);
        let capacity = rng.range(1, 64);
        let len_ab = rng.range(0, 2000);
        let len_ba = rng.range(0, 2000);
        let (a, b) = duplex(capacity);
        let data_ab = Rc::new(pattern(len_ab, seed ^ 0xAB));
        let data_ba = Rc::new(pattern(len_ba, seed ^ 0xBA));
        let got_ab = Rc::new(RefCell::new(Vec::new()));
        let got_ba = Rc::new(RefCell::new(Vec::new()));

        // Each stream end is shared between a reader task and a writer task.
        // Splitting is done with a small shared cell to keep the test simple.
        let a = Rc::new(RefCell::new(Some(a)));
        let b = Rc::new(RefCell::new(Some(b)));

        let tasks: Vec<Task> = vec![
            Box::pin(split_write(a.clone(), data_ab.clone(), Rng::new(seed + 1))),
            Box::pin(split_read(b.clone(), got_ab.clone(), Rng::new(seed + 2))),
            Box::pin(split_write(b.clone(), data_ba.clone(), Rng::new(seed + 3))),
            Box::pin(split_read(a.clone(), got_ba.clone(), Rng::new(seed + 4))),
        ];
        run_interleaved(tasks, &mut rng, 1_000_000);
        assert_eq!(*got_ab.borrow(), *data_ab, "seed {seed} a->b");
        assert_eq!(*got_ba.borrow(), *data_ba, "seed {seed} b->a");
    }
}

/// Polls `f` with exclusive access to the shared stream for one poll at a
/// time. This models two tasks sharing one connection, as a split would.
fn with_stream<T>(
    cell: &Rc<RefCell<Option<DuplexStream>>>,
    f: impl FnOnce(Pin<&mut DuplexStream>) -> T,
) -> T {
    let mut guard = cell.borrow_mut();
    let io = guard.as_mut().unwrap();
    f(Pin::new(io))
}

async fn split_write(cell: Rc<RefCell<Option<DuplexStream>>>, data: Rc<Vec<u8>>, mut rng: Rng) {
    let mut pos = 0;
    while pos < data.len() {
        let n = rng.range(1, 97).min(data.len() - pos);
        let chunk = &data[pos..pos + n];
        let accepted = std::future::poll_fn(|cx| with_stream(&cell, |io| io.poll_write(cx, chunk)))
            .await
            .unwrap();
        assert!(accepted >= 1 && accepted <= n);
        pos += accepted;
    }
    std::future::poll_fn(|cx| with_stream(&cell, |io| io.poll_shutdown(cx)))
        .await
        .unwrap();
}

async fn split_read(
    cell: Rc<RefCell<Option<DuplexStream>>>,
    out: Rc<RefCell<Vec<u8>>>,
    mut rng: Rng,
) {
    let mut buf = [0u8; 128];
    loop {
        let n = rng.range(1, buf.len());
        let dst = &mut buf[..n];
        let got = std::future::poll_fn(|cx| with_stream(&cell, |io| io.poll_read(cx, dst)))
            .await
            .unwrap();
        if got == 0 {
            break;
        }
        out.borrow_mut().extend_from_slice(&buf[..got]);
    }
}

#[test]
fn one_way_transfer_with_owned_streams_under_interleavings() {
    for seed in 0..300u64 {
        let mut rng = Rng::new(seed.wrapping_add(10_000));
        let capacity = rng.range(1, 32);
        let len = rng.range(0, 3000);
        let (a, b) = duplex(capacity);
        let data = Rc::new(pattern(len, seed));
        let got = Rc::new(RefCell::new(Vec::new()));
        let tasks: Vec<Task> = vec![
            Box::pin({
                let data = data.clone();
                let r = Rng::new(seed + 7);
                async move {
                    drop(write_chunked(a, data, r).await);
                }
            }),
            Box::pin({
                let got = got.clone();
                let r = Rng::new(seed + 8);
                async move {
                    drop(read_chunked(b, got, r).await);
                }
            }),
        ];
        run_interleaved(tasks, &mut rng, 1_000_000);
        assert_eq!(*got.borrow(), *data, "seed {seed}");
    }
}

#[test]
fn writer_blocks_at_capacity_and_wakes_when_reader_frees_space() {
    let (mut a, mut b) = duplex(8);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut a).poll_write(&mut cx, &[1u8; 20]);
    assert!(
        matches!(first, Poll::Ready(Ok(8))),
        "accepts only the capacity"
    );
    assert!(Pin::new(&mut a).poll_write(&mut cx, &[2u8; 1]).is_pending());
    assert!(!flag.0.load(Ordering::SeqCst));

    let mut buf = [0u8; 3];
    assert!(matches!(
        Pin::new(&mut b).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(3))
    ));
    assert!(
        flag.0.load(Ordering::SeqCst),
        "reader woke the blocked writer"
    );
    assert_eq!(b.readable_len(), 5);
    assert!(matches!(
        Pin::new(&mut a).poll_write(&mut cx, &[2u8; 10]),
        Poll::Ready(Ok(3))
    ));
}

#[test]
fn reader_blocks_when_empty_and_wakes_on_write() {
    let (mut a, mut b) = duplex(16);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut buf = [0u8; 4];
    assert!(Pin::new(&mut b).poll_read(&mut cx, &mut buf).is_pending());
    assert!(matches!(
        Pin::new(&mut a).poll_write(&mut cx, b"xy"),
        Poll::Ready(Ok(2))
    ));
    assert!(flag.0.load(Ordering::SeqCst));
    assert!(matches!(
        Pin::new(&mut b).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(2))
    ));
    assert_eq!(&buf[..2], b"xy");
}

#[test]
fn shutdown_delivers_buffered_bytes_then_eof() {
    block_on(async {
        let (mut a, mut b) = duplex(64);
        a.write_all(b"hello").await.unwrap();
        a.shutdown().await.unwrap();
        let mut out = Vec::new();
        b.read_to_end(&mut out, 1024).await.unwrap();
        assert_eq!(out, b"hello");
        // EOF is sticky.
        let mut buf = [0u8; 4];
        assert_eq!(b.read(&mut buf).await.unwrap(), 0);
        // Writing after shutdown fails.
        let err = a.write(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        // The other direction still works after a half-close.
        b.write_all(b"reply").await.unwrap();
        let mut reply = [0u8; 5];
        a.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"reply");
    });
}

#[test]
fn shutdown_wakes_a_blocked_reader() {
    let (mut a, mut b) = duplex(4);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    let mut buf = [0u8; 4];
    assert!(Pin::new(&mut b).poll_read(&mut cx, &mut buf).is_pending());
    assert!(Pin::new(&mut a).poll_shutdown(&mut cx).is_ready());
    assert!(flag.0.load(Ordering::SeqCst));
    assert!(matches!(
        Pin::new(&mut b).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(0))
    ));
}

#[test]
fn dropping_one_end_gives_eof_and_broken_pipe() {
    block_on(async {
        let (mut a, b) = duplex(8);
        let (mut c, mut d) = duplex(8);
        c.write_all(b"buffered").await.unwrap();
        drop(c);
        // Buffered bytes stay readable, then EOF.
        let mut out = Vec::new();
        d.read_to_end(&mut out, 100).await.unwrap();
        assert_eq!(out, b"buffered");
        // Writing to a dropped peer fails.
        drop(b);
        let err = a.write_all(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::BrokenPipe);
        let mut buf = [0u8; 1];
        assert_eq!(a.read(&mut buf).await.unwrap(), 0);
    });
}

#[test]
fn dropping_reader_wakes_blocked_writer_with_error() {
    let (mut a, b) = duplex(2);
    let flag = Arc::new(Flag(AtomicBool::new(false)));
    let waker = Waker::from(flag.clone());
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(
        Pin::new(&mut a).poll_write(&mut cx, b"abc"),
        Poll::Ready(Ok(2))
    ));
    assert!(Pin::new(&mut a).poll_write(&mut cx, b"c").is_pending());
    drop(b);
    assert!(flag.0.load(Ordering::SeqCst));
    match Pin::new(&mut a).poll_write(&mut cx, b"c") {
        Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
        other => panic!("unexpected {other:?}"),
    }
}

#[test]
fn zero_capacity_is_raised_to_one_and_empty_buffers_are_noops() {
    block_on(async {
        let (mut a, mut b) = duplex(0);
        assert_eq!(a.write(b"").await.unwrap(), 0);
        assert_eq!(a.write(b"ab").await.unwrap(), 1);
        let mut empty = [0u8; 0];
        assert_eq!(b.read(&mut empty).await.unwrap(), 0);
        let mut one = [0u8; 1];
        assert_eq!(b.read(&mut one).await.unwrap(), 1);
        assert_eq!(one[0], b'a');
        a.flush().await.unwrap();
    });
}

#[test]
fn read_exact_reports_unexpected_eof() {
    block_on(async {
        let (mut a, mut b) = duplex(16);
        a.write_all(b"abc").await.unwrap();
        a.shutdown().await.unwrap();
        let mut buf = [0u8; 4];
        let err = b.read_exact(&mut buf).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    });
}

#[test]
fn read_to_end_enforces_its_limit() {
    block_on(async {
        // Exactly at the limit succeeds.
        let (mut a, mut b) = duplex(64);
        a.write_all(&[7u8; 10]).await.unwrap();
        a.shutdown().await.unwrap();
        let mut out = Vec::new();
        assert_eq!(b.read_to_end(&mut out, 10).await.unwrap(), 10);
        assert_eq!(out.len(), 10);

        // One byte over fails and keeps exactly `limit` bytes.
        let (mut a, mut b) = duplex(64);
        a.write_all(&[7u8; 11]).await.unwrap();
        a.shutdown().await.unwrap();
        let mut out = Vec::new();
        let err = b.read_to_end(&mut out, 10).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
        assert_eq!(out.len(), 10);

        // A zero limit accepts only an empty stream.
        let (mut a, mut b) = duplex(64);
        a.shutdown().await.unwrap();
        let mut out = Vec::new();
        assert_eq!(b.read_to_end(&mut out, 0).await.unwrap(), 0);
    });
}

/// A sink that accepts nothing, to exercise `write_all`'s zero-write path.
struct Closed;

impl AsyncRead for Closed {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }
}

impl AsyncWrite for Closed {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(0))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn write_all_reports_write_zero_and_helpers_work_through_box_and_refs() {
    block_on(async {
        let mut sink = Closed;
        let err = sink.write_all(b"x").await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WriteZero);
        sink.write_all(b"").await.unwrap();

        let (a, b) = duplex(16);
        let mut boxed: Box<DuplexStream> = Box::new(a);
        boxed.write_all(b"via box").await.unwrap();
        let mut b = b;
        let by_ref = &mut b;
        let mut buf = [0u8; 7];
        by_ref.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"via box");
        let mut pinned = Box::pin(Closed);
        assert_eq!(pinned.write(b"abc").await.unwrap(), 0);
    });
}
