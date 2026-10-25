//! Tests of the tokio implementation of the runtime trait.
//!
//! They cover a loopback echo server, concurrent connections, timeouts,
//! abort, panic reporting, blocking tasks, name resolution and graceful
//! shutdown with a drain deadline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use fstp_rt::future::{Either, race};
use fstp_rt::tokio::TokioRuntime;
use fstp_rt::{
    Connection, IoExt, JoinHandle, Listener, Runtime, Shutdown, ShutdownSignal, timeout,
};

fn loopback() -> SocketAddr {
    SocketAddr::from((Ipv4Addr::LOCALHOST, 0))
}

fn rt() -> TokioRuntime {
    TokioRuntime::new_multi_thread(4).unwrap()
}

/// Echoes until the peer shuts down its write direction.
async fn echo<C: Connection>(mut conn: C) -> io::Result<u64> {
    let mut buf = [0u8; 4096];
    let mut total = 0u64;
    loop {
        let n = conn.read(&mut buf).await?;
        if n == 0 {
            conn.shutdown().await?;
            return Ok(total);
        }
        conn.write_all(&buf[..n]).await?;
        total += n as u64;
    }
}

/// Accepts connections until shutdown, spawning one echo task per connection.
async fn echo_server<R: Runtime>(
    rt: R,
    mut listener: R::TcpListener,
    signal: ShutdownSignal,
    accepted: Arc<AtomicUsize>,
) {
    while let Some(res) = signal.run_until(listener.accept()).await {
        let Ok((conn, _peer)) = res else { continue };
        accepted.fetch_add(1, Ordering::SeqCst);
        let conn_signal = signal.clone();
        drop(rt.spawn(async move {
            let _participant = conn_signal;
            let _ = echo(conn).await;
        }));
    }
}

fn pattern(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Sends `data` and reads the echo back concurrently, then checks it.
async fn roundtrip<R: Runtime>(rt: &R, addr: SocketAddr, data: Vec<u8>) -> io::Result<()> {
    let conn = rt.connect_tcp(addr).await?;
    // The write half runs in its own task so that a large payload cannot
    // deadlock against the echo, which writes while we still send.
    let (mut reader, writer) = split(conn);
    let expected = data.clone();
    let send: JoinHandle<io::Result<()>> = rt.spawn(async move {
        let mut writer = writer;
        for chunk in data.chunks(1000) {
            writer.write_all(chunk).await?;
        }
        writer.shutdown().await
    });
    let mut got = Vec::new();
    reader.read_to_end(&mut got, expected.len() + 1).await?;
    send.await.map_err(io::Error::from)??;
    assert_eq!(got, expected);
    Ok(())
}

/// A minimal split for tests: both halves share the stream behind a mutex.
fn split<C: Connection>(conn: C) -> (Half<C>, Half<C>) {
    let shared = Arc::new(std::sync::Mutex::new(conn));
    (Half(shared.clone()), Half(shared))
}

struct Half<C>(Arc<std::sync::Mutex<C>>);

impl<C: Connection> fstp_rt::AsyncRead for Half<C> {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut guard = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *guard).poll_read(cx, buf)
    }
}

impl<C: Connection> fstp_rt::AsyncWrite for Half<C> {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        let mut guard = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *guard).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut guard = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *guard).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        let mut guard = self.0.lock().unwrap();
        std::pin::Pin::new(&mut *guard).poll_shutdown(cx)
    }
}

#[test]
fn echo_server_over_loopback() {
    let rt = rt();
    let shutdown = Shutdown::new();
    let accepted = Arc::new(AtomicUsize::new(0));
    rt.block_on(async {
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        assert_ne!(addr.port(), 0);
        let server = rt.spawn(echo_server(
            rt.clone(),
            listener,
            shutdown.signal(),
            accepted.clone(),
        ));

        let mut conn = rt.connect_tcp(addr).await.unwrap();
        assert_eq!(conn.peer_addr().unwrap(), addr);
        conn.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping");
        conn.shutdown().await.unwrap();
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest, 16).await.unwrap();
        assert!(rest.is_empty());

        roundtrip(&rt, addr, pattern(300_000, 1)).await.unwrap();

        shutdown
            .shutdown(&rt, Duration::from_secs(5))
            .await
            .unwrap();
        server.await.unwrap();
    });
    assert_eq!(accepted.load(Ordering::SeqCst), 2);
}

#[test]
fn concurrent_connections() {
    let rt = rt();
    let shutdown = Shutdown::new();
    let accepted = Arc::new(AtomicUsize::new(0));
    rt.block_on(async {
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = rt.spawn(echo_server(
            rt.clone(),
            listener,
            shutdown.signal(),
            accepted.clone(),
        ));
        let clients: Vec<JoinHandle<io::Result<()>>> = (0..64u64)
            .map(|i| {
                let rt2 = rt.clone();
                rt.spawn(async move {
                    let len = 1 + (i as usize * 7919) % 50_000;
                    roundtrip(&rt2, addr, pattern(len, i)).await
                })
            })
            .collect();
        for c in clients {
            c.await.unwrap().unwrap();
        }
        shutdown
            .shutdown(&rt, Duration::from_secs(5))
            .await
            .unwrap();
        server.await.unwrap();
    });
    assert_eq!(accepted.load(Ordering::SeqCst), 64);
}

#[test]
fn timeout_elapses_and_passes() {
    let rt = rt();
    rt.block_on(async {
        let start = Instant::now();
        let never = std::future::pending::<()>();
        let res = timeout(&rt, Duration::from_millis(50), never).await;
        assert!(res.is_err());
        assert!(start.elapsed() >= Duration::from_millis(50));
        let err: io::Error = res.unwrap_err().into();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);

        let quick = async { 42 };
        assert_eq!(
            timeout(&rt, Duration::from_secs(10), quick).await.unwrap(),
            42
        );

        // A ready future wins even against a zero deadline.
        assert_eq!(timeout(&rt, Duration::ZERO, async { 7 }).await.unwrap(), 7);

        // A read on a silent connection times out.
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut conn = rt.connect_tcp(addr).await.unwrap();
        let mut buf = [0u8; 1];
        let res = timeout(&rt, Duration::from_millis(30), conn.read(&mut buf)).await;
        assert!(res.is_err());
        drop(listener);

        // A huge duration does not overflow.
        let res = timeout(&rt, Duration::MAX, async { 1 }).await;
        assert_eq!(res.unwrap(), 1);
    });
}

#[test]
fn sleep_waits_at_least_the_duration() {
    let rt = rt();
    let start = Instant::now();
    rt.block_on(rt.sleep(Duration::from_millis(20)));
    assert!(start.elapsed() >= Duration::from_millis(20));
    // A sleep future works when polled by a foreign executor.
    let start = Instant::now();
    fstp_rt::future::block_on(rt.sleep(Duration::from_millis(10)));
    assert!(start.elapsed() >= Duration::from_millis(10));
}

struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

#[test]
fn abort_cancels_a_running_task_and_drops_its_state() {
    let rt = rt();
    rt.block_on(async {
        let dropped = Arc::new(AtomicBool::new(false));
        let flag = DropFlag(dropped.clone());
        let handle = rt.spawn(async move {
            let _flag = flag;
            std::future::pending::<()>().await;
        });
        rt.sleep(Duration::from_millis(10)).await;
        assert!(!handle.is_finished());
        handle.abort();
        let err = handle.await.unwrap_err();
        assert!(err.is_cancelled());
        assert!(!err.is_panic());
        assert!(dropped.load(Ordering::SeqCst));

        // Abort through a separate handle, before the task first runs.
        let handle = rt.spawn(async { 5 });
        let abort = handle.abort_handle();
        abort.abort();
        match handle.await {
            Ok(v) => assert_eq!(v, 5, "the task may finish before the abort"),
            Err(e) => assert!(e.is_cancelled()),
        }
        assert!(abort.is_finished());

        // Abort after completion has no effect.
        let handle = rt.spawn(async { 9 });
        rt.sleep(Duration::from_millis(10)).await;
        handle.abort();
        assert_eq!(handle.await.unwrap(), 9);
    });
}

/// A panic inside a task becomes a `JoinError` for the awaiting task. Its
/// `Display` and `Debug` forms never carry the panic payload, which can hold
/// task data, so logging the error leaks no content (R-NF-02).
#[test]
fn panicking_task_is_reported_not_propagated() {
    let rt = rt();
    let out = rt.block_on(async {
        let handle: JoinHandle<u32> = rt.spawn(async {
            panic!("boom in task");
        });
        let err = handle.await.unwrap_err();
        assert!(err.is_panic());
        assert_eq!(err.panic_message(), Some("boom in task"));
        // Display and Debug never carry the payload.
        assert_eq!(err.to_string(), "task panicked");
        assert!(!format!("{err:?}").contains("boom"));

        let blocking: JoinHandle<u32> = rt.spawn_blocking(|| panic!("boom in blocking"));
        let err = blocking.await.unwrap_err();
        assert!(err.is_panic());
        assert_eq!(err.panic_message(), Some("boom in blocking"));

        // The runtime keeps working.
        rt.spawn(async { 3u32 }).await.unwrap()
    });
    assert_eq!(out, 3);
}

#[test]
fn spawn_blocking_runs_off_the_async_workers() {
    // On a current-thread runtime, a blocking job that ran on the async
    // thread would wait forever for the async side to release it.
    let rt = TokioRuntime::new_current_thread().unwrap();
    rt.block_on(async {
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(AtomicBool::new(false));
        let (s, r) = (started.clone(), release.clone());
        let handle = rt.spawn_blocking(move || {
            s.store(true, Ordering::SeqCst);
            let begin = Instant::now();
            while !r.load(Ordering::SeqCst) {
                if begin.elapsed() > Duration::from_secs(10) {
                    return false;
                }
                std::thread::sleep(Duration::from_millis(1));
            }
            true
        });
        while !started.load(Ordering::SeqCst) {
            rt.sleep(Duration::from_millis(1)).await;
        }
        let tick = rt.spawn(async { 1 });
        assert_eq!(tick.await.unwrap(), 1);
        release.store(true, Ordering::SeqCst);
        assert!(
            handle.await.unwrap(),
            "blocking job was released by async code"
        );
    });
}

#[test]
fn resolve_localhost_and_literals() {
    let rt = rt();
    rt.block_on(async {
        let addrs = rt.resolve("127.0.0.1", 5432).await.unwrap();
        assert_eq!(addrs, vec![SocketAddr::from((Ipv4Addr::LOCALHOST, 5432))]);
        let addrs = rt.resolve("localhost", 80).await.unwrap();
        assert!(addrs.iter().all(|a| a.ip().is_loopback() && a.port() == 80));
        assert!(!addrs.is_empty());
        let err = rt.resolve("", 1).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let long = "a".repeat(254);
        let err = rt.resolve(&long, 1).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(rt.resolve("bad\0host", 1).await.is_err());
    });
}

#[test]
fn connect_to_closed_port_fails() {
    let rt = rt();
    rt.block_on(async {
        // Bind and drop to find a port that is very likely closed.
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let res = rt.connect_tcp(addr).await;
        assert!(res.is_err());
    });
}

#[test]
fn shutdown_stops_accepting_and_drains_connections() {
    let rt = rt();
    let shutdown = Shutdown::new();
    let accepted = Arc::new(AtomicUsize::new(0));
    rt.block_on(async {
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = rt.spawn(echo_server(
            rt.clone(),
            listener,
            shutdown.signal(),
            accepted.clone(),
        ));

        // Open a connection and keep it mid-conversation.
        let mut conn = rt.connect_tcp(addr).await.unwrap();
        conn.write_all(b"a").await.unwrap();
        let mut one = [0u8; 1];
        conn.read_exact(&mut one).await.unwrap();
        assert_eq!(shutdown.active(), 2, "accept loop plus one connection");

        // Trigger: the accept loop stops; the open connection keeps working.
        shutdown.trigger();
        server.await.unwrap();
        assert_eq!(shutdown.active(), 1);
        conn.write_all(b"b").await.unwrap();
        conn.read_exact(&mut one).await.unwrap();
        assert_eq!(&one, b"b");

        // New connections are no longer served.
        match rt.connect_tcp(addr).await {
            Err(_) => {}
            Ok(mut late) => {
                let mut buf = [0u8; 1];
                let res = late.read(&mut buf).await;
                assert!(matches!(res, Ok(0) | Err(_)));
            }
        }

        // Drain completes once the client finishes its conversation.
        let drained = shutdown.drained();
        conn.shutdown().await.unwrap();
        let mut rest = Vec::new();
        conn.read_to_end(&mut rest, 16).await.unwrap();
        timeout(&rt, Duration::from_secs(5), drained).await.unwrap();
        assert_eq!(shutdown.active(), 0);
        shutdown
            .shutdown(&rt, Duration::from_millis(1))
            .await
            .unwrap();
    });
    assert_eq!(accepted.load(Ordering::SeqCst), 1);
}

#[test]
fn shutdown_deadline_reports_stuck_tasks_which_can_then_be_aborted() {
    let rt = rt();
    let shutdown = Shutdown::new();
    rt.block_on(async {
        let polite = shutdown.signal();
        let stuck = shutdown.signal();
        let polite_task = rt.spawn(async move {
            polite.notified().await;
            drop(polite);
        });
        let stuck_task = rt.spawn(async move {
            let _participant = stuck;
            std::future::pending::<()>().await;
        });
        let res = shutdown.shutdown(&rt, Duration::from_millis(50)).await;
        let err = res.unwrap_err();
        assert_eq!(err.remaining, 1);
        assert!(err.to_string().contains("1 task"));
        polite_task.await.unwrap();

        stuck_task.abort();
        assert!(stuck_task.await.unwrap_err().is_cancelled());
        timeout(&rt, Duration::from_secs(5), shutdown.drained())
            .await
            .unwrap();
    });
}

#[test]
fn signals_created_after_trigger_see_it_immediately() {
    let shutdown = Shutdown::new();
    assert!(!shutdown.is_triggered());
    shutdown.trigger();
    shutdown.trigger();
    let s = shutdown.signal();
    assert!(s.is_triggered());
    assert!(shutdown.is_triggered());
    fstp_rt::future::block_on(s.notified());
    let r = fstp_rt::future::block_on(s.run_until(async { 1 }));
    assert_eq!(r, None, "nothing runs after shutdown");
    drop(s);
    fstp_rt::future::block_on(shutdown.drained());
}

#[test]
fn race_and_join_helpers() {
    let rt = rt();
    rt.block_on(async {
        let r = race(rt.sleep(Duration::from_secs(10)), async { 5 }).await;
        assert_eq!(r, Either::Right(5));
        let r = race(async { 1 }, async { 2 }).await;
        assert_eq!(r, Either::Left(1));
        let (a, b) = fstp_rt::future::join(
            async {
                rt.sleep(Duration::from_millis(5)).await;
                1
            },
            async { 2 },
        )
        .await;
        assert_eq!((a, b), (1, 2));
        fstp_rt::future::yield_now().await;
    });
}

#[test]
fn current_thread_runtime_runs_tasks_and_io() {
    let rt = TokioRuntime::new_current_thread().unwrap();
    rt.block_on(async {
        assert!(TokioRuntime::current().is_some());
        let listener = rt.bind_tcp(loopback()).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let shutdown = Shutdown::new();
        let accepted = Arc::new(AtomicUsize::new(0));
        let server = rt.spawn(echo_server(
            rt.clone(),
            listener,
            shutdown.signal(),
            accepted.clone(),
        ));
        roundtrip(&rt, addr, pattern(100_000, 9)).await.unwrap();
        shutdown
            .shutdown(&rt, Duration::from_secs(5))
            .await
            .unwrap();
        server.await.unwrap();
    });
    assert!(TokioRuntime::current().is_none());
}

#[test]
fn dropping_the_runtime_cancels_pending_tasks() {
    let rt = rt();
    let handle = rt.spawn(std::future::pending::<()>());
    let rt2 = rt.clone();
    assert!(
        !rt.shutdown_timeout(Duration::from_secs(1)),
        "a clone remains"
    );
    assert!(rt2.shutdown_timeout(Duration::from_secs(5)));
    let err = fstp_rt::future::block_on(handle).unwrap_err();
    assert!(err.is_cancelled());
}

#[test]
fn join_handle_polled_after_completion_reports_an_error() {
    use std::future::Future;
    use std::pin::Pin;
    use std::task::{Context, Poll, Waker};

    let rt = rt();
    let mut handle = rt.spawn(async { 1 });
    assert_eq!(fstp_rt::future::block_on(&mut handle).unwrap(), 1);
    let mut cx = Context::from_waker(Waker::noop());
    match Pin::new(&mut handle).poll(&mut cx) {
        Poll::Ready(Err(e)) => {
            assert!(!e.is_cancelled() && !e.is_panic());
            assert_eq!(e.to_string(), "join handle polled after completion");
        }
        other => panic!("unexpected {other:?}"),
    }
}

/// Review finding phase-deadline-bypass-streaming, other code path.
///
/// A deadline around a whole read loop must fire while the peer keeps the
/// socket readable. tokio gives each task poll a budget of socket
/// operations. Once the loop has used it up, the socket and the timer both
/// return `Pending`, so a timeout that relies on its timer alone never
/// fires while data keeps arriving. The reader takes one byte per read, so it
/// never catches up with the writer.
#[test]
fn review_timeout_fires_while_a_peer_keeps_streaming() {
    use std::io::Write as _;
    let rt = rt();
    let listener = std::net::TcpListener::bind(loopback()).unwrap();
    let addr = listener.local_addr().unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let stop2 = stop.clone();
    let writer = std::thread::spawn(move || {
        let (mut s, _) = listener.accept().unwrap();
        let chunk = vec![b'x'; 64 * 1024];
        let start = Instant::now();
        while !stop2.load(Ordering::SeqCst) && start.elapsed() < Duration::from_secs(6) {
            if s.write_all(&chunk).is_err() {
                break;
            }
        }
    });
    let waited = rt.block_on(async {
        let mut conn = rt.connect_tcp(addr).await.unwrap();
        let start = Instant::now();
        let read_forever = async {
            let mut buf = [0u8; 1];
            loop {
                if conn.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
            }
        };
        let res = timeout(&rt, Duration::from_millis(200), read_forever).await;
        (start.elapsed(), res.is_err())
    });
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    assert!(waited.1, "the read loop ended before the deadline");
    assert!(waited.0 < Duration::from_secs(2), "waited {:?}", waited.0);
}
