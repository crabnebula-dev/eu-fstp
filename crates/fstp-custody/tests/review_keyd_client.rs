//! Review reproducers for the keyd client and frame codec of
//! `fstp-custody` (independent review of lane W2f). Each test fails on
//! the current code and passes once its defect is fixed.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

use std::time::{Duration, Instant};

use fstp_custody::keyd::{Request, RequestId, RootHandle, decode_frame, encode_request};
use fstp_custody::{Chain, Epoch};
use zeroize::Zeroizing;

/// Reads `true` exactly when `$t` implements every bound, at compile
/// time, and compiles either way.
macro_rules! impls {
    ($t:ty: $($tr:tt)+) => {{
        #[allow(dead_code)]
        trait DoesNotImpl {
            const IMPLS: bool = false;
        }
        #[allow(dead_code)]
        impl<T: ?Sized> DoesNotImpl for T {}
        struct Wrapper<T: ?Sized>(::core::marker::PhantomData<T>);
        #[allow(dead_code)]
        impl<T: ?Sized + $($tr)+> Wrapper<T> {
            const IMPLS: bool = true;
        }
        <Wrapper<$t>>::IMPLS
    }};
}

const CANARY: [u8; 32] = [0xc3; 32];

fn wrap_frame() -> Vec<u8> {
    encode_request(&Request::Wrap {
        id: RequestId([1; 16]),
        root: RootHandle {
            chain: Chain::App,
            epoch: Epoch(1),
        },
        aad: b"aad".to_vec(),
        key: Box::new(Zeroizing::new(CANARY)),
    })
    .unwrap()
}

/// I-80 decision of 2026-10-28 ("`S(e)` ... is zeroised on drop"),
/// ADR-001 A1: `decode_frame` copies a frame body into a plain
/// `Vec<u8>`. Both `decode_response` (an `Unwrapped` seal key in the
/// cell or vault) and the keyd request decoder (a `Wrap` seal key) go
/// through it, so the seal key stays in freed heap memory.
#[test]
fn review_keyd_frame_body_zeroizes_on_drop() {
    assert!(
        impls!(fstp_custody::keyd::KeydFrame: zeroize::ZeroizeOnDrop),
        "KeydFrame holds seal key bytes but does not wipe them on drop"
    );
}

/// I-80, design section 3.3 ("no `Debug` output" for `S(e)`): the
/// derived `Debug` of a decoded `Wrap` frame prints the seal key.
#[test]
fn review_keyd_frame_debug_never_shows_a_seal_key() {
    let frame = decode_frame(&wrap_frame()).unwrap();
    let shown = format!("{frame:?}");
    let needle = CANARY
        .iter()
        .map(u8::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    assert!(
        !shown.contains(&needle),
        "the Debug form of a keyd frame shows the seal key"
    );
}

/// ADR-002, `fstp_rt::Runtime::spawn_blocking`: the `Custody` futures of
/// `KeydCustody` do blocking socket I/O inside `poll`. A stalled
/// `fstp-keyd` then holds the executor thread for the 30 s client
/// timeout, and every other task on it waits.
#[cfg(unix)]
#[test]
fn review_keyd_client_poll_never_blocks_the_executor() {
    use fstp_custody::{Custody as _, KeydCustody, RootLabel};
    use std::future::Future as _;
    use std::os::unix::net::UnixListener;
    use std::task::{Context, Waker};

    let dir = std::env::temp_dir().join(format!("fstp-custody-review-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let socket = dir.join("keyd.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    // A stalled server: it accepts and never answers.
    std::thread::spawn(move || {
        let held = listener.accept();
        std::thread::sleep(Duration::from_secs(120));
        drop(held);
    });
    let client = KeydCustody::new(&socket).unwrap();
    let fut = client.create_root(RootLabel {
        cell: None,
        chain: Chain::App,
        epoch: Epoch(1),
    });
    let mut fut = std::pin::pin!(fut);
    let mut cx = Context::from_waker(Waker::noop());
    let start = Instant::now();
    let first = fut.as_mut().poll(&mut cx);
    let took = start.elapsed();
    let _ = std::fs::remove_dir_all(&dir);
    assert!(
        took < Duration::from_secs(1),
        "one poll of create_root blocked the thread for {took:?} (ready: {})",
        first.is_ready()
    );
}
