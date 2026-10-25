//! TH-26, H-05: a mutual TLS server handshake against a hostile client.
//!
//! The fuzzer chooses every byte the "client" sends, plus the IO timing (see
//! `fstp_rt::scripted::ScriptedStream::from_fuzz_input`). The handshake is
//! polled with a no-op waker.
//!
//! Properties checked beyond "no panic":
//!
//! - The handshake terminates within a poll budget that is linear in the
//!   input size.
//! - It never succeeds. Client authentication is required, and the hostile
//!   peer holds no key for a certificate under the trusted test CA.
//! - Every failure is a typed `TlsError`.

#![no_main]

use std::sync::OnceLock;

use fstp_rt::future::poll_bounded;
use fstp_rt::scripted::ScriptedStream;
use fstp_tls::{ServerConfig, TlsError, accept};
use libfuzzer_sys::fuzz_target;

const CA: &[u8] = include_bytes!("../../testdata/ca.pem");
const SERVER: &[u8] = include_bytes!("../../testdata/server.pem");
const SERVER_KEY: &[u8] = include_bytes!("../../testdata/server-key.pem");

fn config() -> &'static ServerConfig {
    static CFG: OnceLock<ServerConfig> = OnceLock::new();
    CFG.get_or_init(|| match ServerConfig::mutual(SERVER, SERVER_KEY, CA) {
        Ok(cfg) => cfg,
        Err(e) => panic!("test certificates are invalid: {e}"),
    })
}

fuzz_target!(|data: &[u8]| {
    let io = ScriptedStream::from_fuzz_input(data);
    let budget = data.len().saturating_mul(4).saturating_add(20_000);
    let outcome = poll_bounded(accept(config(), io), budget);
    let Some(result) = outcome else {
        panic!("server handshake did not terminate within {budget} polls");
    };
    match result {
        Ok(_) => panic!("server handshake succeeded against a hostile client"),
        Err(e) => {
            assert!(
                TlsError::from_io(&e).is_some(),
                "untyped handshake error: {e:?}"
            );
        }
    }
});
