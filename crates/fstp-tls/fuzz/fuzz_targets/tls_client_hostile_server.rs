//! TH-26, H-05: a TLS client handshake against a hostile server.
//!
//! The fuzzer chooses every byte the "server" sends, plus the IO timing:
//! read and write chunk sizes and where the transport returns `Pending`
//! (see `fstp_rt::scripted::ScriptedStream::from_fuzz_input`). The handshake
//! is polled with a no-op waker.
//!
//! Properties checked beyond "no panic":
//!
//! - The handshake terminates within a poll budget that is linear in the
//!   input size. A busy loop or a lost wake-up fails the run.
//! - It never succeeds. The hostile peer holds no key for a certificate under
//!   the trusted test CA, and cannot predict the client's key share.
//! - Every failure is a typed `TlsError`, since the scripted transport itself
//!   never reports an IO error.

#![no_main]

use std::sync::OnceLock;

use fstp_rt::future::poll_bounded;
use fstp_rt::scripted::ScriptedStream;
use fstp_tls::{ClientConfig, TlsError, connect};
use libfuzzer_sys::fuzz_target;

const CA: &[u8] = include_bytes!("../../testdata/ca.pem");
const CLIENT: &[u8] = include_bytes!("../../testdata/client.pem");
const CLIENT_KEY: &[u8] = include_bytes!("../../testdata/client-key.pem");

fn config() -> &'static ClientConfig {
    static CFG: OnceLock<ClientConfig> = OnceLock::new();
    CFG.get_or_init(|| match ClientConfig::mutual(CA, CLIENT, CLIENT_KEY) {
        Ok(cfg) => cfg,
        Err(e) => panic!("test certificates are invalid: {e}"),
    })
}

fuzz_target!(|data: &[u8]| {
    let io = ScriptedStream::from_fuzz_input(data);
    // Each poll consumes at least one script byte, or writes at least one
    // byte of the client's bounded output, or returns one `Pending`.
    let budget = data.len().saturating_mul(4).saturating_add(20_000);
    let outcome = poll_bounded(connect(config(), "localhost", io), budget);
    let Some(result) = outcome else {
        panic!("client handshake did not terminate within {budget} polls");
    };
    match result {
        Ok(_) => panic!("client handshake succeeded against a hostile server"),
        Err(e) => {
            assert!(
                TlsError::from_io(&e).is_some(),
                "untyped handshake error: {e:?}"
            );
        }
    }
});
