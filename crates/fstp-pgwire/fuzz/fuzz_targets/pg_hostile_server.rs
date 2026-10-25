//! TH-26, H-05: the client connection state machine against a hostile
//! server.
//!
//! The first byte picks a mode:
//!
//! - plaintext over the fstp-rt duplex with every authentication method
//!   allowed;
//! - the same, with the session believing it holds a TLS certificate;
//! - the default SCRAM-only policy;
//! - a scripted transport with fuzzed chunking and pending points;
//! - TLS negotiation against hostile bytes;
//! - the fuzzed bytes inside a genuine TLS session on the duplex.
//!
//! After startup the client prepares, queries, streams and decodes rows.
//!
//! Properties beyond "no panic":
//!
//! - the client terminates within a poll budget linear in the input;
//! - under the default policy it never authenticates unless the server
//!   proves the password;
//! - it never completes TLS against a hostile peer;
//! - it uses only allowed authentication methods;
//! - it stays broken once broken;
//! - in every mode, it never sends a cleartext password without TLS and a
//!   server certificate, and sends only the SSLRequest before TLS.
//!
//! See `harness::hostile_server`.

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::hostile_server(data);
});
