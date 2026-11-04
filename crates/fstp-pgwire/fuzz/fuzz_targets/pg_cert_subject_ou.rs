//! I-83, TH-26, H-05: the subject OU reader of the server certificate on
//! arbitrary bytes. The cell and the vault start checks read the cluster
//! kind from it (M3 design section 9.2).
//!
//! Properties beyond "no panic": every OU value lies inside the input, in
//! input order and without overlap, and a second read gives the same
//! values. See `harness::cert_subject_ou`.

#![no_main]

#[path = "../harness.rs"]
mod harness;

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    harness::cert_subject_ou(data);
});
