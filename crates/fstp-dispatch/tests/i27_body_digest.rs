//! I-27, TH-26, m4-design section 15.0 (row "ops.delivery body digest",
//! 2026-11-07): the COMMITTING row records an HMAC-SHA256 of the body
//! under a cell key, never its plain SHA-256. A guessed body cannot be
//! confirmed from the digest without the key, and two cells with
//! different keys record different digests for the same body.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_dispatch::store::{MemDelivery, Phase};
use fstp_dispatch::{
    DigestKey, EndOfData, Envelope, LoadError, Prepared, Refused, Source, Transport, Worker,
};
use fstp_rt::future::block_on;

const OUTBOX: [u8; 16] = [7; 16];
const T: i64 = 1_794_050_000_000_000;

/// A synthetic message body, the same in every cell.
const BODY: &[u8] = b"Subject: Your proposal was received\r\n\r\nSynthetic body.\r\n";

struct One;

impl Source for One {
    async fn load(&mut self, _o: [u8; 16]) -> Result<Prepared, LoadError> {
        Ok(Prepared {
            envelope: Envelope {
                from: "noreply@fund.test".to_owned(),
                to: "lead@example.test".to_owned(),
            },
            body: BODY.to_vec(),
            event: [1; 32],
            template_version: 1,
        })
    }
}

struct Accept;

impl Transport for Accept {
    type Staged = ();
    async fn stage(&mut self, _e: &Envelope, _b: &[u8]) -> Result<(), Refused> {
        Ok(())
    }
    async fn end_of_data(&mut self, _s: ()) -> EndOfData {
        EndOfData::Reply(250)
    }
    async fn abandon(&mut self, _s: ()) {}
}

/// Runs one worker of a cell with `key` until the message is SENT, and
/// returns the digest its COMMITTING row records.
fn committed_digest(key: [u8; 32]) -> [u8; 32] {
    let mut log = MemDelivery::new([OUTBOX]);
    let mut w: Worker<()> = Worker::new([9; 16], DigestKey::new(key));
    for _ in 0..5 {
        block_on(w.step(&mut log, &mut One, &mut Accept, &[OUTBOX], T));
    }
    assert_eq!(log.head(&OUTBOX).map(|h| h.phase), Some(Phase::Sent));
    log.rows(&OUTBOX)
        .iter()
        .find(|r| r.phase == Phase::Committing)
        .and_then(|r| r.commit)
        .map(|c| c.body_digest)
        .expect("a COMMITTING row with its facts")
}

/// I-27, TH-26: the stored body digest is the HMAC-SHA256 of the body
/// under the cell key, and differs from the plain SHA-256 of the body.
#[test]
fn i27_th26_body_digest_is_an_hmac_under_the_cell_key() {
    let key = [0x5a; 32];
    let stored = committed_digest(key);
    assert_ne!(
        stored,
        fstp_crypto::sha256(BODY),
        "I-27: the digest confirms a guessed body without a key"
    );
    assert_eq!(stored, fstp_crypto::hmac_sha256(&key, BODY));
    assert_eq!(
        stored,
        fstp_dispatch::body_digest(&DigestKey::new(key), BODY)
    );
}

/// I-27, TH-26: two cells with different keys record different digests
/// for the same body.
#[test]
fn i27_th26_cells_with_different_keys_record_different_digests() {
    let a = committed_digest([0x11; 32]);
    let b = committed_digest([0x22; 32]);
    assert_ne!(a, b, "I-27: the digest is not bound to the cell key");
}

/// R-NF-02: the key never shows in a debug print of the worker.
#[test]
fn i27_th26_digest_key_is_redacted_in_debug() {
    let w: Worker<()> = Worker::new([9; 16], DigestKey::new([0xab; 32]));
    let shown = format!("{w:?}");
    assert!(!shown.contains("171"), "{shown}");
    assert!(!shown.to_lowercase().contains("ab, ab"), "{shown}");
}
