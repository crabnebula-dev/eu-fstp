//! A test-local reference of the ADR-010 byte layouts (I-24, R-CR-03).
//!
//! It follows ADR-010 "Link function" and "Anchors" and the receipt
//! reading of `fstp_celltest::reference::audit::receipt_message`. It uses
//! `fstp_crypto::sha256` and names no `fstp-audit` item. The vectors in
//! [`vectors`] pin it to values computed outside Rust.

use fstp_crypto::Sha256;

/// A SHA-256 value.
pub(crate) type Hash = [u8; 32];

/// The link label (design section 7.1).
pub(crate) const LINK_LABEL: &[u8] = b"fstp-audit-v1";
/// The genesis label (ADR-010 proposal).
pub(crate) const GENESIS_LABEL: &[u8] = b"fstp-audit-genesis-v1";
/// The row bytes label (ADR-010 proposal).
pub(crate) const ROW_LABEL: &[u8] = b"fstp-audit-row-v1";
/// The anchor message label (ADR-010 proposal).
pub(crate) const ANCHOR_LABEL: &[u8] = b"fstp-anchor-v1";
/// The receipt message label (ADR-010).
pub(crate) const RECEIPT_LABEL: &[u8] = b"fstp-receipt-v1";

/// The test cell: bytes 0 to 15.
pub(crate) const CELL: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
/// A second cell.
pub(crate) const OTHER_CELL: [u8; 16] = [0xF0; 16];

/// The two chains (ADR-010 "Chains").
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Chain {
    /// Byte value 1.
    App,
    /// Byte value 2.
    Vault,
}

impl Chain {
    /// Both chains.
    pub(crate) const ALL: [Chain; 2] = [Chain::App, Chain::Vault];

    /// The ADR-010 byte value.
    pub(crate) const fn byte(self) -> u8 {
        match self {
            Chain::App => 1,
            Chain::Vault => 2,
        }
    }

    /// The other chain.
    pub(crate) const fn other(self) -> Chain {
        match self {
            Chain::App => Chain::Vault,
            Chain::Vault => Chain::App,
        }
    }
}

/// A stored ledger entry, sealed body included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Entry {
    /// The ledger sequence.
    pub(crate) seq: u64,
    /// UTC microseconds.
    pub(crate) at: i64,
    /// The command id.
    pub(crate) command: [u8; 16],
    /// The schema version.
    pub(crate) schema: u16,
    /// The ledger key index.
    pub(crate) key_ix: u32,
    /// The sealed body.
    pub(crate) body: Vec<u8>,
}

/// What a chain row records.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum Kind {
    /// Kind 1: a ledger entry, by sequence.
    Ledger {
        /// The ledger sequence.
        seq: u64,
    },
    /// Kind 2: an event with a sealed body.
    Event {
        /// The sealed body.
        body: Vec<u8>,
    },
}

impl Kind {
    /// The ADR-010 kind code.
    pub(crate) const fn code(&self) -> u16 {
        match self {
            Kind::Ledger { .. } => 1,
            Kind::Event { .. } => 2,
        }
    }
}

/// The columns of a chain row that the designed `ChainRow` holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RowCols {
    /// The row number, from 1.
    pub(crate) n: u64,
    /// UTC microseconds.
    pub(crate) at: i64,
    /// What the row records.
    pub(crate) kind: Kind,
    /// SHA-256 of the row bytes.
    pub(crate) stored_hash: Hash,
}

/// A stored chain row with its link column.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Row {
    /// The designed columns.
    pub(crate) cols: RowCols,
    /// The stored link column.
    pub(crate) link: Hash,
}

/// SHA-256 over the concatenation of `parts`.
pub(crate) fn sha256(parts: &[&[u8]]) -> Hash {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finish()
}

/// `SHA-256("fstp-audit-genesis-v1" || cell || chain)`.
pub(crate) fn genesis(cell: [u8; 16], chain: Chain) -> Hash {
    sha256(&[GENESIS_LABEL, &cell, &[chain.byte()]])
}

/// The ADR-010 row bytes. `None` for a kind 1 row without its entry, or a
/// body longer than `u32::MAX`.
pub(crate) fn row_bytes(at: i64, kind: &Kind, entry: Option<&Entry>) -> Option<Vec<u8>> {
    let mut out = ROW_LABEL.to_vec();
    out.extend_from_slice(&kind.code().to_be_bytes());
    out.extend_from_slice(&at.to_be_bytes());
    match kind {
        Kind::Ledger { seq } => {
            let e = entry?;
            out.extend_from_slice(&seq.to_be_bytes());
            out.extend_from_slice(&e.at.to_be_bytes());
            out.extend_from_slice(&e.command);
            out.extend_from_slice(&e.schema.to_be_bytes());
            out.extend_from_slice(&e.key_ix.to_be_bytes());
            out.extend_from_slice(&u32::try_from(e.body.len()).ok()?.to_be_bytes());
            out.extend_from_slice(&e.body);
        }
        Kind::Event { body } => {
            out.extend_from_slice(&u32::try_from(body.len()).ok()?.to_be_bytes());
            out.extend_from_slice(body);
        }
    }
    Some(out)
}

/// `stored_hash = SHA-256(row bytes)`.
pub(crate) fn stored_hash(at: i64, kind: &Kind, entry: Option<&Entry>) -> Option<Hash> {
    row_bytes(at, kind, entry).map(|b| sha256(&[&b]))
}

/// `SHA-256("fstp-audit-v1" || cell || chain || be64(n) || prev ||
/// stored_hash)`.
pub(crate) fn link(prev: &Hash, cell: [u8; 16], chain: Chain, n: u64, stored_hash: &Hash) -> Hash {
    sha256(&[
        LINK_LABEL,
        &cell,
        &[chain.byte()],
        &n.to_be_bytes(),
        prev,
        stored_hash,
    ])
}

/// `"fstp-anchor-v1" || cell || chain || be64(n) || link || be64(at)`.
pub(crate) fn anchor_message(
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    link: &Hash,
    at: i64,
) -> Vec<u8> {
    let mut out = ANCHOR_LABEL.to_vec();
    out.extend_from_slice(&cell);
    out.push(chain.byte());
    out.extend_from_slice(&n.to_be_bytes());
    out.extend_from_slice(link);
    out.extend_from_slice(&at.to_be_bytes());
    out
}

/// The signed fields of a receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReceiptFields {
    /// The head row number.
    pub(crate) n: u64,
    /// The head link.
    pub(crate) link: Hash,
    /// The witness sequence.
    pub(crate) witness_seq: u64,
    /// The witness chain link.
    pub(crate) witness_link: Hash,
    /// UTC microseconds.
    pub(crate) received_at: i64,
}

/// `"fstp-receipt-v1" || cell || chain || be64(n) || link ||
/// be64(witness_seq) || witness_link || be64(received_at)`. ADR-010 gives
/// the label and the fields only. The order is the W1e reading.
pub(crate) fn receipt_message(cell: [u8; 16], chain: Chain, r: &ReceiptFields) -> Vec<u8> {
    let mut out = RECEIPT_LABEL.to_vec();
    out.extend_from_slice(&cell);
    out.push(chain.byte());
    out.extend_from_slice(&r.n.to_be_bytes());
    out.extend_from_slice(&r.link);
    out.extend_from_slice(&r.witness_seq.to_be_bytes());
    out.extend_from_slice(&r.witness_link);
    out.extend_from_slice(&r.received_at.to_be_bytes());
    out
}

/// Vectors computed on 2026-10-29 with `xxd -r -p | shasum -a 256` over
/// hex strings written from the ADR-010 layouts, not with Rust.
pub(crate) mod vectors {
    use super::{Entry, Kind};

    /// `at` of both vector rows.
    pub(crate) const AT: i64 = 1_700_000_000_000_000;

    /// The kind 2 vector row's kind.
    pub(crate) fn event_kind() -> Kind {
        Kind::Event {
            body: b"event-body".to_vec(),
        }
    }

    /// The kind 1 vector row's kind.
    pub(crate) const LEDGER_KIND: Kind = Kind::Ledger { seq: 7 };

    /// The kind 1 vector row's entry.
    pub(crate) fn entry() -> Entry {
        Entry {
            seq: 7,
            at: 1_699_999_999_999_999,
            command: [
                0xC0, 0xC1, 0xC2, 0xC3, 0xC4, 0xC5, 0xC6, 0xC7, 0xC8, 0xC9, 0xCA, 0xCB, 0xCC, 0xCD,
                0xCE, 0xCF,
            ],
            schema: 3,
            key_ix: 2,
            body: b"sealed".to_vec(),
        }
    }

    /// `genesis(CELL, App)`.
    pub(crate) const GENESIS_APP: &str =
        "928dcff403321db9b4ac982d5036719e98e39db4977faf88bfa0238f525d0046";
    /// `genesis(CELL, Vault)`.
    pub(crate) const GENESIS_VAULT: &str =
        "ade812e5a573892022289aea64328cc61a6e728c5ac45ed2ec741c5f8298e983";
    /// The row bytes of the kind 2 vector row.
    pub(crate) const ROW_EVENT: &str =
        "667374702d61756469742d726f772d7631000200060a24181e40000000000a6576656e742d626f6479";
    /// The row bytes of the kind 1 vector row.
    pub(crate) const ROW_LEDGER: &str = "667374702d61756469742d726f772d7631000100060a24181e4000000000000000000700060a24181e3fffc0c1c2c3c4c5c6c7c8c9cacbcccdcecf000300000002000000067365616c6564";
    /// The stored hash of the kind 2 vector row.
    pub(crate) const STORED_EVENT: &str =
        "080ae226b16321a3f5e6449ac4e6b9042ba45b0eaf0d95a595b13bf5c84aec6b";
    /// The stored hash of the kind 1 vector row.
    pub(crate) const STORED_LEDGER: &str =
        "1064a8931629d3fc2dc6aff3b48c844fe3a75cced937d68eeccfb614ed1d55fa";
    /// Row 1 of the App chain: the kind 2 row after genesis.
    pub(crate) const LINK1_APP: &str =
        "dc3b6bde31bfeeacd1a2de4e660ca4076c4fa83fd834a30243d663a2b137b467";
    /// Row 2 of the App chain: the kind 1 row after row 1.
    pub(crate) const LINK2_APP: &str =
        "c50f2272921f44303c9086a65295cad7f75e62ead1ada0d73143326fddd13a2c";
    /// Row 1 of the Vault chain: the kind 2 row after genesis.
    pub(crate) const LINK1_VAULT: &str =
        "820e89f43e8a42793f3f980fda34e22fad6e90d4605c5d9edba78db10b0c32a0";
    /// SHA-256 of the anchor message for App row 2 at [`AT`].
    pub(crate) const ANCHOR_MESSAGE_SHA: &str =
        "f42b2c7be7bfa32d7bb81f85f7879465bdf09fb43b0624d10f61de9c58face92";
    /// The anchor message length: 14 + 16 + 1 + 8 + 32 + 8.
    pub(crate) const ANCHOR_MESSAGE_LEN: usize = 79;
    /// SHA-256 of the receipt message for App row 2, witness sequence 9,
    /// witness link of 32 bytes 0xA5, received at [`AT`] + 5.
    pub(crate) const RECEIPT_MESSAGE_SHA: &str =
        "363e18ae91eb25f8b9356f81111cde46fa33113d3deac7f921d15d3e4d09977f";
    /// The receipt message length: 15 + 16 + 1 + 8 + 32 + 8 + 32 + 8.
    pub(crate) const RECEIPT_MESSAGE_LEN: usize = 120;
    /// The witness sequence of the receipt vector.
    pub(crate) const RECEIPT_WITNESS_SEQ: u64 = 9;
    /// The witness link of the receipt vector.
    pub(crate) const RECEIPT_WITNESS_LINK: [u8; 32] = [0xA5; 32];
}
