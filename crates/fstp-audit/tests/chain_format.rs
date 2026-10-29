//! I-24 chain format: genesis, row bytes, stored hashes, links and the
//! `ChainWriter` (design section 7.1, ADR-010 "Link function").
//!
//! The layouts are the ADR-010 proposals (open point 2). The recorded
//! vectors were computed outside Rust with `shasum`. The test-local
//! reference is pinned to them by a self-test, then each production
//! function is compared with both.
//!
//! Red until lane W2g lands `genesis`, `link`, the stored hash and
//! `ChainWriter::append`. Each refusal names the stub or the gap.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "test code asserts on known-good values"
)]

mod common;

use common::reference::{
    self as r, CELL, Chain, Entry, Hash, Kind, OTHER_CELL, RowCols, vectors as v,
};
use common::{answered, api, hex, hex32, real_refusal};
use fstp_prop::{Gen, check, prop_assert, prop_assert_eq, prop_assert_ne};

fn gen_cell(g: &mut Gen) -> [u8; 16] {
    let mut c = [0u8; 16];
    for b in &mut c {
        *b = g.u8();
    }
    c
}

fn gen_hash(g: &mut Gen) -> Hash {
    let mut h = [0u8; 32];
    for b in &mut h {
        *b = g.u8();
    }
    h
}

fn gen_chain(g: &mut Gen) -> Chain {
    *g.pick(&Chain::ALL)
}

fn gen_entry(g: &mut Gen, seq: u64) -> Entry {
    let mut command = [0u8; 16];
    for b in &mut command {
        *b = g.u8();
    }
    Entry {
        seq,
        at: g.i64(),
        command,
        schema: g.u16(),
        key_ix: g.u32(),
        body: g.bytes(0..=40),
    }
}

/// A random row kind with its entry for kind 1.
fn gen_kind(g: &mut Gen) -> (Kind, Option<Entry>) {
    if g.bool() {
        let seq = g.u64();
        (Kind::Ledger { seq }, Some(gen_entry(g, seq)))
    } else {
        (
            Kind::Event {
                body: g.bytes(0..=40),
            },
            None,
        )
    }
}

/// The production link of a row with these inputs, its stored hash from
/// the production stored hash.
#[allow(clippy::too_many_arguments, reason = "every link input")]
fn prod_link(
    prev: &Hash,
    cell: [u8; 16],
    chain: Chain,
    n: u64,
    at: i64,
    kind: &Kind,
    entry: Option<&Entry>,
) -> Result<Hash, String> {
    let sh = answered("stored hash", api::stored_hash(at, kind, entry))?;
    let cols = RowCols {
        n,
        at,
        kind: kind.clone(),
        stored_hash: sh,
    };
    answered("link", api::link(prev, cell, chain, &cols))
}

// ---------------------------------------------------------------------------
// The test reference against the recorded vectors.

/// ADR-010 "Record at first use": the test-local reference reproduces the
/// genesis, row bytes, stored hash and link vectors computed with
/// `shasum`. Green: it pins the reference the other tests use.
#[test]
fn adr010_test_reference_matches_recorded_vectors() {
    let g_app = r::genesis(CELL, Chain::App);
    let ev = v::event_kind();
    let e = v::entry();
    let sh_ev = r::stored_hash(v::AT, &ev, None).unwrap();
    let sh_led = r::stored_hash(v::AT, &v::LEDGER_KIND, Some(&e)).unwrap();
    let l1 = r::link(&g_app, CELL, Chain::App, 1, &sh_ev);
    let got = (
        g_app,
        r::genesis(CELL, Chain::Vault),
        r::row_bytes(v::AT, &ev, None).unwrap(),
        r::row_bytes(v::AT, &v::LEDGER_KIND, Some(&e)).unwrap(),
        sh_ev,
        sh_led,
        l1,
        r::link(&l1, CELL, Chain::App, 2, &sh_led),
        r::link(
            &r::genesis(CELL, Chain::Vault),
            CELL,
            Chain::Vault,
            1,
            &sh_ev,
        ),
    );
    let want = (
        hex32(v::GENESIS_APP),
        hex32(v::GENESIS_VAULT),
        hex(v::ROW_EVENT),
        hex(v::ROW_LEDGER),
        hex32(v::STORED_EVENT),
        hex32(v::STORED_LEDGER),
        hex32(v::LINK1_APP),
        hex32(v::LINK2_APP),
        hex32(v::LINK1_VAULT),
    );
    assert_eq!(got, want);
}

// ---------------------------------------------------------------------------
// Genesis.

/// I-24, ADR-010: `genesis = SHA-256("fstp-audit-genesis-v1" || cell ||
/// chain)`, against the recorded vectors.
#[test]
fn i24_genesis_matches_recorded_vectors() {
    let got = [
        api::genesis(CELL, Chain::App),
        api::genesis(CELL, Chain::Vault),
    ];
    assert_eq!(
        got,
        [Ok(hex32(v::GENESIS_APP)), Ok(hex32(v::GENESIS_VAULT))]
    );
}

/// I-24, ADR-010: "The genesis link binds the cell and the chain". Two
/// genesis links are equal only for the same cell and chain.
#[test]
fn i24_genesis_binds_cell_and_chain() {
    check("i24_genesis_binds_cell_and_chain", |g| {
        let (c1, ch1) = (gen_cell(g), gen_chain(g));
        let (c2, ch2) = if g.bool() {
            (c1, ch1.other())
        } else {
            (gen_cell(g), gen_chain(g))
        };
        let a = answered("genesis", api::genesis(c1, ch1))?;
        let b = answered("genesis", api::genesis(c2, ch2))?;
        prop_assert_eq!(a == b, c1 == c2 && ch1 == ch2);
        prop_assert_eq!(a, r::genesis(c1, ch1));
        Ok(())
    });
}

/// ADR-010 "Chains": `App` is byte value 1 and `Vault` is 2.
#[test]
fn adr010_chain_ids_are_bytes_one_and_two() {
    let got = [api::chain_byte(Chain::App), api::chain_byte(Chain::Vault)];
    assert_eq!(got, [Ok(1), Ok(2)]);
}

// ---------------------------------------------------------------------------
// Row bytes and stored hashes.

/// I-24, ADR-010: the row bytes of both vector rows, kind 2 and kind 1.
#[test]
fn i24_row_bytes_match_recorded_vectors() {
    let got = [
        api::row_bytes(v::AT, &v::event_kind(), None),
        api::row_bytes(v::AT, &v::LEDGER_KIND, Some(&v::entry())),
    ];
    assert_eq!(got, [Ok(hex(v::ROW_EVENT)), Ok(hex(v::ROW_LEDGER))]);
}

/// I-24, ADR-010: `stored_hash_n = SHA-256(row bytes)` for both vector
/// rows.
#[test]
fn i24_stored_hash_matches_recorded_vectors() {
    let got = [
        api::stored_hash(v::AT, &v::event_kind(), None),
        api::stored_hash(v::AT, &v::LEDGER_KIND, Some(&v::entry())),
    ];
    assert_eq!(
        got,
        [Ok(hex32(v::STORED_EVENT)), Ok(hex32(v::STORED_LEDGER))]
    );
}

/// I-24, ADR-010: the production stored hash equals the test reference
/// on random rows of both kinds.
#[test]
fn i24_stored_hash_matches_test_reference() {
    check("i24_stored_hash_matches_test_reference", |g| {
        let at = g.i64();
        let (kind, entry) = gen_kind(g);
        let got = answered("stored hash", api::stored_hash(at, &kind, entry.as_ref()))?;
        prop_assert_eq!(Some(got), r::stored_hash(at, &kind, entry.as_ref()));
        Ok(())
    });
}

/// I-24, ADR-010: a kind 1 row's stored hash needs its ledger entry. A
/// row whose entry is not given has no stored hash.
#[test]
fn i24_stored_hash_of_a_ledger_row_needs_its_entry() {
    let r = api::stored_hash(v::AT, &v::LEDGER_KIND, None);
    if let Err(msg) = real_refusal("stored hash of a kind 1 row without its entry", &r) {
        panic!("{msg}");
    }
}

/// I-24, ADR-010: a kind 1 row's stored hash refuses an entry whose `seq`
/// is not the one the row names.
#[test]
fn i24_stored_hash_refuses_an_entry_of_another_seq() {
    let mut e = v::entry();
    e.seq = 8;
    let r = api::stored_hash(v::AT, &v::LEDGER_KIND, Some(&e));
    if let Err(msg) = real_refusal("stored hash of a kind 1 row with another entry", &r) {
        panic!("{msg}");
    }
}

// ---------------------------------------------------------------------------
// Links.

/// I-24, design section 7.1: `link_n = SHA-256("fstp-audit-v1" || cell ||
/// chain || be64(n) || link_{n-1} || stored_hash_n)`, against the
/// recorded vectors of App rows 1 and 2 and Vault row 1.
#[test]
fn i24_link_matches_recorded_vectors() {
    let row = |n: u64, kind: Kind, sh: &str| RowCols {
        n,
        at: v::AT,
        kind,
        stored_hash: hex32(sh),
    };
    let got = [
        api::link(
            &hex32(v::GENESIS_APP),
            CELL,
            Chain::App,
            &row(1, v::event_kind(), v::STORED_EVENT),
        ),
        api::link(
            &hex32(v::LINK1_APP),
            CELL,
            Chain::App,
            &row(2, v::LEDGER_KIND, v::STORED_LEDGER),
        ),
        api::link(
            &hex32(v::GENESIS_VAULT),
            CELL,
            Chain::Vault,
            &row(1, v::event_kind(), v::STORED_EVENT),
        ),
    ];
    assert_eq!(
        got,
        [
            Ok(hex32(v::LINK1_APP)),
            Ok(hex32(v::LINK2_APP)),
            Ok(hex32(v::LINK1_VAULT))
        ]
    );
}

/// I-24: the production link equals the test reference on random inputs.
/// The link reads the row's stored hash column, not its other columns.
#[test]
fn i24_link_matches_test_reference() {
    check("i24_link_matches_test_reference", |g| {
        let (prev, cell, chain) = (gen_hash(g), gen_cell(g), gen_chain(g));
        let (kind, _) = gen_kind(g);
        let cols = RowCols {
            n: g.u64_in(1..=u64::MAX),
            at: g.i64(),
            kind,
            stored_hash: gen_hash(g),
        };
        let got = answered("link", api::link(&prev, cell, chain, &cols))?;
        prop_assert_eq!(got, r::link(&prev, cell, chain, cols.n, &cols.stored_hash));
        Ok(())
    });
}

/// A field the link must bind (ADR-010 "Link function").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Field {
    Cell,
    Chain,
    N,
    Prev,
    RowAt,
    Kind,
    Seq,
    EventBody,
    EntryAt,
    Command,
    Schema,
    KeyIx,
    EntryBody,
}

const FIELDS: [Field; 13] = [
    Field::Cell,
    Field::Chain,
    Field::N,
    Field::Prev,
    Field::RowAt,
    Field::Kind,
    Field::Seq,
    Field::EventBody,
    Field::EntryAt,
    Field::Command,
    Field::Schema,
    Field::KeyIx,
    Field::EntryBody,
];

/// Everything one link depends on.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Input {
    cell: [u8; 16],
    chain: Chain,
    prev: Hash,
    n: u64,
    at: i64,
    kind: Kind,
    entry: Option<Entry>,
}

impl Input {
    fn link(&self) -> Result<Hash, String> {
        prod_link(
            &self.prev,
            self.cell,
            self.chain,
            self.n,
            self.at,
            &self.kind,
            self.entry.as_ref(),
        )
    }

    /// `self` with `field` changed, or `None` when it does not apply.
    fn changed(&self, field: Field) -> Option<Input> {
        let mut b = self.clone();
        match field {
            Field::Cell => b.cell[0] ^= 1,
            Field::Chain => b.chain = b.chain.other(),
            Field::N => b.n = if b.n == u64::MAX { 1 } else { b.n + 1 },
            Field::Prev => b.prev[0] ^= 1,
            Field::RowAt => b.at = b.at.wrapping_add(1),
            Field::Kind => return None,
            Field::Seq => match (&mut b.kind, b.entry.as_mut()) {
                (Kind::Ledger { seq }, Some(e)) => {
                    *seq = seq.wrapping_add(1);
                    e.seq = *seq;
                }
                _ => return None,
            },
            Field::EventBody => match &mut b.kind {
                Kind::Event { body } => body.push(0),
                Kind::Ledger { .. } => return None,
            },
            Field::EntryAt | Field::Command | Field::Schema | Field::KeyIx | Field::EntryBody => {
                let e = b.entry.as_mut()?;
                match field {
                    Field::EntryAt => e.at = e.at.wrapping_add(1),
                    Field::Command => e.command[0] ^= 1,
                    Field::Schema => e.schema = e.schema.wrapping_add(1),
                    Field::KeyIx => e.key_ix = e.key_ix.wrapping_add(1),
                    _ => e.body.push(0),
                }
            }
        }
        Some(b)
    }

    /// A kind 1 input and a kind 2 input whose payload bytes are equal.
    /// The kind 1 `seq` carries the event body length in its top four
    /// bytes, so only the kind code tells the two rows apart.
    fn kind_pair(&self) -> Option<(Input, Input)> {
        let body = match (&self.kind, self.entry.as_ref()) {
            (Kind::Ledger { .. }, Some(e)) => e.body.clone(),
            (Kind::Event { body }, _) => body.clone(),
            (Kind::Ledger { .. }, None) => return None,
        };
        // payload = be64(seq) || be64(at) || command || be16 || be32 ||
        // be32(len) || body, 42 bytes before the body.
        let payload_len = 42 + u64::try_from(body.len()).ok()?;
        let seq = (payload_len - 4) << 32;
        let entry = Entry {
            seq,
            at: self.at,
            command: [0x4B; 16],
            schema: 1,
            key_ix: 0,
            body,
        };
        let ledger = Input {
            kind: Kind::Ledger { seq },
            entry: Some(entry),
            ..self.clone()
        };
        let row = r::row_bytes(ledger.at, &ledger.kind, ledger.entry.as_ref())?;
        // The payload starts after the label, the kind code and `at`.
        let payload = row.get(r::ROW_LABEL.len() + 10..)?;
        let event = Input {
            kind: Kind::Event {
                body: payload.get(4..)?.to_vec(),
            },
            entry: None,
            ..self.clone()
        };
        Some((ledger, event))
    }
}

/// I-24, ADR-010 "The link binds every column of the chain row, apart
/// from `stored_hash` and `link` themselves, and every column of the
/// referenced ledger entry". For each field, an input that differs in it
/// gets another production link. The kind field compares a kind 1 row
/// with a kind 2 row of the same payload bytes.
#[test]
fn i24_link_binds_every_field() {
    check("i24_link_binds_every_field", |g| {
        let (kind, entry) = gen_kind(g);
        let base = Input {
            cell: gen_cell(g),
            chain: gen_chain(g),
            prev: gen_hash(g),
            n: g.u64_in(1..=u64::MAX),
            at: g.i64(),
            kind,
            entry,
        };
        for field in FIELDS {
            let (a, b) = match field {
                Field::Kind => match base.kind_pair() {
                    Some(pair) => pair,
                    None => continue,
                },
                _ => match base.changed(field) {
                    Some(b) => (base.clone(), b),
                    None => continue,
                },
            };
            prop_assert_ne!(a.link()?, b.link()?, "the link does not bind {:?}", field);
        }
        Ok(())
    });
}

// ---------------------------------------------------------------------------
// ChainWriter.

/// I-24, design section 7.1: a `ChainWriter` resumed at a head reports
/// that head. Green: the W0 stub holds it.
#[test]
fn i24_chain_writer_resume_reports_its_head() {
    check("i24_chain_writer_resume_reports_its_head", |g| {
        let (n, l) = (g.u64(), gen_hash(g));
        prop_assert_eq!(api::writer_resume_head(n, l), (n, l));
        Ok(())
    });
}

/// I-24, design section 7.1: `ChainWriter` is the only code that computes
/// links. Appending random rows from genesis gives the reference head
/// after each row, on both chains.
#[test]
fn i24_chain_writer_appends_rows_with_reference_links() {
    check("i24_chain_writer_appends_rows_with_reference_links", |g| {
        let (cell, chain) = (gen_cell(g), gen_chain(g));
        let mut head = (0u64, r::genesis(cell, chain));
        let mut want = head;
        let rows = g.usize_in(1..=6);
        for _ in 0..rows {
            let at = g.i64();
            let (kind, entry) = gen_kind(g);
            head = answered(
                "append",
                api::writer_append(head, cell, chain, at, &kind, entry.as_ref()),
            )?;
            let sh = r::stored_hash(at, &kind, entry.as_ref()).unwrap();
            want = (want.0 + 1, r::link(&want.1, cell, chain, want.0 + 1, &sh));
            prop_assert_eq!(head, want);
        }
        Ok(())
    });
}

/// I-24: the writer never wraps the row number. Appending after row
/// `u64::MAX` is refused.
#[test]
fn i24_chain_writer_refuses_to_pass_the_last_row_number() {
    let kind = v::event_kind();
    let r = api::writer_append(
        (u64::MAX, hex32(v::LINK1_APP)),
        CELL,
        Chain::App,
        v::AT,
        &kind,
        None,
    );
    if let Err(msg) = real_refusal("append after row u64::MAX", &r) {
        panic!("{msg}");
    }
}

/// I-24, ADR-010: rows of one cell's chain never link like rows of
/// another cell's or the other chain. The same rows from genesis give
/// different heads for each of the four cell and chain pairs.
#[test]
fn i24_chain_writer_heads_differ_per_cell_and_chain() {
    check("i24_chain_writer_heads_differ_per_cell_and_chain", |g| {
        let at = g.i64();
        let (kind, entry) = gen_kind(g);
        let mut heads = Vec::new();
        for cell in [CELL, OTHER_CELL] {
            for chain in Chain::ALL {
                let start = (0, answered("genesis", api::genesis(cell, chain))?);
                heads.push(answered(
                    "append",
                    api::writer_append(start, cell, chain, at, &kind, entry.as_ref()),
                )?);
            }
        }
        for (i, a) in heads.iter().enumerate() {
            prop_assert!(heads[i + 1..].iter().all(|b| b != a), "heads {heads:?}");
        }
        Ok(())
    });
}
