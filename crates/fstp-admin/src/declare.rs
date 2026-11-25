//! The declared restore of `fstp-admin restore` (ADR-012 record of lane
//! m10/declared-restore). Every reading here is interim, pending Daniel.
//!
//! After both clusters are restored, promoted and their keys kept, and
//! while the cell and the vault are stopped, `fstp-admin`:
//!
//! 1. reads the head of each restored chain, `audit.chain` of the cell
//!    database and `vault_audit.chain` of the vault database, with `psql`;
//! 2. stops the witness, which holds each chain in memory;
//! 3. runs `fstp-witness declare-restore` for the App and the Vault chain,
//!    under one job of 16 random bytes;
//! 4. leaves the start of every service to the restore, which follows.
//!
//! The cell and the vault then start. Each lost window is recorded in
//! their audit chains, and tenant admins acknowledge it on the System
//! page. `fstp-admin` holds no witness key: the witness's own binary
//! signs.

use crate::fail::{Cause, Fail};
use crate::layout::{Cluster, Layout};
use crate::stack;
use crate::svc::Manager;

/// The label of a chain's genesis link (`fstp_audit::chain::GENESIS_LABEL`).
const GENESIS_LABEL: &[u8] = b"fstp-audit-genesis-v1";

/// The head of a restored chain, as `psql` prints it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Head {
    /// The chain has no row.
    Empty,
    /// The last row's number and its link in lowercase hex.
    At(u64, String),
}

/// The query that prints the head of `c`'s chain: nothing for an empty
/// chain, or `<n> <64 hex digits>`.
#[must_use]
pub fn head_sql(c: Cluster) -> &'static str {
    match c {
        Cluster::App => {
            "SELECT n || ' ' || encode(link, 'hex') FROM audit.chain ORDER BY n DESC LIMIT 1;\n"
        }
        Cluster::Vault => {
            "SELECT n || ' ' || encode(link, 'hex') FROM vault_audit.chain ORDER BY n DESC LIMIT 1;\n"
        }
    }
}

/// Reads what [`head_sql`] printed. One spelling: an empty text, or a
/// decimal row number from 1 with no leading zero, one space and 64
/// lowercase hex digits. Fuzzed (`chain_head_parse`).
#[must_use]
pub fn parse_head(text: &str) -> Option<Head> {
    if text.is_empty() {
        return Some(Head::Empty);
    }
    let (n, link) = text.split_once(' ')?;
    let digits = !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()) && !n.starts_with('0');
    let hex = link.len() == 64 && link.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
    if !digits || !hex {
        return None;
    }
    Some(Head::At(n.parse().ok()?, link.to_owned()))
}

/// The chain byte of `c` (`fstp_audit::ChainId::byte`).
const fn chain_byte(c: Cluster) -> u8 {
    match c {
        Cluster::App => 1,
        Cluster::Vault => 2,
    }
}

/// The chain word of `fstp-witness declare-restore`.
const fn chain_word(c: Cluster) -> &'static str {
    match c {
        Cluster::App => "app",
        Cluster::Vault => "vault",
    }
}

/// The genesis link of `c`'s chain of `cell`, in lowercase hex.
#[must_use]
pub fn genesis_hex(cell: &[u8; 16], c: Cluster) -> String {
    let mut bytes = GENESIS_LABEL.to_vec();
    bytes.extend_from_slice(cell);
    bytes.push(chain_byte(c));
    crate::pki::hex(&fstp_crypto::sha256(&bytes))
}

/// The arguments after `declare-restore` for `c`'s chain at `head`.
#[must_use]
pub fn witness_args(cell: &[u8; 16], c: Cluster, head: &Head, job: &str) -> Vec<String> {
    let (n, link) = match head {
        Head::Empty => (0, genesis_hex(cell, c)),
        Head::At(n, link) => (*n, link.clone()),
    };
    vec![
        crate::pki::hex(cell),
        chain_word(c).to_owned(),
        n.to_string(),
        link,
        job.to_owned(),
    ]
}

/// Steps 1 to 3 of the module documentation, for both chains of `cell`.
/// The witness is left stopped: the restore starts every service next.
///
/// # Errors
///
/// [`Fail::Step`] naming `declare restore` when a head does not read or
/// the witness refuses a declaration.
pub fn declare_both(layout: &Layout, m: &Manager, cell: &[u8; 16]) -> Result<(), Fail> {
    let step = |c: Cause| Fail::Step("declare restore", c);
    let mut heads = Vec::with_capacity(2);
    for c in Cluster::ALL {
        let text = crate::pg::psql(
            layout,
            c,
            &crate::pg::dbname(c, cell),
            head_sql(c),
            "the head of the restored chain",
        )
        .map_err(|e| step(e.into()))?;
        heads.push((c, parse_head(&text).ok_or_else(|| step(Cause::Io))?));
    }
    let job = crate::pki::random_hex(16).map_err(|e| step(Cause::Pki(e)))?;
    m.stop(&stack::witness(layout))
        .map_err(|e| step(e.into()))?;
    for (c, head) in &heads {
        crate::witness::declare_restore(layout, &witness_args(cell, *c, head, &job))
            .map_err(|e| step(e.into()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const LINK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";

    /// ADR-012 record of lane m10/declared-restore: the head of a restored
    /// chain reads in one spelling, and an empty chain is declared at its
    /// genesis link, as `fstp_audit::chain::genesis` computes it.
    #[test]
    fn adr012_declare_restore_reads_the_restored_head() {
        assert_eq!(parse_head(""), Some(Head::Empty));
        assert_eq!(
            parse_head(&format!("42 {LINK}")),
            Some(Head::At(42, LINK.to_owned()))
        );
        for bad in [
            format!("042 {LINK}"),
            format!("0 {LINK}"),
            format!("42  {LINK}"),
            format!("42 {}", LINK.to_uppercase()),
            format!("42 {}", &LINK[2..]),
            format!("42 {LINK}\n"),
            "42".to_owned(),
        ] {
            assert_eq!(parse_head(&bad), None, "{bad:?}");
        }
        assert_eq!(
            genesis_hex(&[0; 16], Cluster::Vault),
            "91f58a5e70f7568fa5f157d72adbeaabceebfbd6107d34f9ce485571bec07366"
        );
        let job = "ab".repeat(16);
        assert_eq!(
            witness_args(&[1; 16], Cluster::App, &Head::At(7, LINK.to_owned()), &job),
            vec![
                "01".repeat(16),
                "app".to_owned(),
                "7".to_owned(),
                LINK.to_owned(),
                job.clone()
            ]
        );
        assert_eq!(
            witness_args(&[0; 16], Cluster::Vault, &Head::Empty, &job)[2..4],
            ["0".to_owned(), genesis_hex(&[0; 16], Cluster::Vault)]
        );
    }
}
