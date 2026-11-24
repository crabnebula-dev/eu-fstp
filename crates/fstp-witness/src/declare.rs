//! `declare-restore`: the root-only console command that records a
//! declared restore at a self-hosted witness (ADR-012 record of lane
//! m10/declared-restore, ADR-010 "Self-hosted witness"). Every reading
//! here is interim, pending Daniel.
//!
//! ```text
//! fstp-witness declare-restore <cell> <app|vault> <head n> <head link> <job>
//! ```
//!
//! The cell is 32 lowercase hex digits, the head link 64 and the job 32.
//! The head row is a decimal number with no sign and no leading zero.
//! `fstp-admin restore` runs it as root through the witness OS user,
//! after the restored database is promoted and while the witness is
//! stopped. The running witness holds each chain in memory, so a record
//! appended behind it would break the store's witness sequence.
//!
//! The command loads the whole file store first and refuses a store that
//! does not load. It then opens the receipt key through the witness's own
//! `fstp-keyd` entry, signs the declaration with it under
//! `fstp_audit::witness::RESTORE_CONTEXT` and appends one record. A
//! self-hosted host has no restore declaration key, so the receipt key
//! signs. Only root reaches the command, which keeps the claim within the
//! host-root scope of ADR-010 open point 7.
//!
//! Like the install commands, it writes no output (R-NF-02). Its exit
//! status says whether the record was written. The cell and the vault
//! report the lost window, from the record, at their next start.

use fstp_audit::witness::{Declaration, sign_declaration};
use fstp_audit::{CellId, ChainId, CompositeSigningKey, Link};
use fstp_custody::Custody as _;

use crate::WitnessError;
use crate::chain_witness::{ChainWitness, DeclareRefusal};
use crate::config::{self, WitnessStore};
use crate::file_store::FileStore;
use crate::install::unhex;

/// The arguments of `declare-restore`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeclareArgs {
    /// The cell.
    pub cell: CellId,
    /// The chain.
    pub chain: ChainId,
    /// The head the restored chain resumes from.
    pub head: (u64, Link),
    /// The restore job.
    pub job: [u8; 16],
}

fn hex_array<const N: usize>(t: &str) -> Option<[u8; N]> {
    if t.len() != N.checked_mul(2)? {
        return None;
    }
    <[u8; N]>::try_from(unhex(t)?.as_slice()).ok()
}

/// A decimal row number with one spelling: digits only, no leading zero
/// unless it is `0`, and no more than `u64::MAX`.
fn decimal(t: &str) -> Option<u64> {
    let canonical =
        !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit()) && (t == "0" || !t.starts_with('0'));
    if canonical { t.parse().ok() } else { None }
}

/// Parses the five arguments after `declare-restore`. Fuzzed
/// (`declare_args_parse`).
///
/// # Errors
///
/// [`WitnessError::Config`] naming `arguments` for any other input.
pub fn parse_args(args: &[&str]) -> Result<DeclareArgs, WitnessError> {
    let bad = WitnessError::Config("arguments");
    let [cell, chain, n, link, job] = args else {
        return Err(bad);
    };
    let chain = match *chain {
        "app" => ChainId::App,
        "vault" => ChainId::Vault,
        _ => return Err(bad),
    };
    Ok(DeclareArgs {
        cell: CellId(hex_array(cell).ok_or(bad)?),
        chain,
        head: (decimal(n).ok_or(bad)?, Link(hex_array(link).ok_or(bad)?)),
        job: hex_array(job).ok_or(bad)?,
    })
}

/// Records the declaration of `a` in `store`, signed with `key`, at
/// `now`. The chain is loaded from the store, so the head is checked
/// against the witness log as the store holds it.
///
/// # Errors
///
/// [`WitnessError::Store`] when the chain does not load or the record
/// does not write, [`WitnessError::Invalid`] naming
/// `DeclarationShape` when the witness core refuses the head or the
/// chain holds the most declarations, and [`WitnessError::Signing`].
pub fn declare(
    store: &FileStore,
    key: &CompositeSigningKey,
    a: &DeclareArgs,
    now: i64,
) -> Result<Declaration, WitnessError> {
    let registered = store
        .load_registry()
        .map_err(WitnessError::Store)?
        .into_iter()
        .any(|c| c.cell == a.cell && c.revoked_at.is_none());
    if !registered {
        return Err(WitnessError::Config("cell"));
    }
    let loaded = store
        .load_chain(a.cell, a.chain)
        .map_err(WitnessError::Store)?;
    let mut core = ChainWitness::resume(a.cell, a.chain, loaded.state);
    let fields = core
        .declare_restore(&loaded.log, a.head, a.job, now)
        .map_err(|e| match e {
            DeclareRefusal::NotLive | DeclareRefusal::TooMany | DeclareRefusal::Exhausted => {
                WitnessError::Invalid(fstp_audit::Invalid::DeclarationShape)
            }
        })?;
    let d = sign_declaration(key, a.cell, a.chain, &fields).map_err(|e| match e {
        fstp_audit::AuditError::Signing(c) => WitnessError::Signing(c),
        _ => WitnessError::Invalid(fstp_audit::Invalid::DeclarationShape),
    })?;
    store
        .append_declaration(a.cell, a.chain, &d)
        .map_err(WitnessError::Store)?;
    Ok(d)
}

fn now_us() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// `declare-restore <cell> <app|vault> <head n> <head link> <job>`
/// (module documentation).
///
/// # Errors
///
/// [`WitnessError::Config`] for a SaaS witness, a malformed argument or an
/// unknown cell, [`WitnessError::Custody`] when custody does not unwrap
/// the receipt key, and the errors of [`declare`].
pub fn run(args: &[&str]) -> Result<(), WitnessError> {
    let a = parse_args(args)?;
    let path =
        std::env::var_os(crate::CONFIG_ENV).ok_or(WitnessError::Config(crate::CONFIG_ENV))?;
    let bytes = std::fs::read(&path).map_err(|_| WitnessError::Config(crate::CONFIG_ENV))?;
    let cfg = config::decode_config(&bytes)?;
    let WitnessStore::Files { dir } = &cfg.store else {
        return Err(WitnessError::Config("store"));
    };
    // The whole store loads first, so a damaged store is never written.
    let store = FileStore::open(dir).map_err(WitnessError::Store)?;
    let key_bytes = std::fs::read(cfg.credentials_dir.join(config::RECEIPT_KEY_FILE))
        .map_err(|_| WitnessError::Config(config::RECEIPT_KEY_FILE))?;
    let key_file = config::decode_receipt_key_file(&key_bytes)?;
    let custody = fstp_custody::keyd::KeydCustody::new(&cfg.keyd_socket)
        .map_err(|_| WitnessError::Config("keyd_socket"))?;
    let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1)
        .map_err(|e| WitnessError::Io(e.kind()))?;
    let seal = rt.block_on(async {
        custody
            .unwrap(
                &config::root_of(&key_file),
                &fstp_custody::WrappedSealKey(key_file.wrapped.clone()),
                &fstp_custody::Aad(config::wrap_aad(key_file.epoch)),
            )
            .await
            .map_err(|_| WitnessError::Custody)
    })?;
    let key = config::open_receipt_key(&key_file, &seal)?;
    drop(seal);
    declare(&store, &key, &a, now_us()).map(drop)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    const CELL: &str = "0123456789abcdef0123456789abcdef";
    const LINK: &str = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
    const JOB: &str = "ffeeddccbbaa99887766554433221100";

    /// ADR-012 record of lane m10/declared-restore: the arguments have one
    /// spelling each.
    #[test]
    fn adr012_declare_restore_arguments_have_one_spelling() {
        let a = parse_args(&[CELL, "vault", "42", LINK, JOB]).unwrap();
        assert_eq!(a.chain, ChainId::Vault);
        assert_eq!(a.head.0, 42);
        assert_eq!(a.cell.0[0], 0x01);
        assert_eq!(a.job[0], 0xff);
        assert_eq!(
            parse_args(&[CELL, "app", "0", LINK, JOB]).unwrap().head.0,
            0
        );
        for bad in [
            [CELL, "App", "42", LINK, JOB],
            [CELL, "app", "042", LINK, JOB],
            [CELL, "app", "+42", LINK, JOB],
            [CELL, "app", "", LINK, JOB],
            [CELL, "app", "18446744073709551616", LINK, JOB],
            ["0123456789ABCDEF0123456789abcdef", "app", "1", LINK, JOB],
            [CELL, "app", "1", &LINK[2..], JOB],
            [CELL, "app", "1", LINK, "ff"],
        ] {
            assert!(parse_args(&bad).is_err(), "{bad:?}");
        }
        assert!(parse_args(&[CELL, "app", "1", LINK]).is_err());
    }
}
