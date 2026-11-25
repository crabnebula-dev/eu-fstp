//! The facts of the tenant admins' System page in the production cell
//! (ADR-028 record of lane L20).
//!
//! - The host status file: `fstp-admin` writes it, and the cell reads it
//!   read-only from the path that `host_status` of `cell.json` names. The
//!   grammar is `fstp_obs::host_status`, which holds no free text
//!   (R-NF-02). The cell neither logs nor quotes the file.
//! - The vault answers when it answers `epoch`, a question that names
//!   nobody.
//! - Outgoing mail works when the ADR-027 channel probe passes.
//!
//! Each live check has [`CHECK_LIMIT`], so a silent peer slows the page
//! by at most that.

use std::io::Read as _;
use std::path::Path;
use std::time::Duration;

use fstp_api_core::system::{
    ArchiveState, CustodianState, DrillStep, HostFile, HostNext, HostParts, HostReport, PartState,
    RouteState, SnapshotStep,
};
use fstp_domain::time::Timestamp;
use fstp_obs::host_status::{self, HostStatus};

/// How long one live check of the page may take.
pub(crate) const CHECK_LIMIT: Duration = Duration::from_secs(10);

fn part(s: host_status::PartState) -> PartState {
    match s {
        host_status::PartState::Running => PartState::Running,
        host_status::PartState::Unhealthy => PartState::Unhealthy,
        host_status::PartState::Stopped => PartState::Stopped,
    }
}

/// The step of a failed keystore snapshot, in the reply's words (ADR-012
/// record of lane m10/key-pin-reason).
fn snapshot_step(s: Option<fstp_obs::SnapshotFailure>) -> SnapshotStep {
    use fstp_obs::SnapshotFailure as F;
    match s {
        None => SnapshotStep::None,
        Some(F::Busy) => SnapshotStep::Busy,
        Some(F::Image) => SnapshotStep::Image,
        Some(F::Database) => SnapshotStep::Database,
        Some(F::Custody) => SnapshotStep::Custody,
        Some(F::Upload) => SnapshotStep::Upload,
        Some(F::Fetch) => SnapshotStep::Fetch,
        Some(F::Open) => SnapshotStep::Open,
        Some(F::Check) => SnapshotStep::Check,
        Some(F::Pointer) => SnapshotStep::Pointer,
    }
}

fn instant(secs: i64) -> Timestamp {
    Timestamp::from_micros(secs.saturating_mul(1_000_000))
}

/// The API core's report of a decoded file.
fn report(s: &HostStatus) -> Option<HostReport> {
    Some(HostReport {
        written_at: instant(s.written_at),
        setup_done: s.setup_done,
        parts: HostParts {
            cell: part(s.parts.cell),
            vault: part(s.parts.vault),
            witness: part(s.parts.witness),
            edge: part(s.parts.edge),
            databases: part(s.parts.databases),
            keys: part(s.parts.keys),
        },
        backups_configured: s.backups_configured,
        last_backup: s.last_backup.map(instant),
        last_key_copy: s.last_key_copy.map(instant),
        last_vault_erasure: s.last_vault_erasure.map(instant),
        last_app_snapshot: s.last_app_snapshot.map(instant),
        app_snapshot_failed: s.app_snapshot_failed,
        app_snapshot_step: snapshot_step(s.app_snapshot_step),
        last_vault_snapshot: s.last_vault_snapshot.map(instant),
        vault_snapshot_failed: s.vault_snapshot_failed,
        vault_snapshot_step: snapshot_step(s.vault_snapshot_step),
        certificate_days: s.certificate_days,
        self_signed: s.self_signed,
        route: match s.route {
            host_status::RouteState::Current => RouteState::Current,
            host_status::RouteState::Mismatch => RouteState::Mismatch,
            host_status::RouteState::Unknown => RouteState::Unknown,
        },
        next: HostNext::of(s.next.word())?,
        custodian: match s.custodian {
            host_status::CustodianState::Linked => CustodianState::Linked,
            host_status::CustodianState::Unreachable => CustodianState::Unreachable,
            host_status::CustodianState::Unpaired => CustodianState::Unpaired,
            host_status::CustodianState::NotUsed => CustodianState::NotUsed,
        },
        guard_owed: s.guard_owed,
        guard_copy_owed: s.guard_copy_owed,
        wal_archive: match s.wal_archive {
            host_status::WalArchive::Ok => ArchiveState::Ok,
            host_status::WalArchive::Late => ArchiveState::Late,
            host_status::WalArchive::Failing => ArchiveState::Failing,
            host_status::WalArchive::Unknown => ArchiveState::Unknown,
        },
        last_wal_archived: s.last_wal_archived.map(instant),
        last_drill_passed: s.last_drill_passed.map(instant),
        drill_step: match s.drill_step {
            None => DrillStep::None,
            Some(fstp_obs::drill_status::Step::Space) => DrillStep::Space,
            Some(fstp_obs::drill_status::Step::Restore) => DrillStep::Restore,
            Some(fstp_obs::drill_status::Step::Recovery) => DrillStep::Recovery,
            Some(fstp_obs::drill_status::Step::Database) => DrillStep::Database,
            Some(fstp_obs::drill_status::Step::Keystore) => DrillStep::Keystore,
            Some(fstp_obs::drill_status::Step::Cleanup) => DrillStep::Cleanup,
            Some(fstp_obs::drill_status::Step::Witness) => DrillStep::Witness,
        },
        drill_seconds: s.drill_seconds,
        witness_copy: match s.witness_copy {
            host_status::WalArchive::Ok => ArchiveState::Ok,
            host_status::WalArchive::Late => ArchiveState::Late,
            host_status::WalArchive::Failing => ArchiveState::Failing,
            host_status::WalArchive::Unknown => ArchiveState::Unknown,
        },
        last_witness_copied: s.last_witness_copied.map(instant),
    })
}

/// Reads the host status file at `path`, or says why there is none. A
/// file longer than the grammar allows is not read past its limit.
pub(crate) fn read_host_file(path: Option<&Path>) -> HostFile {
    let Some(path) = path else {
        return HostFile::NotConfigured;
    };
    let file = match std::fs::File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return HostFile::Missing,
        Err(_) => return HostFile::Unreadable,
    };
    let mut bytes = Vec::new();
    let limit = u64::try_from(host_status::MAX_LEN).unwrap_or(u64::MAX);
    if file
        .take(limit.saturating_add(1))
        .read_to_end(&mut bytes)
        .is_err()
    {
        return HostFile::Unreadable;
    }
    match host_status::decode(&bytes).ok().as_ref().and_then(report) {
        Some(r) => HostFile::Present(r),
        None => HostFile::Unreadable,
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::panic)]

    use super::*;
    use fstp_obs::host_status::{Next, Parts, encode};

    fn sample() -> HostStatus {
        HostStatus {
            written_at: 1_795_000_000,
            setup_done: true,
            parts: Parts {
                keys: host_status::PartState::Stopped,
                ..Parts::RUNNING
            },
            backups_configured: true,
            last_backup: Some(1_794_990_000),
            last_key_copy: None,
            last_vault_erasure: Some(1_794_995_000),
            last_app_snapshot: Some(1_794_996_000),
            app_snapshot_failed: false,
            app_snapshot_step: None,
            last_vault_snapshot: None,
            vault_snapshot_failed: true,
            vault_snapshot_step: Some(fstp_obs::SnapshotFailure::Pointer),
            certificate_days: Some(4),
            self_signed: true,
            route: host_status::RouteState::Current,
            next: Next::CopyKeys,
            custodian: host_status::CustodianState::Unpaired,
            guard_owed: false,
            guard_copy_owed: false,
            wal_archive: host_status::WalArchive::Failing,
            last_wal_archived: Some(1_794_998_000),
            last_drill_passed: Some(1_794_000_000),
            drill_step: Some(fstp_obs::drill_status::Step::Cleanup),
            drill_seconds: Some(412),
            witness_copy: host_status::WalArchive::Late,
            last_witness_copied: Some(1_794_997_000),
        }
    }

    fn temp(name: &str) -> std::path::PathBuf {
        let tag = fstp_crypto::random_array::<6>().unwrap();
        std::env::temp_dir().join(format!(
            "fstp-l20-{name}-{}",
            tag.iter().map(|b| format!("{b:02x}")).collect::<String>()
        ))
    }

    /// ADR-028 record of lane L20, R-NF-02: the cell reads the four states
    /// of the host status file, and maps a present one field by field.
    /// Every next word of `fstp-obs` is a word of the reply.
    #[test]
    fn adr028_l20_host_status_read_states() {
        assert_eq!(read_host_file(None), HostFile::NotConfigured);
        let missing = temp("missing");
        assert_eq!(read_host_file(Some(&missing)), HostFile::Missing);
        let bad = temp("bad");
        std::fs::write(&bad, b"{\"email\":\"a@example.eu\"}").unwrap();
        assert_eq!(read_host_file(Some(&bad)), HostFile::Unreadable);
        let long = temp("long");
        let mut text = encode(&sample()).into_bytes();
        text.extend(std::iter::repeat_n(b' ', host_status::MAX_LEN));
        std::fs::write(&long, &text).unwrap();
        assert_eq!(read_host_file(Some(&long)), HostFile::Unreadable);
        let good = temp("good");
        std::fs::write(&good, encode(&sample())).unwrap();
        let HostFile::Present(r) = read_host_file(Some(&good)) else {
            panic!("a present file");
        };
        assert_eq!(r.written_at, Timestamp::from_micros(1_795_000_000_000_000));
        assert_eq!(r.parts.keys, PartState::Stopped);
        assert_eq!(r.parts.cell, PartState::Running);
        assert_eq!(r.last_key_copy, None);
        // ADR-028 record of lane L26: the keystore snapshots of L27.
        assert_eq!(
            r.last_app_snapshot,
            Some(Timestamp::from_micros(1_794_996_000_000_000))
        );
        assert!(!r.app_snapshot_failed);
        assert_eq!(r.last_vault_snapshot, None);
        assert!(r.vault_snapshot_failed);
        // ADR-012 record of lane m10/key-pin-reason: where each failed.
        assert_eq!(r.app_snapshot_step, SnapshotStep::None);
        assert_eq!(r.vault_snapshot_step, SnapshotStep::Pointer);
        for f in fstp_obs::SnapshotFailure::ALL {
            assert_eq!(snapshot_step(Some(f)).wire(), f.as_str());
            assert_eq!(SnapshotStep::of(f.as_str()), Some(snapshot_step(Some(f))));
        }
        assert_eq!(r.certificate_days, Some(4));
        assert!(r.self_signed);
        // ADR-028 record of lane `m10/backup-health`: the WAL archive.
        assert_eq!(r.wal_archive, ArchiveState::Failing);
        assert_eq!(
            r.last_wal_archived,
            Some(Timestamp::from_micros(1_794_998_000_000_000))
        );
        assert_eq!(
            r.last_drill_passed,
            Some(Timestamp::from_micros(1_794_000_000_000_000))
        );
        assert_eq!(r.drill_step, DrillStep::Cleanup);
        assert_eq!(r.drill_seconds, Some(412));
        // ADR-028 record of lane `m10/witness-copy`: the witness copy.
        assert_eq!(r.witness_copy, ArchiveState::Late);
        assert_eq!(
            r.last_witness_copied,
            Some(Timestamp::from_micros(1_794_997_000_000_000))
        );
        assert_eq!(r.next.wire(), "copy_keys");
        for n in Next::ALL {
            assert_eq!(HostNext::of(n.word()).map(HostNext::wire), Some(n.word()));
        }
        for p in [bad, long, good] {
            let _ = std::fs::remove_file(p);
        }
    }
}
