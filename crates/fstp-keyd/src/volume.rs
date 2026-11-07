//! The key volume rule (design section 3.3, ADR-004 part 2, Q32 A, I-81).
//!
//! ADR-004 part 2 names btrfs, ZFS, overlayfs and network filesystems as
//! unfit key volumes. No denylist can name every copy-on-write, FUSE or
//! network filesystem, so full assurance is an allowlist of ext4 and XFS,
//! as the W1d reference reads it. Since the I-81 NOTE of 2026-11-01 any
//! other volume is not refused: [`check_key_volume`] returns
//! [`Assurance::Reduced`] with a reason, and `fstp-keyd` starts and logs
//! it.
//!
//! std exposes no `statfs`, and the libc crate is allowed only in a build
//! role (ADR-001 record). So [`check_key_volume`] reads the filesystem
//! type of the mount that holds the volume from `/proc/self/mountinfo`,
//! through the in-house parser [`decode_mountinfo`]. That parser has a
//! fuzz target from its first commit (`mountinfo_decode`). ext4 with
//! `data=journal`, the mode that copies data blocks into the journal
//! (ADR-004 part 2 verify list), is never full. Only Linux has
//! `/proc/self/mountinfo`, so no other host reports full assurance.
//!
//! The magic values are `EXT4_SUPER_MAGIC` and `XFS_SUPER_MAGIC` of the
//! Linux header `include/uapi/linux/magic.h`. Lane W2f wrote them from
//! that header's text as remembered, so the check against the headers of
//! the CI image and the ADR-004 record are with the lead.
//!
//! # One decision
//!
//! [`key_volume_accepted`] is the one decision over the filesystem type,
//! and the W1 test `i81_keyd_refuses_copy_on_write_key_volume` tests it.
//! [`check_mount`], which `serve` reaches through [`check_key_volume`]
//! and [`assurance_of_mount`],
//! maps the `mountinfo` type name to the `statfs` magic that the kernel
//! reports for it ([`type_magic`]) and asks the same decision. So the
//! check that grants `Full` is the check the W1 test constrains. ext2
//! and ext3 report the ext4 magic, so `statfs` alone cannot tell them
//! from ext4. The `mountinfo` name can, and design section 3.3 (Q32 A)
//! allows ext4 and XFS only, so [`check_mount`] also requires the name to
//! be one of [`ACCEPTED_VOLUMES`]. Found by the fuzz target
//! `mountinfo_decode` in CI on 2026-10-31.

use std::path::{Component, Path, PathBuf};

use fstp_obs::assurance::{Assurance, ReducedReason};

use crate::KeydError;

/// `EXT4_SUPER_MAGIC` of `linux/magic.h`.
pub const EXT4_SUPER_MAGIC: u64 = 0xef53;
/// `XFS_SUPER_MAGIC` of `linux/magic.h`.
pub const XFS_SUPER_MAGIC: u64 = 0x5846_5342;

/// The filesystems a key volume may use, by `mountinfo` type name and
/// `statfs` magic.
pub const ACCEPTED_VOLUMES: [(&str, u64); 2] =
    [("ext4", EXT4_SUPER_MAGIC), ("xfs", XFS_SUPER_MAGIC)];

/// The `mountinfo` type names whose `statfs` magic [`type_magic`] knows.
/// ext2 and ext3 report the ext4 magic, since one driver serves all three.
/// Every other name maps to no magic and is refused.
pub const KNOWN_TYPES: [(&str, u64); 4] = [
    ("ext2", EXT4_SUPER_MAGIC),
    ("ext3", EXT4_SUPER_MAGIC),
    ("ext4", EXT4_SUPER_MAGIC),
    ("xfs", XFS_SUPER_MAGIC),
];

/// The `statfs` magic of the `mountinfo` type name `name`, if
/// [`KNOWN_TYPES`] names it.
#[must_use]
pub fn type_magic(name: &str) -> Option<u64> {
    KNOWN_TYPES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, m)| *m)
}

/// The mount options that make a key volume unsafe even on an accepted
/// filesystem: data journalling copies data blocks into the journal,
/// where an overwrite in place does not reach them.
pub const REFUSED_OPTIONS: [&str; 1] = ["data=journal"];

/// The longest `mountinfo` text the parser reads.
pub const MAX_MOUNTINFO_BYTES: usize = 4 << 20;
/// The most mounts the parser reads.
pub const MAX_MOUNTS: usize = 65_536;
/// The most fields one `mountinfo` line has.
pub const MAX_FIELDS: usize = 64;

/// Whether `fstp-keyd` accepts a key volume whose `statfs` type is
/// `magic`: only ext4 and XFS. Every other value is refused. It is the
/// one decision over the filesystem type, and [`check_mount`] asks it.
#[must_use]
pub fn key_volume_accepted(magic: u64) -> bool {
    ACCEPTED_VOLUMES.iter().any(|(_, m)| *m == magic)
}

/// One mount of `/proc/self/mountinfo`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountEntry {
    /// The mount point, unescaped.
    pub mount_point: PathBuf,
    /// The filesystem type name.
    pub fstype: String,
    /// The per-mount options and the superblock options.
    pub options: Vec<String>,
}

/// Parses `/proc/self/mountinfo`. Fuzzed (`mountinfo_decode`).
///
/// Each line is `id parent major:minor root mount-point options
/// [optional fields] - fstype source super-options`. Octal escapes such
/// as `\040` are decoded in the mount point.
///
/// # Errors
///
/// Refuses input above [`MAX_MOUNTINFO_BYTES`] or [`MAX_MOUNTS`], text
/// that is not UTF-8, a line without the ` - ` separator or with too
/// few fields, and a bad escape.
pub fn decode_mountinfo(text: &[u8]) -> Result<Vec<MountEntry>, KeydError> {
    if text.len() > MAX_MOUNTINFO_BYTES {
        return Err(KeydError::Malformed("mountinfo is too long"));
    }
    let text =
        std::str::from_utf8(text).map_err(|_| KeydError::Malformed("mountinfo is not UTF-8"))?;
    let mut out = Vec::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        if out.len() >= MAX_MOUNTS {
            return Err(KeydError::Malformed("mountinfo has too many mounts"));
        }
        out.push(decode_line(line)?);
    }
    Ok(out)
}

fn decode_line(line: &str) -> Result<MountEntry, KeydError> {
    let fields: Vec<&str> = line.split(' ').take(MAX_FIELDS.saturating_add(1)).collect();
    if fields.len() > MAX_FIELDS {
        return Err(KeydError::Malformed("a mountinfo line has too many fields"));
    }
    let sep = fields
        .iter()
        .position(|f| *f == "-")
        .ok_or(KeydError::Malformed("a mountinfo line has no separator"))?;
    let (head, tail) = fields.split_at(sep);
    let [_id, _parent, _dev, _root, mount_point, mount_options, ..] = head else {
        return Err(KeydError::Malformed("a mountinfo line has too few fields"));
    };
    let [_dash, fstype, _source, super_options] = tail else {
        return Err(KeydError::Malformed("a mountinfo line has too few fields"));
    };
    if fstype.is_empty() || mount_point.is_empty() {
        return Err(KeydError::Malformed("a mountinfo line has an empty field"));
    }
    let mut options: Vec<String> = mount_options.split(',').map(str::to_owned).collect();
    options.extend(super_options.split(',').map(str::to_owned));
    Ok(MountEntry {
        mount_point: PathBuf::from(unescape(mount_point)?),
        fstype: (*fstype).to_owned(),
        options,
    })
}

/// Decodes the octal escapes `\ooo` of a mountinfo field.
fn unescape(field: &str) -> Result<String, KeydError> {
    let bytes = field.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'\\' {
            let digits = bytes
                .get(i.saturating_add(1)..i.saturating_add(4))
                .ok_or(KeydError::Malformed("a mountinfo escape is cut short"))?;
            let mut v: u32 = 0;
            for d in digits {
                if !(b'0'..=b'7').contains(d) {
                    return Err(KeydError::Malformed("a mountinfo escape is not octal"));
                }
                v = v
                    .checked_mul(8)
                    .and_then(|v| v.checked_add(u32::from(d.saturating_sub(b'0'))))
                    .ok_or(KeydError::Malformed("a mountinfo escape is out of range"))?;
            }
            out.push(
                u8::try_from(v)
                    .map_err(|_| KeydError::Malformed("a mountinfo escape is out of range"))?,
            );
            i = i.saturating_add(4);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8(out).map_err(|_| KeydError::Malformed("a mountinfo escape is not UTF-8"))
}

/// The mount of `mounts` that holds the absolute path `path`: the one
/// with the longest mount point that is an ancestor of it, and the last
/// such line when two share a mount point, as the later mount covers the
/// earlier.
#[must_use]
pub fn mount_of<'a>(mounts: &'a [MountEntry], path: &Path) -> Option<&'a MountEntry> {
    let mut best: Option<(&MountEntry, usize)> = None;
    for m in mounts {
        if path.starts_with(&m.mount_point) {
            let depth = m
                .mount_point
                .components()
                .filter(|c| matches!(c, Component::Normal(_)))
                .count();
            if best.is_none_or(|(_, d)| depth >= d) {
                best = Some((m, depth));
            }
        }
    }
    best.map(|(m, _)| m)
}

/// Whether the mount `m` may hold a key volume: its type name is one of
/// [`ACCEPTED_VOLUMES`], its `statfs` magic passes [`key_volume_accepted`]
/// through [`type_magic`], and it does not journal data blocks. So the
/// check never accepts a type the magic decision refuses, and it refuses
/// ext2 and ext3, which share the ext4 magic.
///
/// # Errors
///
/// Returns [`KeydError::Volume`] with the rule it breaks.
pub fn check_mount(m: &MountEntry) -> Result<(), KeydError> {
    let named = ACCEPTED_VOLUMES.iter().any(|(n, _)| *n == m.fstype);
    if !named || !type_magic(&m.fstype).is_some_and(key_volume_accepted) {
        return Err(KeydError::Volume("the key volume is not on ext4 or XFS"));
    }
    if m.options
        .iter()
        .any(|o| REFUSED_OPTIONS.contains(&o.as_str()))
    {
        return Err(KeydError::Volume("the key volume journals data blocks"));
    }
    Ok(())
}

/// The reason a mount that [`check_mount`] refuses runs at reduced
/// assurance, by its `mountinfo` type name. An accepted type with
/// `data=journal` gives [`ReducedReason::DataJournal`].
#[must_use]
pub fn reduced_reason(m: &MountEntry) -> ReducedReason {
    match m.fstype.as_str() {
        "ext4" | "xfs" => ReducedReason::DataJournal,
        "ext2" => ReducedReason::Ext2,
        "ext3" => ReducedReason::Ext3,
        "btrfs" => ReducedReason::Btrfs,
        "zfs" => ReducedReason::Zfs,
        "tmpfs" | "ramfs" => ReducedReason::Tmpfs,
        "overlay" => ReducedReason::Overlay,
        "vfat" | "msdos" | "fat" => ReducedReason::Fat,
        "exfat" => ReducedReason::ExFat,
        "ntfs" | "ntfs3" => ReducedReason::Ntfs,
        "hfsplus" => ReducedReason::HfsPlus,
        "apfs" => ReducedReason::Apfs,
        "nfs" | "nfs4" | "cifs" | "smb3" | "smbfs" | "9p" | "afs" | "ceph" | "glusterfs" => {
            ReducedReason::NetworkFilesystem
        }
        t if t == "fuse" || t == "fuseblk" || t.starts_with("fuse.") => {
            ReducedReason::FuseFilesystem
        }
        _ => ReducedReason::UnknownFilesystem,
    }
}

/// The I-81 assurance of a key volume on the mount `m`. It is
/// [`Assurance::Full`] exactly when [`check_mount`] accepts the mount, so
/// [`key_volume_accepted`] stays the one decision for `Full`. Every other
/// mount runs at reduced assurance, with [`reduced_reason`].
#[must_use]
pub fn assurance_of_mount(m: &MountEntry) -> Assurance {
    match check_mount(m) {
        Ok(()) => Assurance::Full,
        Err(_) => Assurance::Reduced(reduced_reason(m)),
    }
}

/// The I-81 assurance of the key volume directory `volume` (I-81 NOTE of
/// 2026-11-01). On Linux it reads the mount that holds the volume from
/// `/proc/self/mountinfo` and asks [`assurance_of_mount`]. No other host
/// reports [`Assurance::Full`]: macOS gives [`ReducedReason::NotLinux`],
/// Windows [`ReducedReason::WindowsUnchecked`] and any other host
/// [`ReducedReason::HostUnchecked`]. A path that does not resolve gives
/// [`ReducedReason::PathUnresolved`] on every host. `fstp-keyd` starts
/// at either level and logs it.
#[must_use]
pub fn check_key_volume(volume: &Path) -> Assurance {
    let Ok(canonical) = volume.canonicalize() else {
        return Assurance::Reduced(ReducedReason::PathUnresolved);
    };
    host_assurance(&canonical)
}

#[cfg(target_os = "linux")]
fn host_assurance(canonical: &Path) -> Assurance {
    let Ok(text) = std::fs::read("/proc/self/mountinfo") else {
        return Assurance::Reduced(ReducedReason::MountTableUnreadable);
    };
    let Ok(mounts) = decode_mountinfo(&text) else {
        return Assurance::Reduced(ReducedReason::MountTableUnreadable);
    };
    match mount_of(&mounts, canonical) {
        Some(m) => assurance_of_mount(m),
        None => Assurance::Reduced(ReducedReason::NoMount),
    }
}

#[cfg(target_os = "macos")]
fn host_assurance(_canonical: &Path) -> Assurance {
    Assurance::Reduced(ReducedReason::NotLinux)
}

#[cfg(windows)]
fn host_assurance(_canonical: &Path) -> Assurance {
    Assurance::Reduced(ReducedReason::WindowsUnchecked)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
fn host_assurance(_canonical: &Path) -> Assurance {
    Assurance::Reduced(ReducedReason::HostUnchecked)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing, reason = "test code")]

    use super::*;

    const SAMPLE: &[u8] = b"22 1 8:1 / / rw,relatime - ext4 /dev/sda1 rw,errors=remount-ro\n\
36 22 98:0 /mnt1 /var/lib rw,noatime master:1 - xfs /dev/sdb1 rw,attr2\n\
37 36 98:2 / /var/lib/key\\040volume rw shared:7 master:2 - btrfs /dev/sdc1 rw\n\
38 22 98:3 / /srv/journal rw - ext4 /dev/sdd1 rw,data=journal\n";

    /// I-81, Q32 A: the mountinfo parser reads the type, the unescaped
    /// mount point and both option lists, and the mount of a path is the
    /// deepest one that holds it.
    #[test]
    fn i81_keyd_mountinfo_names_the_mount_of_the_key_volume() {
        let mounts = decode_mountinfo(SAMPLE).unwrap();
        assert_eq!(mounts.len(), 4);
        assert_eq!(mounts[2].mount_point, PathBuf::from("/var/lib/key volume"));
        assert_eq!(mounts[2].fstype, "btrfs");
        let of = |p: &str| mount_of(&mounts, Path::new(p)).unwrap().fstype.clone();
        assert_eq!(of("/var/lib/fstp-keyd"), "xfs");
        assert_eq!(of("/var/lib/key volume/keys"), "btrfs");
        assert_eq!(of("/etc"), "ext4");
        assert!(check_mount(mount_of(&mounts, Path::new("/var/lib/x")).unwrap()).is_ok());
        assert!(check_mount(mount_of(&mounts, Path::new("/var/lib/key volume")).unwrap()).is_err());
        assert!(check_mount(mount_of(&mounts, Path::new("/srv/journal/k")).unwrap()).is_err());
    }

    /// I-81 NOTE (2026-11-01): a mount reports `Full` exactly when
    /// `check_mount` accepts it, and every other mount reports `Reduced`
    /// with the reason of its type. ext2, ext3 and data journalling never
    /// report `Full`.
    #[test]
    fn i81_note_mount_assurance_is_full_only_where_check_mount_accepts() {
        let mounts = decode_mountinfo(SAMPLE).unwrap();
        let at = |p: &str| assurance_of_mount(mount_of(&mounts, Path::new(p)).unwrap());
        assert_eq!(at("/var/lib/x"), Assurance::Full);
        assert_eq!(at("/etc"), Assurance::Full);
        assert_eq!(
            at("/var/lib/key volume/k"),
            Assurance::Reduced(ReducedReason::Btrfs)
        );
        assert_eq!(
            at("/srv/journal/k"),
            Assurance::Reduced(ReducedReason::DataJournal)
        );
        for (name, reason) in [
            ("ext2", ReducedReason::Ext2),
            ("ext3", ReducedReason::Ext3),
            ("zfs", ReducedReason::Zfs),
            ("tmpfs", ReducedReason::Tmpfs),
            ("overlay", ReducedReason::Overlay),
            ("nfs4", ReducedReason::NetworkFilesystem),
            ("fuse.sshfs", ReducedReason::FuseFilesystem),
            ("vfat", ReducedReason::Fat),
            ("exfat", ReducedReason::ExFat),
            ("ntfs3", ReducedReason::Ntfs),
            ("hfsplus", ReducedReason::HfsPlus),
            ("apfs", ReducedReason::Apfs),
            ("bcachefs", ReducedReason::UnknownFilesystem),
        ] {
            let m = MountEntry {
                mount_point: PathBuf::from("/k"),
                fstype: name.to_owned(),
                options: vec!["rw".to_owned()],
            };
            assert!(check_mount(&m).is_err(), "{name}");
            assert_eq!(assurance_of_mount(&m), Assurance::Reduced(reason), "{name}");
        }
    }

    /// I-81 NOTE (2026-11-01): a key volume path that does not resolve
    /// runs at reduced assurance on every host, and only Linux can report
    /// `Full`.
    #[test]
    fn i81_note_volume_assurance_off_linux_is_never_full() {
        let gone = std::env::temp_dir().join("fstp-keyd-no-such-volume-for-i81-note");
        assert_eq!(
            check_key_volume(&gone),
            Assurance::Reduced(ReducedReason::PathUnresolved)
        );
        let here = check_key_volume(&std::env::temp_dir());
        if !cfg!(target_os = "linux") {
            assert_ne!(here, Assurance::Full);
        }
    }

    /// TH-26: lines without the separator, with too few fields or with a
    /// bad escape are refused.
    #[test]
    fn i81_keyd_mountinfo_refuses_malformed_lines() {
        for bad in [
            &b"22 1 8:1 / / rw - ext4 /dev/sda1\n"[..],
            b"22 1 8:1 / / rw ext4 /dev/sda1 rw\n",
            b"22 1 8:1 / /a\\09 rw - ext4 /dev/sda1 rw\n",
            b"22 1 / / rw - ext4 /dev/sda1 rw\n",
            b"\xff\n",
        ] {
            assert!(decode_mountinfo(bad).is_err(), "{bad:?}");
        }
    }
}
