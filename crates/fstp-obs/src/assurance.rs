//! The deployment mode and the key custody assurance (I-81 NOTE of
//! 2026-11-01, design 21.0 row "Hardware and development mode", ADR-004
//! part 2).
//!
//! Daniel decided on 2026-11-01 that the platform runs on any hardware.
//! File custody meets I-81 in full only on a Linux key volume of ext4 or
//! XFS. Anywhere else `fstp-keyd` still starts and reports
//! [`Assurance::Reduced`] with a [`ReducedReason`]. Every type here is a
//! closed enum whose text is a constant, so the start event that carries
//! them holds no free text (R-NF-02).
//!
//! A process takes its [`DeploymentMode`] from [`MODE_ENV`]
//! ([`deployment_mode_from_env`]). A release build refuses an unset or
//! misspelt mode, so it never falls back to development in silence. A
//! debug build without the variable runs in development mode and logs
//! [`HostCheck::DeploymentModeUnset`].

use std::ffi::OsStr;

/// The variable that names the deployment mode: `production` or
/// `development`, in that spelling only.
pub const MODE_ENV: &str = "FSTP_DEPLOYMENT_MODE";

/// How a deployment runs. Authorisation, step-up and every domain
/// invariant are enforced in both modes. In development mode a host or
/// platform check warns and never stops a start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DeploymentMode {
    /// A deployment that serves real users.
    Production,
    /// A developer's own machine or a test run.
    Development,
}

impl DeploymentMode {
    /// The mode as [`MODE_ENV`] spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Production => "production",
            Self::Development => "development",
        }
    }

    /// The mode of its one spelling, or `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "production" => Some(Self::Production),
            "development" => Some(Self::Development),
            _ => None,
        }
    }
}

/// A mode a process runs in, and whether it was defaulted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeChoice {
    /// The mode.
    pub mode: DeploymentMode,
    /// True when [`MODE_ENV`] was unset in a debug build, so the mode is
    /// development by default. The process logs
    /// [`HostCheck::DeploymentModeUnset`] then.
    pub defaulted: bool,
}

/// Why no deployment mode could be chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ModeError {
    /// A release build found [`MODE_ENV`] unset.
    Unset,
    /// [`MODE_ENV`] holds neither spelling.
    Invalid,
}

impl std::fmt::Display for ModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unset => write!(f, "{MODE_ENV} is unset; a release build needs it"),
            Self::Invalid => write!(f, "{MODE_ENV} is neither production nor development"),
        }
    }
}

impl std::error::Error for ModeError {}

/// The mode for the value `value` of [`MODE_ENV`], in a release build
/// when `release` is true. An unset value is development in a debug build
/// and refused in a release build.
///
/// # Errors
///
/// [`ModeError::Unset`] for an unset value in a release build, and
/// [`ModeError::Invalid`] for any value but the two spellings.
pub fn resolve_mode(value: Option<&OsStr>, release: bool) -> Result<ModeChoice, ModeError> {
    match value {
        Some(v) => {
            let mode = v
                .to_str()
                .and_then(DeploymentMode::parse)
                .ok_or(ModeError::Invalid)?;
            Ok(ModeChoice {
                mode,
                defaulted: false,
            })
        }
        None if release => Err(ModeError::Unset),
        None => Ok(ModeChoice {
            mode: DeploymentMode::Development,
            defaulted: true,
        }),
    }
}

/// The mode of this process, from [`MODE_ENV`] ([`resolve_mode`]). A
/// build without debug assertions counts as a release build.
///
/// # Errors
///
/// As [`resolve_mode`].
pub fn deployment_mode_from_env() -> Result<ModeChoice, ModeError> {
    let value = std::env::var_os(MODE_ENV);
    resolve_mode(value.as_deref(), !cfg!(debug_assertions))
}

/// Why key custody runs at reduced assurance for I-81.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReducedReason {
    /// The key volume is APFS.
    Apfs,
    /// The key volume is HFS+.
    HfsPlus,
    /// The key volume is NTFS.
    Ntfs,
    /// The key volume is FAT.
    Fat,
    /// The key volume is exFAT.
    ExFat,
    /// The key volume is btrfs.
    Btrfs,
    /// The key volume is ZFS.
    Zfs,
    /// The key volume is tmpfs.
    Tmpfs,
    /// The key volume is an overlay mount.
    Overlay,
    /// The key volume is ext2.
    Ext2,
    /// The key volume is ext3.
    Ext3,
    /// The key volume is a network filesystem.
    NetworkFilesystem,
    /// The key volume is a FUSE filesystem.
    FuseFilesystem,
    /// The key volume's filesystem type is none the check knows.
    UnknownFilesystem,
    /// The key volume is ext4 mounted with `data=journal`.
    DataJournal,
    /// The key volume is ext4 or XFS on a host that is not Linux.
    NotLinux,
    /// The host is Windows, where the type is not checked.
    WindowsUnchecked,
    /// The host is neither Linux, macOS nor Windows.
    HostUnchecked,
    /// The host's mount table could not be read or parsed.
    MountTableUnreadable,
    /// No mount of the mount table holds the key volume.
    NoMount,
    /// The key volume path does not resolve.
    PathUnresolved,
    /// The key volume is a fresh directory under the system temporary
    /// directory, made in development mode.
    TemporaryVolume,
}

impl ReducedReason {
    /// Every reason, in code order.
    pub const ALL: [ReducedReason; 22] = [
        Self::Apfs,
        Self::HfsPlus,
        Self::Ntfs,
        Self::Fat,
        Self::ExFat,
        Self::Btrfs,
        Self::Zfs,
        Self::Tmpfs,
        Self::Overlay,
        Self::Ext2,
        Self::Ext3,
        Self::NetworkFilesystem,
        Self::FuseFilesystem,
        Self::UnknownFilesystem,
        Self::DataJournal,
        Self::NotLinux,
        Self::WindowsUnchecked,
        Self::HostUnchecked,
        Self::MountTableUnreadable,
        Self::NoMount,
        Self::PathUnresolved,
        Self::TemporaryVolume,
    ];

    /// The reason as a sentence for an operator or a tenant admin, such
    /// as "APFS is copy-on-write".
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Apfs => "APFS is copy-on-write",
            Self::HfsPlus => "HFS+ is not ext4 or XFS",
            Self::Ntfs => "NTFS is not ext4 or XFS",
            Self::Fat => "FAT is not ext4 or XFS",
            Self::ExFat => "exFAT is not ext4 or XFS",
            Self::Btrfs => "btrfs is copy-on-write",
            Self::Zfs => "ZFS is copy-on-write",
            Self::Tmpfs => "tmpfs is not ext4 or XFS",
            Self::Overlay => "overlay is not ext4 or XFS",
            Self::Ext2 => "ext2 is not ext4 or XFS",
            Self::Ext3 => "ext3 is not ext4 or XFS",
            Self::NetworkFilesystem => "a network filesystem is not ext4 or XFS",
            Self::FuseFilesystem => "a FUSE filesystem is not ext4 or XFS",
            Self::UnknownFilesystem => "the filesystem type is unknown",
            Self::DataJournal => "ext4 with data=journal copies data blocks into the journal",
            Self::NotLinux => "full assurance is checked only on Linux",
            Self::WindowsUnchecked => "the filesystem type is not checked on Windows",
            Self::HostUnchecked => "the filesystem type is not checked on this host",
            Self::MountTableUnreadable => "the mount table could not be read",
            Self::NoMount => "no mount holds the key volume",
            Self::PathUnresolved => "the key volume path does not resolve",
            Self::TemporaryVolume => "the key volume is a fresh temporary directory",
        }
    }

    /// The one-byte code of the reason, from 1.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::Apfs => 1,
            Self::HfsPlus => 2,
            Self::Ntfs => 3,
            Self::Fat => 4,
            Self::ExFat => 5,
            Self::Btrfs => 6,
            Self::Zfs => 7,
            Self::Tmpfs => 8,
            Self::Overlay => 9,
            Self::Ext2 => 10,
            Self::Ext3 => 11,
            Self::NetworkFilesystem => 12,
            Self::FuseFilesystem => 13,
            Self::UnknownFilesystem => 14,
            Self::DataJournal => 15,
            Self::NotLinux => 16,
            Self::WindowsUnchecked => 17,
            Self::HostUnchecked => 18,
            Self::MountTableUnreadable => 19,
            Self::NoMount => 20,
            Self::PathUnresolved => 21,
            Self::TemporaryVolume => 22,
        }
    }

    /// The reason of `code`, or `None`.
    #[must_use]
    pub fn from_code(code: u8) -> Option<Self> {
        Self::ALL.into_iter().find(|r| r.code() == code)
    }
}

/// The I-81 assurance of a key custody backend.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Assurance {
    /// I-81 is met in full: a Linux key volume of ext4 or XFS without
    /// data journalling. The install still must keep it out of every
    /// backup and snapshot (ADR-004 part 2).
    Full,
    /// Key custody runs, but I-81 is not met in full, for the reason.
    Reduced(ReducedReason),
}

/// The level byte of [`Assurance::Full`] on the wire.
pub const ASSURANCE_FULL: u8 = 1;
/// The level byte of [`Assurance::Reduced`] on the wire.
pub const ASSURANCE_REDUCED: u8 = 2;

impl Assurance {
    /// The level as a word: `full` or `reduced`.
    #[must_use]
    pub const fn level(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Reduced(_) => "reduced",
        }
    }

    /// The reason, or `None` at full assurance.
    #[must_use]
    pub const fn reason(self) -> Option<ReducedReason> {
        match self {
            Self::Full => None,
            Self::Reduced(r) => Some(r),
        }
    }

    /// The two wire bytes: the level, then the reason code or 0.
    #[must_use]
    pub const fn encode(self) -> [u8; 2] {
        match self {
            Self::Full => [ASSURANCE_FULL, 0],
            Self::Reduced(r) => [ASSURANCE_REDUCED, r.code()],
        }
    }

    /// The assurance of its two wire bytes, in their one spelling.
    #[must_use]
    pub fn decode(bytes: [u8; 2]) -> Option<Self> {
        match bytes {
            [ASSURANCE_FULL, 0] => Some(Self::Full),
            [ASSURANCE_REDUCED, code] => ReducedReason::from_code(code).map(Self::Reduced),
            _ => None,
        }
    }
}

/// A host or platform check that warned instead of stopping a start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HostCheck {
    /// [`MODE_ENV`] is unset, so a debug build runs in development mode.
    DeploymentModeUnset,
    /// No key volume is named, so development mode made a fresh
    /// temporary one.
    KeyVolumeTemporary,
    /// The socket directory is missing, so development mode made a fresh
    /// temporary one.
    SocketDirTemporary,
    /// No passphrase source answered, so development mode made a random
    /// passphrase for the fresh temporary key volume. That key table
    /// cannot reopen after the process ends.
    PassphraseEphemeral,
}

impl HostCheck {
    /// The check as a `snake_case` word.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::DeploymentModeUnset => "deployment_mode_unset",
            Self::KeyVolumeTemporary => "key_volume_temporary",
            Self::SocketDirTemporary => "socket_dir_temporary",
            Self::PassphraseEphemeral => "passphrase_ephemeral",
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use super::*;

    /// I-81 NOTE (2026-11-01): every reduced reason has its own code and
    /// sentence, and the wire form round-trips in one spelling only.
    #[test]
    fn i81_assurance_codes_round_trip_in_one_spelling() {
        let mut codes = std::collections::BTreeSet::new();
        let mut texts = std::collections::BTreeSet::new();
        for r in ReducedReason::ALL {
            assert!(codes.insert(r.code()), "{r:?} shares a code");
            assert!(texts.insert(r.as_str()), "{r:?} shares a sentence");
            assert_eq!(ReducedReason::from_code(r.code()), Some(r));
            let a = Assurance::Reduced(r);
            assert_eq!(Assurance::decode(a.encode()), Some(a));
        }
        assert_eq!(Assurance::decode(Assurance::Full.encode()), Some(Assurance::Full));
        for level in 0..=u8::MAX {
            for code in 0..=u8::MAX {
                if let Some(a) = Assurance::decode([level, code]) {
                    assert_eq!(a.encode(), [level, code]);
                }
            }
        }
        assert_eq!(ReducedReason::from_code(0), None);
    }

    /// I-81 NOTE (2026-11-01): the reasons name the common filesystems,
    /// and the copy-on-write ones say so.
    #[test]
    fn i81_reasons_name_the_common_filesystems() {
        assert_eq!(ReducedReason::Apfs.as_str(), "APFS is copy-on-write");
        assert_eq!(ReducedReason::Btrfs.as_str(), "btrfs is copy-on-write");
        assert_eq!(ReducedReason::Zfs.as_str(), "ZFS is copy-on-write");
        assert_eq!(
            ReducedReason::WindowsUnchecked.as_str(),
            "the filesystem type is not checked on Windows"
        );
        for (r, name) in [
            (ReducedReason::HfsPlus, "HFS+"),
            (ReducedReason::Ntfs, "NTFS"),
            (ReducedReason::Fat, "FAT"),
            (ReducedReason::ExFat, "exFAT"),
            (ReducedReason::Tmpfs, "tmpfs"),
            (ReducedReason::Overlay, "overlay"),
            (ReducedReason::UnknownFilesystem, "unknown"),
        ] {
            assert!(r.as_str().contains(name), "{r:?}: {}", r.as_str());
        }
    }

    /// Design 21.0 (2026-11-01): the mode is explicit. A release build
    /// refuses an unset mode, so it never runs in development mode in
    /// silence. Only the two spellings are accepted.
    #[test]
    fn i81_note_release_build_never_defaults_to_development() {
        assert_eq!(resolve_mode(None, true), Err(ModeError::Unset));
        assert_eq!(
            resolve_mode(None, false),
            Ok(ModeChoice {
                mode: DeploymentMode::Development,
                defaulted: true
            })
        );
        for release in [false, true] {
            for (text, mode) in [
                ("production", DeploymentMode::Production),
                ("development", DeploymentMode::Development),
            ] {
                assert_eq!(
                    resolve_mode(Some(OsStr::new(text)), release),
                    Ok(ModeChoice {
                        mode,
                        defaulted: false
                    })
                );
            }
            for bad in ["", "Production", "dev", "prod", " production", "development\n"] {
                assert_eq!(
                    resolve_mode(Some(OsStr::new(bad)), release),
                    Err(ModeError::Invalid),
                    "{bad:?}"
                );
            }
        }
    }
}
