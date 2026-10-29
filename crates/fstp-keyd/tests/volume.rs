//! The key volume rule of `fstp-keyd` (design section 3.3, ADR-004 part 2,
//! Q32 A, I-81).
//!
//! ADR-004 part 2: "`fstp-keyd` refuses to start if the key volume is
//! btrfs, ZFS, overlayfs or a network filesystem." The W1d reference
//! reads that as an allowlist of ext4 and XFS, since no denylist can name
//! every copy-on-write, FUSE or network filesystem. This test follows
//! that reading, and so is a property over every `statfs` type value.
//!
//! The magic values below were written from memory, as the W1d reference
//! wrote them (`EXT4_SUPER_MAGIC` and `XFS_SUPER_MAGIC` of
//! `linux/magic.h`). Lane W2f checks them against the kernel headers of
//! the CI image and records them in ADR-004.
//!
//! Lane W2f exposed the pure check `fstp_keyd::key_volume_accepted`,
//! which [`volume_accepted`] calls.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "test code"
)]

mod common;

use common::Fail;
use fstp_prop::{Gen, prop_assert_eq};

/// The `statfs` types a key volume may have: ext4 and XFS.
const ACCEPTED: [(&str, u64); 2] = [("ext4", 0xef53), ("xfs", 0x5846_5342)];

/// Some types a key volume must not have, written from memory as above.
const REFUSED: [(&str, u64); 6] = [
    ("btrfs", 0x9123_683e),
    ("zfs", 0x2fc1_2fc1),
    ("overlayfs", 0x794c_7630),
    ("nfs", 0x6969),
    ("tmpfs", 0x0102_1994),
    ("fuse", 0x6573_5546),
];

/// Whether `fstp-keyd` accepts a key volume of `statfs` type `magic`,
/// through `fstp_keyd::key_volume_accepted`.
fn volume_accepted(magic: u64) -> Result<bool, Fail> {
    Ok(fstp_keyd::key_volume_accepted(magic))
}

/// I-81, design section 3.3 (Q32 A): ext4 and XFS are accepted, and the
/// listed copy-on-write, overlay, memory, FUSE and network filesystems
/// are refused.
#[test]
fn i81_keyd_volume_check_accepts_ext4_and_xfs_and_refuses_the_rest() {
    let mut wrong = Vec::new();
    for (name, magic) in ACCEPTED {
        if !volume_accepted(magic).unwrap_or_else(|e| panic!("{e}")) {
            wrong.push(format!("{name} refused"));
        }
    }
    for (name, magic) in REFUSED {
        if volume_accepted(magic).unwrap_or_else(|e| panic!("{e}")) {
            wrong.push(format!("{name} accepted"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:?}");
}

/// I-81, design section 3.3: the rule is an allowlist. Every `statfs`
/// type other than ext4 and XFS is refused.
#[test]
fn i81_keyd_volume_check_is_an_allowlist() {
    fstp_prop::check("i81_keyd_volume_check_is_an_allowlist", |g: &mut Gen| {
        let magic = if g.bool() {
            g.u64()
        } else {
            u64::from(g.u32())
        };
        let want = ACCEPTED.iter().any(|(_, m)| *m == magic);
        prop_assert_eq!(volume_accepted(magic)?, want, "type {magic:#x}");
        Ok(())
    });
}
