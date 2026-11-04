//! Review reproducers for lane W2f: the key volume rule (design section
//! 3.3, ADR-004 part 2, Q32 A, I-81).

#![allow(clippy::unwrap_used, clippy::expect_used, reason = "test code")]

use std::path::PathBuf;

use fstp_keyd::volume::{MountEntry, check_mount};
use fstp_keyd::{EXT4_SUPER_MAGIC, XFS_SUPER_MAGIC, key_volume_accepted};

/// I-81: the W1 test `i81_keyd_refuses_copy_on_write_key_volume` is green
/// through `key_volume_accepted(magic)`. `serve` never calls it: it
/// decides through `check_mount` over the mountinfo type name. So the W1
/// test does not constrain the check that guards a start. The two
/// decisions already differ: ext2 and ext3 carry the ext4 `statfs` magic.
/// The test asks that `serve` never accepts a type the magic decision
/// refuses. Since 2026-10-31 `serve` is stricter by name: design 3.3
/// (Q32 A) allows ext4 and XFS only, so ext2 and ext3 are refused although
/// they carry the ext4 magic (found by the `mountinfo_decode` fuzz target).
#[test]
fn review_volume_check_tested_by_w1_is_not_the_one_serve_makes() {
    let cases: [(&str, u64); 4] = [
        ("ext2", EXT4_SUPER_MAGIC),
        ("ext3", EXT4_SUPER_MAGIC),
        ("ext4", EXT4_SUPER_MAGIC),
        ("xfs", XFS_SUPER_MAGIC),
    ];
    for (name, magic) in cases {
        let mount = MountEntry {
            mount_point: PathBuf::from("/var/lib/fstp-keyd"),
            fstype: name.to_owned(),
            options: vec!["rw".to_owned()],
        };
        let accepted = check_mount(&mount).is_ok();
        if accepted {
            assert!(
                key_volume_accepted(magic),
                "serve accepts {name}, which the tested magic decision refuses"
            );
        }
        assert_eq!(
            accepted,
            name == "ext4" || name == "xfs",
            "serve must accept exactly ext4 and XFS by name, not {name}"
        );
    }
}
