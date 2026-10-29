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
/// The test asks that the decision the W1 test exercises is the one
/// `serve` makes.
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
        assert_eq!(
            check_mount(&mount).is_ok(),
            key_volume_accepted(magic),
            "serve and the tested magic decision disagree on {name}"
        );
    }
}
