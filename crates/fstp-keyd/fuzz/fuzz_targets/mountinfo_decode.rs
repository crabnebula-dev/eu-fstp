//! Fuzz target `mountinfo_decode` of `fstp-keyd` (TH-26, H-05). The
//! parser of `/proc/self/mountinfo` that the key volume check reads
//! (design section 3.3, Q32 A). It is in-house, so it has this target
//! from its first commit (`.claude/CLAUDE.md`).
//!
//! Checks: no panic; limits enforced; a refusal has a short display;
//! every accepted mount names a type and a mount point; the mount of a
//! path is one of the parsed mounts; and the volume rule never accepts a
//! type outside ext4 and XFS.

#![no_main]

use libfuzzer_sys::fuzz_target;

/// The longest error display the target accepts.
const DISPLAY_LIMIT: usize = 512;

fuzz_target!(|data: &[u8]| {
    match fstp_keyd::decode_mountinfo(data) {
        Ok(mounts) => {
            assert!(mounts.len() <= data.len(), "more mounts than input bytes");
            for m in &mounts {
                assert!(!m.fstype.is_empty(), "a mount with no type");
                assert!(
                    !m.mount_point.as_os_str().is_empty(),
                    "a mount with no mount point"
                );
                if fstp_keyd::volume::check_mount(m).is_ok() {
                    assert!(
                        m.fstype == "ext4" || m.fstype == "xfs",
                        "accepted a {} volume",
                        m.fstype
                    );
                }
            }
            let path = std::path::Path::new("/var/lib/fstp-keyd");
            if let Some(m) = fstp_keyd::volume::mount_of(&mounts, path) {
                assert!(
                    path.starts_with(&m.mount_point),
                    "a mount that holds no such path"
                );
            }
        }
        Err(e) => {
            let shown = e.to_string();
            assert!(!shown.is_empty(), "an empty error display");
            assert!(
                shown.len() <= DISPLAY_LIMIT,
                "an error display of {} bytes",
                shown.len()
            );
        }
    }
});
