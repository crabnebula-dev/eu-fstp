//! Fuzz target `wal_history_decode` of `fstp-backup` (TH-26, H-05,
//! ADR-012 record of lane `m10/backup-pitr`).
//!
//! Design checks: no panic. A history file that decodes has parents
//! strictly increasing and below its own timeline, switch points never
//! decreasing, and a path whose timelines increase. The rewrite of
//! `postgresql.auto.conf` takes the same bytes: it never panics, and its
//! output sets each recovery setting only in the lines it appended.

#![no_main]

use fstp_backup::recovery::{self, Run};
use fstp_backup::timeline;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let (own, body) = match data.split_first() {
        Some((b, rest)) => (u32::from(*b), rest),
        None => (2, data),
    };
    if let Ok(h) = timeline::decode_history(own, body) {
        assert!(!h.is_empty());
        for w in h.windows(2) {
            assert!(w[0].parent < w[1].parent);
            assert!(w[0].end <= w[1].end);
        }
        assert!(h.iter().all(|s| s.parent >= 1 && s.parent < own));
        let p = timeline::path(own, &h);
        for w in p.windows(2) {
            assert!(w[0].tli < w[1].tli);
        }
        for seg in [0u64, 3, 1 << 32] {
            for c in timeline::candidates(&p, seg, Some(16 << 20), 1) {
                assert_eq!(c.segment, seg);
            }
        }
    }
    let settings = recovery::settings(Some(1_795_514_400), Run::Final);
    if let Ok(out) = recovery::rewrite_auto_conf(body, &settings) {
        assert!(out.ends_with(&settings));
        let kept = &out[..out.len() - settings.len()];
        for line in kept.lines() {
            let t = line.trim_start();
            if t.starts_with('#') {
                continue;
            }
            for name in recovery::NAMES {
                let owned = t.get(..name.len()).is_some_and(|h| h.eq_ignore_ascii_case(name))
                    && t
                        .get(name.len()..)
                        .and_then(|r| r.chars().next())
                        .is_none_or(|c| c == '=' || c.is_whitespace());
                assert!(!owned, "a recovery setting survived the rewrite");
            }
        }
    }
});
