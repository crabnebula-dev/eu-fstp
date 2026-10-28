//! The `/proc/<pid>/maps` reader of the isolation harness (M3 design
//! sections 14.4 and 15, lane W1a). The I-80 root canary tests read
//! `/proc/<pid>/mem` only through the readable regions it returns, so a
//! region it drops is memory the scan never sees. The reader is a
//! test-only parser with the fuzz target `proc_maps_decode` (TH-26).
//!
//! Each line is `start-end perms offset dev inode [path]`: addresses and
//! offset in lowercase hex of at most 16 digits, perms `[r-][w-][x-][ps]`,
//! dev `hex:hex`, inode decimal, and the path after padding spaces. Written
//! test first: the decoder refuses until lane W1a lands it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use fstp_celltest::procmem::{MapRegion, decode_proc_maps};
use fstp_prop::{Gen, check};

fn region(start: u64, end: u64, readable: bool, path: Option<&str>) -> MapRegion {
    MapRegion {
        start,
        end,
        readable,
        path: path.map(str::to_owned),
    }
}

/// I-80 instrument, design section 14.4: a maps text as Linux writes it,
/// with file mappings, pseudo paths, an anonymous mapping with trailing
/// padding, a path with spaces and the 16-digit vsyscall address.
#[test]
fn harness_procmem_decodes_a_linux_maps_text() {
    let text = "\
5581b6c4a000-5581b6c4c000 r--p 00000000 fd:01 1835037                    /usr/bin/cat
5581b6c4c000-5581b6c51000 r-xp 00002000 fd:01 1835037                    /usr/bin/cat
5581b7a1d000-5581b7a3e000 rw-p 00000000 00:00 0                          [heap]
7f2d1c000000-7f2d1c021000 rw-p 00000000 00:00 0 \n\
7f2d1c021000-7f2d20000000 ---p 00000000 00:00 0
7f2d20000000-7f2d20001000 rw-s 00000000 00:05 4711                       /tmp/a dir/seg (deleted)
7ffc3b5e1000-7ffc3b602000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 --xp 00000000 00:00 0                  [vsyscall]
";
    let want = vec![
        region(
            0x5581_b6c4_a000,
            0x5581_b6c4_c000,
            true,
            Some("/usr/bin/cat"),
        ),
        region(
            0x5581_b6c4_c000,
            0x5581_b6c5_1000,
            true,
            Some("/usr/bin/cat"),
        ),
        region(0x5581_b7a1_d000, 0x5581_b7a3_e000, true, Some("[heap]")),
        region(0x7f2d_1c00_0000, 0x7f2d_1c02_1000, true, None),
        region(0x7f2d_1c02_1000, 0x7f2d_2000_0000, false, None),
        region(
            0x7f2d_2000_0000,
            0x7f2d_2000_1000,
            true,
            Some("/tmp/a dir/seg (deleted)"),
        ),
        region(0x7ffc_3b5e_1000, 0x7ffc_3b60_2000, true, Some("[stack]")),
        region(
            0xffff_ffff_ff60_0000,
            0xffff_ffff_ff60_1000,
            false,
            Some("[vsyscall]"),
        ),
    ];
    assert_eq!(decode_proc_maps(text.as_bytes()).unwrap(), want);
}

/// One generated line and the region it describes.
fn gen_line(g: &mut Gen) -> (String, MapRegion) {
    let start = g.u64_in(0..=u64::MAX - 1);
    let end = g.u64_in(start + 1..=u64::MAX);
    let readable = g.bool();
    let perms = format!(
        "{}{}{}{}",
        if readable { 'r' } else { '-' },
        if g.bool() { 'w' } else { '-' },
        if g.bool() { 'x' } else { '-' },
        if g.bool() { 's' } else { 'p' },
    );
    let width = g.usize_in(1..=16);
    let offset = g.u64();
    let dev = format!("{:02x}:{:02x}", g.u8(), g.u8());
    let inode = g.u64();
    let path = g
        .option(|g| {
            *g.pick(&[
                "[heap]",
                "[stack]",
                "[vdso]",
                "[anon:scudo:primary]",
                "/usr/lib/x86_64-linux-gnu/libc.so.6",
                "/tmp/a b/c (deleted)",
                "/srv/fstp/bin/fstp-cell",
            ])
        })
        .map(str::to_owned);
    let pad = " ".repeat(g.usize_in(1..=30));
    let mut line = format!(
        "{start:0width$x}-{end:0width$x} {perms} {offset:08x} {dev} {inode}",
        width = width
    );
    match &path {
        Some(p) => {
            line.push_str(&pad);
            line.push_str(p);
        }
        None if g.bool() => line.push_str(&pad),
        None => {}
    }
    let r = MapRegion {
        start,
        end,
        readable,
        path,
    };
    (line, r)
}

/// I-80 instrument, design section 14.4: generated maps texts decode to
/// exactly the regions they describe, in order, with or without a final
/// newline.
#[test]
fn harness_procmem_decodes_generated_maps_texts() {
    check("harness_procmem_decodes_generated_maps_texts", |g| {
        let lines = g.vec(0..=12, gen_line);
        let mut text: String = lines
            .iter()
            .map(|(l, _)| l.as_str())
            .collect::<Vec<_>>()
            .join("\n");
        if !lines.is_empty() && g.bool() {
            text.push('\n');
        }
        let want: Vec<MapRegion> = lines.into_iter().map(|(_, r)| r).collect();
        match decode_proc_maps(text.as_bytes()) {
            Ok(got) if got == want => Ok(()),
            Ok(got) => Err(format!("{text:?} decoded as {got:?}, expected {want:?}")),
            Err(e) => Err(format!("{text:?} refused: {e:?}")),
        }
    });
}

/// TH-26, design section 15: malformed lines are refused rather than read
/// as a region with made-up bounds. A valid line is accepted first, so a
/// decoder that refuses everything fails this test.
#[test]
fn harness_procmem_refuses_malformed_lines() {
    decode_proc_maps(b"00400000-00401000 r--p 00000000 08:01 42 /bin/x\n").unwrap();
    for bad in [
        "zz400000-00401000 r--p 00000000 08:01 42",
        "00401000-00400000 r--p 00000000 08:01 42",
        "00400000-00400000 r--p 00000000 08:01 42",
        "00400000 r--p 00000000 08:01 42",
        "00400000-00401000 r--p 00000000 08:01",
        "00400000-00401000 r-p 00000000 08:01 42",
        "00400000-00401000 r--q 00000000 08:01 42",
        "00400000-00401000 a--p 00000000 08:01 42",
        "00400000-00401000 r--p 00000000 0801 42",
        "00400000-00401000 r--p 00000000 08:01 4x2",
        "00400000-00401000 r--p 0000zz00 08:01 42",
        "10000000000000000-20000000000000000 r--p 00000000 08:01 42",
        "-00401000 r--p 00000000 08:01 42",
        "00400000-00401000",
    ] {
        assert!(
            decode_proc_maps(bad.as_bytes()).is_err(),
            "accepted malformed line {bad:?}"
        );
    }
}

/// TH-26: a malformed line anywhere refuses the whole text, so a scan never
/// runs over a partial region list.
#[test]
fn harness_procmem_refuses_a_text_with_one_malformed_line() {
    let good = "00400000-00401000 r--p 00000000 08:01 42 /bin/x";
    decode_proc_maps(format!("{good}\n{good}\n").as_bytes()).unwrap();
    let text = format!("{good}\n00401000-00400000 r--p 00000000 08:01 42\n{good}\n");
    assert!(decode_proc_maps(text.as_bytes()).is_err());
}

/// I-80 instrument, design section 14.4: a mapped file whose path is not
/// UTF-8 does not refuse the maps text, so one odd file name cannot stop
/// the memory scan of a process. The path is decoded lossily.
#[test]
fn harness_procmem_accepts_a_path_that_is_not_utf8() {
    let mut text = b"00400000-00401000 r--p 00000000 08:01 42 /tmp/x".to_vec();
    text.extend_from_slice(&[0xff, 0xfe]);
    text.extend_from_slice(b"\n");
    let regions = decode_proc_maps(&text).unwrap();
    assert_eq!(
        regions,
        vec![region(
            0x0040_0000,
            0x0040_1000,
            true,
            Some("/tmp/x\u{fffd}\u{fffd}")
        )]
    );
}
