//! Review reproducers for the W1c interface: pieces later lanes need but cannot add
//! without editing a W1c-owned file or another lane's file (design section 10).
//!
//! The missing items cannot be named without a compile failure, so each test
//! scans the crate source at run time. Each fails against the current
//! interface and passes once the missing piece exists.

use std::path::{Path, PathBuf};

fn src_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("src")
}

fn read_src(rel: &str) -> Result<String, String> {
    let path = src_dir().join(rel);
    std::fs::read_to_string(&path).map_err(|e| format!("cannot read {}: {e}", path.display()))
}

fn all_src() -> Result<String, String> {
    fn walk(dir: &Path, out: &mut String) -> Result<(), String> {
        let mut entries: Vec<PathBuf> = std::fs::read_dir(dir)
            .map_err(|e| format!("cannot list {}: {e}", dir.display()))?
            .filter_map(|e| e.ok().map(|e| e.path()))
            .collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.extension().is_some_and(|x| x == "rs") {
                let text = std::fs::read_to_string(&p)
                    .map_err(|e| format!("cannot read {}: {e}", p.display()))?;
                out.push_str(&text);
                out.push('\n');
            }
        }
        Ok(())
    }
    let mut out = String::new();
    walk(&src_dir(), &mut out)?;
    Ok(out)
}

/// The body of `impl <ty> {` in `text`, by brace counting, or empty.
fn impl_block<'a>(text: &'a str, ty: &str) -> &'a str {
    let head = format!("impl {ty} {{");
    let Some(start) = text.find(&head) else {
        return "";
    };
    let Some(body) = start
        .checked_add(head.len())
        .and_then(|from| text.get(from..))
    else {
        return "";
    };
    let mut depth = 1usize;
    for (i, c) in body.char_indices() {
        match c {
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return body.get(..i).unwrap_or(body);
                }
            }
            _ => {}
        }
    }
    body
}

/// Whether some function in `text` or in `impl <ty>` returns `ty`, bare or
/// inside `Result` or `Option`.
fn has_constructor(text: &str, ty: &str) -> bool {
    let direct = [
        format!("-> {ty} "),
        format!("-> {ty}\n"),
        format!("-> Result<{ty},"),
        format!("-> Option<{ty}>"),
    ];
    if direct.iter().any(|p| text.contains(p.as_str())) {
        return true;
    }
    let block = impl_block(text, ty);
    ["-> Self", "-> Result<Self,", "-> Option<Self>"]
        .iter()
        .any(|p| block.contains(p))
}

/// Whether a public (not crate-private) function anywhere in the crate returns `ty`.
fn has_public_constructor(text: &str, ty: &str) -> bool {
    text.lines().any(|line| {
        let l = line.trim_start();
        l.starts_with("pub fn")
            && (l.contains(&format!("-> {ty}"))
                || l.contains(&format!("-> Result<{ty},"))
                || l.contains(&format!("-> Option<{ty}>")))
    }) || {
        let block = impl_block(text, ty);
        block.lines().any(|line| {
            let l = line.trim_start();
            l.starts_with("pub fn")
                && (l.contains("-> Self")
                    || l.contains("-> Result<Self,")
                    || l.contains("-> Option<Self>"))
        })
    }
}

/// W2 (scenario from genesis) and the testkit generators of W3 build a
/// `PolicyVersion` outside the crate for `CreateProgramme`. `FrozenValues.p01`
/// is a `Criteria`, whose fields are private and which has no constructor.
/// Lane L-SCORE adds it only in W3, after W2.
#[test]
fn review_criteria_constructible_outside_the_crate() {
    let text = all_src().expect("crate source");
    assert!(
        has_public_constructor(&text, "Criteria"),
        "no public function returns Criteria, so no PolicyVersion can be built outside \
         fstp-domain and W2 cannot run CreateProgramme from genesis"
    );
}

/// `decide`, `queries`, `apply` and `due` live in W1c-owned `engine.rs` and
/// dispatch nowhere. Each lane must then edit `engine.rs` to wire its
/// commands and records, and W3 runs L-POL, L-SOD and L-SCORE in parallel
/// on that one file. A per-lane stub that the engine delegates to avoids that.
#[test]
fn review_engine_delegates_to_lane_modules() {
    let engine = read_src("engine.rs").expect("engine.rs");
    let missing: Vec<&str> = [
        "policy",
        "programme",
        "roles",
        "assignment",
        "proposal",
        "decision",
        "grant",
        "payment",
        "amendment",
    ]
    .into_iter()
    .filter(|lane| !engine.contains(&format!("{lane}::")))
    .collect();
    assert!(
        missing.is_empty(),
        "engine.rs never delegates to these lane modules, so each lane must edit a \
         W1c-owned file: {missing:?}"
    );
}

/// The decode path of the four witness-only payloads is crate-private
/// (design section 3.5), but no crate-private constructor exists. Lane
/// L-CODEC (W3) cannot build them from `codec/`, because their fields are
/// private to modules that L-LIFE (W4) and L-MONEY (W5) own.
#[test]
fn review_witness_payloads_have_a_crate_private_decode_constructor() {
    let missing: Vec<&str> = [
        ("decision.rs", "Stage1Closed"),
        ("decision.rs", "EffectiveScoreSet"),
        ("grant.rs", "GrantDecided"),
        ("payment.rs", "PaymentReleased"),
    ]
    .into_iter()
    .filter(|(file, ty)| {
        let text = read_src(file).unwrap_or_default();
        !has_constructor(&text, ty)
    })
    .map(|(_, ty)| ty)
    .collect();
    assert!(
        missing.is_empty(),
        "no constructor at all, so the record decoder in codec/ cannot build: {missing:?}"
    );
}

/// The committee ranking view (`SPEC/02-domain/roles-and-sod.md`, design
/// section 3.7) shows a title and neutral summary written by the assigned
/// reviewers. No command or record carries them, so lane L-REV cannot fill
/// `RankingRow` without editing W1c-owned `command.rs` and `record.rs`.
#[test]
fn review_ranking_view_summary_has_a_command() {
    let command = read_src("command.rs")
        .expect("command.rs")
        .to_ascii_lowercase();
    let record = read_src("record.rs")
        .expect("record.rs")
        .to_ascii_lowercase();
    assert!(
        command.contains("summary") && record.contains("summary"),
        "no command or record carries the reviewers' title and neutral summary"
    );
}
