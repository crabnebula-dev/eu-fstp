//! I-80: no root key exists in plaintext outside its custody backend
//! (design section 14.4, ADR-004 part 2 "Custody interface").
//!
//! Lane W1d wrote these tests before the production code. The structural
//! checks run now. The world, memory and file custody tests are red until
//! the cell runtime (lane W3a), `fstp-keyd` and `KeydCustody` (lane W2f)
//! and the CI isolation job (lane W4) land.
//!
//! The design asks for compile-fail twins. The dependency policy admits no
//! compile-fail harness, so the twins are trait probes that the compiler
//! evaluates, and source scans over the declarations. Each probe has a
//! teeth twin on a type that does implement the trait.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use fstp_celltest::custody_sim::CustodySim;
use fstp_celltest::scan::{Needle, StoreSet, scan_bytes};
use fstp_celltest::world::{CycleScript, DbMode, VaultLayout, World, WorldSpec};
use fstp_custody::{
    Aad, Custody, CustodyError, DestroyReceipt, EcdsaSignature, KeydCustody, RootLabel, RootRef,
    SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};
use fstp_keys::{CellId, Chain, Epoch};
use fstp_rt::future::block_on;

// ---------------------------------------------------------------------------
// Trait probes.

/// Whether `$t` implements the trait bound `$tr`, decided at compile time.
/// An inherent constant with the bound shadows the trait constant only
/// when the bound holds.
macro_rules! implements {
    ($t:ty: $($tr:tt)+) => {{
        #[allow(dead_code)]
        struct Probe<T: ?Sized>(std::marker::PhantomData<T>);
        #[allow(dead_code)]
        trait Fallback {
            const IMPLS: bool = false;
        }
        impl<T: ?Sized> Fallback for Probe<T> {}
        #[allow(dead_code)]
        impl<T: ?Sized + $($tr)+> Probe<T> {
            const IMPLS: bool = true;
        }
        <Probe<$t>>::IMPLS
    }};
}

/// The traits of `$t` through which a root, a seal key or a custody file
/// could be copied or shown. Each must be absent.
macro_rules! escape_traits {
    ($t:ty) => {{
        let mut out: Vec<&'static str> = Vec::new();
        if implements!($t: Clone) {
            out.push("Clone");
        }
        if implements!($t: std::fmt::Debug) {
            out.push("Debug");
        }
        if implements!($t: Copy) {
            out.push("Copy");
        }
        if implements!($t: std::fmt::Display) {
            out.push("Display");
        }
        if implements!($t: Default) {
            out.push("Default");
        }
        out
    }};
}

// ---------------------------------------------------------------------------
// Source scans.

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .unwrap()
        .to_path_buf()
}

fn rel(p: &Path) -> String {
    p.strip_prefix(repo_root())
        .unwrap_or(p)
        .to_string_lossy()
        .into_owned()
}

/// Every file under `dir` whose name ends with `suffix`, without build
/// output or version control.
fn files(dir: &Path, suffix: &str, out: &mut Vec<PathBuf>) {
    let Ok(read) = fs::read_dir(dir) else {
        return;
    };
    for entry in read.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        if name == "target" || name == ".git" {
            continue;
        }
        if path.is_dir() {
            files(&path, suffix, out);
        } else if name.to_string_lossy().ends_with(suffix) {
            out.push(path);
        }
    }
}

/// `text` without `//` and `/* */` comments. String and character
/// literals are kept, so a name inside a string still counts.
fn strip_comments(text: &str) -> String {
    let b: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut in_str = false;
    while i < b.len() {
        let c = b[i];
        if in_str {
            out.push(c);
            if c == '\\' && i + 1 < b.len() {
                out.push(b[i + 1]);
                i += 2;
                continue;
            }
            if c == '"' {
                in_str = false;
            }
            i += 1;
        } else if c == '"' {
            in_str = true;
            out.push(c);
            i += 1;
        } else if c == '/' && b.get(i + 1) == Some(&'/') {
            while i < b.len() && b[i] != '\n' {
                i += 1;
            }
        } else if c == '/' && b.get(i + 1) == Some(&'*') {
            let mut depth = 0usize;
            while i < b.len() {
                if b[i] == '/' && b.get(i + 1) == Some(&'*') {
                    depth += 1;
                    i += 2;
                } else if b[i] == '*' && b.get(i + 1) == Some(&'/') {
                    depth -= 1;
                    i += 2;
                    if depth == 0 {
                        break;
                    }
                } else {
                    if b[i] == '\n' {
                        out.push('\n');
                    }
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

fn ident_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// The 1-based lines of `code` that name `word` as a whole identifier.
fn lines_naming(code: &str, word: &str) -> Vec<usize> {
    let mut out = Vec::new();
    for (n, line) in code.lines().enumerate() {
        let mut from = 0;
        while let Some(at) = line[from..].find(word) {
            let start = from + at;
            let end = start + word.len();
            let before = line[..start].chars().next_back();
            let after = line[end..].chars().next();
            if !before.is_some_and(ident_char) && !after.is_some_and(ident_char) {
                out.push(n + 1);
                break;
            }
            from = end;
        }
    }
    out
}

/// The crates allowed to name `RootMaterial` (layering rule 7).
const ROOT_MATERIAL_CRATES: [&str; 2] = ["crates/fstp-keyd/", "crates/fstp-celltest/"];

/// The findings of the `RootMaterial` rule over `(path, source)` pairs.
fn root_material_findings(sources: &[(String, String)]) -> Vec<String> {
    let mut found = Vec::new();
    for (path, text) in sources {
        if ROOT_MATERIAL_CRATES.iter().any(|c| path.starts_with(c)) {
            continue;
        }
        for line in lines_naming(&strip_comments(text), "RootMaterial") {
            found.push(format!("{path}:{line}"));
        }
    }
    found
}

fn crate_sources() -> Vec<(String, String)> {
    let mut paths = Vec::new();
    files(&repo_root().join("crates"), ".rs", &mut paths);
    paths
        .iter()
        .map(|p| (rel(p), fs::read_to_string(p).unwrap()))
        .collect()
}

/// The part of a manifest line before a `#` comment that is outside a
/// string.
fn toml_code(line: &str) -> &str {
    let mut quote = None;
    for (i, c) in line.char_indices() {
        match (c, quote) {
            ('"' | '\'', None) => quote = Some(c),
            (q, Some(open)) if q == open => quote = None,
            ('#', None) => return &line[..i],
            _ => {}
        }
    }
    line
}

/// Whether `key` names the custody crate: `fstp-custody` or
/// `fstp_custody`, quoted or not, alone or before a dotted key such as
/// `.workspace`.
fn custody_key(key: &str) -> bool {
    let key = key.trim().trim_matches(|c| c == '"' || c == '\'');
    let head = key.split('.').next().unwrap_or("").trim();
    head == "fstp-custody" || head == "fstp_custody"
}

/// The strings that follow `package =` on a manifest line, as in an
/// inline rename or a `package` key of a dependency table.
fn package_names(code: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut rest = code;
    while let Some(at) = rest.find("package") {
        let before = rest[..at].chars().next_back();
        let after = rest[at + "package".len()..].trim_start();
        rest = &rest[at + "package".len()..];
        if before.is_some_and(|c| ident_char(c) || c == '-') {
            continue;
        }
        let Some(value) = after.strip_prefix('=') else {
            continue;
        };
        let value = value.trim_start();
        let Some(open) = value.chars().next().filter(|c| *c == '"' || *c == '\'') else {
            continue;
        };
        let body = &value[1..];
        if let Some(end) = body.find(open) {
            out.push(&body[..end]);
        }
    }
    out
}

/// Whether a manifest names `fstp-custody` as a dependency, in any form
/// Cargo reads. That is a key line (`fstp-custody = ...` or
/// `fstp-custody.workspace = true`), or a table header such as
/// `[dependencies.fstp-custody]`, also under `target`. A rename through
/// `package = "fstp-custody"` counts too, inline or in a table.
fn manifest_names_custody(text: &str) -> bool {
    text.lines().any(|line| {
        let code = toml_code(line).trim();
        if package_names(code).iter().any(|p| custody_key(p)) {
            return true;
        }
        if let Some(header) = code.strip_prefix('[') {
            let header = header.trim_start_matches('[').trim_end_matches(']');
            return header
                .rsplit_once("dependencies.")
                .is_some_and(|(_, dep)| custody_key(dep));
        }
        code.split_once('=')
            .is_some_and(|(key, _)| custody_key(key))
    })
}

/// The crates whose manifest names `fstp-custody` as a dependency.
fn custody_dependents() -> BTreeSet<String> {
    let mut manifests = Vec::new();
    files(&repo_root().join("crates"), "Cargo.toml", &mut manifests);
    files(&repo_root().join("tools"), "Cargo.toml", &mut manifests);
    let mut out = BTreeSet::new();
    for m in manifests {
        let text = fs::read_to_string(&m).unwrap();
        let names_it = manifest_names_custody(&text);
        let own = rel(&m) == "crates/fstp-custody/Cargo.toml";
        if names_it && !own {
            out.insert(rel(m.parent().unwrap()));
        }
    }
    out
}

/// The text from `start` to its matching closing brace.
fn block_from(code: &str, start: usize) -> &str {
    let mut depth = 0usize;
    for (i, c) in code[start..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return &code[start..start + i + 1];
                }
            }
            _ => {}
        }
    }
    &code[start..]
}

/// The method names a `trait` or `impl` block declares.
fn fn_names(block: &str) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let mut rest = block;
    while let Some(at) = rest.find("fn ") {
        let before = rest[..at].chars().next_back();
        let after = &rest[at + 3..];
        let name: String = after.chars().take_while(|c| ident_char(*c)).collect();
        if !before.is_some_and(ident_char) && !name.is_empty() {
            out.insert(name);
        }
        rest = &rest[at + 3..];
    }
    out
}

fn custody_lib() -> String {
    strip_comments(&fs::read_to_string(repo_root().join("crates/fstp-custody/src/lib.rs")).unwrap())
}

/// The six operations of ADR-004 part 2 "Custody interface".
const CUSTODY_OPS: [&str; 6] = [
    "create_root",
    "destroy",
    "sign",
    "unwrap",
    "usage_since",
    "wrap",
];

// ---------------------------------------------------------------------------
// I-80 structure.

/// I-80, ADR-004 "There is no export operation. No code path can ask for
/// root material": the `Custody` trait declares exactly the six
/// operations, and none of them returns root material. Every twin below
/// covers one way root material could escape.
#[test]
fn i80_custody_has_no_export_and_root_material_cannot_escape() {
    let code = custody_lib();
    let at = code.find("pub trait Custody").expect("the Custody trait");
    let block = block_from(&code, at);
    let names = fn_names(block);
    let want: BTreeSet<String> = CUSTODY_OPS.iter().map(|s| (*s).to_owned()).collect();
    assert_eq!(names, want, "the Custody trait surface");
    assert!(
        !block.contains("RootMaterial") && !block.contains("[u8; 32]>"),
        "a Custody operation returns root material:\n{block}"
    );
}

/// I-80 twin: `fstp_keyd::RootMaterial` has no `Clone`, `Debug`, `Copy`,
/// `Display` or `Default`.
#[test]
fn i80_twin_keyd_root_material_has_no_escape_trait() {
    assert_eq!(escape_traits!(fstp_keyd::RootMaterial), Vec::<&str>::new());
}

/// I-80 twin: the decoded custody file of the key volume, which holds
/// root material, has no escape trait.
#[test]
fn i80_twin_keyd_custody_file_has_no_escape_trait() {
    assert_eq!(escape_traits!(fstp_keyd::CustodyFile), Vec::<&str>::new());
}

/// I-80 twin: the simulator's root material has no escape trait either.
#[test]
fn i80_twin_simulator_root_material_has_no_escape_trait() {
    assert_eq!(
        escape_traits!(fstp_celltest::custody_sim::RootMaterial),
        Vec::<&str>::new()
    );
}

/// I-80 twin, ADR-004 part 2: an epoch seal key `S(e)` is not a root key,
/// and still has "no `Clone` and no `Debug` output".
#[test]
fn i80_twin_seal_key_has_no_escape_trait() {
    assert_eq!(escape_traits!(SealKey), Vec::<&str>::new());
}

/// I-80 twin: no `fstp-keyd` field or method hands out root bytes. The
/// root material and custody file structs have no public field, and the
/// methods of their `impl` blocks return no bytes and no root material.
#[test]
fn i80_twin_root_material_bytes_unreachable_outside_fstp_keyd() {
    let code = strip_comments(
        &fs::read_to_string(repo_root().join("crates/fstp-keyd/src/lib.rs")).unwrap(),
    );
    let mut found = Vec::new();
    for ty in ["RootMaterial", "CustodyFile"] {
        let decl = code
            .find(&format!("pub struct {ty}"))
            .unwrap_or_else(|| panic!("pub struct {ty}"));
        let body = block_from(&code, decl);
        if body
            .lines()
            .skip(1)
            .any(|l| l.trim_start().starts_with("pub "))
        {
            found.push(format!("{ty} has a public field"));
        }
        let mut from = 0;
        while let Some(at) = code[from..].find(&format!("impl {ty} {{")) {
            let start = from + at;
            let block = block_from(&code, start);
            for sig in block.split("pub fn ").skip(1) {
                let sig = sig.split('{').next().unwrap_or_default();
                let ret = sig.split("->").nth(1).unwrap_or_default();
                if ["u8", "RootMaterial", "Vec<", "Zeroizing"]
                    .iter()
                    .any(|t| ret.contains(t))
                {
                    found.push(format!("{ty}: pub fn {}", sig.trim()));
                }
            }
            from = start + block.len();
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// I-80 twin: no `ToJson` or `FromJson` impl exists for root material, a
/// custody file or a seal key, anywhere in the workspace.
#[test]
fn i80_twin_no_serialisation_of_root_material_or_seal_keys() {
    let mut found = Vec::new();
    for (path, text) in crate_sources() {
        let code: String = strip_comments(&text)
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        for header in code.split("impl").skip(1) {
            let header = header.split('{').next().unwrap_or_default();
            let serialises = header.contains("ToJson") || header.contains("FromJson");
            let target = ["RootMaterial", "CustodyFile", "SealKey"]
                .iter()
                .find(|t| !lines_naming(header, &format!("for {t}")).is_empty());
            if serialises && let Some(t) = target {
                found.push(format!("{path}: impl{header} ({t})"));
            }
        }
    }
    assert!(found.is_empty(), "{found:#?}");
}

/// I-80 teeth: the probe sees `Clone`, `Debug`, `Copy`, `Display` and
/// `Default` on a type that has them.
#[test]
fn i80_teeth_trait_probe_sees_escape_traits() {
    assert_eq!(
        escape_traits!(String),
        vec!["Clone", "Debug", "Display", "Default"]
    );
    assert_eq!(
        escape_traits!(u8),
        vec!["Clone", "Debug", "Copy", "Display", "Default"]
    );
}

/// I-80 teeth: the custody trait scan sees an export method.
#[test]
fn i80_teeth_custody_surface_scan_sees_an_export() {
    let code = "pub trait Custody: Send { fn create_root(&self); fn wrap(&self); fn unwrap(&self); fn destroy(&self); fn sign(&self); fn usage_since(&self); fn export(&self) -> RootMaterial; }";
    let names = fn_names(block_from(code, 0));
    assert!(names.contains("export"));
    assert_ne!(names.len(), CUSTODY_OPS.len());
}

/// I-80, design section 2.4 rule 7: the identifier `RootMaterial`
/// appears only in `fstp-keyd` and `fstp-celltest`. The rule is about
/// crates, so the deps-check tool that enforces it is outside this scan.
#[test]
fn i80_root_material_named_only_in_keyd() {
    let found = root_material_findings(&crate_sources());
    assert!(found.is_empty(), "{found:#?}");
}

/// I-80, design section 2.4 rule 7: only `fstp-cell`, `fstp-vault`,
/// `fstp-control`, `fstp-backup`, `fstp-keyd` and `fstp-celltest` name
/// `fstp-custody` in their manifests. A fuzz project counts as part of
/// its crate. This test checks direct dependencies, in every manifest
/// form. Reach is transitive, as through `fstp-cell` or `fstp-backup`.
/// The deps-check rule 7 in `tools/deps-check/src/layering_m3.rs` checks
/// that reach over the resolved `cargo metadata` graph, and the
/// deps-check gate runs it.
#[test]
fn i80_only_listed_crates_reach_fstp_custody() {
    let allowed: BTreeSet<String> = [
        "crates/fstp-backup",
        "crates/fstp-cell",
        "crates/fstp-celltest",
        "crates/fstp-control",
        "crates/fstp-keyd",
        "crates/fstp-vault",
    ]
    .iter()
    .map(|s| (*s).to_owned())
    .collect();
    // A crate's own fuzz project is part of that crate.
    let extra: Vec<String> = custody_dependents()
        .into_iter()
        .filter(|d| {
            !d.starts_with("crates/fstp-custody/")
                && !allowed
                    .iter()
                    .any(|a| d == a || d.starts_with(&format!("{a}/")))
        })
        .collect();
    assert!(extra.is_empty(), "{extra:#?}");
}

/// I-80 teeth for the manifest scan of rule 7: each form Cargo reads as
/// a dependency on `fstp-custody` is seen. Those are a key, a dotted
/// key, a table header, a target table header, an inline rename and a
/// rename in a table. A comment, a description, a longer crate name and
/// another rename are not seen. The real tree's `fstp-keyd` and
/// `fstp-celltest` manifests are seen.
#[test]
fn i80_teeth_custody_manifest_scan_sees_every_form() {
    let seen = [
        "[dependencies]\nfstp-custody = { path = \"../fstp-custody\" }\n",
        "[dependencies]\nfstp-custody.workspace = true\n",
        "[dev-dependencies]\n\"fstp_custody\" = \"0.1\"\n",
        "[dependencies.fstp-custody]\nworkspace = true\n",
        "[target.'cfg(unix)'.dependencies.fstp-custody]\nworkspace = true\n",
        "[dependencies]\ncust = { package = \"fstp-custody\", path = \"x\" }\n",
        "[dependencies.cust]\npackage = 'fstp-custody'\nworkspace = true\n",
    ];
    let unseen = [
        "[dependencies]\n# fstp-custody = { workspace = true }\n",
        "[package]\ndescription = \"talks to fstp-custody\"\n",
        "[dependencies]\nfstp-custodyx = \"1\"\nfstp-custody-sim = \"1\"\n",
        "[dependencies]\ncust = { package = \"fstp-custodyx\", path = \"x\" }\n",
        "[dependencies.fstp-custody-sim]\nworkspace = true\n",
    ];
    let mut wrong = Vec::new();
    for m in seen {
        if !manifest_names_custody(m) {
            wrong.push(format!("missed: {m:?}"));
        }
    }
    for m in unseen {
        if manifest_names_custody(m) {
            wrong.push(format!("false hit: {m:?}"));
        }
    }
    let real = custody_dependents();
    for c in ["crates/fstp-keyd", "crates/fstp-celltest"] {
        if !real.contains(c) {
            wrong.push(format!("the real manifest of {c} was not seen"));
        }
    }
    assert!(wrong.is_empty(), "{wrong:#?}");
}

/// I-80 teeth: the `RootMaterial` scan sees a seeded name in a cell
/// source, a renamed import and a string, and skips a comment.
#[test]
fn i80_teeth_root_material_scan_sees_a_seeded_name() {
    let seeded = vec![
        (
            "crates/fstp-cell/src/a.rs".to_owned(),
            "use fstp_keyd::RootMaterial as R;\n".to_owned(),
        ),
        (
            "crates/fstp-vault/src/b.rs".to_owned(),
            "let s = \"RootMaterial\";\n".to_owned(),
        ),
        (
            "crates/fstp-control/src/c.rs".to_owned(),
            "// RootMaterial in a comment\nfn f() {}\n".to_owned(),
        ),
        (
            "crates/fstp-keyd/src/lib.rs".to_owned(),
            "pub struct RootMaterial;\n".to_owned(),
        ),
    ];
    assert_eq!(
        root_material_findings(&seeded),
        vec![
            "crates/fstp-cell/src/a.rs:1".to_owned(),
            "crates/fstp-vault/src/b.rs:1".to_owned()
        ]
    );
}

// ---------------------------------------------------------------------------
// What a custody client sees.

fn label(chain: Chain, epoch: u64) -> RootLabel {
    RootLabel {
        cell: Some(CellId([7; 16])),
        chain,
        epoch: Epoch(epoch),
    }
}

/// Every byte a custody client receives in one create, destroy and usage
/// round, as stores: handles, receipts, usage pages and error displays.
fn client_view<C: Custody>(c: &C) -> Result<StoreSet, CustodyError> {
    let mut set = StoreSet::default();
    let root = block_on(c.create_root(label(Chain::App, 1)))?;
    set.push("client/root-ref", format!("{root:?}").into_bytes());
    set.push("client/handle", root.handle.0.clone());
    let page = block_on(c.usage_since(&root, UsageCursor::default()))?;
    for (i, op) in page.operations.iter().enumerate() {
        set.push(format!("client/usage/{i}"), op.clone());
    }
    let receipt = block_on(c.destroy(&root))?;
    set.push("client/receipt", receipt.0);
    if let Err(e) = block_on(c.destroy(&root)) {
        set.push("client/error", e.to_string().into_bytes());
    }
    Ok(set)
}

/// A custody backend that leaks: its destroy receipt carries the root
/// bytes. The teeth twin of every I-80 client-view scan.
struct LeakyCustody(CustodySim);

impl Custody for LeakyCustody {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        self.0.create_root(label)
    }
    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        self.0.wrap(root, key, aad)
    }
    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        self.0.unwrap(root, w, aad)
    }
    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let leaked = self
            .0
            .with_material(root, |m| m.expose().to_vec())
            .unwrap_or_default();
        let r = block_on(self.0.destroy(root)).map(|mut d| {
            d.0.extend_from_slice(&leaked);
            d
        });
        std::future::ready(r)
    }
    fn sign(
        &self,
        key: &SignKeyRef,
        digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        self.0.sign(key, digest)
    }
    fn usage_since(
        &self,
        root: &RootRef,
        cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        self.0.usage_since(root, cursor)
    }
}

/// I-80 teeth: a custody backend whose receipt carries the root bytes is
/// caught by the client-view scan.
#[test]
fn i80_teeth_leaking_custody_is_caught() {
    let leaky = LeakyCustody(CustodySim::for_cell(3));
    let view = client_view(&leaky).unwrap();
    let report = scan_bytes(&view, &leaky.0.root_needles()).unwrap();
    assert!(
        report
            .hits
            .iter()
            .any(|(store, _)| store == "client/receipt"),
        "the leak went undetected: {report:?}"
    );
}

/// I-80: the honest simulator gives its client no root byte, in any
/// encoding. The control twin of `i80_teeth_leaking_custody_is_caught`.
#[test]
fn i80_simulator_client_view_holds_no_root_bytes() {
    let sim = CustodySim::for_cell(3);
    let view = client_view(&sim).unwrap();
    let report = scan_bytes(&view, &sim.root_needles()).unwrap();
    assert!(report.is_clean(), "{report:?}");
}

// ---------------------------------------------------------------------------
// File custody (design section 3.3, Q32 A).

/// The seam of [`keyd_root_needles`]: `fstp-keyd` gives a test no needle
/// of its root bytes. Lane W2f adds a test-only hook, as the simulator's
/// `--needles-out` does, and this helper then reads it.
const KEYD_NEEDLE_SEAM: &str = "fstp-keyd exposes no test needles of its root bytes (lane W2f; compare fstp-custody-sim --needles-out)";

fn keyd_root_needles(volume: &Path) -> Result<Vec<Needle>, String> {
    let _ = volume;
    Err(KEYD_NEEDLE_SEAM.to_owned())
}

/// The environment variable that names a directory on an ext4 or XFS
/// filesystem, for the key volumes of the file custody tests.
const KEY_VOLUME_ENV: &str = "FSTP_KEY_VOLUME_DIR";

/// The seam of [`key_volume_root`]: `fstp-keyd` accepts only an ext4 or
/// XFS key volume. `std::env::temp_dir()` is APFS on macOS and often
/// tmpfs on Linux, so a correct `fstp-keyd` refuses it. The CI isolation
/// job (lane W4) sets the variable to an ext4 or XFS mount.
const KEY_VOLUME_SEAM: &str = "FSTP_KEY_VOLUME_DIR is unset: the file custody tests need a directory on an ext4 or XFS mount, which the CI isolation job provides (design section 3.3, lane W4)";

/// The directory under which the file custody tests make key volumes.
fn key_volume_root() -> Result<PathBuf, String> {
    match std::env::var_os(KEY_VOLUME_ENV) {
        Some(dir) if !dir.is_empty() => Ok(PathBuf::from(dir)),
        _ => Err(KEY_VOLUME_SEAM.to_owned()),
    }
}

/// The socket and key volume of one test, both fresh and removed when
/// dropped. The socket lives in the temporary directory. The volume
/// lives under [`key_volume_root`].
struct Scratch {
    socket_dir: PathBuf,
    socket: PathBuf,
    volume: PathBuf,
}

impl Scratch {
    fn new(name: &str) -> Scratch {
        let leaf = format!("fstp-w1d-{name}-{}", std::process::id());
        let root = key_volume_root().unwrap_or_else(|e| panic!("{e}"));
        let socket_dir = std::env::temp_dir().join(&leaf);
        let volume = root.join(&leaf);
        for dir in [&socket_dir, &volume] {
            let _ = fs::remove_dir_all(dir);
            fs::create_dir_all(dir).unwrap();
        }
        Scratch {
            socket: socket_dir.join("keyd.sock"),
            socket_dir,
            volume,
        }
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.socket_dir);
        let _ = fs::remove_dir_all(&self.volume);
    }
}

/// A running `fstp-keyd` that a test started with [`keyd_start`].
struct KeydRun {
    socket: PathBuf,
}

/// Starts `fstp-keyd` on `socket` and `volume` and returns its client
/// once the socket is bound. It reports a server that exits first.
fn keyd_start(socket: &Path, volume: &Path) -> Result<(KeydCustody, KeydRun), String> {
    let (done, exited) = std::sync::mpsc::channel();
    {
        let (socket, volume) = (socket.to_path_buf(), volume.to_path_buf());
        std::thread::spawn(move || {
            let _ = done.send(fstp_keyd::serve(&socket, &volume));
        });
    }
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while !socket.exists() {
        match exited.try_recv() {
            Ok(Err(e)) => return Err(format!("fstp_keyd::serve: {e}")),
            Ok(Ok(())) => return Err("fstp_keyd::serve returned before binding".to_owned()),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => {
                return Err("fstp_keyd::serve panicked".to_owned());
            }
            Err(std::sync::mpsc::TryRecvError::Empty) => {}
        }
        if std::time::Instant::now() > deadline {
            return Err(format!("fstp-keyd bound no socket at {}", socket.display()));
        }
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let client = KeydCustody::new(socket).map_err(|e| format!("KeydCustody::new: {e}"))?;
    Ok((
        client,
        KeydRun {
            socket: socket.to_path_buf(),
        },
    ))
}

/// The seam of [`keyd_stop`]: `fstp_keyd::serve` runs until shutdown and
/// takes no stop handle. `fstp-celltest` cannot spawn the `fstp-keyd`
/// binary to kill it, since the binary is in another package. Joining the
/// server thread would block forever. Lane W2f adds a serve with a stop
/// handle, or a way to run the binary as a child, and this helper then
/// stops through it.
const KEYD_STOP_SEAM: &str = "fstp-keyd has no serve with a stop handle, and fstp-celltest cannot run the fstp-keyd binary as a child to kill it, so no test can restart it (lane W2f)";

/// Stops the server of `run`.
fn keyd_stop_server(run: &KeydRun) -> Result<(), String> {
    let _ = run;
    Err(KEYD_STOP_SEAM.to_owned())
}

/// Stops `fstp-keyd`, waits until it has stopped, and removes its socket
/// file, so the next [`keyd_start`] binds afresh and reloads the volume
/// from disk.
fn keyd_stop(run: KeydRun) -> Result<(), String> {
    keyd_stop_server(&run)?;
    match fs::remove_file(&run.socket) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("removing {}: {e}", run.socket.display())),
    }
}

/// Every file of the key volume, as stores.
fn volume_stores(volume: &Path) -> StoreSet {
    let mut paths = Vec::new();
    files(volume, "", &mut paths);
    let mut set = StoreSet::default();
    for p in paths {
        set.push(
            format!("volume/{}", p.display()),
            fs::read(&p).unwrap_or_default(),
        );
    }
    set
}

/// I-80, design section 3.3: with file custody, root bytes exist only in
/// `fstp-keyd`. The client of a create, usage and destroy round never
/// receives them, and the key volume never holds them in the clear.
#[test]
fn i80_file_custody_root_confined_to_keyd() {
    let scratch = Scratch::new("i80-keyd");
    let (client, run) =
        keyd_start(&scratch.socket, &scratch.volume).unwrap_or_else(|e| panic!("{e}"));
    let mut view = client_view(&client).unwrap_or_else(|e| panic!("{e}"));
    for (name, bytes) in volume_stores(&scratch.volume).stores {
        view.push(name, bytes);
    }
    let needles = keyd_root_needles(&scratch.volume).unwrap_or_else(|e| panic!("{e}"));
    let report = scan_bytes(&view, &needles).unwrap();
    assert!(report.is_clean(), "{report:?}");
    drop(client);
    keyd_stop(run).unwrap_or_else(|e| panic!("{e}"));
}

// ---------------------------------------------------------------------------
// Worlds (design section 14.3).

fn spec(process_mode: bool) -> WorldSpec {
    WorldSpec {
        cells: 2,
        mode: DbMode::Shared,
        vault_layout: VaultLayout::SeparateCluster,
        self_hosted: false,
        process_mode,
    }
}

fn script(steps: &[&str]) -> CycleScript {
    CycleScript {
        steps: steps.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// The cycle of I-80: a call cycle, a text erasure and a yearly rotation,
/// then a base backup and a keystore snapshot. The step names are the
/// cycle vocabulary lane W3b defines.
const CYCLE: [&str; 6] = [
    "call-cycle",
    "erase-text",
    "rotate-chain",
    "base-backup",
    "wal-archive",
    "keystore-snapshot",
];

/// The seam of [`world_root_needles`]: the world holds a custody
/// simulator but exposes no needle of its roots. Lane W3b adds the
/// accessor, and this helper then calls it.
const WORLD_NEEDLE_SEAM: &str =
    "fstp_celltest::world::World exposes no needles of its custody simulator's roots (lane W3b)";

fn world_root_needles(world: &World) -> Result<Vec<Needle>, String> {
    let _ = world;
    Err(WORLD_NEEDLE_SEAM.to_owned())
}

/// I-80: after a cycle, an erasure and a rotation, no root canary is in
/// any database, dump, log, metrics sink, egress capture or backup of the
/// world, in any encoding.
#[test]
fn i80_root_canary_absent_from_logs_dumps_and_backups() {
    let world = World::start(spec(false)).unwrap_or_else(|e| panic!("{e}"));
    for cell in 0..2 {
        if let Err(e) = world.run_cycle(cell, &script(&CYCLE)).result {
            panic!("cell {cell}: {e} (NotImplemented)");
        }
    }
    let stores = world.stores().unwrap_or_else(|e| panic!("{e}"));
    let needles = world_root_needles(&world).unwrap_or_else(|e| panic!("{e}"));
    let report = scan_bytes(&stores, &needles).unwrap();
    assert!(report.is_clean(), "{report:?}");
}

/// I-80, Q27: the Linux-only memory scans run in CI. This companion runs
/// on every platform and checks that `ci.yml` names both.
#[test]
fn i80_memory_scan_runs_in_linux_ci() {
    let ci = fs::read_to_string(repo_root().join(".github/workflows/ci.yml")).unwrap();
    let missing: Vec<&str> = [
        "i80_root_canary_absent_from_cell_and_vault_memory",
        "i80_destroyed_epoch_seal_key_absent_from_process_memory",
    ]
    .into_iter()
    .filter(|t| !ci.contains(t))
    .collect();
    assert!(missing.is_empty(), "ci.yml does not run {missing:?}");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use fstp_celltest::egress::Component;
    use fstp_celltest::procmem::read_memory;

    /// The seam of [`process_ids`]: a process-mode world exposes no
    /// process id of its components. Lane W3b adds the accessor.
    const PID_SEAM: &str =
        "fstp_celltest::world::World exposes no process ids of its components (lane W3b)";

    fn process_ids(world: &World, cell: u8, c: Component) -> Result<u32, String> {
        let _ = (world, cell, c);
        Err(PID_SEAM.to_owned())
    }

    /// The seam of [`epoch_seal_needles`]: the simulator gives no canary
    /// epoch seal key `S(e)` (ADR-004 part 2, the proposed reading for
    /// W1d). Lane W1a adds it, and this helper then reads it.
    const SEAL_NEEDLE_SEAM: &str = "fstp_celltest::custody_sim gives no canary epoch seal keys S(e) (ADR-004 part 2, lane W1a)";

    fn epoch_seal_needles(world: &World, destroyed_only: bool) -> Result<Vec<Needle>, String> {
        let _ = (world, destroyed_only);
        Err(SEAL_NEEDLE_SEAM.to_owned())
    }

    fn memory_hits(world: &World, needles: &[Needle]) -> Vec<String> {
        let mut hits = Vec::new();
        for cell in 0..2 {
            for c in [Component::Cell, Component::Vault] {
                let pid = process_ids(world, cell, c).unwrap_or_else(|e| panic!("{e}"));
                let regions = read_memory(pid).unwrap_or_else(|e| panic!("{e}"));
                let mut set = StoreSet::default();
                for r in regions {
                    assert!(r.complete, "region {:?} was not read whole", r.region);
                    set.push(format!("{} {cell} {:?}", c.label(), r.region), r.bytes);
                }
                let report = scan_bytes(&set, needles).unwrap();
                hits.extend(report.hits.into_iter().map(|(s, n)| format!("{s}: {n}")));
            }
        }
        hits
    }

    /// I-80, Linux, process mode: after a cycle, an erasure and a
    /// rotation, no root canary is in the memory of any `fstp-cell` or
    /// `fstp-vault` process.
    #[test]
    fn i80_root_canary_absent_from_cell_and_vault_memory() {
        let world = World::start(spec(true)).unwrap_or_else(|e| panic!("{e}"));
        for cell in 0..2 {
            if let Err(e) = world.run_cycle(cell, &script(&CYCLE)).result {
                panic!("cell {cell}: {e} (NotImplemented)");
            }
        }
        let needles = world_root_needles(&world).unwrap_or_else(|e| panic!("{e}"));
        let hits = memory_hits(&world, &needles);
        assert!(hits.is_empty(), "{hits:#?}");
    }

    /// I-80, ADR-004 part 2 (epoch seal keys, Daniel 2026-10-28): after an
    /// epoch is destroyed and zeroised, no copy of its `S(e)` is in the
    /// memory of any `fstp-cell` or `fstp-vault` process.
    #[test]
    fn i80_destroyed_epoch_seal_key_absent_from_process_memory() {
        let world = World::start(spec(true)).unwrap_or_else(|e| panic!("{e}"));
        for cell in 0..2 {
            if let Err(e) = world.run_cycle(cell, &script(&CYCLE)).result {
                panic!("cell {cell}: {e} (NotImplemented)");
            }
        }
        let needles = epoch_seal_needles(&world, true).unwrap_or_else(|e| panic!("{e}"));
        let hits = memory_hits(&world, &needles);
        assert!(hits.is_empty(), "{hits:#?}");
    }
}
