//! A typed view of `cargo metadata --format-version 1` output.
//!
//! Only the fields that the checks need are read. Every field access is
//! checked, so malformed or hostile input yields a [`MetaError`] and never a
//! panic.

use std::collections::{BTreeMap, HashMap};

use fstp_json::{Array, ParseLimits, Value};

/// Parse limits for `cargo metadata` output.
///
/// A large workspace produces several megabytes. These bounds leave ample
/// headroom while still capping memory use on hostile input.
pub(crate) fn metadata_limits() -> ParseLimits {
    ParseLimits::default()
        .with_max_input_bytes(256 << 20)
        .with_max_depth(64)
        .with_max_string_bytes(16 << 20)
        .with_max_container_len(1_000_000)
        .with_max_nodes(50_000_000)
}

/// The kind of a dependency edge.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum DepKind {
    /// A `[dependencies]` edge.
    Normal,
    /// A `[build-dependencies]` edge.
    Build,
    /// A `[dev-dependencies]` edge.
    Dev,
}

impl DepKind {
    fn from_json(v: Option<&Value>, ctx: &str) -> Result<DepKind, MetaError> {
        match v {
            None | Some(Value::Null) => Ok(DepKind::Normal),
            Some(Value::String(s)) if s == "build" => Ok(DepKind::Build),
            Some(Value::String(s)) if s == "dev" => Ok(DepKind::Dev),
            Some(other) => Err(MetaError::new(format!(
                "{ctx}: unknown dependency kind {}",
                other.to_compact()
            ))),
        }
    }

    /// The label cargo uses, with `normal` for plain dependencies.
    pub(crate) fn label(self) -> &'static str {
        match self {
            DepKind::Normal => "normal",
            DepKind::Build => "build",
            DepKind::Dev => "dev",
        }
    }
}

/// A dependency as declared in a package manifest.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DepDecl {
    /// The package name of the dependency.
    pub(crate) name: String,
    /// The key under which the manifest declares it, if renamed.
    pub(crate) rename: Option<String>,
    /// Normal, build or dev.
    pub(crate) kind: DepKind,
    /// Whether the dependency is optional.
    pub(crate) optional: bool,
}

impl DepDecl {
    /// The key that feature definitions use to refer to this dependency.
    pub(crate) fn key(&self) -> &str {
        self.rename.as_deref().unwrap_or(&self.name)
    }
}

/// A build target of a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Target {
    /// Target name.
    pub(crate) name: String,
    /// Target kinds such as `lib`, `bin` or `custom-build`.
    pub(crate) kinds: Vec<String>,
    /// Absolute path of the target's root source file.
    pub(crate) src_path: String,
}

/// A package from the `packages` array.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Package {
    /// Package id.
    pub(crate) id: String,
    /// Package name.
    pub(crate) name: String,
    /// Exact version.
    pub(crate) version: String,
    /// Source, or `None` for a path package.
    pub(crate) source: Option<String>,
    /// Absolute path of the package's `Cargo.toml`.
    pub(crate) manifest_path: String,
    /// The `[features]` table, including implicit features of optional dependencies.
    pub(crate) features: BTreeMap<String, Vec<String>>,
    /// Declared dependencies.
    pub(crate) dependencies: Vec<DepDecl>,
    /// Build targets.
    pub(crate) targets: Vec<Target>,
    /// Whether `[package.metadata] cargo-fuzz = true` is set.
    pub(crate) cargo_fuzz: bool,
}

impl Package {
    /// Whether this is a path package, which this repository treats as in-house.
    pub(crate) fn is_path(&self) -> bool {
        self.source.is_none()
    }
}

/// One edge of a resolve node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct NodeDep {
    /// Index of the target package in [`Metadata::packages`].
    pub(crate) pkg: usize,
    /// The kinds under which the edge exists on the filtered platform.
    pub(crate) kinds: Vec<DepKind>,
}

/// A node of the resolve graph.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Node {
    /// Index of the package in [`Metadata::packages`].
    pub(crate) pkg: usize,
    /// Outgoing edges.
    pub(crate) deps: Vec<NodeDep>,
    /// Features enabled on this package, as cargo reports them.
    pub(crate) features: Vec<String>,
}

/// The parsed metadata of one cargo workspace for one platform.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct Metadata {
    /// All packages.
    pub(crate) packages: Vec<Package>,
    /// Resolve nodes.
    pub(crate) nodes: Vec<Node>,
    /// Node index for each package index that has a node.
    pub(crate) node_of_pkg: HashMap<usize, usize>,
    /// Package indices of the workspace members.
    pub(crate) members: Vec<usize>,
    /// Absolute workspace root.
    pub(crate) workspace_root: String,
}

/// A malformed metadata document.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct MetaError {
    message: String,
}

impl MetaError {
    pub(crate) fn new(message: impl Into<String>) -> MetaError {
        MetaError {
            message: message.into(),
        }
    }
}

impl std::fmt::Display for MetaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

fn field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a Value, MetaError> {
    v.get(key)
        .ok_or_else(|| MetaError::new(format!("{ctx}: missing field `{key}`")))
}

fn str_field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a str, MetaError> {
    field(v, key, ctx)?
        .as_str()
        .ok_or_else(|| MetaError::new(format!("{ctx}: field `{key}` is not a string")))
}

fn opt_str_field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<Option<&'a str>, MetaError> {
    match v.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s)),
        Some(_) => Err(MetaError::new(format!(
            "{ctx}: field `{key}` is neither a string nor null"
        ))),
    }
}

fn array_field<'a>(v: &'a Value, key: &str, ctx: &str) -> Result<&'a Array, MetaError> {
    field(v, key, ctx)?
        .as_array()
        .ok_or_else(|| MetaError::new(format!("{ctx}: field `{key}` is not an array")))
}

fn string_array(v: &Value, ctx: &str) -> Result<Vec<String>, MetaError> {
    let arr = v
        .as_array()
        .ok_or_else(|| MetaError::new(format!("{ctx}: expected an array of strings")))?;
    arr.iter()
        .map(|s| {
            s.as_str()
                .map(str::to_owned)
                .ok_or_else(|| MetaError::new(format!("{ctx}: expected an array of strings")))
        })
        .collect()
}

fn parse_package(v: &Value) -> Result<Package, MetaError> {
    let id = str_field(v, "id", "package")?.to_owned();
    let ctx = format!("package {id}");
    let name = str_field(v, "name", &ctx)?.to_owned();
    let version = str_field(v, "version", &ctx)?.to_owned();
    let source = opt_str_field(v, "source", &ctx)?.map(str::to_owned);
    let manifest_path = str_field(v, "manifest_path", &ctx)?.to_owned();

    let mut features = BTreeMap::new();
    match v.get("features") {
        None | Some(Value::Null) => {}
        Some(Value::Object(obj)) => {
            for (k, vals) in obj.iter() {
                features.insert(k.to_owned(), string_array(vals, &ctx)?);
            }
        }
        Some(_) => {
            return Err(MetaError::new(format!(
                "{ctx}: field `features` is not an object"
            )));
        }
    }

    let mut dependencies = Vec::new();
    for d in array_field(v, "dependencies", &ctx)?.iter() {
        let name = str_field(d, "name", &ctx)?.to_owned();
        let rename = opt_str_field(d, "rename", &ctx)?.map(str::to_owned);
        let kind = DepKind::from_json(d.get("kind"), &ctx)?;
        let optional = match d.get("optional") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(b)) => *b,
            Some(_) => {
                return Err(MetaError::new(format!(
                    "{ctx}: dependency field `optional` is not a boolean"
                )));
            }
        };
        dependencies.push(DepDecl {
            name,
            rename,
            kind,
            optional,
        });
    }

    let mut targets = Vec::new();
    if let Some(ts) = v.get("targets") {
        let ts = ts
            .as_array()
            .ok_or_else(|| MetaError::new(format!("{ctx}: field `targets` is not an array")))?;
        for t in ts.iter() {
            targets.push(Target {
                name: str_field(t, "name", &ctx)?.to_owned(),
                kinds: string_array(field(t, "kind", &ctx)?, &ctx)?,
                src_path: str_field(t, "src_path", &ctx)?.to_owned(),
            });
        }
    }

    let cargo_fuzz = matches!(
        v.get("metadata").and_then(|m| m.get("cargo-fuzz")),
        Some(Value::Bool(true))
    );

    Ok(Package {
        id,
        name,
        version,
        source,
        manifest_path,
        features,
        dependencies,
        targets,
        cargo_fuzz,
    })
}

/// Parses `cargo metadata --format-version 1` output.
pub(crate) fn parse_metadata(input: &[u8]) -> Result<Metadata, MetaError> {
    let doc = fstp_json::parse_with(input, &metadata_limits())
        .map_err(|e| MetaError::new(format!("cargo metadata output is not valid JSON: {e}")))?;
    from_value(&doc)
}

/// Builds a [`Metadata`] from an already parsed document.
pub(crate) fn from_value(doc: &Value) -> Result<Metadata, MetaError> {
    if doc.as_object().is_none() {
        return Err(MetaError::new("metadata: top level is not an object"));
    }
    match doc.get("version").and_then(Value::as_u64) {
        Some(1) => {}
        _ => return Err(MetaError::new("metadata: format version is not 1")),
    }

    let mut packages = Vec::new();
    let mut index: HashMap<String, usize> = HashMap::new();
    for p in array_field(doc, "packages", "metadata")?.iter() {
        let pkg = parse_package(p)?;
        if index.insert(pkg.id.clone(), packages.len()).is_some() {
            return Err(MetaError::new(format!(
                "metadata: duplicate package id {}",
                pkg.id
            )));
        }
        packages.push(pkg);
    }
    let lookup = |id: &str, ctx: &str| -> Result<usize, MetaError> {
        index
            .get(id)
            .copied()
            .ok_or_else(|| MetaError::new(format!("{ctx}: unknown package id {id}")))
    };

    let mut members = Vec::new();
    for m in array_field(doc, "workspace_members", "metadata")?.iter() {
        let id = m
            .as_str()
            .ok_or_else(|| MetaError::new("metadata: workspace member id is not a string"))?;
        members.push(lookup(id, "workspace_members")?);
    }

    let resolve = field(doc, "resolve", "metadata")?;
    if resolve.is_null() {
        return Err(MetaError::new(
            "metadata: `resolve` is null; run without --no-deps",
        ));
    }
    let mut nodes = Vec::new();
    let mut node_of_pkg = HashMap::new();
    for n in array_field(resolve, "nodes", "resolve")?.iter() {
        let pkg = lookup(str_field(n, "id", "resolve node")?, "resolve node")?;
        let ctx = format!("resolve node {}", packages.get(pkg).map_or("", |p| &p.id));
        let mut deps = Vec::new();
        for d in array_field(n, "deps", &ctx)?.iter() {
            let target = lookup(str_field(d, "pkg", &ctx)?, &ctx)?;
            let mut kinds = Vec::new();
            for k in array_field(d, "dep_kinds", &ctx)?.iter() {
                let kind = DepKind::from_json(k.get("kind"), &ctx)?;
                if !kinds.contains(&kind) {
                    kinds.push(kind);
                }
            }
            deps.push(NodeDep { pkg: target, kinds });
        }
        let features = match n.get("features") {
            None | Some(Value::Null) => Vec::new(),
            Some(f) => string_array(f, &ctx)?,
        };
        if node_of_pkg.insert(pkg, nodes.len()).is_some() {
            return Err(MetaError::new(format!("{ctx}: duplicate resolve node")));
        }
        nodes.push(Node {
            pkg,
            deps,
            features,
        });
    }

    let workspace_root = str_field(doc, "workspace_root", "metadata")?.to_owned();
    Ok(Metadata {
        packages,
        nodes,
        node_of_pkg,
        members,
        workspace_root,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const WEAK: &str = include_str!("../testdata/weak-optional.json");

    #[test]
    fn parses_fixture_fields() {
        let m = parse_metadata(WEAK.as_bytes()).unwrap();
        assert_eq!(m.members.len(), 1);
        let webpki = m
            .packages
            .iter()
            .find(|p| p.name == "rustls-webpki")
            .unwrap();
        assert_eq!(webpki.version, "0.103.16");
        assert!(!webpki.is_path());
        assert_eq!(
            webpki.features.get("alloc").unwrap(),
            &vec!["ring?/alloc".to_owned(), "pki-types/alloc".to_owned()]
        );
        let ring = webpki
            .dependencies
            .iter()
            .find(|d| d.name == "ring")
            .unwrap();
        assert!(ring.optional);
        assert_eq!(ring.kind, DepKind::Normal);
        let pki = webpki
            .dependencies
            .iter()
            .find(|d| d.name == "rustls-pki-types")
            .unwrap();
        assert_eq!(pki.key(), "pki-types");
    }

    #[test]
    fn rejects_wrong_shapes_without_panicking() {
        for bad in [
            "",
            "[]",
            "{}",
            r#"{"version": 2}"#,
            r#"{"version": 1, "packages": {}}"#,
            r#"{"version": 1, "packages": [], "workspace_members": ["x"]}"#,
            r#"{"version": 1, "packages": [], "workspace_members": [], "resolve": null}"#,
            r#"{"version": 1, "packages": [], "workspace_members": [],
                "resolve": {"nodes": [{"id": "nope", "deps": [], "features": []}]},
                "workspace_root": "/"}"#,
        ] {
            assert!(parse_metadata(bad.as_bytes()).is_err(), "{bad}");
        }
    }

    #[test]
    fn unknown_dep_kind_is_an_error() {
        let doc = WEAK.replace("\"kind\": \"build\"", "\"kind\": \"weird\"");
        let err = parse_metadata(doc.as_bytes()).unwrap_err();
        assert!(err.to_string().contains("unknown dependency kind"), "{err}");
    }

    /// TH-15: the gate's input parser must never panic, even on corrupted
    /// metadata, so a broken toolchain cannot crash the gate open.
    #[test]
    fn th15_metadata_parser_never_panics_on_mutations() {
        fstp_prop::check("th15_metadata_parser_never_panics_on_mutations", |g| {
            let mut bytes = WEAK.as_bytes().to_vec();
            let edits = g.usize_in(1..=8);
            for _ in 0..edits {
                if bytes.is_empty() {
                    break;
                }
                let at = g.usize_in(0..=bytes.len().saturating_sub(1));
                match g.u8_in(0..=2) {
                    0 => bytes[at] = g.u8(),
                    1 => {
                        bytes.remove(at);
                    }
                    _ => bytes.truncate(at),
                }
            }
            let _ = parse_metadata(&bytes);
            Ok(())
        });
    }
}
