//! The release SBOM (R-NF-07, ADR-003, M9 design lane S1).
//!
//! `deps-check sbom` writes a CycloneDX 1.6 JSON document from the same
//! resolved trees that the allowlist gate reads. Nothing here is a third
//! party tool: the document is built as an `fstp-json` value.
//!
//! - Every third-party crate that deps-check resolves is one component,
//!   with its version, its `.crate` SHA-256 or its pinned git commit, its
//!   deps-check role and its ADRs. A runtime crate without a checksum or
//!   pin is refused.
//! - Every package of `web/package-lock.json` and `e2e/package-lock.json`
//!   is one component, with its `sha512` integrity as a hex hash.
//! - Node.js and npm, the build and test hosts of ADR-003, are components.
//! - Only runtime crates have the CycloneDX scope `required`. Everything
//!   else has scope `excluded` and the property `fstp:stage` set to
//!   `build-time`, so build and test tools stay apart from what ships.
//! - Tier B crates carry `fstp:tier-b`, `confirmed` or `unconfirmed`,
//!   from `deps/tier-b-confirmations.txt` (I-74).
//! - Licences are the `license` field each package declares.
//! - The output has no timestamp and no random serial number, and every
//!   list is sorted, so two runs give identical bytes.
//!
//! TODO(legal): the format is CycloneDX 1.6 JSON (M9 design D5). Whether
//! the CRA implementing acts name a format is open (`05-compliance/cra.md`).

use std::collections::{BTreeMap, BTreeSet};

use fstp_json::{Array, Object, Value};

use crate::allowlist::{Entry, valid_checksum};
use crate::git_source;
use crate::graph::{Aggregate, PkgKey, Role};
use crate::npm::NpmLock;
use crate::tier_b::{self, TierB};

/// The CycloneDX specification version written.
pub(crate) const SPEC_VERSION: &str = "1.6";

/// The build and test hosts of the ADR-003 amendment, as CI pins them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct HostTools {
    /// The pinned Node.js version, `major.minor.patch`.
    pub(crate) node_version: String,
    /// SHA-256 of the linux-x64 Node.js archive CI checks.
    pub(crate) node_sha256: String,
    /// The npm version bundled with that Node.js.
    pub(crate) npm_version: String,
}

/// Everything the SBOM is built from.
pub(crate) struct Inputs<'a> {
    /// The aggregated resolved trees of every cargo project.
    pub(crate) agg: &'a Aggregate,
    /// The `.crate` checksum of each package, from the lockfiles.
    pub(crate) checksums: &'a BTreeMap<PkgKey, String>,
    /// The allowlist, for git pins and Tier B source hashes.
    pub(crate) entries: &'a [Entry],
    /// The Tier B markers and confirmations.
    pub(crate) tier: &'a TierB,
    /// The licence each crate declares.
    pub(crate) licences: &'a BTreeMap<PkgKey, String>,
    /// Each npm project directory with its parsed lockfile.
    pub(crate) npm: &'a [(String, NpmLock)],
    /// Node.js and npm.
    pub(crate) host: &'a HostTools,
    /// The platform version, written as the SBOM subject's version.
    pub(crate) version: &'a str,
}

/// One component before rendering.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct Component {
    /// `library` or `application`.
    kind: &'static str,
    name: String,
    version: String,
    purl: String,
    role: Role,
    sha256: Option<String>,
    sha512: Option<String>,
    /// Repository URL and commit of a pinned git source.
    git: Option<(String, String)>,
    licence: Option<String>,
    adrs: BTreeSet<String>,
    /// The npm projects that lock the package.
    projects: BTreeSet<String>,
    /// `Some(confirmed)` for a Tier B crate.
    tier_b: Option<bool>,
}

/// Builds the SBOM and returns its bytes, or every reason it cannot.
pub(crate) fn build(inputs: &Inputs<'_>) -> Result<String, Vec<String>> {
    let mut errors = Vec::new();
    let mut all: BTreeMap<String, Component> = BTreeMap::new();
    for c in cargo_components(inputs, &mut errors)
        .into_iter()
        .chain(npm_components(inputs.npm, &mut errors))
        .chain(host_components(inputs.host, &mut errors))
    {
        match all.get_mut(&c.purl) {
            Some(seen) => {
                seen.role = seen.role.max(c.role);
                seen.projects.extend(c.projects);
                if seen.licence.is_none() {
                    seen.licence = c.licence;
                }
            }
            None => {
                all.insert(c.purl.clone(), c);
            }
        }
    }
    if !errors.is_empty() {
        errors.sort();
        errors.dedup();
        return Err(errors);
    }
    let mut text = render(all.values(), inputs.version).to_pretty();
    text.push('\n');
    Ok(text)
}

/// Every crate of the resolved trees.
fn cargo_components(inputs: &Inputs<'_>, errors: &mut Vec<String>) -> Vec<Component> {
    // ADR-001 A3: every package from a Tier B crate's git repository is Tier B.
    let tier_repos: BTreeSet<&str> = inputs
        .entries
        .iter()
        .filter(|e| inputs.tier.markers.contains(&e.name))
        .filter_map(|e| git_source::repo_url(&e.checksum))
        .collect();
    let mut out = Vec::new();
    for ((name, version), usage) in &inputs.agg.usage {
        let key = (name.clone(), version.clone());
        let entry = inputs
            .entries
            .iter()
            .find(|e| &e.name == name && &e.version == version);
        let git = entry
            .and_then(|e| git_source::parse_pinned(&e.checksum))
            .map(|g| (g.url.to_owned(), g.commit.to_owned()));
        let sha256 = inputs
            .checksums
            .get(&key)
            .filter(|s| valid_checksum(s))
            .cloned();
        if usage.role == Role::Runtime && sha256.is_none() && git.is_none() {
            errors.push(format!(
                "{name} {version} is a runtime crate with no .crate SHA-256 and no pinned git source (R-NF-07)"
            ));
        }
        let is_tier_b = inputs.tier.markers.contains(name)
            || entry
                .and_then(|e| git_source::repo_url(&e.checksum))
                .is_some_and(|u| tier_repos.contains(u));
        let tier_b = is_tier_b.then(|| {
            tier_b::expected_hash(inputs.entries, name, version).is_some_and(|h| {
                inputs
                    .tier
                    .confirmations
                    .iter()
                    .any(|c| &c.krate == name && &c.version == version && c.hash == h)
            })
        });
        out.push(Component {
            kind: "library",
            name: name.clone(),
            version: version.clone(),
            purl: format!("pkg:cargo/{name}@{version}"),
            role: usage.role,
            sha256,
            git,
            licence: inputs.licences.get(&key).cloned(),
            adrs: usage.adrs.clone(),
            tier_b,
            ..Component::default()
        });
    }
    out
}

/// Every package of the npm lockfiles. `web/` holds the compiler, a build
/// tool; `e2e/` holds Playwright, a test tool (ADR-003).
fn npm_components(npm: &[(String, NpmLock)], errors: &mut Vec<String>) -> Vec<Component> {
    let mut out = Vec::new();
    for (project, lock) in npm {
        let role = if project == "web" {
            Role::Build
        } else {
            Role::Test
        };
        for p in &lock.packages {
            let Some(version) = p.version.clone() else {
                errors.push(format!("{project}: {} has no version", p.key));
                continue;
            };
            let sha512 = p.integrity.as_deref().and_then(integrity_hex);
            if sha512.is_none() {
                errors.push(format!(
                    "{project}: {} {version} has no sha512 integrity value",
                    p.name
                ));
            }
            let encoded = p.name.replacen('@', "%40", 1);
            out.push(Component {
                kind: "library",
                name: p.name.clone(),
                version: version.clone(),
                purl: format!("pkg:npm/{encoded}@{version}"),
                role,
                sha512,
                licence: p.license.clone(),
                adrs: BTreeSet::from(["ADR-003".to_owned()]),
                projects: BTreeSet::from([project.clone()]),
                ..Component::default()
            });
        }
    }
    out
}

/// Node.js and npm, the build and test hosts (ADR-003 amendment).
fn host_components(host: &HostTools, errors: &mut Vec<String>) -> Vec<Component> {
    if !valid_checksum(&host.node_sha256) {
        errors.push(format!(
            "the Node.js archive digest `{}` is not a SHA-256 in lowercase hex",
            host.node_sha256
        ));
    }
    for (what, v) in [("Node.js", &host.node_version), ("npm", &host.npm_version)] {
        if !crate::allowlist::valid_version(v) {
            errors.push(format!("the {what} version `{v}` is not exact"));
        }
    }
    let adrs = BTreeSet::from(["ADR-003".to_owned()]);
    vec![
        Component {
            kind: "application",
            name: "node".into(),
            version: host.node_version.clone(),
            purl: format!("pkg:generic/node@{}", host.node_version),
            role: Role::Build,
            sha256: Some(host.node_sha256.clone()),
            adrs: adrs.clone(),
            ..Component::default()
        },
        Component {
            kind: "application",
            name: "npm".into(),
            version: host.npm_version.clone(),
            purl: format!("pkg:npm/npm@{}", host.npm_version),
            role: Role::Build,
            adrs,
            ..Component::default()
        },
    ]
}

/// The CycloneDX document.
fn render<'a>(components: impl Iterator<Item = &'a Component>, version: &str) -> Value {
    let s = |v: &str| Value::String(v.to_owned());
    let mut subject = Object::new();
    subject.insert("type", s("application"));
    subject.insert("bom-ref", s("fstp"));
    subject.insert("name", s("fstp"));
    subject.insert("version", s(version));
    let mut tool = Object::new();
    tool.insert("type", s("application"));
    tool.insert("name", s("deps-check"));
    tool.insert("version", s(version));
    let mut tools = Object::new();
    tools.insert(
        "components",
        Value::Array(Array::from(vec![Value::Object(tool)])),
    );
    let mut metadata = Object::new();
    metadata.insert("tools", Value::Object(tools));
    metadata.insert("component", Value::Object(subject));

    let mut root = Object::new();
    root.insert(
        "$schema",
        s("http://cyclonedx.org/schema/bom-1.6.schema.json"),
    );
    root.insert("bomFormat", s("CycloneDX"));
    root.insert("specVersion", s(SPEC_VERSION));
    root.insert("version", Value::from(1_u64));
    root.insert("metadata", Value::Object(metadata));
    root.insert(
        "components",
        Value::Array(components.map(render_component).collect()),
    );
    Value::Object(root)
}

fn render_component(c: &Component) -> Value {
    let s = |v: &str| Value::String(v.to_owned());
    let pair = |a: &str, av: &str, b: &str, bv: &str| {
        let mut o = Object::new();
        o.insert(a, s(av));
        o.insert(b, s(bv));
        Value::Object(o)
    };
    let runtime = c.role == Role::Runtime;
    let mut o = Object::new();
    o.insert("type", s(c.kind));
    o.insert("bom-ref", s(&c.purl));
    o.insert("name", s(&c.name));
    o.insert("version", s(&c.version));
    o.insert("scope", s(if runtime { "required" } else { "excluded" }));
    let hashes: Array = [("SHA-256", &c.sha256), ("SHA-512", &c.sha512)]
        .into_iter()
        .filter_map(|(alg, h)| h.as_deref().map(|h| pair("alg", alg, "content", h)))
        .collect();
    if !hashes.is_empty() {
        o.insert("hashes", Value::Array(hashes));
    }
    if let Some(l) = &c.licence {
        let mut lic = Object::new();
        lic.insert("expression", s(&licence_expression(l)));
        o.insert(
            "licenses",
            Value::Array(Array::from(vec![Value::Object(lic)])),
        );
    }
    o.insert("purl", s(&c.purl));
    if let Some((url, _)) = &c.git {
        o.insert(
            "externalReferences",
            Value::Array(Array::from(vec![pair("type", "vcs", "url", url)])),
        );
    }
    let mut props = vec![
        ("fstp:role", c.role.label().to_owned()),
        (
            "fstp:stage",
            if runtime { "runtime" } else { "build-time" }.to_owned(),
        ),
    ];
    if !c.adrs.is_empty() {
        props.push(("fstp:adr", join(&c.adrs)));
    }
    if let Some((_, commit)) = &c.git {
        props.push(("fstp:git-commit", commit.clone()));
    }
    if !c.projects.is_empty() {
        props.push(("fstp:npm-project", join(&c.projects)));
    }
    if let Some(confirmed) = c.tier_b {
        props.push((
            "fstp:tier-b",
            if confirmed {
                "confirmed"
            } else {
                "unconfirmed"
            }
            .to_owned(),
        ));
    }
    o.insert(
        "properties",
        Value::Array(
            props
                .iter()
                .map(|(n, v)| pair("name", n, "value", v))
                .collect(),
        ),
    );
    Value::Object(o)
}

fn join(items: &BTreeSet<String>) -> String {
    items
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(",")
}

/// A declared licence as an SPDX expression: cargo's old `A/B` form
/// means `A OR B`.
fn licence_expression(l: &str) -> String {
    l.split('/').map(str::trim).collect::<Vec<_>>().join(" OR ")
}

/// The value of one standard base64 digit.
fn digit(b: u8) -> Option<u32> {
    let v = match b {
        b'A'..=b'Z' => b.checked_sub(b'A')?,
        b'a'..=b'z' => b.checked_sub(b'a')?.checked_add(26)?,
        b'0'..=b'9' => b.checked_sub(b'0')?.checked_add(52)?,
        b'+' => 62,
        b'/' => 63,
        _ => return None,
    };
    Some(u32::from(v))
}

/// Decodes an npm `sha512-<base64>` integrity value to lowercase hex.
/// A SHA-512 is 64 bytes: 86 digits and `==`, nothing else.
pub(crate) fn integrity_hex(integrity: &str) -> Option<String> {
    let body = integrity.strip_prefix("sha512-")?.strip_suffix("==")?;
    if body.len() != 86 {
        return None;
    }
    let mut bytes: Vec<u8> = Vec::with_capacity(64);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for b in body.bytes() {
        acc = (acc << 6) | digit(b)?;
        bits = bits.checked_add(6)?;
        if bits >= 8 {
            bits = bits.checked_sub(8)?;
            bytes.push(u8::try_from((acc >> bits) & 0xff).ok()?);
            acc &= (1_u32 << bits).checked_sub(1)?;
        }
    }
    // 86 digits carry 516 bits: 64 bytes and four zero padding bits.
    if bytes.len() != 64 || acc != 0 {
        return None;
    }
    Some(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use crate::allowlist::tests::{SUM_A, SUM_B};
    use crate::graph::Usage;
    use crate::npm::LockPackage;
    use crate::tier_b::Confirmation;

    const GIT: &str = "git+https://github.com/crabnebula-dev/moduletto?rev=6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683#6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683";
    /// The ADR-003 record of typescript 6.0.3.
    const TS_INTEGRITY: &str = "sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw==";
    const NODE_SHA: &str = "60e3b0a8500819514aca603487c254298cd776de0698d3cd08f11dba5b8289a8";

    fn usage(role: Role, adr: &str) -> Usage {
        Usage {
            role,
            linux: role != Role::Platform,
            adrs: BTreeSet::from([adr.to_owned()]),
            ..Usage::default()
        }
    }

    fn key(n: &str, v: &str) -> PkgKey {
        (n.to_owned(), v.to_owned())
    }

    fn entry(name: &str, version: &str, checksum: &str, role: Role) -> Entry {
        Entry {
            name: name.into(),
            version: version.into(),
            checksum: checksum.into(),
            adrs: BTreeSet::from(["ADR-001".to_owned()]),
            role,
            note: "synthetic".into(),
        }
    }

    struct World {
        agg: Aggregate,
        checksums: BTreeMap<PkgKey, String>,
        entries: Vec<Entry>,
        tier: TierB,
        licences: BTreeMap<PkgKey, String>,
        npm: Vec<(String, NpmLock)>,
        host: HostTools,
    }

    impl World {
        /// A small synthetic tree: two runtime crates (one Tier B from
        /// git, one Tier B from crates.io), a build crate, a test crate,
        /// a platform crate, and the web/ and e2e/ npm trees.
        fn new() -> World {
            let mut agg = Aggregate::default();
            agg.usage
                .insert(key("aws-lc-rs", "1.18.2"), usage(Role::Runtime, "ADR-001"));
            agg.usage
                .insert(key("moduletto", "0.1.0"), usage(Role::Runtime, "ADR-001"));
            agg.usage
                .insert(key("der", "0.7.10"), usage(Role::Runtime, "ADR-001"));
            agg.usage
                .insert(key("cc", "1.10.0"), usage(Role::Build, "ADR-001"));
            agg.usage
                .insert(key("arbitrary", "1.5.0"), usage(Role::Test, "ADR-003"));
            agg.usage
                .insert(key("r-efi", "6.0.0"), usage(Role::Platform, "ADR-003"));
            let checksums = BTreeMap::from([
                (key("aws-lc-rs", "1.18.2"), SUM_A.to_owned()),
                (key("der", "0.7.10"), SUM_B.to_owned()),
                (key("cc", "1.10.0"), SUM_A.to_owned()),
                (key("arbitrary", "1.5.0"), SUM_B.to_owned()),
                (key("r-efi", "6.0.0"), SUM_A.to_owned()),
            ]);
            let entries = vec![
                entry("aws-lc-rs", "1.18.2", SUM_A, Role::Runtime),
                entry("moduletto", "0.1.0", GIT, Role::Runtime),
                entry("der", "0.7.10", SUM_B, Role::Runtime),
            ];
            let tier = TierB {
                markers: BTreeSet::from(["moduletto".to_owned(), "der".to_owned()]),
                confirmations: vec![Confirmation {
                    krate: "der".into(),
                    version: "0.7.10".into(),
                    hash: SUM_B.into(),
                    date: "2026-11-06".into(),
                    findings: "synthetic".into(),
                }],
            };
            let licences = BTreeMap::from([
                (
                    key("aws-lc-rs", "1.18.2"),
                    "ISC AND (Apache-2.0 OR ISC)".to_owned(),
                ),
                (key("cc", "1.10.0"), "MIT/Apache-2.0".to_owned()),
            ]);
            let ts = |v: &str| LockPackage {
                key: "node_modules/typescript".into(),
                name: "typescript".into(),
                version: Some(v.into()),
                integrity: Some(TS_INTEGRITY.into()),
                license: Some("Apache-2.0".into()),
                ..LockPackage::default()
            };
            let pw = |name: &str| LockPackage {
                key: format!("node_modules/{name}"),
                name: name.into(),
                version: Some("1.64.1".into()),
                integrity: Some(TS_INTEGRITY.into()),
                license: Some("Apache-2.0".into()),
                ..LockPackage::default()
            };
            let npm = vec![
                (
                    "web".to_owned(),
                    NpmLock {
                        root_deps: vec!["typescript".into()],
                        packages: vec![ts("6.0.3")],
                    },
                ),
                (
                    "e2e".to_owned(),
                    NpmLock {
                        root_deps: vec!["@playwright/test".into(), "typescript".into()],
                        packages: vec![pw("@playwright/test"), pw("playwright"), ts("6.0.3")],
                    },
                ),
            ];
            World {
                agg,
                checksums,
                entries,
                tier,
                licences,
                npm,
                host: HostTools {
                    node_version: "24.11.1".into(),
                    node_sha256: NODE_SHA.into(),
                    npm_version: "11.6.2".into(),
                },
            }
        }

        fn inputs(&self) -> Inputs<'_> {
            Inputs {
                agg: &self.agg,
                checksums: &self.checksums,
                entries: &self.entries,
                tier: &self.tier,
                licences: &self.licences,
                npm: &self.npm,
                host: &self.host,
                version: "0.1.0",
            }
        }

        fn doc(&self) -> Value {
            let text = build(&self.inputs()).unwrap();
            fstp_json::parse(text.as_bytes()).unwrap()
        }
    }

    fn components(doc: &Value) -> Vec<&Value> {
        doc.get("components")
            .and_then(Value::as_array)
            .unwrap()
            .iter()
            .collect()
    }

    fn find<'a>(doc: &'a Value, purl: &str) -> &'a Value {
        components(doc)
            .into_iter()
            .find(|c| c.get("purl").and_then(Value::as_str) == Some(purl))
            .unwrap_or_else(|| panic!("no component {purl}"))
    }

    fn prop<'a>(c: &'a Value, name: &str) -> Option<&'a str> {
        c.get("properties")?
            .as_array()?
            .iter()
            .find(|p| p.get("name").and_then(Value::as_str) == Some(name))?
            .get("value")?
            .as_str()
    }

    fn str_at<'a>(c: &'a Value, k: &str) -> Option<&'a str> {
        c.get(k).and_then(Value::as_str)
    }

    fn hash(c: &Value, alg: &str) -> Option<String> {
        c.get("hashes")?
            .as_array()?
            .iter()
            .find(|h| str_at(h, "alg") == Some(alg))
            .and_then(|h| str_at(h, "content"))
            .map(str::to_owned)
    }

    /// R-NF-07, M9 design `r_nf_07_sbom_matches_tree`: the cargo components
    /// are exactly the crates of the deps-check resolved tree, each with
    /// its version and role, in a CycloneDX 1.6 document.
    #[test]
    fn r_nf_07_sbom_matches_tree() {
        let w = World::new();
        let doc = w.doc();
        assert_eq!(str_at(&doc, "bomFormat"), Some("CycloneDX"));
        assert_eq!(str_at(&doc, "specVersion"), Some(SPEC_VERSION));
        let cargo: BTreeSet<(String, String, String)> = components(&doc)
            .into_iter()
            .filter(|c| str_at(c, "purl").is_some_and(|p| p.starts_with("pkg:cargo/")))
            .map(|c| {
                (
                    str_at(c, "name").unwrap().to_owned(),
                    str_at(c, "version").unwrap().to_owned(),
                    prop(c, "fstp:role").unwrap().to_owned(),
                )
            })
            .collect();
        let tree: BTreeSet<(String, String, String)> = w
            .agg
            .usage
            .iter()
            .map(|((n, v), u)| (n.clone(), v.clone(), u.role.label().to_owned()))
            .collect();
        assert_eq!(cargo, tree);
        let npm: BTreeSet<&str> = components(&doc)
            .into_iter()
            .filter_map(|c| str_at(c, "purl"))
            .filter(|p| p.starts_with("pkg:npm/"))
            .collect();
        assert_eq!(
            npm,
            BTreeSet::from([
                "pkg:npm/%40playwright/test@1.64.1",
                "pkg:npm/npm@11.6.2",
                "pkg:npm/playwright@1.64.1",
                "pkg:npm/typescript@6.0.3",
            ])
        );
        let refs: Vec<&str> = components(&doc)
            .into_iter()
            .filter_map(|c| str_at(c, "bom-ref"))
            .collect();
        let mut sorted = refs.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(refs, sorted, "bom-refs are unique and sorted");
    }

    /// R-NF-07: two runs over the same tree give identical bytes, with no
    /// timestamp and no random serial number.
    #[test]
    fn r_nf_07_sbom_two_runs_give_identical_bytes() {
        let w = World::new();
        let a = build(&w.inputs()).unwrap();
        let b = build(&w.inputs()).unwrap();
        assert_eq!(a, b);
        assert!(!a.contains("timestamp"), "{a}");
        assert!(!a.contains("serialNumber"), "{a}");
        // The npm projects in the other order give the same document.
        let mut w2 = World::new();
        w2.npm.reverse();
        assert_eq!(build(&w2.inputs()).unwrap(), a);
    }

    /// R-NF-07: every runtime crate carries its version and its `.crate`
    /// SHA-256, or the pinned commit of its git source (ADR-001 A3).
    #[test]
    fn r_nf_07_sbom_runtime_packages_carry_version_and_checksum() {
        let w = World::new();
        let doc = w.doc();
        let aws = find(&doc, "pkg:cargo/aws-lc-rs@1.18.2");
        assert_eq!(str_at(aws, "version"), Some("1.18.2"));
        assert_eq!(str_at(aws, "scope"), Some("required"));
        assert_eq!(hash(aws, "SHA-256").as_deref(), Some(SUM_A));
        assert_eq!(prop(aws, "fstp:adr"), Some("ADR-001"));
        let moduletto = find(&doc, "pkg:cargo/moduletto@0.1.0");
        assert_eq!(
            prop(moduletto, "fstp:git-commit"),
            Some("6c1ae92f2bf14eb56b5d48d1e7fc6f7ca5843683")
        );
        let vcs = moduletto
            .get("externalReferences")
            .and_then(Value::as_array)
            .and_then(|a| a.first())
            .unwrap();
        assert_eq!(
            str_at(vcs, "url"),
            Some("https://github.com/crabnebula-dev/moduletto")
        );
        for c in components(&doc) {
            if prop(c, "fstp:role") == Some("runtime") {
                assert!(str_at(c, "version").is_some_and(|v| !v.is_empty()));
                assert!(
                    hash(c, "SHA-256").is_some() || prop(c, "fstp:git-commit").is_some(),
                    "{}",
                    c.to_compact()
                );
            }
        }
    }

    /// R-NF-07: a runtime crate without a checksum or a pinned git source
    /// is refused, never written without one.
    #[test]
    fn r_nf_07_sbom_refuses_runtime_package_without_checksum() {
        let mut w = World::new();
        w.checksums.remove(&key("aws-lc-rs", "1.18.2"));
        let errs = build(&w.inputs()).unwrap_err();
        assert!(
            errs.iter().any(|e| e.contains("aws-lc-rs 1.18.2")),
            "{errs:?}"
        );
    }

    /// R-NF-07, ADR-003: build and test tools (Node.js, npm, tsc,
    /// Playwright, and crates with the build, test or platform role) are
    /// marked build-time and excluded; only runtime crates are required.
    #[test]
    fn r_nf_07_sbom_marks_build_time_tools() {
        let w = World::new();
        let doc = w.doc();
        for purl in [
            "pkg:generic/node@24.11.1",
            "pkg:npm/npm@11.6.2",
            "pkg:npm/typescript@6.0.3",
            "pkg:npm/%40playwright/test@1.64.1",
            "pkg:npm/playwright@1.64.1",
            "pkg:cargo/cc@1.10.0",
            "pkg:cargo/arbitrary@1.5.0",
            "pkg:cargo/r-efi@6.0.0",
        ] {
            let c = find(&doc, purl);
            assert_eq!(prop(c, "fstp:stage"), Some("build-time"), "{purl}");
            assert_eq!(str_at(c, "scope"), Some("excluded"), "{purl}");
        }
        let node = find(&doc, "pkg:generic/node@24.11.1");
        assert_eq!(hash(node, "SHA-256").as_deref(), Some(NODE_SHA));
        let ts = find(&doc, "pkg:npm/typescript@6.0.3");
        assert_eq!(prop(ts, "fstp:role"), Some("build"));
        assert_eq!(prop(ts, "fstp:npm-project"), Some("e2e,web"));
        assert_eq!(
            hash(ts, "SHA-512"),
            integrity_hex(TS_INTEGRITY),
            "the integrity becomes a hex SHA-512"
        );
        assert_eq!(
            prop(find(&doc, "pkg:npm/playwright@1.64.1"), "fstp:role"),
            Some("test")
        );
        for c in components(&doc) {
            let runtime = prop(c, "fstp:role") == Some("runtime");
            assert_eq!(
                str_at(c, "scope") == Some("required"),
                runtime,
                "{}",
                c.to_compact()
            );
            assert_eq!(
                prop(c, "fstp:stage") == Some("runtime"),
                runtime,
                "{}",
                c.to_compact()
            );
        }
    }

    /// R-NF-07, I-74: Tier B crates carry their confirmation status, and
    /// other crates carry none.
    #[test]
    fn r_nf_07_sbom_tier_b_carries_confirmation_status() {
        let w = World::new();
        let doc = w.doc();
        assert_eq!(
            prop(find(&doc, "pkg:cargo/der@0.7.10"), "fstp:tier-b"),
            Some("confirmed")
        );
        assert_eq!(
            prop(find(&doc, "pkg:cargo/moduletto@0.1.0"), "fstp:tier-b"),
            Some("unconfirmed")
        );
        assert_eq!(
            prop(find(&doc, "pkg:cargo/aws-lc-rs@1.18.2"), "fstp:tier-b"),
            None
        );
    }

    /// R-NF-07: declared licences become CycloneDX licence expressions;
    /// the old `A/B` form reads as `A OR B`.
    #[test]
    fn r_nf_07_sbom_licences() {
        let w = World::new();
        let doc = w.doc();
        let expr = |purl: &str| {
            find(&doc, purl)
                .get("licenses")
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|l| str_at(l, "expression"))
                .map(str::to_owned)
        };
        assert_eq!(
            expr("pkg:cargo/aws-lc-rs@1.18.2").as_deref(),
            Some("ISC AND (Apache-2.0 OR ISC)")
        );
        assert_eq!(
            expr("pkg:cargo/cc@1.10.0").as_deref(),
            Some("MIT OR Apache-2.0")
        );
        assert_eq!(
            expr("pkg:npm/typescript@6.0.3").as_deref(),
            Some("Apache-2.0")
        );
        assert_eq!(expr("pkg:cargo/arbitrary@1.5.0"), None);
    }

    /// R-NF-07: the integrity decoder yields 128 hex digits for a valid
    /// value and refuses anything else.
    #[test]
    fn r_nf_07_integrity_decodes_to_sha512_hex() {
        let hex = integrity_hex(TS_INTEGRITY).unwrap();
        assert_eq!(hex.len(), 128);
        assert!(hex.starts_with("cb64efbb1499"), "{hex}");
        for bad in [
            "",
            "sha512-",
            "sha256-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw==",
            "sha512-y2Tv",
            "sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdBw=",
            "sha512-y2TvuxSZPDyQakkFRPZHKFm+KKVqIisdg9/CZwm9ftvKXLP8NRWj38/ODjNbr43SsoXqNuAisEf1GdCxqWcdB*==",
        ] {
            assert_eq!(integrity_hex(bad), None, "{bad}");
        }
    }

    /// R-NF-07: a malformed Node.js digest or an npm package without an
    /// integrity value is refused.
    #[test]
    fn r_nf_07_sbom_refuses_unhashed_tools() {
        let mut w = World::new();
        w.host.node_sha256 = "abc".into();
        assert!(build(&w.inputs()).is_err());
        let mut w = World::new();
        if let Some((_, lock)) = w.npm.get_mut(0)
            && let Some(p) = lock.packages.get_mut(0)
        {
            p.integrity = None;
        }
        let errs = build(&w.inputs()).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("typescript")), "{errs:?}");
    }
}
