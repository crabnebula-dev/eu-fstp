//! Findings and the text and JSON reports.

use std::collections::BTreeMap;

use fstp_json::{Array, Object, Value};

use crate::graph::{Aggregate, PkgKey, Role};

/// How serious a finding is.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Severity {
    /// Reported, but the gate still passes.
    Warning,
    /// Fails the gate.
    Error,
}

impl Severity {
    fn label(self) -> &'static str {
        match self {
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

/// One result of a check.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct Finding {
    /// Error or warning. Errors sort last, so they end up at the bottom of the output.
    pub(crate) severity: Severity,
    /// A stable slug such as `unlisted` or `python-file`.
    pub(crate) code: &'static str,
    /// Human-readable detail.
    pub(crate) message: String,
}

impl Finding {
    /// An error finding.
    pub(crate) fn error(code: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Error,
            code,
            message: message.into(),
        }
    }

    /// A warning finding.
    pub(crate) fn warning(code: &'static str, message: impl Into<String>) -> Finding {
        Finding {
            severity: Severity::Warning,
            code,
            message: message.into(),
        }
    }
}

/// A short summary of one analysed context.
#[derive(Clone, Debug)]
pub(crate) struct ContextSummary {
    /// Project label.
    pub(crate) label: String,
    /// Target triple, or `all targets`.
    pub(crate) platform: String,
    /// Whether the context ran with `--all-features`.
    pub(crate) all_features: bool,
    /// Packages in the resolve graph.
    pub(crate) resolved: usize,
}

/// Fuzz gate result for one crate.
#[derive(Clone, Debug)]
pub(crate) struct FuzzSummary {
    /// Crate name.
    pub(crate) krate: String,
    /// Fuzz target names, empty when the project is missing or broken.
    pub(crate) targets: Vec<String>,
    /// Whether deps/fuzz-required.txt lists the crate.
    pub(crate) required: bool,
}

/// Everything the report prints.
pub(crate) struct Report<'a> {
    /// Analysed contexts.
    pub(crate) contexts: &'a [ContextSummary],
    /// Graph analysis.
    pub(crate) aggregate: &'a Aggregate,
    /// Lockfile checksum of each crates.io package.
    pub(crate) checksums: &'a BTreeMap<PkgKey, String>,
    /// Fuzz projects.
    pub(crate) fuzz: &'a [FuzzSummary],
    /// Number of files the Python scan inspected.
    pub(crate) scanned_files: usize,
    /// All findings, sorted.
    pub(crate) findings: &'a [Finding],
}

impl Report<'_> {
    /// Number of error findings.
    pub(crate) fn errors(&self) -> usize {
        self.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .count()
    }

    /// Renders the text report.
    pub(crate) fn text(&self) -> String {
        let mut out = String::new();
        out.push_str(
            "deps-check: dependency allowlist, no-Python, fuzz-target and layering gates\n\n",
        );
        out.push_str("Contexts (cargo metadata --locked):\n");
        for c in self.contexts {
            let features = if c.all_features {
                "all features"
            } else {
                "default features"
            };
            out.push_str(&format!(
                "  {:<26} {:<26} {features:<16} {} resolved packages\n",
                c.label, c.platform, c.resolved
            ));
        }

        let mut counts: BTreeMap<Role, usize> = BTreeMap::new();
        for u in self.aggregate.usage.values() {
            let slot = counts.entry(u.role).or_insert(0);
            *slot = slot.saturating_add(1);
        }
        out.push_str(&format!(
            "\nThird-party packages built: {} (runtime {}, build {}, test {}, platform {})\n",
            self.aggregate.usage.len(),
            counts.get(&Role::Runtime).copied().unwrap_or(0),
            counts.get(&Role::Build).copied().unwrap_or(0),
            counts.get(&Role::Test).copied().unwrap_or(0),
            counts.get(&Role::Platform).copied().unwrap_or(0),
        ));
        for ((name, version), u) in &self.aggregate.usage {
            out.push_str(&format!(
                "  {:<18} {:<10} {:<8} {:<24} via {}\n",
                name,
                version,
                u.role.label(),
                join(u.adrs.iter(), ","),
                join(u.roots.iter(), ", ")
            ));
        }

        if !self.aggregate.excluded.is_empty() {
            out.push_str("\nIn a resolve graph but never built (not counted as used):\n");
            for ((name, version), reasons) in &self.aggregate.excluded {
                out.push_str(&format!("  {name} {version}\n"));
                for (reason, seen) in reasons {
                    out.push_str(&format!(
                        "    - {reason}\n      in {} on {}\n",
                        join(seen.labels.iter(), ", "),
                        join(seen.platforms.iter(), ", ")
                    ));
                }
            }
        }

        out.push_str("\nFuzz projects (crates/*/fuzz, tools/*/fuzz):\n");
        for f in self.fuzz {
            let req = if f.required { "required" } else { "optional" };
            if f.targets.is_empty() {
                out.push_str(&format!("  {:<14} {req:<8} no usable targets\n", f.krate));
            } else {
                out.push_str(&format!(
                    "  {:<14} {req:<8} {} target(s): {}\n",
                    f.krate,
                    f.targets.len(),
                    f.targets.join(", ")
                ));
            }
        }

        out.push_str(&format!(
            "\nPython scan: {} files inspected (excluding .git and build output)\n",
            self.scanned_files
        ));

        if !self.findings.is_empty() {
            out.push_str("\nFindings:\n");
            for f in self.findings {
                out.push_str(&format!(
                    "  {}[{}]: {}\n",
                    f.severity.label(),
                    f.code,
                    f.message
                ));
            }
        }
        let errors = self.errors();
        let warnings = self.findings.len().saturating_sub(errors);
        if errors == 0 {
            out.push_str(&format!("\nResult: PASS ({warnings} warning(s))\n"));
        } else {
            out.push_str(&format!(
                "\nResult: FAIL ({errors} error(s), {warnings} warning(s))\n"
            ));
        }
        out
    }

    /// Renders the machine-readable report, for the release SBOM (R-NF-07).
    pub(crate) fn json(&self) -> Value {
        let s = |v: &str| Value::String(v.to_owned());
        let list = |items: &mut dyn Iterator<Item = &String>| {
            Value::Array(items.map(|v| Value::String(v.clone())).collect::<Array>())
        };
        let mut root = Object::new();
        root.insert(
            "result",
            s(if self.errors() == 0 { "pass" } else { "fail" }),
        );
        let contexts: Array = self
            .contexts
            .iter()
            .map(|c| {
                let mut o = Object::new();
                o.insert("label", s(&c.label));
                o.insert("platform", s(&c.platform));
                o.insert("resolved", Value::from(c.resolved));
                Value::Object(o)
            })
            .collect();
        root.insert("contexts", Value::Array(contexts));
        let packages: Array = self
            .aggregate
            .usage
            .iter()
            .map(|((name, version), u)| {
                let mut o = Object::new();
                o.insert("name", s(name));
                o.insert("version", s(version));
                o.insert("role", s(u.role.label()));
                if let Some(sum) = self.checksums.get(&(name.clone(), version.clone())) {
                    o.insert("checksum", s(sum));
                }
                o.insert("adrs", list(&mut u.adrs.iter()));
                o.insert("roots", list(&mut u.roots.iter()));
                o.insert("contexts", list(&mut u.contexts.keys()));
                o.insert("platforms", list(&mut u.platforms.iter()));
                Value::Object(o)
            })
            .collect();
        root.insert("packages", Value::Array(packages));
        let excluded: Array = self
            .aggregate
            .excluded
            .iter()
            .map(|((name, version), reasons)| {
                let mut o = Object::new();
                o.insert("name", s(name));
                o.insert("version", s(version));
                let reasons: Array = reasons
                    .iter()
                    .map(|(reason, seen)| {
                        let mut r = Object::new();
                        r.insert("reason", s(reason));
                        r.insert("contexts", list(&mut seen.labels.iter()));
                        r.insert("platforms", list(&mut seen.platforms.iter()));
                        Value::Object(r)
                    })
                    .collect();
                o.insert("reasons", Value::Array(reasons));
                Value::Object(o)
            })
            .collect();
        root.insert("excluded", Value::Array(excluded));
        let findings: Array = self
            .findings
            .iter()
            .map(|f| {
                let mut o = Object::new();
                o.insert("severity", s(f.severity.label()));
                o.insert("code", s(f.code));
                o.insert("message", s(&f.message));
                Value::Object(o)
            })
            .collect();
        root.insert("findings", Value::Array(findings));
        Value::Object(root)
    }
}

fn join<'a>(items: impl Iterator<Item = &'a String>, sep: &str) -> String {
    let v: Vec<&str> = items.map(String::as_str).collect();
    if v.is_empty() {
        "-".to_owned()
    } else {
        v.join(sep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph::Usage;
    use std::collections::BTreeSet;

    #[test]
    fn report_lists_roles_and_result() {
        let mut agg = Aggregate::default();
        agg.usage.insert(
            ("tokio".into(), "1.54.1".into()),
            Usage {
                role: Role::Runtime,
                linux: true,
                adrs: BTreeSet::from(["ADR-002".to_owned()]),
                roots: BTreeSet::from(["tokio".to_owned()]),
                contexts: BTreeMap::from([("workspace".to_owned(), Role::Runtime)]),
                platforms: BTreeSet::from(["x86_64-unknown-linux-gnu".to_owned()]),
            },
        );
        let findings = vec![Finding::error("unlisted", "x 1.0.0 is not allowlisted")];
        let report = Report {
            contexts: &[],
            aggregate: &agg,
            checksums: &BTreeMap::new(),
            fuzz: &[],
            scanned_files: 3,
            findings: &findings,
        };
        let text = report.text();
        assert!(text.contains("tokio"), "{text}");
        assert!(
            text.contains("runtime 1, build 0, test 0, platform 0"),
            "{text}"
        );
        assert!(text.contains("error[unlisted]"), "{text}");
        assert!(
            text.contains("Result: FAIL (1 error(s), 0 warning(s))"),
            "{text}"
        );
        let json = report.json().to_compact();
        assert!(json.contains(r#""result":"fail""#), "{json}");
        assert!(json.contains(r#""role":"runtime""#), "{json}");
    }
}
