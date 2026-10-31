//! The async runtime rule (ADR-002, `docs/handoff/m3-design.md` section 2.4
//! rule 10).
//!
//! ADR-002 allowlists tokio and smol. Two checks hold its decision:
//!
//! - `runtime-one-per-binary`: the resolved graph of each `[[bin]]` target
//!   of a workspace member holds at most one of them. A binary ships its
//!   package's normal and build dependencies, so dev edges do not count.
//! - `runtime-direct`: in-house code uses a runtime only through the
//!   internal trait in `fstp-rt`, so no other workspace member depends on
//!   tokio or smol directly, under any dependency kind.
//!
//! The rules match tokio and smol by package name, whatever the source, as
//! the layering rules do.

use crate::layering::{SHIPPED, members, reach, render_path};
use crate::metadata::Metadata;
use crate::report::Finding;

/// The allowlisted runtimes (ADR-002).
const RUNTIMES: [&str; 2] = ["tokio", "smol"];
/// The crate that holds the internal runtime trait.
const RT: &str = "fstp-rt";

/// Runs both checks over one workspace context.
pub(crate) fn check(meta: &Metadata) -> Vec<Finding> {
    let mut out = Vec::new();
    for (&krate, &start) in &members(meta) {
        if RUNTIMES.contains(&krate) {
            continue;
        }
        let Some(pkg) = meta.packages.get(start) else {
            continue;
        };

        if krate != RT {
            let node = meta
                .node_of_pkg
                .get(&start)
                .and_then(|&n| meta.nodes.get(n));
            for dep in node.map(|n| n.deps.as_slice()).unwrap_or_default() {
                let Some(d) = meta.packages.get(dep.pkg) else {
                    continue;
                };
                if RUNTIMES.contains(&d.name.as_str()) {
                    let kinds: Vec<&str> = dep.kinds.iter().map(|k| k.label()).collect();
                    out.push(Finding::error(
                        "runtime-direct",
                        format!(
                            "{krate} depends directly ({}) on {}; in-house code uses a runtime only through the internal trait in {RT} (ADR-002)",
                            kinds.join(", "),
                            d.name
                        ),
                    ));
                }
            }
        }

        let bins: Vec<&str> = pkg
            .targets
            .iter()
            .filter(|t| t.kinds.iter().any(|k| k == "bin"))
            .map(|t| t.name.as_str())
            .collect();
        if bins.is_empty() {
            continue;
        }
        let parent = reach(meta, start, &SHIPPED);
        let mut found: Vec<(&str, String)> = Vec::new();
        for rt in RUNTIMES {
            if let Some(&pkg) = parent
                .keys()
                .find(|&&i| meta.packages.get(i).is_some_and(|p| p.name == rt))
            {
                found.push((rt, render_path(meta, &parent, start, pkg)));
            }
        }
        if found.len() > 1 {
            let names: Vec<&str> = found.iter().map(|(n, _)| *n).collect();
            let paths: Vec<&str> = found.iter().map(|(_, p)| p.as_str()).collect();
            for bin in bins {
                out.push(Finding::error(
                    "runtime-one-per-binary",
                    format!(
                        "binary {bin} of {krate} holds {} ({}); each binary uses exactly one runtime (ADR-002, design section 2.4 rule 10)",
                        names.join(" and "),
                        paths.join("; ")
                    ),
                ));
            }
        }
    }
    out
}
