//! The command-line entry point: runs every gate and prints the report.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::allowlist::{self, Entry};
use crate::cargo::{self, Query};
use crate::fuzz;
use crate::graph::{self, Context, ProjectKind};
use crate::lockfile::{self, Lockfile};
use crate::metadata::{self, Metadata};
use crate::provenance::{self, ProjectLock};
use crate::python;
use crate::repo::{self, ProjectDir};
use crate::report::{self, ContextSummary, Finding, Report};

/// Platforms whose roles the allowlist describes.
const PLATFORMS: [&str; 2] = ["x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu"];
/// The label of contexts that run without `--filter-platform`.
const ALL_TARGETS: &str = "all targets";
/// Upper bound on concurrent `cargo metadata` processes.
const MAX_WORKERS: usize = 8;

const ALLOWLIST: &str = "deps/allowlist.txt";
const ROOTS: &str = "deps/adr-roots.txt";
const FUZZ_REQUIRED: &str = "deps/fuzz-required.txt";
const ADR_DIR: &str = "docs/adr";

const ALLOWLIST_HEADER: &str = "\
# Third-party crates allowed in any build of this repository (TH-15).
# Checked by tools/deps-check against every Cargo.lock in the repository,
# for every cargo project, with default features and with --all-features.
#
# Format: one entry per line, fields separated by whitespace:
#   <name> <exact version> <sha256> <ADR ids, comma-separated> <role> <note>
# sha256 is the .crate checksum that every Cargo.lock must record.
# role is the highest allowed use on x86_64 and aarch64 Linux:
#   runtime   linked into shipped artifacts
#   build     build scripts and their dependencies only
#   test      dev-dependencies and fuzz projects only
#   platform  never built for x86_64 or aarch64 Linux; only another target
#             or a custom cfg reaches it
# The ADR ids are the ADRs whose resolved tree contains the crate
# (deps/adr-roots.txt names each tree's root). Each of those ADRs records
# the exact `name version`.
#
# Regenerate with: cargo run -p deps-check --locked -- --print-allowlist
# Any change to this file needs review against the ADRs.
";

struct Options {
    root: PathBuf,
    offline: bool,
    json: Option<PathBuf>,
    print_allowlist: bool,
}

const USAGE: &str = "\
Usage: deps-check [--root <dir>] [--offline] [--json <file>] [--print-allowlist]

  --root <dir>         repository root (default: current directory)
  --offline            pass --offline to cargo metadata
  --json <file>        also write a machine-readable report
  --print-allowlist    print an allowlist generated from the current graph
";

fn parse_args() -> Result<Options, String> {
    let mut opts = Options {
        root: PathBuf::from("."),
        offline: false,
        json: None,
        print_allowlist: false,
    };
    let mut args = std::env::args_os().skip(1);
    while let Some(a) = args.next() {
        match a.to_str() {
            Some("--root") => {
                opts.root = args.next().ok_or("--root needs a value")?.into();
            }
            Some("--json") => {
                opts.json = Some(args.next().ok_or("--json needs a value")?.into());
            }
            Some("--offline") => opts.offline = true,
            Some("--print-allowlist") => opts.print_allowlist = true,
            Some("-h" | "--help") => return Err(String::new()),
            _ => return Err(format!("unknown argument {}", a.to_string_lossy())),
        }
    }
    Ok(opts)
}

fn read_policy(root: &Path, rel: &str, findings: &mut Vec<Finding>) -> Option<String> {
    match fs::read_to_string(root.join(rel)) {
        Ok(t) => Some(t),
        Err(e) => {
            findings.push(Finding::error(
                "policy-file",
                format!("cannot read {rel}: {e}"),
            ));
            None
        }
    }
}

fn line_errors(
    code: &'static str,
    rel: &str,
    errs: Vec<allowlist::LineError>,
    findings: &mut Vec<Finding>,
) {
    for e in errs {
        findings.push(Finding::error(code, format!("{rel} {e}")));
    }
}

/// Reads each ADR's text by identifier, `None` when no file exists.
fn adr_texts(root: &Path, entries: &[Entry]) -> BTreeMap<String, Option<String>> {
    let mut files: BTreeMap<String, PathBuf> = BTreeMap::new();
    if let Ok(reader) = fs::read_dir(root.join(ADR_DIR)) {
        for item in reader.flatten() {
            let name = item.file_name().to_string_lossy().into_owned();
            if let Some(id) = name.get(..7)
                && allowlist::valid_adr(id)
                && name.ends_with(".md")
            {
                files.insert(id.to_owned(), item.path());
            }
        }
    }
    let mut out = BTreeMap::new();
    for adr in entries.iter().flat_map(|e| e.adrs.iter()) {
        if !out.contains_key(adr) {
            let text = files.get(adr).and_then(|p| fs::read_to_string(p).ok());
            out.insert(adr.clone(), text);
        }
    }
    out
}

/// One `cargo metadata` run: a project and a query.
#[derive(Clone, Copy)]
struct Job {
    project: usize,
    platform: Option<&'static str>,
    all_features: bool,
}

/// Every job, project by project. The first job of each project is the
/// primary one (x86_64 Linux, default features).
fn jobs(projects: usize) -> Vec<Job> {
    let mut out = Vec::new();
    for project in 0..projects {
        for all_features in [false, true] {
            for platform in PLATFORMS.iter().copied().map(Some).chain([None]) {
                out.push(Job {
                    project,
                    platform,
                    all_features,
                });
            }
        }
    }
    out
}

/// Runs every job on a few worker threads and returns the results in job order.
fn run_jobs(jobs: &[Job], dirs: &[PathBuf], offline: bool) -> Vec<Result<Metadata, String>> {
    let next = AtomicUsize::new(0);
    let workers = std::thread::available_parallelism()
        .map_or(2, |n| n.get())
        .clamp(1, MAX_WORKERS);
    let mut results: Vec<(usize, Result<Metadata, String>)> = std::thread::scope(|s| {
        let handles: Vec<_> = (0..workers)
            .map(|_| {
                s.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let i = next.fetch_add(1, Ordering::SeqCst);
                        let Some(job) = jobs.get(i) else { break };
                        let q = Query {
                            platform: job.platform,
                            all_features: job.all_features,
                            offline,
                        };
                        let result = match dirs.get(job.project) {
                            Some(dir) => cargo::metadata(dir, q).and_then(|bytes| {
                                metadata::parse_metadata(&bytes).map_err(|e| e.to_string())
                            }),
                            None => Err("unknown project".to_owned()),
                        };
                        done.push((i, result));
                    }
                    done
                })
            })
            .collect();
        handles
            .into_iter()
            .flat_map(|h| h.join().unwrap_or_default())
            .collect()
    });
    results.sort_by_key(|(i, _)| *i);
    let mut out: Vec<Result<Metadata, String>> = Vec::with_capacity(jobs.len());
    let mut it = results.into_iter().peekable();
    for i in 0..jobs.len() {
        match it.peek() {
            Some((j, _)) if *j == i => {
                if let Some((_, r)) = it.next() {
                    out.push(r);
                }
            }
            _ => out.push(Err("metadata worker failed".to_owned())),
        }
    }
    out
}

/// Reads and parses each project's lockfile.
fn read_locks(
    root: &Path,
    projects: &[ProjectDir],
    findings: &mut Vec<Finding>,
) -> Vec<Option<Lockfile>> {
    projects
        .iter()
        .map(|p| {
            let rel = p.rel.join("Cargo.lock");
            let shown = rel.display().to_string();
            match fs::read_to_string(root.join(&rel)) {
                Ok(text) => match lockfile::parse(&text) {
                    Ok(l) => Some(l),
                    Err(errs) => {
                        line_errors("lockfile-syntax", &shown, errs, findings);
                        None
                    }
                },
                Err(e) => {
                    findings.push(Finding::error(
                        "lockfile-syntax",
                        format!("cannot read {shown}: {e}"),
                    ));
                    None
                }
            }
        })
        .collect()
}

/// Runs every gate and prints the report. Returns success only when no
/// gate reports an error.
pub fn run() -> ExitCode {
    let opts = match parse_args() {
        Ok(o) => o,
        Err(msg) => {
            if !msg.is_empty() {
                eprintln!("deps-check: {msg}");
            }
            eprint!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    let root = match fs::canonicalize(&opts.root) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("deps-check: cannot resolve {}: {e}", opts.root.display());
            return ExitCode::from(2);
        }
    };
    let mut findings: Vec<Finding> = Vec::new();

    // --print-allowlist may run before the allowlist exists.
    let allowlist_text = if opts.print_allowlist && !root.join(ALLOWLIST).exists() {
        Some(String::new())
    } else {
        read_policy(&root, ALLOWLIST, &mut findings)
    };
    let entries: Vec<Entry> = match allowlist_text {
        Some(t) => allowlist::parse_allowlist(&t).unwrap_or_else(|e| {
            line_errors("policy-syntax", ALLOWLIST, e, &mut findings);
            Vec::new()
        }),
        None => Vec::new(),
    };
    let roots = match read_policy(&root, ROOTS, &mut findings) {
        Some(t) => allowlist::parse_roots(&t).unwrap_or_else(|e| {
            line_errors("policy-syntax", ROOTS, e, &mut findings);
            BTreeMap::new()
        }),
        None => BTreeMap::new(),
    };
    let required = match read_policy(&root, FUZZ_REQUIRED, &mut findings) {
        Some(t) => allowlist::parse_fuzz_required(&t).unwrap_or_else(|e| {
            line_errors("policy-syntax", FUZZ_REQUIRED, e, &mut findings);
            Vec::new()
        }),
        None => Vec::new(),
    };

    // One walk serves project discovery, the repository checks and the Python scan.
    let walk = repo::walk(&root, &repo::target_dir_inside(&root));
    findings.extend(walk.findings.iter().cloned());
    findings.extend(repo::check_cargo_config(&root, &walk));
    findings.extend(repo::check_symlinks(&root, &walk));
    findings.extend(repo::check_manifest_overrides(&root, &walk));
    let (projects, project_findings) = repo::projects(&walk);
    findings.extend(project_findings);
    let locks = read_locks(&root, &projects, &mut findings);

    let dirs: Vec<PathBuf> = projects.iter().map(|p| root.join(&p.rel)).collect();
    let jobs = jobs(projects.len());
    let raw = run_jobs(&jobs, &dirs, opts.offline);

    let mut contexts = Vec::new();
    let mut summaries = Vec::new();
    let mut primary: BTreeMap<usize, Result<Metadata, String>> = BTreeMap::new();
    for (job, result) in jobs.iter().zip(raw.iter()) {
        let Some(project) = projects.get(job.project) else {
            continue;
        };
        let platform = job.platform.unwrap_or(ALL_TARGETS).to_owned();
        match result {
            Ok(meta) => {
                summaries.push(ContextSummary {
                    label: project.label.clone(),
                    platform: platform.clone(),
                    all_features: job.all_features,
                    resolved: meta.nodes.len(),
                });
                contexts.push(Context {
                    label: project.label.clone(),
                    platform,
                    linux: job.platform.is_some(),
                    all_features: job.all_features,
                    kind: project.kind,
                    meta,
                });
            }
            Err(e) => findings.push(Finding::error(
                "metadata-failed",
                format!(
                    "{} ({platform}{}): {e}",
                    project.label,
                    if job.all_features {
                        ", all features"
                    } else {
                        ""
                    }
                ),
            )),
        }
        primary.entry(job.project).or_insert_with(|| result.clone());
    }
    let agg = graph::aggregate(&contexts, &roots);

    let project_locks: Vec<ProjectLock<'_>> = projects
        .iter()
        .zip(locks.iter())
        .filter_map(|(p, l)| {
            l.as_ref().map(|lock| ProjectLock {
                label: &p.label,
                path: p.rel.join("Cargo.lock").display().to_string(),
                lock,
            })
        })
        .collect();
    let checksums = provenance::lock_checksums(&project_locks);

    if opts.print_allowlist {
        let errors: Vec<&Finding> = findings
            .iter()
            .chain(agg.findings.iter())
            .filter(|f| f.severity == report::Severity::Error)
            .collect();
        for f in &errors {
            eprintln!("deps-check: {}: {}", f.code, f.message);
        }
        for (name, features) in &agg.root_features {
            eprintln!(
                "deps-check: root {name} enables {}",
                allowlist::features_field(features)
            );
        }
        print!(
            "{ALLOWLIST_HEADER}\n{}",
            allowlist::render_entries(&allowlist::generate(&agg, &entries, &checksums))
        );
        return if errors.is_empty() {
            ExitCode::SUCCESS
        } else {
            ExitCode::FAILURE
        };
    }

    findings.extend(agg.findings.iter().cloned());

    let workspace_index = projects.iter().position(|p| p.rel.as_os_str().is_empty());
    let workspace_meta = workspace_index
        .and_then(|i| primary.get(&i))
        .and_then(|r| r.as_ref().ok());
    let main_members: BTreeSet<PathBuf> = workspace_meta
        .map(|m| {
            m.members
                .iter()
                .filter_map(|&i| m.packages.get(i))
                .filter_map(|p| fs::canonicalize(&p.manifest_path).ok())
                .collect()
        })
        .unwrap_or_default();
    findings.extend(provenance::check_locations(
        &contexts,
        &root,
        &main_members,
        &provenance::registry_src(),
    ));
    findings.extend(provenance::check_shadowing(
        &contexts,
        &entries,
        &project_locks,
    ));
    findings.extend(provenance::reconcile(&agg, &project_locks));
    findings.extend(provenance::check_checksums(&agg, &entries, &project_locks));
    findings.extend(repo::check_manifest_coverage(&root, &walk, &contexts));

    let scan = python::scan(&root, &walk);
    findings.extend(scan.findings);

    let fuzz_projects: Vec<fuzz::FuzzProject> = projects
        .iter()
        .enumerate()
        .filter(|(_, p)| p.kind == ProjectKind::Fuzz)
        .map(|(i, p)| fuzz::FuzzProject {
            dir: root.join(&p.rel),
            meta: primary
                .get(&i)
                .cloned()
                .unwrap_or_else(|| Err("not analysed".to_owned())),
        })
        .collect();
    let (fuzz_summary, fuzz_findings) =
        fuzz::check(&root, &required, workspace_meta, &fuzz_projects);
    findings.extend(fuzz_findings);

    findings.extend(allowlist::compare(&agg, &entries));
    findings.extend(allowlist::compare_root_features(&agg, &roots));
    findings.extend(allowlist::check_adr_records(
        &entries,
        &adr_texts(&root, &entries),
    ));

    findings.sort();
    findings.dedup();
    let report = Report {
        contexts: &summaries,
        aggregate: &agg,
        checksums: &checksums,
        fuzz: &fuzz_summary,
        scanned_files: scan.files,
        findings: &findings,
    };
    print!("{}", report.text());
    if let Some(path) = &opts.json
        && let Err(e) = fs::write(path, report.json().to_pretty())
    {
        eprintln!("deps-check: cannot write {}: {e}", path.display());
        return ExitCode::from(2);
    }
    if report.errors() == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
