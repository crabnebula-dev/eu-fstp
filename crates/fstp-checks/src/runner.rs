//! The checks runner (`payment-requests.md` Automated checks, I-32,
//! R-PR-02, R-PR-03).
//!
//! [`run`] judges one payment request at submission or acceptance and
//! takes its evidence snapshot. Per line it runs:
//!
//! - **Evidence** (P-34, P-65, I-62). Under "public deliverables" every
//!   line needs a public location, a release identifier, an SPDX licence
//!   and a report. Under "progress report" a partial line needs the report
//!   only. The line that brings its milestone to fully claimed always
//!   needs all four.
//! - **Balance** (I-58, I-59). The lines of one milestone fit its
//!   available balance. A request-wide result checks that the request fits
//!   the contract total (I-31).
//! - **Public location**, when one is given. A 2xx answer without
//!   credentials passes. A redirect is not followed.
//! - **Licence**, when public deliverables are needed or a licence is
//!   declared. The declared expression parses and P-26 accepts it. The
//!   licence file at the release carries an SPDX tag, the detected
//!   expression is the declared one, and P-26 accepts it.
//!
//! Every fetch goes through [`Fetch`], which the cell fills with its
//! egress client (allowlist, address ranges, size and time caps).
//! Retrieved bytes are untrusted data: they are hashed, scanned for the
//! licence tag, and dropped. A reason quotes only the grantee's own
//! evidence and parsed SPDX tokens, never retrieved text.

use std::collections::BTreeMap;
use std::future::Future;

use fstp_domain::command::Command;
use fstp_domain::id::{ContentDigest, LineId, MilestoneId, RequestId, TextId, TextRef};
use fstp_domain::payment::{CheckKind, CheckPhase, CheckResult};
use fstp_domain::policy::LicenceSet;
use fstp_domain::time::Timestamp;

use crate::detect::{Detected, detect};
use crate::snapshot::{LineSnapshot, Retrieval, Snapshot};
use crate::spdx::{Expr, parse};
use crate::url::DeliverableUrl;

/// One answer of a fetch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Fetched {
    /// The HTTP status.
    pub status: u16,
    /// The body, within the fetcher's size cap.
    pub body: Vec<u8>,
}

/// Why a fetch gave no answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FetchFault {
    /// The cell egress refused the host or address.
    Refused,
    /// The host could not be reached.
    Unreachable,
    /// The body exceeded the size cap.
    TooLarge,
    /// The fetch exceeded the time cap.
    TimedOut,
}

/// An unauthenticated GET of a deliverable URL. Implementations send no
/// credentials and follow no redirect.
pub trait Fetch {
    /// Fetches `url`.
    fn fetch(
        &self,
        url: &DeliverableUrl,
    ) -> impl Future<Output = Result<Fetched, FetchFault>> + Send;
}

/// The P-65 options for partial claims.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PartialEvidence {
    /// Every line carries public deliverables under an accepted licence.
    PublicDeliverables,
    /// Partial lines carry a progress report.
    ProgressReport,
}

/// The programme rules the checks apply.
#[derive(Clone, Copy, Debug)]
pub struct Rules<'a> {
    /// P-26: the accepted licences.
    pub licences: &'a LicenceSet,
    /// P-65: the evidence of partial claims.
    pub partial: PartialEvidence,
}

/// The evidence of one line, with the stored texts resolved.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EvidenceInput {
    /// The public location.
    pub location: Option<String>,
    /// The release or commit identifier.
    pub release: Option<String>,
    /// The declared SPDX expression.
    pub licence: Option<String>,
    /// The digest of the progress or delivery report.
    pub report: Option<ContentDigest>,
}

/// One line of the request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LineInput {
    /// The line.
    pub line: LineId,
    /// The milestone it claims.
    pub milestone: MilestoneId,
    /// The requested amount in minor units.
    pub amount: i64,
    /// Its evidence.
    pub evidence: EvidenceInput,
}

/// The request as the runner reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RequestInput {
    /// The request.
    pub request: RequestId,
    /// The phase of this run.
    pub phase: CheckPhase,
    /// Its lines, in request order.
    pub lines: Vec<LineInput>,
    /// Per milestone of the effective plan: its amount minus its paid
    /// amount and minus the pending lines of every other request.
    pub available: BTreeMap<MilestoneId, i64>,
    /// The effective contract amount in minor units.
    pub contract_total: i64,
    /// Paid plus pending of every other request of the grant.
    pub claimed_elsewhere: i64,
    /// The instant of the run.
    pub retrieved_at: Timestamp,
}

/// The outcome of one check, with its reason as text.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Outcome {
    /// The line, or `None` for the whole request.
    pub line: Option<LineId>,
    /// The check.
    pub check: CheckKind,
    /// The reason of a failure, for the grantee (R-PR-02).
    pub failure: Option<String>,
}

/// One run of the checks with its snapshot.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckRun {
    /// The request.
    pub request: RequestId,
    /// The phase.
    pub phase: CheckPhase,
    /// Every outcome. Each line has at least one.
    pub outcomes: Vec<Outcome>,
    /// The evidence snapshot.
    pub snapshot: Snapshot,
    /// The digest of the snapshot.
    pub digest: ContentDigest,
}

impl CheckRun {
    /// Whether every check passed.
    pub fn passed(&self) -> bool {
        self.outcomes.iter().all(|o| o.failure.is_none())
    }

    /// The `RecordChecks` of this run, and each reason text with the
    /// reference the command names it by. `next_text` allocates the text
    /// ids. The caller stores the texts and the encoded snapshot, and
    /// submits the command as the System.
    pub fn into_command(
        self,
        mut next_text: impl FnMut() -> TextId,
    ) -> (Command, Vec<(TextRef, String)>) {
        let mut texts = Vec::new();
        let results = self
            .outcomes
            .into_iter()
            .map(|o| {
                let failure = o.failure.map(|why| {
                    let r = TextRef::new(
                        next_text(),
                        ContentDigest::from_bytes(fstp_crypto::sha256(why.as_bytes())),
                    );
                    texts.push((r, why));
                    r
                });
                CheckResult {
                    line: o.line,
                    check: o.check,
                    failure,
                }
            })
            .collect();
        (
            Command::RecordChecks {
                request: self.request,
                phase: self.phase,
                results,
                snapshot: self.digest,
            },
            texts,
        )
    }
}

fn retrieval(r: &Result<Fetched, FetchFault>) -> Retrieval {
    match r {
        Ok(f) => Retrieval::Got {
            status: f.status,
            sha256: fstp_crypto::sha256(&f.body),
            len: u64::try_from(f.body.len()).unwrap_or(u64::MAX),
        },
        Err(FetchFault::Refused) => Retrieval::Refused,
        Err(FetchFault::Unreachable) => Retrieval::Unreachable,
        Err(FetchFault::TooLarge) => Retrieval::TooLarge,
        Err(FetchFault::TimedOut) => Retrieval::TimedOut,
    }
}

fn fault_reason(what: &str, f: FetchFault) -> String {
    match f {
        FetchFault::Refused => format!(
            "The {what} is on a host that is not on the cell's forge allowlist, so the checks could not retrieve it."
        ),
        FetchFault::Unreachable => format!("The {what} could not be reached."),
        FetchFault::TooLarge => format!("The {what} is larger than the checks retrieve."),
        FetchFault::TimedOut => format!("Retrieving the {what} took longer than the checks allow."),
    }
}

/// What a line's evidence check found missing (P-34, P-65, I-62).
fn missing(ev: &EvidenceInput, public: bool) -> Vec<&'static str> {
    let mut out = Vec::new();
    if public {
        if ev.location.is_none() {
            out.push("public location");
        }
        if ev.release.is_none() {
            out.push("release identifier");
        }
        if ev.licence.is_none() {
            out.push("SPDX licence");
        }
    }
    if ev.report.is_none() {
        out.push("report");
    }
    out
}

async fn location_check<F: Fetch>(
    ev: &EvidenceInput,
    fetch: &F,
    snap: &mut LineSnapshot,
) -> Option<Option<String>> {
    let loc = ev.location.as_deref()?;
    let url = match DeliverableUrl::parse(loc) {
        Ok(u) => u,
        Err(e) => return Some(Some(format!("The public location is not accepted: {e}."))),
    };
    let got = fetch.fetch(&url).await;
    snap.location_page = Some(retrieval(&got));
    Some(match got {
        Ok(f) if (200..300).contains(&f.status) => None,
        Ok(f) if f.status == 401 || f.status == 403 => {
            Some("The public location needs authentication, so it is not public.".to_owned())
        }
        Ok(f) if (300..400).contains(&f.status) => Some(
            "The public location answers with a redirect. Give the final address, since the checks do not follow redirects."
                .to_owned(),
        ),
        Ok(f) => Some(format!(
            "The public location answered with status {}.",
            f.status
        )),
        Err(e) => Some(fault_reason("public location", e)),
    })
}

async fn licence_check<F: Fetch>(
    ev: &EvidenceInput,
    public: bool,
    rules: &Rules<'_>,
    fetch: &F,
    snap: &mut LineSnapshot,
) -> Option<Option<String>> {
    let declared_text = match (&ev.licence, public) {
        (Some(l), _) => l.as_str(),
        (None, true) => {
            return Some(Some(
                "No SPDX licence was declared for the deliverables.".to_owned(),
            ));
        }
        (None, false) => return None,
    };
    let Ok(declared) = parse(declared_text) else {
        return Some(Some(
            "The declared licence is not a valid SPDX licence expression.".to_owned(),
        ));
    };
    if !declared.accepted(rules.licences) {
        return Some(Some(format!(
            "The declared licence {declared} is not among the licences the programme accepts (P-26)."
        )));
    }
    let (Some(loc), Some(release)) = (ev.location.as_deref(), ev.release.as_deref()) else {
        return Some(public.then(|| {
            "The licence cannot be detected without a public location and a release identifier."
                .to_owned()
        }));
    };
    let Ok(base) = DeliverableUrl::parse(loc) else {
        return Some(Some(
            "The licence cannot be detected, since the public location is not accepted.".to_owned(),
        ));
    };
    let Ok(file) = base.licence_file(release) else {
        return Some(Some(
            "The release identifier may hold only letters, digits, dots, dashes and underscores."
                .to_owned(),
        ));
    };
    let got = fetch.fetch(&file).await;
    snap.licence_file = Some(retrieval(&got));
    let body = match got {
        Ok(f) if (200..300).contains(&f.status) => f.body,
        Ok(f) if f.status == 404 => {
            return Some(Some(format!(
                "Release {release} has no LICENSE file at the public location, or the release does not exist."
            )));
        }
        Ok(f) => {
            return Some(Some(format!(
                "The LICENSE file of release {release} answered with status {}.",
                f.status
            )));
        }
        Err(e) => return Some(Some(fault_reason("LICENSE file", e))),
    };
    Some(judge_detected(
        detect(&body),
        &declared,
        release,
        rules,
        snap,
    ))
}

fn judge_detected(
    d: Detected,
    declared: &Expr,
    release: &str,
    rules: &Rules<'_>,
    snap: &mut LineSnapshot,
) -> Option<String> {
    let found = match d {
        Detected::Found(e) => e,
        Detected::Absent => {
            return Some(format!(
                "The LICENSE file of release {release} has no SPDX-License-Identifier line."
            ));
        }
        Detected::Invalid => {
            return Some(format!(
                "The SPDX-License-Identifier of release {release} is not a valid expression."
            ));
        }
        Detected::Conflict => {
            return Some(format!(
                "The LICENSE file of release {release} names different licences."
            ));
        }
    };
    snap.detected = Some(found.to_string());
    if !found.same(declared) {
        return Some(format!(
            "Release {release} is licensed {found}, which differs from the declared licence {declared}."
        ));
    }
    if !found.accepted(rules.licences) {
        return Some(format!(
            "The detected licence {found} is not among the licences the programme accepts (P-26)."
        ));
    }
    None
}

/// Runs the checks of `input` under `rules`, fetching through `fetch`.
pub async fn run<F: Fetch>(input: &RequestInput, rules: &Rules<'_>, fetch: &F) -> CheckRun {
    let mut outcomes = Vec::new();
    let mut lines = Vec::new();
    let mut claimed: BTreeMap<MilestoneId, i64> = BTreeMap::new();
    let mut total: i64 = 0;
    for l in &input.lines {
        let before = claimed.get(&l.milestone).copied().unwrap_or(0);
        let after = before.checked_add(l.amount);
        if let Some(a) = after {
            claimed.insert(l.milestone, a);
        }
        total = total.checked_add(l.amount).unwrap_or(i64::MAX);
        let available = input.available.get(&l.milestone).copied();
        let balance = match (available, after) {
            _ if l.amount <= 0 => Some("The requested amount must be above zero.".to_owned()),
            (None, _) => Some(
                "The milestone is not in the effective contract plan of the grant (I-59)."
                    .to_owned(),
            ),
            (Some(av), Some(a)) if a <= av => None,
            (Some(_), _) => Some(
                "The requested amount exceeds the milestone's available balance (I-58).".to_owned(),
            ),
        };
        let fills = matches!((available, after), (Some(av), Some(a)) if a >= av);
        let public = rules.partial == PartialEvidence::PublicDeliverables || fills;
        outcomes.push(Outcome {
            line: Some(l.line),
            check: CheckKind::Balance,
            failure: balance,
        });
        let miss = missing(&l.evidence, public);
        outcomes.push(Outcome {
            line: Some(l.line),
            check: CheckKind::Evidence,
            failure: (!miss.is_empty()).then(|| {
                let why = format!("Missing evidence: {} (P-34).", miss.join(", "));
                if fills && rules.partial == PartialEvidence::ProgressReport {
                    format!(
                        "{why} This line brings the milestone to fully claimed, so it needs public deliverables (I-62)."
                    )
                } else {
                    why
                }
            }),
        });
        let mut snap = LineSnapshot {
            line: l.line,
            location: l.evidence.location.clone(),
            release: l.evidence.release.clone(),
            declared: l.evidence.licence.clone(),
            detected: None,
            report: l.evidence.report,
            location_page: None,
            licence_file: None,
        };
        if let Some(failure) = location_check(&l.evidence, fetch, &mut snap).await {
            outcomes.push(Outcome {
                line: Some(l.line),
                check: CheckKind::PublicLocation,
                failure,
            });
        }
        if let Some(failure) = licence_check(&l.evidence, public, rules, fetch, &mut snap).await {
            outcomes.push(Outcome {
                line: Some(l.line),
                check: CheckKind::Licence,
                failure,
            });
        }
        lines.push(snap);
    }
    let fits = input
        .claimed_elsewhere
        .checked_add(total)
        .is_some_and(|t| t <= input.contract_total);
    outcomes.push(Outcome {
        line: None,
        check: CheckKind::Balance,
        failure: (!fits).then(|| {
            "The request together with the grant's paid and pending amounts exceeds the contract amount (I-31)."
                .to_owned()
        }),
    });
    let snapshot = Snapshot {
        request: input.request,
        phase: input.phase,
        retrieved_at: input.retrieved_at,
        lines,
    };
    let digest = snapshot.digest();
    CheckRun {
        request: input.request,
        phase: input.phase,
        outcomes,
        snapshot,
        digest,
    }
}
