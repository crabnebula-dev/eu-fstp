//! The creator shell of a configured serving cell (ADR-027, gap G13).
//!
//! [`FactsShell`] gives a creator command the facts only the cell holds:
//!
//! - The probes. A request for activation, an approval and an override
//!   run every probe in their request, through
//!   [`CreatorShell::facts_fresh`]. Every other command reads the last
//!   results. A synchronous read of a report command takes results no
//!   older than [`FRESH_US`], and an older or missing one is absent, so
//!   its check fails closed (Q5).
//! - No Q35 answer of its own. The cell's decision then asks the vault
//!   (`fstp_cell_core::creator::q35_queries`).
//! - No pre-check provider and no score tools until M7 (Q38 C).
//! - The funder profile from the shipped profiles. Their wording is
//!   `TODO(legal)`, so `LegalWordingPending` stays a failure until Daniel
//!   approves it (Q6).
//! - The Guide inputs of a publication (I-51, I-52, R-GA-01): the
//!   template of the programme's P-53 profile over its complete creator
//!   draft, the configured platform address, the stored narratives read
//!   from the cell's text store while live, and the data protection
//!   texts. Those are the tenant's own notice when its settings name one.
//!   The platform default is `TODO(legal)` in `fstp-tenant`, so while it
//!   applies the shell gives no Guide, and the publication is refused
//!   with I-52.
//!
//! A test world may build a [`FactsShell`] with its own prober and data
//! protection texts. It reads the shipped profiles only (rule A9b). Claims built on it say so.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_cell_core::CellState;
use fstp_cell_core::creator::{CreatorFacts, GuideInputs};
use fstp_creator::{CreatorCommand, PortPresence, ProbeKind, ProbeOutcome, ProbeSet};
use fstp_domain::id::{CallId, TextId};
use fstp_guide::{FunderProfile, ProfileSource};
use fstp_rt::Runtime;

use super::dns::{TcpResolver, TxtResolver};
use super::probe::{CellProber, ProbeSettings, Prober};
use super::{CreatorShell, ShellFuture};
use crate::public::TextOpener;

/// How old, in microseconds, a probe result a synchronous read of a
/// report command takes may be: 60 seconds (ADR-027).
pub const FRESH_US: i64 = 60_000_000;

/// The settings of a serving cell's creator shell (ADR-027). Lane L4
/// wires them from the configuration file.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ShellSettings {
    /// The DNS resolver of the sending domain probe, TCP port 53.
    pub resolver: Option<SocketAddr>,
    /// The probe settings.
    pub probes: ProbeSettings,
    /// The `https:` address applicants create an account on, which the
    /// Guide names (`{{platform.url}}`).
    pub platform_url: Option<String>,
}

/// The data protection texts a Guide names when the tenant set no notice
/// of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlatformNotice {
    /// The data protection summary.
    pub summary: String,
    /// The privacy statement address.
    pub privacy_statement_url: String,
    /// Whether the wording is approved. The platform default is not
    /// (`TODO(legal)`), and the shell gives no Guide with it.
    pub approved: bool,
}

impl PlatformNotice {
    /// The platform default of `fstp-tenant`. TODO(legal): Daniel approves
    /// its wording. Until then it is not approved.
    pub fn platform_default() -> PlatformNotice {
        PlatformNotice {
            summary: fstp_tenant::PLATFORM_DATA_PROTECTION_SUMMARY.to_owned(),
            privacy_statement_url: fstp_tenant::PLATFORM_PRIVACY_STATEMENT_URL.to_owned(),
            approved: false,
        }
    }
}

/// The cell clock, UTC microseconds.
pub type Clock = Arc<dyn Fn() -> i64 + Send + Sync>;

/// The creator shell of a configured serving cell (module documentation).
pub struct FactsShell {
    prober: Option<Arc<dyn Prober>>,
    notice: PlatformNotice,
    platform_url: Option<String>,
    ports: PortPresence,
    clock: Clock,
    last: Mutex<BTreeMap<ProbeKind, (ProbeOutcome, i64)>>,
}

impl std::fmt::Debug for FactsShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FactsShell")
            .field("prober", &self.prober.is_some())
            .field("platform_url", &self.platform_url)
            .field("ports", &self.ports)
            .finish_non_exhaustive()
    }
}

/// The system clock, UTC microseconds.
fn system_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|d| i64::try_from(d.as_micros()).ok())
        .unwrap_or(0)
}

/// The shell of a serving cell on `rt` with `settings` (ADR-027): the
/// prober over the configured relay and resolver, the shipped profiles,
/// the platform data protection default, no pre-check provider and the
/// system clock. The cell's start takes it through
/// `crate::process::StartOptions::creator_shell`.
pub fn production_shell<R: Runtime>(rt: R, settings: ShellSettings) -> Arc<dyn CreatorShell> {
    production_probes(rt, settings).0
}

/// [`production_shell`] and the onboarding probes of the API core over
/// the same prober (ADR-026 record of lane L18): the channel probe of the
/// configured relay and the sending domain probe of a saved domain.
pub fn production_probes<R: Runtime>(
    rt: R,
    settings: ShellSettings,
) -> (Arc<dyn CreatorShell>, Arc<dyn super::probe::TenantProbe>) {
    let resolver = settings
        .resolver
        .and_then(|addr| TcpResolver::new(rt.clone(), addr).ok())
        .map(|r| Arc::new(r) as Arc<dyn TxtResolver>);
    let prober = Arc::new(CellProber::new(rt, settings.probes, resolver));
    let shell = FactsShell::new(Some(Arc::clone(&prober) as Arc<dyn Prober>))
        .with_platform_url(settings.platform_url);
    (Arc::new(shell), prober)
}

impl FactsShell {
    /// A shell over `prober`, or none, so every probe is absent. It reads
    /// the shipped profiles and the platform data protection default, has
    /// no pre-check provider, no platform address and the system clock.
    pub fn new(prober: Option<Arc<dyn Prober>>) -> FactsShell {
        FactsShell {
            prober,
            notice: PlatformNotice::platform_default(),
            platform_url: None,
            ports: PortPresence::default(),
            clock: Arc::new(system_now),
            last: Mutex::new(BTreeMap::new()),
        }
    }

    /// The same shell with `notice` as the data protection texts of a
    /// tenant with no notice of its own.
    pub fn with_notice(mut self, notice: PlatformNotice) -> FactsShell {
        self.notice = notice;
        self
    }

    /// The same shell naming `url` as the platform address of its Guides.
    pub fn with_platform_url(mut self, url: Option<String>) -> FactsShell {
        self.platform_url = url;
        self
    }

    /// The same shell with the ports `ports`.
    pub fn with_ports(mut self, ports: PortPresence) -> FactsShell {
        self.ports = ports;
        self
    }

    /// The same shell reading the time from `clock`.
    pub fn with_clock(mut self, clock: Clock) -> FactsShell {
        self.clock = clock;
        self
    }

    /// Runs every probe now and keeps the results.
    pub async fn run_probes(&self) {
        let Some(prober) = &self.prober else {
            return;
        };
        for p in ProbeKind::ALL {
            let outcome = prober.run(p).await;
            let now = (self.clock)();
            self.last
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(p, (outcome, now));
        }
    }

    /// The kept probe results. A command that reads the report takes only
    /// results no older than [`FRESH_US`].
    fn probes(&self, cmd: &CreatorCommand) -> ProbeSet {
        let now = (self.clock)();
        let strict = runs_probes(cmd);
        let last = self.last.lock().unwrap_or_else(PoisonError::into_inner);
        let mut set = ProbeSet::absent();
        for p in ProbeKind::ALL {
            if let Some((outcome, at)) = last.get(&p)
                && (!strict || now.saturating_sub(*at) <= FRESH_US)
            {
                set.set(p, *outcome);
            }
        }
        set
    }

    /// The Guide inputs of `call` on `state` with the stored `texts`, and
    /// the tenant's own summary if it set a notice (module documentation).
    fn guide_with(
        &self,
        state: &CellState,
        call: CallId,
        texts: BTreeMap<TextId, String>,
        tenant_summary: Option<String>,
    ) -> Option<GuideInputs> {
        let engine = state.engine();
        let programme = fstp_domain::programme::call(&engine.core, call)?.programme();
        let head = fstp_domain::policy::head(&engine.core, programme)?;
        // The engine compiles the creator draft again. A draft with a gap
        // gives no Guide, so the publication is refused with I-52.
        let compiled = fstp_engine::compose::draft_compiled(engine, programme)?;
        if !compiled.unset.is_empty() {
            return None;
        }
        let name = fstp_engine::compose::profile_name(&head.frozen.p53)?;
        let profile = shipped(&name)?;
        let template = fstp_guide::parse_template(profile.guide_template().as_bytes()).ok()?;
        let platform_url = self.platform_url.clone()?;
        let (summary, privacy) = match engine.tenant.state().map(|ts| ts.settings().guide_notice())
        {
            Some(fstp_tenant::GuideNotice::Tenant(o)) => {
                (tenant_summary?, o.privacy_statement_url.clone())
            }
            Some(fstp_tenant::GuideNotice::Platform) | None => {
                if !self.notice.approved {
                    return None;
                }
                (
                    self.notice.summary.clone(),
                    self.notice.privacy_statement_url.clone(),
                )
            }
        };
        Some(GuideInputs {
            template,
            compiled: None,
            platform_url,
            data_protection_summary: summary,
            privacy_statement_url: privacy,
            texts,
            precheck_available: self.ports.precheck,
        })
    }
}

/// The shipped funder profile `name`: production loads no other (rule
/// A9b).
fn shipped(name: &str) -> Option<FunderProfile> {
    fstp_guide::ShippedProfiles.profile(name).ok()
}

/// Whether `cmd` runs every probe in its request (design 3.2 "Fresh
/// probes"; ADR-027).
fn runs_probes(cmd: &CreatorCommand) -> bool {
    matches!(
        cmd,
        CreatorCommand::RequestActivation { .. }
            | CreatorCommand::ApproveActivation { .. }
            | CreatorCommand::OverrideActivation { .. }
    )
}

/// The ids of every stored text the creator draft's spec `spec` names:
/// each object of exactly the members `digest` and `text`, the stored
/// form of a narrative.
pub fn stored_text_ids(spec: &fstp_json::Value, out: &mut BTreeSet<TextId>) {
    match spec {
        fstp_json::Value::Object(o) => {
            let members: Vec<&str> = o.iter().map(|(k, _)| k).collect();
            if members.len() == 2
                && members.contains(&"digest")
                && members.contains(&"text")
                && let Some(id) = o
                    .get("text")
                    .and_then(fstp_json::Value::as_str)
                    .and_then(|s| s.parse::<u128>().ok())
            {
                out.insert(TextId::from_raw(id));
                return;
            }
            for (_, v) in o.iter() {
                stored_text_ids(v, out);
            }
        }
        fstp_json::Value::Array(a) => {
            for v in a.iter() {
                stored_text_ids(v, out);
            }
        }
        _ => {}
    }
}

impl CreatorShell for FactsShell {
    fn facts(&self, state: &CellState, cmd: &CreatorCommand) -> CreatorFacts {
        let profile = fstp_engine::compose::profile_ref(state.engine(), cmd)
            .and_then(|r| fstp_engine::compose::profile_name(&r))
            .and_then(|name| shipped(&name));
        CreatorFacts {
            probes: self.probes(cmd),
            exclusion_classes_known: None,
            proximity_lists_declared: None,
            ports: self.ports,
            profile,
            guide: None,
        }
    }

    fn facts_fresh<'a>(
        &'a self,
        state: &'a CellState,
        cmd: &'a CreatorCommand,
    ) -> ShellFuture<'a, CreatorFacts> {
        Box::pin(async move {
            if runs_probes(cmd) {
                self.run_probes().await;
            }
            self.facts(state, cmd)
        })
    }

    /// The Guide inputs without the text store: a draft whose narratives
    /// are all inline binds, and one with a stored narrative is refused.
    fn guide(&self, state: &CellState, call: CallId) -> Option<GuideInputs> {
        self.guide_with(state, call, BTreeMap::new(), None)
    }

    fn guide_fresh<'a>(
        &'a self,
        state: &'a CellState,
        call: CallId,
        texts: &'a dyn TextOpener,
    ) -> ShellFuture<'a, Option<GuideInputs>> {
        Box::pin(async move {
            let engine = state.engine();
            let programme = fstp_domain::programme::call(&engine.core, call)?.programme();
            let view = fstp_creator::draft_view(&engine.core, &engine.creator, programme)?;
            let mut ids = BTreeSet::new();
            stored_text_ids(&view.spec, &mut ids);
            let mut opened = BTreeMap::new();
            for id in ids {
                if let Some(text) = texts.open(id).await {
                    opened.insert(id, text);
                }
            }
            let tenant_summary = match engine.tenant.state().map(|ts| ts.settings().guide_notice())
            {
                Some(fstp_tenant::GuideNotice::Tenant(o)) => texts.open(o.summary.id()).await,
                _ => None,
            };
            self.guide_with(state, call, opened, tenant_summary)
        })
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, reason = "test code")]

    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicI64, Ordering};

    use fstp_creator::{CheckId, CreatorCommand, DraftRevision, ProbeKind, ProbeOutcome, Severity};
    use fstp_domain::id::{DecisionId, ProgrammeId};

    use super::super::dns::{DnsError, LookupFuture, TxtResolver};
    use super::super::probe::{ProbeFuture, Prober, sending_domain};
    use super::*;

    /// A prober whose every probe gives `outcome`, counting its runs.
    struct FakeProber {
        outcome: ProbeOutcome,
        runs: AtomicI64,
    }

    impl Prober for FakeProber {
        fn run(&self, _probe: ProbeKind) -> ProbeFuture<'_> {
            self.runs.fetch_add(1, Ordering::SeqCst);
            Box::pin(std::future::ready(self.outcome))
        }
    }

    fn shell(outcome: Option<ProbeOutcome>, now: Arc<AtomicI64>) -> FactsShell {
        let prober = outcome.map(|outcome| {
            Arc::new(FakeProber {
                outcome,
                runs: AtomicI64::new(0),
            }) as Arc<dyn Prober>
        });
        FactsShell::new(prober).with_clock(Arc::new(move || now.load(Ordering::SeqCst)))
    }

    fn revision() -> DraftRevision {
        DraftRevision::new(1, fstp_ledger::Seq::from_raw(1))
    }

    fn approve() -> CreatorCommand {
        CreatorCommand::ApproveActivation {
            programme: ProgrammeId::from_raw(1),
            revision: revision(),
            decision: DecisionId::from_raw(1),
        }
    }

    fn acknowledge() -> CreatorCommand {
        CreatorCommand::AcknowledgeWarning {
            programme: ProgrammeId::from_raw(1),
            revision: revision(),
            warning: fstp_creator::WarningKey {
                check: CheckId::RosterShort,
                subject: fstp_creator::CheckSubject::Draft,
            },
        }
    }

    fn fresh(s: &FactsShell, cmd: &CreatorCommand) -> ProbeSet {
        let state = CellState::genesis();
        fstp_rt::future::block_on(s.facts_fresh(&state, cmd)).probes
    }

    /// The check each probe outcome gives, as the creator reads it.
    fn check_of(p: ProbeKind) -> CheckId {
        match p {
            ProbeKind::Channel => CheckId::ChannelUnreachable,
            ProbeKind::SendingDomain => CheckId::SendingDomainUnverified,
            ProbeKind::Inference => CheckId::InferenceUnreachable,
        }
    }

    /// Q5, I-66, design 3.2 "Fresh probes": a reachable fake prober runs
    /// every probe at the approval, and every probe passes.
    #[test]
    fn q5_fake_prober_reachable_passes() {
        let s = shell(Some(ProbeOutcome::Pass), Arc::new(AtomicI64::new(0)));
        assert_eq!(fresh(&s, &approve()), ProbeSet::passing());
    }

    /// Q5, I-66: an unreachable fake prober fails every probe, and the
    /// channel and sending domain checks are failures.
    #[test]
    fn q5_fake_prober_unreachable_fails() {
        let s = shell(Some(ProbeOutcome::Fail), Arc::new(AtomicI64::new(0)));
        let set = fresh(&s, &approve());
        for p in ProbeKind::ALL {
            assert_eq!(set.get(p), ProbeOutcome::Fail, "{p:?}");
        }
        assert_eq!(check_of(ProbeKind::Channel).severity(), Severity::Failure);
        assert_eq!(
            check_of(ProbeKind::SendingDomain).severity(),
            Severity::Failure
        );
    }

    /// Q5, I-66: with no prober every probe is absent, which the creator
    /// reads as a failure for the channel and the sending domain, and as
    /// the inference warning.
    #[test]
    fn q5_absent_prober_reports_failure() {
        let s = shell(None, Arc::new(AtomicI64::new(0)));
        let set = fresh(&s, &approve());
        assert_eq!(set, ProbeSet::absent());
        assert_eq!(set.get(ProbeKind::Channel), ProbeOutcome::Absent);
        assert_eq!(check_of(ProbeKind::Channel).severity(), Severity::Failure);
        assert_eq!(check_of(ProbeKind::Inference).severity(), Severity::Warning);
    }

    /// I-66, ADR-027: a synchronous read of an approval takes no result
    /// older than [`FRESH_US`], while another command reads the last one.
    #[test]
    fn i66_stale_probe_results_are_absent_at_approval() {
        let now = Arc::new(AtomicI64::new(0));
        let s = shell(Some(ProbeOutcome::Pass), Arc::clone(&now));
        fstp_rt::future::block_on(s.run_probes());
        let state = CellState::genesis();
        assert_eq!(s.facts(&state, &approve()).probes, ProbeSet::passing());
        now.store(FRESH_US + 1, Ordering::SeqCst);
        assert_eq!(s.facts(&state, &approve()).probes, ProbeSet::absent());
        assert_eq!(s.facts(&state, &acknowledge()).probes, ProbeSet::passing());
    }

    /// A resolver over fixed records, by name.
    struct FakeResolver(BTreeMap<String, Vec<Vec<u8>>>);

    impl TxtResolver for FakeResolver {
        fn txt<'a>(&'a self, name: &'a str) -> LookupFuture<'a> {
            let got = self.0.get(name).cloned().ok_or(DnsError::Unreachable);
            Box::pin(std::future::ready(got))
        }
    }

    fn records(dmarc: &str) -> FakeResolver {
        let mut m = BTreeMap::new();
        m.insert(
            "calls.example.org".to_owned(),
            vec![b"v=spf1 -all".to_vec()],
        );
        m.insert(
            "_dmarc.calls.example.org".to_owned(),
            vec![dmarc.as_bytes().to_vec()],
        );
        m.insert(
            "s1._domainkey.calls.example.org".to_owned(),
            vec![b"v=DKIM1; p=MIIB".to_vec()],
        );
        FakeResolver(m)
    }

    /// Q5, ADR-026 record of lane L18: the onboarding probe checks the
    /// domain the tenant admin saved, with the configured DKIM selector. A
    /// correctly configured domain passes, another domain fails, and with
    /// no selector the probe is absent.
    #[test]
    fn q5_tenant_prober_checks_the_saved_domain() {
        use super::super::probe::{CellProber, ProbeSettings, TenantProbe};
        let rt = fstp_rt::tokio::TokioRuntime::new_multi_thread(1).unwrap();
        let resolver = || Some(Arc::new(records("v=DMARC1; p=reject")) as Arc<dyn TxtResolver>);
        let settings = |selector: Option<&str>| ProbeSettings {
            dkim_selector: selector.map(str::to_owned),
            ..ProbeSettings::default()
        };
        let p = CellProber::new(rt.clone(), settings(Some("s1")), resolver());
        let run = |p: &CellProber<_>, d: &str| fstp_rt::future::block_on(TenantProbe::domain(p, d));
        assert_eq!(run(&p, "calls.example.org"), ProbeOutcome::Pass);
        assert_eq!(run(&p, "other.example.org"), ProbeOutcome::Fail);
        let none = CellProber::new(rt, settings(None), resolver());
        assert_eq!(run(&none, "calls.example.org"), ProbeOutcome::Absent);
    }

    /// ADR-027: the sending domain passes with SPF, DKIM and DMARC through
    /// a fake resolver, and fails with a bad DMARC record or an
    /// unreachable resolver.
    #[test]
    fn adr027_sending_domain_probe_over_a_fake_resolver() {
        let run = |r: &FakeResolver, selector: &str| {
            fstp_rt::future::block_on(sending_domain(r, "calls.example.org", selector))
        };
        assert_eq!(
            run(&records("v=DMARC1; p=reject"), "s1"),
            ProbeOutcome::Pass
        );
        assert_eq!(run(&records("v=DMARC1; p=bad"), "s1"), ProbeOutcome::Fail);
        assert_eq!(
            run(&records("v=DMARC1; p=reject"), "s2"),
            ProbeOutcome::Fail
        );
    }
}
