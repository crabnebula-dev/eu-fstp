//! Probes the shell runs for a report (M4 design section 3.2, `Prober`).
//!
//! An approval makes the shell run every probe in the same request. The
//! report at approval reads those results, never stored ones.

use std::collections::BTreeMap;

/// One probe.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeKind {
    /// Every enabled channel of P-32 (`ChannelUnreachable`).
    Channel,
    /// SPF, DKIM and DMARC of the sending domain
    /// (`SendingDomainUnverified`).
    SendingDomain,
    /// The P-21 inference provider (`InferenceUnreachable`).
    Inference,
}

impl ProbeKind {
    /// Every probe, in catalogue order.
    pub const ALL: [ProbeKind; 3] = [
        ProbeKind::Channel,
        ProbeKind::SendingDomain,
        ProbeKind::Inference,
    ];

    /// The probe's name in JSON.
    pub const fn name(self) -> &'static str {
        match self {
            ProbeKind::Channel => "Channel",
            ProbeKind::SendingDomain => "SendingDomain",
            ProbeKind::Inference => "Inference",
        }
    }

    /// The probe with JSON name `name`.
    pub fn from_name(name: &str) -> Option<ProbeKind> {
        ProbeKind::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// The outcome of one probe run.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProbeOutcome {
    /// The probe passed.
    Pass,
    /// The probe failed.
    Fail,
    /// No prober exists. Channels and the sending domain then fail closed
    /// (Q5, interim, pending Daniel). Inference gives its warning.
    Absent,
}

impl ProbeOutcome {
    /// Every outcome.
    pub const ALL: [ProbeOutcome; 3] =
        [ProbeOutcome::Pass, ProbeOutcome::Fail, ProbeOutcome::Absent];

    /// The outcome's name in JSON.
    pub const fn name(self) -> &'static str {
        match self {
            ProbeOutcome::Pass => "Pass",
            ProbeOutcome::Fail => "Fail",
            ProbeOutcome::Absent => "Absent",
        }
    }

    /// The outcome with JSON name `name`.
    pub fn from_name(name: &str) -> Option<ProbeOutcome> {
        ProbeOutcome::ALL.into_iter().find(|p| p.name() == name)
    }
}

/// The result of every probe. A probe with no result is
/// [`ProbeOutcome::Absent`].
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct ProbeSet {
    outcomes: BTreeMap<ProbeKind, ProbeOutcome>,
}

impl ProbeSet {
    /// No probe result: every probe is absent.
    pub fn absent() -> ProbeSet {
        ProbeSet::default()
    }

    /// Every probe passed.
    pub fn passing() -> ProbeSet {
        let mut s = ProbeSet::default();
        for p in ProbeKind::ALL {
            s.outcomes.insert(p, ProbeOutcome::Pass);
        }
        s
    }

    /// The same set with `probe` at `outcome`.
    pub fn with(mut self, probe: ProbeKind, outcome: ProbeOutcome) -> ProbeSet {
        self.outcomes.insert(probe, outcome);
        self
    }

    /// Sets `probe` to `outcome`.
    pub fn set(&mut self, probe: ProbeKind, outcome: ProbeOutcome) {
        self.outcomes.insert(probe, outcome);
    }

    /// The outcome of `probe`.
    pub fn get(&self, probe: ProbeKind) -> ProbeOutcome {
        self.outcomes
            .get(&probe)
            .copied()
            .unwrap_or(ProbeOutcome::Absent)
    }
}
