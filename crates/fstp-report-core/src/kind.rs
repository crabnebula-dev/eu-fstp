//! The outputs of the funder profile and what they cover (R-RP-04).

use fstp_domain::id::{CallId, ProgrammeId};

/// One output of the profile.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReportKind {
    /// Fields for announcing the call on the Funding & Tenders Portal.
    CallPublicationRecord,
    /// Guide, proposal form, contract template and notice.
    OpenCallPackage,
    /// Recipients per period with amounts committed and paid.
    PeriodicReportingData,
    /// The audit file of one call, with hashes.
    AuditFile,
    /// The per-call selection report of the FSTP work package.
    DeliverableDraft,
}

impl ReportKind {
    /// Every output, in the order of the profile table.
    pub const ALL: [ReportKind; 5] = [
        ReportKind::CallPublicationRecord,
        ReportKind::OpenCallPackage,
        ReportKind::PeriodicReportingData,
        ReportKind::AuditFile,
        ReportKind::DeliverableDraft,
    ];

    /// The stored name.
    pub const fn name(self) -> &'static str {
        match self {
            ReportKind::CallPublicationRecord => "call_publication_record",
            ReportKind::OpenCallPackage => "open_call_package",
            ReportKind::PeriodicReportingData => "periodic_reporting_data",
            ReportKind::AuditFile => "audit_file",
            ReportKind::DeliverableDraft => "deliverable_draft",
        }
    }

    /// The output of a stored name.
    pub fn from_name(name: &str) -> Option<ReportKind> {
        ReportKind::ALL.into_iter().find(|k| k.name() == name)
    }

    /// The template version (R-RP-01).
    pub const fn template(self) -> &'static str {
        match self {
            ReportKind::CallPublicationRecord => "horizon-europe/call_publication_record/1",
            ReportKind::OpenCallPackage => "horizon-europe/open_call_package/1",
            ReportKind::PeriodicReportingData => "horizon-europe/periodic_reporting_data/1",
            ReportKind::AuditFile => "horizon-europe/audit_file/1",
            ReportKind::DeliverableDraft => "horizon-europe/deliverable_draft/1",
        }
    }
}

/// What an output covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Scope {
    /// One call.
    Call(CallId),
    /// One programme.
    Programme(ProgrammeId),
}
