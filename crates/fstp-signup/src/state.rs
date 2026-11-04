//! Commands of journey J0, the fold of the control plane records, and the
//! provisioning gate (TH-46, R-TN-01, Q22; M4 design sections 2.2 and
//! 3.5).
//!
//! The rules:
//!
//! - Operator staff offer one version of each agreement
//!   (`AgreementsOffered`). Every version is at least 1, no version moves
//!   back, and a new offer changes at least one version (`BadOffer`).
//!   Interim, pending Daniel: the design does not say where the offered
//!   versions live. This crate keeps them in the ledger, so the fold
//!   knows which version was offered when each acceptance was recorded.
//! - A tenant signs up once (`TenantExists`). Every later command and
//!   record of a tenant needs its sign-up first (`UnknownTenant`).
//! - An acceptance names the current offer exactly and is refused whole
//!   if any version differs (`VersionNotOffered`), or if nothing is
//!   offered yet (`NoOffer`). It records one `AgreementAccepted` per
//!   agreement not yet accepted at that version. No record repeats a
//!   (tenant, agreement, version). The form values are checked before
//!   the tenant is looked up.
//! - Interim, pending Daniel: [`APPROVALS_NEEDED`] distinct operator
//!   staff approve the tenant's identity. One staff member approves at
//!   most once (`SameReviewer`). A rejection by any staff member is final
//!   (`ReviewRejected`): nothing further folds for that tenant.
//! - [`provision_permit`] issues a permit only for a signed-up tenant
//!   with no rejection, the current offer accepted in full, enough
//!   distinct approvals, and no provisioning yet.
//! - After `TenantProvisioned`, the gate never permits that tenant again
//!   and no review of it folds (`AlreadyProvisioned`). Acceptances of
//!   later offers still fold.
//! - [`SignupState::apply`] checks each record against the same rules as
//!   [`decide`], so a forged ledger never folds into a permit.

use std::collections::{BTreeMap, BTreeSet};

use crate::error::{FormError, Refusal, SignupError};
use crate::record::CpRecord;
use crate::text::{TextFault, check_text};
use crate::types::{
    Agreement, AgreementFields, AgreementVersions, ReviewOutcome, SignupFields, StaffId, TenantId,
};

/// A control plane command of journey J0.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CpCommand {
    /// `cp.offer_agreements`: operator staff publish the agreement
    /// versions that tenants accept from now on.
    OfferAgreements {
        /// One version of each agreement.
        versions: AgreementVersions,
        /// The acting staff member.
        staff: StaffId,
        /// Unix seconds.
        at: i64,
    },
    /// `cp.signup`.
    Signup {
        /// The new tenant's id, from the shell.
        tenant: TenantId,
        /// The decoded form.
        form: SignupFields,
        /// Unix seconds.
        at: i64,
    },
    /// `cp.accept_agreements`. The versions must equal the current offer
    /// of the ledger.
    AcceptAgreements {
        /// The decoded form.
        form: AgreementFields,
        /// Unix seconds.
        at: i64,
    },
    /// `cp.review_tenant`.
    ReviewTenant {
        /// The tenant.
        tenant: TenantId,
        /// The acting staff member.
        staff: StaffId,
        /// The outcome.
        outcome: ReviewOutcome,
        /// Unix seconds.
        at: i64,
    },
    /// `cp.record_provisioned`: the shell records that the `Provisioner`
    /// created the tenant's cell. It passes the same gate as
    /// [`provision_permit`].
    RecordProvisioned {
        /// The tenant.
        tenant: TenantId,
        /// Unix seconds.
        at: i64,
    },
}

/// What the fold keeps of one tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct TenantFile {
    /// The sign-up values (Q22: kept in the control plane).
    signup: SignupFields,
    /// Every accepted (agreement, version).
    accepted: BTreeSet<(Agreement, u32)>,
    /// The staff who approved the tenant's identity.
    approvers: BTreeSet<StaffId>,
    /// Whether any staff member rejected it. The rejection record names
    /// who did.
    rejected: bool,
    /// Whether the tenant's cell was provisioned.
    provisioned: bool,
}

/// The control plane onboarding state, a fold of [`CpRecord`] values.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct SignupState {
    /// The current offer, once operator staff made one.
    offer: Option<AgreementVersions>,
    tenants: BTreeMap<TenantId, TenantFile>,
}

/// Checks that `next` may follow the current offer: every version is at
/// least 1, none moves back, and at least one changes.
fn check_offer(
    current: Option<AgreementVersions>,
    next: AgreementVersions,
) -> Result<(), SignupError> {
    let positive = next.pairs().iter().all(|(_, v)| *v != 0);
    let forward = current
        .is_none_or(|cur| cur != next && Agreement::ALL.iter().all(|a| next.of(*a) >= cur.of(*a)));
    if positive && forward {
        Ok(())
    } else {
        Err(Refusal::BadOffer.into())
    }
}

/// The provisioning gate over one tenant's file that is not rejected.
/// Returns the offer the tenant accepted in full.
fn gate(
    file: &TenantFile,
    offer: Option<AgreementVersions>,
) -> Result<AgreementVersions, SignupError> {
    if file.provisioned {
        return Err(Refusal::AlreadyProvisioned.into());
    }
    let offer = offer.ok_or(SignupError::Refused(Refusal::NoOffer))?;
    let accepted = offer.pairs().iter().all(|key| file.accepted.contains(key));
    if !accepted {
        return Err(Refusal::AgreementsNotAccepted.into());
    }
    if file.approvers.len() < APPROVALS_NEEDED {
        return Err(Refusal::ReviewPending.into());
    }
    Ok(offer)
}

impl SignupState {
    /// The empty state.
    pub fn new() -> SignupState {
        SignupState::default()
    }

    /// Folds one record. A record that breaks a rule is refused and the
    /// state stays as it was.
    pub fn apply(&mut self, record: &CpRecord) -> Result<(), SignupError> {
        record.check_values()?;
        let offer = self.offer;
        match record {
            CpRecord::AgreementsOffered { versions, .. } => {
                check_offer(offer, *versions)?;
                self.offer = Some(*versions);
            }
            CpRecord::SignedUp {
                tenant,
                legal_name,
                billing_address,
                contracting_signatory,
                ..
            } => {
                if self.tenants.contains_key(tenant) {
                    return Err(Refusal::TenantExists.into());
                }
                self.tenants.insert(
                    *tenant,
                    TenantFile {
                        signup: SignupFields {
                            legal_name: legal_name.clone(),
                            billing_address: billing_address.clone(),
                            contracting_signatory: contracting_signatory.clone(),
                        },
                        accepted: BTreeSet::new(),
                        approvers: BTreeSet::new(),
                        rejected: false,
                        provisioned: false,
                    },
                );
            }
            CpRecord::AgreementAccepted {
                tenant,
                agreement,
                version,
                ..
            } => {
                let file = self.open_file_mut(*tenant)?;
                let offer = offer.ok_or(SignupError::Refused(Refusal::NoOffer))?;
                if offer.of(*agreement) != *version {
                    return Err(Refusal::VersionNotOffered.into());
                }
                if file.accepted.contains(&(*agreement, *version)) {
                    return Err(Refusal::AlreadyAccepted.into());
                }
                file.accepted.insert((*agreement, *version));
            }
            CpRecord::TenantReviewed {
                tenant,
                outcome,
                by,
                ..
            } => {
                let file = self.open_file_mut(*tenant)?;
                if file.provisioned {
                    return Err(Refusal::AlreadyProvisioned.into());
                }
                match outcome {
                    ReviewOutcome::Approved => {
                        if file.approvers.contains(by) {
                            return Err(Refusal::SameReviewer.into());
                        }
                        file.approvers.insert(*by);
                    }
                    ReviewOutcome::Rejected => file.rejected = true,
                }
            }
            CpRecord::TenantProvisioned {
                tenant, versions, ..
            } => {
                let file = self.open_file_mut(*tenant)?;
                if gate(file, offer)? != *versions {
                    return Err(Refusal::VersionNotOffered.into());
                }
                file.provisioned = true;
            }
        }
        Ok(())
    }

    /// Folds a stored ledger from the empty state. The first record that
    /// breaks a rule refuses the whole ledger.
    pub fn replay(records: &[CpRecord]) -> Result<SignupState, SignupError> {
        let mut s = SignupState::new();
        for r in records {
            s.apply(r)?;
        }
        Ok(s)
    }

    /// The current offer, if operator staff made one. The agreement form
    /// renders these versions.
    pub fn offered(&self) -> Option<AgreementVersions> {
        self.offer
    }

    /// The sign-up values of `tenant`, if it signed up.
    pub fn signup(&self, tenant: TenantId) -> Option<&SignupFields> {
        self.tenants.get(&tenant).map(|f| &f.signup)
    }

    /// Whether `tenant` accepted `agreement` at `version`.
    pub fn has_accepted(&self, tenant: TenantId, agreement: Agreement, version: u32) -> bool {
        self.tenants
            .get(&tenant)
            .is_some_and(|f| f.accepted.contains(&(agreement, version)))
    }

    /// The staff who approved `tenant`'s identity, in id order.
    pub fn approvers(&self, tenant: TenantId) -> impl Iterator<Item = StaffId> + '_ {
        self.tenants
            .get(&tenant)
            .into_iter()
            .flat_map(|f| f.approvers.iter().copied())
    }

    /// Whether a staff member rejected `tenant`'s identity.
    pub fn is_rejected(&self, tenant: TenantId) -> bool {
        self.tenants.get(&tenant).is_some_and(|f| f.rejected)
    }

    /// Whether `tenant`'s cell was provisioned.
    pub fn is_provisioned(&self, tenant: TenantId) -> bool {
        self.tenants.get(&tenant).is_some_and(|f| f.provisioned)
    }

    /// The file of a signed-up tenant with no rejection.
    fn open_file(&self, tenant: TenantId) -> Result<&TenantFile, SignupError> {
        let file = self
            .tenants
            .get(&tenant)
            .ok_or(SignupError::Refused(Refusal::UnknownTenant))?;
        if file.rejected {
            return Err(Refusal::ReviewRejected.into());
        }
        Ok(file)
    }

    fn open_file_mut(&mut self, tenant: TenantId) -> Result<&mut TenantFile, SignupError> {
        let file = self
            .tenants
            .get_mut(&tenant)
            .ok_or(SignupError::Refused(Refusal::UnknownTenant))?;
        if file.rejected {
            return Err(Refusal::ReviewRejected.into());
        }
        Ok(file)
    }
}

/// Checks a text value of a command's form.
fn form_text(name: &'static str, value: &str, line_breaks: bool) -> Result<(), SignupError> {
    match check_text(value, line_breaks) {
        Ok(()) => Ok(()),
        Err(TextFault::TooLong) => Err(FormError::ValueTooLong(name).into()),
        Err(TextFault::Bad) => Err(FormError::BadValue(name).into()),
    }
}

/// Decides a command over `state` and returns the records to fold. A
/// refusal records nothing.
///
/// The agreement form can reach the control plane before any session
/// exists. Its values and versions are checked before the tenant is
/// looked up. The shell answers every [`SignupError::Refused`] of that
/// form with one response, so the refusals do not tell a caller which
/// tenant ids exist.
pub fn decide(state: &SignupState, cmd: &CpCommand) -> Result<Vec<CpRecord>, SignupError> {
    match cmd {
        CpCommand::OfferAgreements {
            versions,
            staff,
            at,
        } => {
            check_offer(state.offer, *versions)?;
            Ok(vec![CpRecord::AgreementsOffered {
                versions: *versions,
                by: *staff,
                at: *at,
            }])
        }
        CpCommand::Signup { tenant, form, at } => {
            form_text("legal_name", &form.legal_name, false)?;
            form_text("billing_address", &form.billing_address, true)?;
            form_text("contracting_signatory", &form.contracting_signatory, false)?;
            if state.tenants.contains_key(tenant) {
                return Err(Refusal::TenantExists.into());
            }
            Ok(vec![CpRecord::SignedUp {
                tenant: *tenant,
                legal_name: form.legal_name.clone(),
                billing_address: form.billing_address.clone(),
                contracting_signatory: form.contracting_signatory.clone(),
                at: *at,
            }])
        }
        CpCommand::AcceptAgreements { form, at } => {
            form_text("accepted_by", &form.accepted_by, false)?;
            let offer = state.offer.ok_or(SignupError::Refused(Refusal::NoOffer))?;
            if form.versions != offer {
                return Err(Refusal::VersionNotOffered.into());
            }
            let file = state.open_file(form.tenant)?;
            let records: Vec<CpRecord> = offer
                .pairs()
                .into_iter()
                .filter(|key| !file.accepted.contains(key))
                .map(|(agreement, version)| CpRecord::AgreementAccepted {
                    tenant: form.tenant,
                    agreement,
                    version,
                    by: form.accepted_by.clone(),
                    at: *at,
                })
                .collect();
            if records.is_empty() {
                return Err(Refusal::AlreadyAccepted.into());
            }
            Ok(records)
        }
        CpCommand::ReviewTenant {
            tenant,
            staff,
            outcome,
            at,
        } => {
            let file = state.open_file(*tenant)?;
            if file.provisioned {
                return Err(Refusal::AlreadyProvisioned.into());
            }
            if *outcome == ReviewOutcome::Approved && file.approvers.contains(staff) {
                return Err(Refusal::SameReviewer.into());
            }
            Ok(vec![CpRecord::TenantReviewed {
                tenant: *tenant,
                outcome: *outcome,
                by: *staff,
                at: *at,
            }])
        }
        CpCommand::RecordProvisioned { tenant, at } => {
            let versions = gate(state.open_file(*tenant)?, state.offer)?;
            Ok(vec![CpRecord::TenantProvisioned {
                tenant: *tenant,
                versions,
                at: *at,
            }])
        }
    }
}

/// The number of distinct staff approvals the gate needs. Interim,
/// pending Daniel.
///
/// The design records one reviewer per review (`TenantReviewed { outcome,
/// by }`). This crate borrows the decided two-staff rule of the first
/// tenant admin verification (`roles-and-sod.md`), which is the stricter
/// reading. This constant is the single switch: a one-reviewer answer
/// changes it and the M-REVIEW reference in the test kit.
pub const APPROVALS_NEEDED: usize = 2;

/// The proof that a tenant passed the provisioning gate (TH-46). Only
/// [`provision_permit`] makes one. It is neither `Clone` nor `Copy`, so
/// [`Provisioner::provision`] consumes it and one gate pass serves one
/// call.
///
/// ```compile_fail
/// fn needs_clone<T: Clone>() {}
/// needs_clone::<fstp_signup::ProvisionPermit>();
/// ```
#[derive(Debug)]
pub struct ProvisionPermit {
    tenant: TenantId,
    versions: AgreementVersions,
}

impl ProvisionPermit {
    /// The tenant to provision.
    pub fn tenant(&self) -> TenantId {
        self.tenant
    }

    /// The agreement versions the tenant accepted, as offered when the
    /// permit was issued.
    pub fn versions(&self) -> AgreementVersions {
        self.versions
    }
}

/// The provisioning gate (TH-46). It refuses, in this order: a tenant
/// that did not sign up, a rejected review, a tenant already provisioned,
/// no offer, an offered version not accepted, and fewer than
/// [`APPROVALS_NEEDED`] distinct staff approvals.
pub fn provision_permit(
    state: &SignupState,
    tenant: TenantId,
) -> Result<ProvisionPermit, SignupError> {
    let versions = gate(state.open_file(tenant)?, state.offer)?;
    Ok(ProvisionPermit { tenant, versions })
}

/// The `Provisioner` port as the control plane calls it. The adapter that
/// creates a SaaS cell implements it in `fstp-control` (M3). It takes a
/// [`ProvisionPermit`] by value, so no call can provision a tenant that
/// did not pass the gate. Self-hosted cells skip the review and this
/// port.
///
/// The shell runs one serialised control plane transaction per
/// provisioning. It folds the ledger, calls [`provision_permit`], calls
/// `provision`, and on success appends the record that
/// [`CpCommand::RecordProvisioned`] decides, then commits. A rejection or
/// a new offer recorded before that transaction is seen by the gate, and
/// the `TenantProvisioned` record stops any later permit for the tenant.
/// The adapter is idempotent per tenant id, so a retry after a crash
/// between `provision` and the commit is safe.
pub trait Provisioner {
    /// What the adapter reports when provisioning fails.
    type Error;

    /// Provisions the cell of `permit`'s tenant.
    fn provision(&mut self, permit: ProvisionPermit) -> Result<(), Self::Error>;
}
