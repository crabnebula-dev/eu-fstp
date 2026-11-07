//! The records of the `Contract` ledger envelope (M5 design section 4.1)
//! and their stored JSON form.
//!
//! Each record is an object with a `type` member and its fields. Ids are
//! decimal strings, digests 64 lowercase hex digits, and enums lowercase
//! snake-case names. Unknown and missing members are refused. Errors name
//! schema members only, never input content (R-NF-02).

use fstp_domain::id::{AccountId, ContractId, DecisionId, PlanVersionId, ProposalId};
use fstp_json::typed::{expect_object, reject_unknown};
use fstp_json::{Array, FromJson, FromJsonError, Object, ToJson, Value};

use crate::digest::Digest;
use crate::model::{ChangeStatus, Party, PartyRole, Route, Side, valid_field};

/// One record of the `Contract` envelope.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum ContractRecord {
    /// A version was drafted from the template and the plan (R-CT-01, I-49).
    Drafted {
        /// The contract.
        contract: ContractId,
        /// The proposal.
        proposal: ProposalId,
        /// The version number.
        version: u32,
        /// The template version (P-29).
        template: u32,
        /// The plan version.
        plan: PlanVersionId,
        /// The amount determination.
        determination: DecisionId,
        /// The parties.
        parties: Vec<Party>,
        /// The digest of the generated terms.
        base: Digest,
    },
    /// A clause change was proposed or decided (R-CT-04).
    ClauseChange {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The clause number.
        clause: u32,
        /// The digest of the diff text against the template.
        diff: Digest,
        /// The proposing side.
        proposer: Side,
        /// The status this record sets.
        status: ChangeStatus,
        /// The new terms digest when accepted.
        base: Option<Digest>,
    },
    /// The version was sent for signature, frozen with its revision 0.
    Sent {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// SHA-256 of revision 0.
        revision0: Digest,
    },
    /// A programme manager approved the advanced route for one party
    /// (P-30 step 3).
    AdvancedApproved {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The party's field.
        party: String,
        /// The approver.
        approver: AccountId,
        /// The digest of the reason text.
        reason: Digest,
    },
    /// A party's validated signature was applied (I-30).
    SignatureApplied {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// The party's field.
        party: String,
        /// The route.
        route: Route,
        /// The revision number this signature created, from 1.
        revision: u32,
        /// SHA-256 of the new revision.
        revision_digest: Digest,
        /// SHA-256 of the signer certificate.
        signer_certificate: Digest,
        /// Digest of the `fstp-sigval` validation report.
        report: Digest,
    },
    /// The version became effective with the countersignature.
    Effective {
        /// The contract.
        contract: ContractId,
        /// The version.
        version: u32,
        /// SHA-256 of the final revision.
        final_digest: Digest,
    },
    /// A later version replaced an earlier one.
    VersionSuperseded {
        /// The contract.
        contract: ContractId,
        /// The replaced version.
        old: u32,
        /// The replacing version.
        new: u32,
    },
    /// The contract ended early.
    Terminated {
        /// The contract.
        contract: ContractId,
        /// The latest version at termination.
        version: u32,
        /// The digest of the reason text.
        reason: Digest,
        /// SHA-256 of the sealed draft, when no party had signed.
        sealed_draft: Option<Digest>,
    },
}

impl ContractRecord {
    /// The contract the record is about.
    #[must_use]
    pub fn contract(&self) -> ContractId {
        match self {
            ContractRecord::Drafted { contract, .. }
            | ContractRecord::ClauseChange { contract, .. }
            | ContractRecord::Sent { contract, .. }
            | ContractRecord::AdvancedApproved { contract, .. }
            | ContractRecord::SignatureApplied { contract, .. }
            | ContractRecord::Effective { contract, .. }
            | ContractRecord::VersionSuperseded { contract, .. }
            | ContractRecord::Terminated { contract, .. } => *contract,
        }
    }

    /// The stored type tag.
    #[must_use]
    pub const fn tag(&self) -> &'static str {
        match self {
            ContractRecord::Drafted { .. } => "contract_drafted",
            ContractRecord::ClauseChange { .. } => "clause_change",
            ContractRecord::Sent { .. } => "contract_sent",
            ContractRecord::AdvancedApproved { .. } => "advanced_approved",
            ContractRecord::SignatureApplied { .. } => "signature_applied",
            ContractRecord::Effective { .. } => "contract_effective",
            ContractRecord::VersionSuperseded { .. } => "version_superseded",
            ContractRecord::Terminated { .. } => "contract_terminated",
        }
    }
}

// ---------------------------------------------------------------------------
// Primitive spellings.

fn id(raw: u128) -> Value {
    Value::String(raw.to_string())
}

fn take_id(v: &Value) -> Result<u128, FromJsonError> {
    let Value::String(s) = v else {
        return Err(FromJsonError::wrong_type("string", v));
    };
    let ok = !s.is_empty()
        && s.len() <= 39
        && s.bytes().all(|b| b.is_ascii_digit())
        && (s.len() == 1 || !s.starts_with('0'));
    if !ok {
        return Err(FromJsonError::invalid("not a decimal id"));
    }
    s.parse::<u128>()
        .map_err(|_| FromJsonError::invalid("not a decimal id"))
}

fn route_name(r: Route) -> &'static str {
    match r {
        Route::WalletQes => "wallet_qes",
        Route::QtspRemoteQes => "qtsp_remote_qes",
        Route::Advanced => "advanced",
    }
}

fn role_name(r: PartyRole) -> &'static str {
    match r {
        PartyRole::Lead => "lead",
        PartyRole::TeamMember => "team_member",
        PartyRole::Guardian => "guardian",
        PartyRole::Signatory => "signatory",
    }
}

fn side_name(s: Side) -> &'static str {
    match s {
        Side::Grantee => "grantee",
        Side::Operator => "operator",
    }
}

fn status_name(s: ChangeStatus) -> &'static str {
    match s {
        ChangeStatus::Proposed => "proposed",
        ChangeStatus::Accepted => "accepted",
        ChangeStatus::Rejected => "rejected",
    }
}

fn take_name<T: Copy>(v: &Value, table: &[(&str, T)]) -> Result<T, FromJsonError> {
    let Value::String(s) = v else {
        return Err(FromJsonError::wrong_type("string", v));
    };
    table
        .iter()
        .find(|(n, _)| n == s)
        .map(|(_, t)| *t)
        .ok_or_else(|| FromJsonError::invalid("unknown enum value"))
}

const ROUTES: [(&str, Route); 3] = [
    ("wallet_qes", Route::WalletQes),
    ("qtsp_remote_qes", Route::QtspRemoteQes),
    ("advanced", Route::Advanced),
];
const ROLES: [(&str, PartyRole); 4] = [
    ("lead", PartyRole::Lead),
    ("team_member", PartyRole::TeamMember),
    ("guardian", PartyRole::Guardian),
    ("signatory", PartyRole::Signatory),
];
const SIDES: [(&str, Side); 2] = [("grantee", Side::Grantee), ("operator", Side::Operator)];
const STATUSES: [(&str, ChangeStatus); 3] = [
    ("proposed", ChangeStatus::Proposed),
    ("accepted", ChangeStatus::Accepted),
    ("rejected", ChangeStatus::Rejected),
];

fn field_name(v: &Value) -> Result<String, FromJsonError> {
    let s = String::from_json(v)?;
    if !valid_field(&s) {
        return Err(FromJsonError::invalid("not a signature field name"));
    }
    Ok(s)
}

fn party_json(p: &Party) -> Value {
    let mut o = Object::new();
    o.insert("field", Value::String(p.field.clone()));
    o.insert("role", Value::String(role_name(p.role).to_owned()));
    o.insert("account", id(p.account.raw()));
    Value::Object(o)
}

fn take_party(v: &Value) -> Result<Party, FromJsonError> {
    let o = expect_object(v)?;
    reject_unknown(o, &["field", "role", "account"])?;
    Ok(Party {
        field: field_name(get(o, "field")?).map_err(|e| e.at_field("field"))?,
        role: take_name(get(o, "role")?, &ROLES).map_err(|e| e.at_field("role"))?,
        account: AccountId::from_raw(
            take_id(get(o, "account")?).map_err(|e| e.at_field("account"))?,
        ),
    })
}

fn get<'a>(o: &'a Object, key: &'static str) -> Result<&'a Value, FromJsonError> {
    o.get(key)
        .ok_or_else(|| FromJsonError::invalid("missing member").at_field(key))
}

/// Reads one member with `f`, naming the member on error.
fn take<T>(
    o: &Object,
    key: &'static str,
    f: impl FnOnce(&Value) -> Result<T, FromJsonError>,
) -> Result<T, FromJsonError> {
    f(get(o, key)?).map_err(|e| e.at_field(key))
}

fn opt_digest(v: &Value) -> Result<Option<Digest>, FromJsonError> {
    match v {
        Value::Null => Ok(None),
        other => Digest::from_json(other).map(Some),
    }
}

fn opt_digest_json(d: Option<Digest>) -> Value {
    d.map_or(Value::Null, |d| d.to_json())
}

fn u32_of(v: &Value) -> Result<u32, FromJsonError> {
    u32::from_json(v)
}

impl ToJson for ContractRecord {
    fn to_json(&self) -> Value {
        let mut o = Object::new();
        o.insert("type", Value::String(self.tag().to_owned()));
        o.insert("contract", id(self.contract().raw()));
        match self {
            ContractRecord::Drafted {
                proposal,
                version,
                template,
                plan,
                determination,
                parties,
                base,
                ..
            } => {
                o.insert("proposal", id(proposal.raw()));
                o.insert("version", version.to_json());
                o.insert("template", template.to_json());
                o.insert("plan", id(plan.raw()));
                o.insert("determination", id(determination.raw()));
                let mut a = Array::new();
                for p in parties {
                    a.push(party_json(p));
                }
                o.insert("parties", Value::Array(a));
                o.insert("base", base.to_json());
            }
            ContractRecord::ClauseChange {
                version,
                clause,
                diff,
                proposer,
                status,
                base,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("clause", clause.to_json());
                o.insert("diff", diff.to_json());
                o.insert("proposer", Value::String(side_name(*proposer).to_owned()));
                o.insert("status", Value::String(status_name(*status).to_owned()));
                o.insert("base", opt_digest_json(*base));
            }
            ContractRecord::Sent {
                version, revision0, ..
            } => {
                o.insert("version", version.to_json());
                o.insert("revision0", revision0.to_json());
            }
            ContractRecord::AdvancedApproved {
                version,
                party,
                approver,
                reason,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("party", Value::String(party.clone()));
                o.insert("approver", id(approver.raw()));
                o.insert("reason", reason.to_json());
            }
            ContractRecord::SignatureApplied {
                version,
                party,
                route,
                revision,
                revision_digest,
                signer_certificate,
                report,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("party", Value::String(party.clone()));
                o.insert("route", Value::String(route_name(*route).to_owned()));
                o.insert("revision", revision.to_json());
                o.insert("revision_digest", revision_digest.to_json());
                o.insert("signer_certificate", signer_certificate.to_json());
                o.insert("report", report.to_json());
            }
            ContractRecord::Effective {
                version,
                final_digest,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("final_digest", final_digest.to_json());
            }
            ContractRecord::VersionSuperseded { old, new, .. } => {
                o.insert("old", old.to_json());
                o.insert("new", new.to_json());
            }
            ContractRecord::Terminated {
                version,
                reason,
                sealed_draft,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("reason", reason.to_json());
                o.insert("sealed_draft", opt_digest_json(*sealed_draft));
            }
        }
        Value::Object(o)
    }
}

impl FromJson for ContractRecord {
    fn from_json(value: &Value) -> Result<ContractRecord, FromJsonError> {
        let o = expect_object(value)?;
        let tag = take(o, "type", String::from_json)?;
        let contract = ContractId::from_raw(take(o, "contract", take_id)?);
        let fields: &[&str] = match tag.as_str() {
            "contract_drafted" => &[
                "type",
                "contract",
                "proposal",
                "version",
                "template",
                "plan",
                "determination",
                "parties",
                "base",
            ],
            "clause_change" => &[
                "type", "contract", "version", "clause", "diff", "proposer", "status", "base",
            ],
            "contract_sent" => &["type", "contract", "version", "revision0"],
            "advanced_approved" => &["type", "contract", "version", "party", "approver", "reason"],
            "signature_applied" => &[
                "type",
                "contract",
                "version",
                "party",
                "route",
                "revision",
                "revision_digest",
                "signer_certificate",
                "report",
            ],
            "contract_effective" => &["type", "contract", "version", "final_digest"],
            "version_superseded" => &["type", "contract", "old", "new"],
            "contract_terminated" => &["type", "contract", "version", "reason", "sealed_draft"],
            _ => return Err(FromJsonError::invalid("unknown record type").at_field("type")),
        };
        reject_unknown(o, fields)?;
        let r = match tag.as_str() {
            "contract_drafted" => {
                let parties = take(o, "parties", |v| match v {
                    Value::Array(a) => a
                        .iter()
                        .enumerate()
                        .map(|(i, p)| take_party(p).map_err(|e| e.at_index(i)))
                        .collect::<Result<Vec<_>, _>>(),
                    other => Err(FromJsonError::wrong_type("array", other)),
                })?;
                ContractRecord::Drafted {
                    contract,
                    proposal: ProposalId::from_raw(take(o, "proposal", take_id)?),
                    version: take(o, "version", u32_of)?,
                    template: take(o, "template", u32_of)?,
                    plan: PlanVersionId::from_raw(take(o, "plan", take_id)?),
                    determination: DecisionId::from_raw(take(o, "determination", take_id)?),
                    parties,
                    base: take(o, "base", Digest::from_json)?,
                }
            }
            "clause_change" => ContractRecord::ClauseChange {
                contract,
                version: take(o, "version", u32_of)?,
                clause: take(o, "clause", u32_of)?,
                diff: take(o, "diff", Digest::from_json)?,
                proposer: take(o, "proposer", |v| take_name(v, &SIDES))?,
                status: take(o, "status", |v| take_name(v, &STATUSES))?,
                base: take(o, "base", opt_digest)?,
            },
            "contract_sent" => ContractRecord::Sent {
                contract,
                version: take(o, "version", u32_of)?,
                revision0: take(o, "revision0", Digest::from_json)?,
            },
            "advanced_approved" => ContractRecord::AdvancedApproved {
                contract,
                version: take(o, "version", u32_of)?,
                party: take(o, "party", field_name)?,
                approver: AccountId::from_raw(take(o, "approver", take_id)?),
                reason: take(o, "reason", Digest::from_json)?,
            },
            "signature_applied" => ContractRecord::SignatureApplied {
                contract,
                version: take(o, "version", u32_of)?,
                party: take(o, "party", field_name)?,
                route: take(o, "route", |v| take_name(v, &ROUTES))?,
                revision: take(o, "revision", u32_of)?,
                revision_digest: take(o, "revision_digest", Digest::from_json)?,
                signer_certificate: take(o, "signer_certificate", Digest::from_json)?,
                report: take(o, "report", Digest::from_json)?,
            },
            "contract_effective" => ContractRecord::Effective {
                contract,
                version: take(o, "version", u32_of)?,
                final_digest: take(o, "final_digest", Digest::from_json)?,
            },
            "version_superseded" => ContractRecord::VersionSuperseded {
                contract,
                old: take(o, "old", u32_of)?,
                new: take(o, "new", u32_of)?,
            },
            _ => ContractRecord::Terminated {
                contract,
                version: take(o, "version", u32_of)?,
                reason: take(o, "reason", Digest::from_json)?,
                sealed_draft: take(o, "sealed_draft", opt_digest)?,
            },
        };
        Ok(r)
    }
}

/// The stored form of a contract command, for the cell's command log. It
/// uses the record spellings, with `type` naming the command. The cell
/// does not read it back yet.
impl ToJson for crate::decide::ContractCommand {
    fn to_json(&self) -> Value {
        use crate::decide::ContractCommand as C;
        let mut o = Object::new();
        let (tag, contract) = match self {
            C::Draft { contract, .. } => ("draft", contract),
            C::ProposeChange { contract, .. } => ("propose_change", contract),
            C::DecideChange { contract, .. } => ("decide_change", contract),
            C::Send { contract, .. } => ("send", contract),
            C::ApproveAdvanced { contract, .. } => ("approve_advanced", contract),
            C::ApplySignature { contract, .. } => ("apply_signature", contract),
            C::Terminate { contract, .. } => ("terminate", contract),
        };
        o.insert("type", Value::String(tag.to_owned()));
        o.insert("contract", id(contract.raw()));
        match self {
            C::Draft {
                proposal,
                version,
                template,
                plan,
                determination,
                parties,
                base,
                ..
            } => {
                o.insert("proposal", id(proposal.raw()));
                o.insert("version", version.to_json());
                o.insert("template", template.to_json());
                o.insert("plan", id(plan.raw()));
                o.insert("determination", id(determination.raw()));
                let mut a = Array::new();
                for p in parties {
                    a.push(party_json(p));
                }
                o.insert("parties", Value::Array(a));
                o.insert("base", base.to_json());
            }
            C::ProposeChange {
                version,
                clause,
                diff,
                proposer,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("clause", clause.to_json());
                o.insert("diff", diff.to_json());
                o.insert("proposer", Value::String(side_name(*proposer).to_owned()));
            }
            C::DecideChange {
                version,
                clause,
                accept,
                base,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("clause", clause.to_json());
                o.insert("accept", Value::Bool(*accept));
                o.insert("base", opt_digest_json(*base));
            }
            C::Send {
                version, revision0, ..
            } => {
                o.insert("version", version.to_json());
                o.insert("revision0", revision0.to_json());
            }
            C::ApproveAdvanced {
                version,
                party,
                reason,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("party", Value::String(party.clone()));
                o.insert("reason", reason.to_json());
            }
            C::ApplySignature {
                version,
                party,
                route,
                base_revision,
                revision,
                signer_certificate,
                report,
                ..
            } => {
                o.insert("version", version.to_json());
                o.insert("party", Value::String(party.clone()));
                o.insert("route", Value::String(route_name(*route).to_owned()));
                o.insert("base_revision", base_revision.to_json());
                o.insert("revision", revision.to_json());
                o.insert("signer_certificate", signer_certificate.to_json());
                o.insert("report", report.to_json());
            }
            C::Terminate {
                reason,
                sealed_draft,
                ..
            } => {
                o.insert("reason", reason.to_json());
                o.insert("sealed_draft", opt_digest_json(*sealed_draft));
            }
        }
        Value::Object(o)
    }
}
