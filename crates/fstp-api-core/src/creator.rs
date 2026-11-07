//! The creator, bridge and import operations of journey J1: their strict
//! request forms, the commands they build and their read models (M4
//! design sections 2.2, 3.2, 3.3 and 3.7; lane m4wire).
//!
//! A request is one JSON object of the route's path parameters and the
//! body members, as for every other operation (`forms.rs`). [`check`] is
//! the strict decoder: unknown and missing members are refused, and every
//! value is judged by a trial build through the creator command codec, so
//! a field value decodes only with its field's strict decoder and an
//! amount only as an ADR-006 string. [`build`] turns a checked request
//! into the engine command, with the values only the server supplies.
//!
//! # Request forms
//!
//! Ids the server draws are never request members: the programme and its
//! first policy version of `creator.open_draft`, the invitation, the
//! decision of an approval, the tenant template and the import document.
//!
//! - `creator.open_draft`: `{}`. The draft starts under the default
//!   funder profile, Horizon Europe version 1 (P-53).
//! - `creator.apply_start`: `{base, start}`, where `start` is `{kind:
//!   "blank"}`, `{kind: "template", template, version}`, `{kind: "clone",
//!   source}` or `{kind: "import", document}`.
//! - `creator.save_fields`: `{base, fields: [{field, value}]}`, one edit
//!   per field and at least one. `field` is the `<step>.<member>` key and
//!   `value` the spec JSON. The server takes the value's canonical RFC
//!   8785 text and its SHA-256 through `fstp-crypto` as the value digest.
//! - `creator.accept_narrative`: `{base}`, with the field key in the route.
//! - `creator.invite`: `{email, role, organisation?}`. The role is a wire
//!   name of `fstp_access::INVITED_ROLES`. The email is stored in the text
//!   store, and the command carries its reference only (ADR-007).
//! - `creator.withdraw_invitation` and `creator.save_as_template`: `{}`.
//! - `creator.acknowledge`: `{revision, warning}`, where `warning` is the
//!   `key` of a report row.
//! - `creator.request_activation` and `creator.approve_activation`:
//!   `{revision}`.
//! - `import.upload`: `{media, text}`, with `media` `text/plain` or
//!   `text/markdown` (Q24).
//! - `import.resolve`: `{base, conflict_acknowledged, resolution, shown}`,
//!   where `resolution` is `{kind: "confirm", value}`, `{kind: "edit",
//!   value}` or `{kind: "dismiss"}`, and `shown` the listed digest.
//!
//! A revision travels as the opaque string `"<seq>.<entry>"` of two
//! canonical decimals: the draft's revision count and the ledger entry
//! that made it.
//!
//! # Interim readings, pending Daniel (design section 15.0)
//!
//! - The default funder profile of a new draft is the only M4 profile.
//! - An invitation's email is confidential text owned by the programme.
//! - A warning key is the canonical JSON text of the creator codec's key
//!   form, so it names its check and subject exactly.
//! - The shipped template catalogue is a copy of
//!   `fstp_programme::shipped_templates`, which this crate cannot name. A
//!   test of `fstp-api-testkit` checks the copy against the source.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use fstp_access::{BridgeKind, CreatorKind, ImportKind, OpKind, OpSpec};
use fstp_creator::{
    CheckDetail, CheckResult, CheckSubject, CreatorCommand, DraftRevision, InvitationId, Invitee,
    Severity, StartingPoint, TemplateId, ValidationReport,
};
use fstp_domain::id::{
    AccountId, DecisionId, OrganisationId, PolicyVersionId, ProgrammeId, TextRef,
};
use fstp_domain::policy::{FunderProfileRef, OpaqueValue};
use fstp_domain::roles::Role;
use fstp_engine::{BridgeCommand, Command};
use fstp_import::{
    AccountRef, BlobAddress, ClientResolution, ImportCommand, ImportDocument, ImportDocumentId,
    ImportLimits, ImportMedia, ImportProposalId, ProgrammeRef, SaltedDigest, TextDigest,
    UntrustedValue, ValueDigest,
};
use fstp_json::{FromJson, Object, ToJson, Value};
use fstp_ledger::Seq;

use crate::ApiError;
use crate::forms::{REQUEST_RULE, canonical_id};

/// The most field edits one save may carry.
pub(crate) const MAX_EDITS: usize = 256;

/// The longest invitation email, in bytes (RFC 5321 path limit).
const MAX_EMAIL: usize = 254;

/// The previews of journey J1, as the route segment names them.
pub(crate) const PREVIEWS: [&str; 3] = ["guide", "public", "contract"];

/// The shipped template catalogue: id, version and name, as
/// `fstp_programme::shipped_templates` holds it (module documentation).
pub(crate) const SHIPPED_TEMPLATES: &[(u128, u32, &str)] = &[(1, 1, "SuperSAFE")];

/// One creator, bridge or import operation that a person sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Form {
    /// `creator.open_draft`.
    OpenDraft,
    /// `creator.apply_start`.
    ApplyStart,
    /// `creator.save_fields`.
    SaveFields,
    /// `creator.accept_narrative`.
    AcceptNarrative,
    /// `creator.invite`.
    Invite,
    /// `creator.withdraw_invitation`.
    Withdraw,
    /// `creator.acknowledge`.
    Acknowledge,
    /// `creator.request_activation`.
    RequestActivation,
    /// `creator.approve_activation`.
    ApproveActivation,
    /// `creator.save_as_template`.
    SaveAsTemplate,
    /// `import.upload`.
    Upload,
    /// `import.resolve`.
    Resolve,
}

/// The form of an operation, or `None` for an operation of another kind
/// or one no person sends (`ImportCommand::RecordProposals`).
pub(crate) fn form_of(spec: &OpSpec) -> Option<Form> {
    let f = match spec.kind {
        OpKind::Creator(k) => match k {
            CreatorKind::OpenDraft => Form::OpenDraft,
            CreatorKind::ApplyStart => Form::ApplyStart,
            CreatorKind::SaveFields => Form::SaveFields,
            CreatorKind::AcceptNarrative => Form::AcceptNarrative,
            CreatorKind::Invite => Form::Invite,
            CreatorKind::WithdrawInvitation => Form::Withdraw,
            CreatorKind::AcknowledgeWarning => Form::Acknowledge,
            CreatorKind::RequestActivation => Form::RequestActivation,
            CreatorKind::ApproveActivation => Form::ApproveActivation,
            CreatorKind::SaveAsTenantTemplate => Form::SaveAsTemplate,
        },
        OpKind::Bridge(BridgeKind::ResolveImport) => Form::Resolve,
        OpKind::Import(ImportKind::RegisterDocument) => Form::Upload,
        _ => return None,
    };
    Some(f)
}

impl Form {
    /// The body members the client must send, and those it may send.
    const fn members(self) -> (&'static [&'static str], &'static [&'static str]) {
        match self {
            Form::OpenDraft | Form::Withdraw | Form::SaveAsTemplate => (&[], &[]),
            Form::ApplyStart => (&["base", "start"], &[]),
            Form::SaveFields => (&["base", "fields"], &[]),
            Form::AcceptNarrative => (&["base"], &[]),
            Form::Invite => (&["email", "role"], &["organisation"]),
            Form::Acknowledge => (&["revision", "warning"], &[]),
            Form::RequestActivation | Form::ApproveActivation => (&["revision"], &[]),
            Form::Upload => (&["media", "text"], &[]),
            Form::Resolve => (
                &["base", "conflict_acknowledged", "resolution", "shown"],
                &[],
            ),
        }
    }
}

fn bad() -> ApiError {
    ApiError::bad_request(REQUEST_RULE)
}

/// The values only the server supplies to a build. A trial build and the
/// dry run use [`Supplied::placeholder`]. The build that executes uses
/// the stored text and blob.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Supplied {
    /// The acting account.
    pub(crate) actor: AccountId,
    /// The stored invitation email.
    pub(crate) contact: Option<TextRef>,
    /// The stored upload: its blob address and the salted digest of its
    /// normalised text.
    pub(crate) upload: Option<(BlobAddress, TextDigest)>,
    /// The link token of an invitation, drawn once per call so the dry
    /// run and the execution name the same invitation (J2, lane inv).
    pub(crate) link: Option<[u8; 32]>,
}

impl Supplied {
    /// Placeholders that no guard reads: a text reference with id 0 and
    /// the email's digest, and an all-zero blob address and text digest.
    pub(crate) const fn placeholder(actor: AccountId) -> Supplied {
        Supplied {
            actor,
            contact: None,
            upload: None,
            link: None,
        }
    }
}

/// Checks the body of a creator, bridge or import request: exactly the
/// form's members, then a trial build (design section 3.7 step 1).
pub(crate) fn check(spec: &OpSpec, request: &Object, params: &[&str]) -> Result<(), ApiError> {
    let Some(form) = form_of(spec) else {
        // `RecordProposals` has no route, so no request reaches it.
        return Err(bad());
    };
    let (required, optional) = form.members();
    let body: Vec<&str> = request.keys().filter(|k| !params.contains(k)).collect();
    if body
        .iter()
        .any(|m| !required.contains(m) && !optional.contains(m))
        || required.iter().any(|r| !body.contains(r))
    {
        return Err(bad());
    }
    let supplied = Supplied::placeholder(AccountId::from_raw(0));
    build(form, request, &supplied, &mut || Ok(1)).map(|_| ())
}

// ---------------------------------------------------------------------------
// Values
// ---------------------------------------------------------------------------

/// The opaque wire form of a draft revision: `"<seq>.<entry>"`.
pub(crate) fn revision_text(r: DraftRevision) -> String {
    format!("{}.{}", r.seq(), r.entry().raw())
}

/// The revision of its wire form, or `None`.
pub(crate) fn parse_revision(s: &str) -> Option<DraftRevision> {
    let (seq, entry) = s.split_once('.')?;
    let seq = u32::try_from(canonical_id(seq)?).ok()?;
    let entry = u64::try_from(canonical_id(entry)?).ok()?;
    Some(DraftRevision::new(seq, Seq::from_raw(entry)))
}

/// The revision at member `name`.
fn revision_at(request: &Object, name: &str) -> Result<DraftRevision, ApiError> {
    request
        .get(name)
        .and_then(Value::as_str)
        .and_then(parse_revision)
        .ok_or_else(bad)
}

/// The canonical id at member `name`.
fn id_at(o: &Object, name: &str) -> Result<u128, ApiError> {
    o.get(name)
        .and_then(Value::as_str)
        .and_then(canonical_id)
        .ok_or_else(bad)
}

/// The programme of the route.
fn programme(request: &Object) -> Result<ProgrammeId, ApiError> {
    id_at(request, "programme").map(ProgrammeId::from_raw)
}

/// The object `v` with exactly the members `names`.
fn exact<'a>(v: &'a Value, names: &[&str]) -> Result<&'a Object, ApiError> {
    let o = v.as_object().ok_or_else(bad)?;
    if o.len() != names.len() || names.iter().any(|n| !o.contains_key(n)) {
        return Err(bad());
    }
    Ok(o)
}

/// The default funder profile of a new draft: Horizon Europe version 1,
/// as P-53 spells it (`{"profile": ..., "version": 1}`).
pub(crate) fn default_profile() -> Result<FunderProfileRef, ApiError> {
    let mut o = Object::new();
    let _ = o.insert("profile", Value::from(fstp_guide::HORIZON_EUROPE));
    let _ = o.insert("version", Value::from(1u32));
    OpaqueValue::from_value(&Value::Object(o))
        .map(FunderProfileRef)
        .map_err(|_| ApiError::NotImplemented("the default funder profile reference"))
}

/// Lowercase hexadecimal of 32 bytes.
fn hex32(b: [u8; 32]) -> Value {
    Value::String(crate::action::hex(&b))
}

/// The role of a wire name of `fstp_access::INVITED_ROLES`.
fn invited_role(name: &str) -> Option<Role> {
    Role::ALL
        .iter()
        .copied()
        .find(|r| fstp_access::invitable(*r) && fstp_access::role_wire_name(*r) == name)
}

/// Whether `s` is a plausible email address: at most [`MAX_EMAIL`]
/// bytes, one `@` with text on both sides, a dot in the domain, and no
/// whitespace or control character. The invitation link proves it.
fn plausible_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    s.len() <= MAX_EMAIL
        && !local.is_empty()
        && domain.len() > 2
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains('@')
        && !s.chars().any(|c| c.is_whitespace() || c.is_control())
}

/// The canonical RFC 8785 text of a field value, and its SHA-256: the
/// value digest of a save (design 3.2 `FieldEdit`).
fn value_text(v: &Value) -> Result<(String, [u8; 32]), ApiError> {
    let text = fstp_json::to_canonical(v).map_err(|_| bad())?;
    let digest = fstp_crypto::sha256(text.as_bytes());
    Ok((text, digest))
}

/// A tagged JSON object of the creator codec.
fn tagged(kind: &str, members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    let _ = o.insert("kind", Value::from(kind));
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

/// The codec form of a revision.
fn put_revision(r: DraftRevision) -> Value {
    let mut o = Object::new();
    let _ = o.insert("seq", Value::String(r.seq().to_string()));
    let _ = o.insert("entry", Value::String(r.entry().raw().to_string()));
    Value::Object(o)
}

/// Decodes a creator command of the codec form. A form the codec refuses
/// is a bad request: an unknown field, a value its field's strict decoder
/// refuses, or a value that is not canonical.
fn decode(v: &Value) -> Result<CreatorCommand, ApiError> {
    CreatorCommand::from_json(v).map_err(|_| bad())
}

// ---------------------------------------------------------------------------
// Builds
// ---------------------------------------------------------------------------

/// Builds the engine command of a checked request (module documentation).
/// `draw` draws a fresh id.
pub(crate) fn build(
    form: Form,
    request: &Object,
    supplied: &Supplied,
    draw: &mut dyn FnMut() -> Result<u128, ApiError>,
) -> Result<Command, ApiError> {
    let creator = |c: CreatorCommand| Ok(Command::Creator(c));
    match form {
        Form::OpenDraft => {
            let programme = ProgrammeId::from_raw(draw()?);
            let version = PolicyVersionId::from_raw(draw()?);
            creator(CreatorCommand::OpenDraft {
                programme,
                version,
                profile: default_profile()?,
            })
        }
        Form::ApplyStart => creator(CreatorCommand::ApplyStart {
            programme: programme(request)?,
            base: revision_at(request, "base")?,
            start: start(request.get("start").ok_or_else(bad)?)?,
        }),
        Form::SaveFields => save_fields(request).and_then(creator),
        Form::AcceptNarrative => {
            let field = request
                .get("field")
                .and_then(Value::as_str)
                .ok_or_else(bad)?;
            let v = tagged(
                "AcceptNarrative",
                vec![
                    (
                        "programme",
                        Value::String(programme(request)?.raw().to_string()),
                    ),
                    ("base", put_revision(revision_at(request, "base")?)),
                    ("field", Value::from(field)),
                ],
            );
            decode(&v).and_then(creator)
        }
        Form::Invite => invite(request, supplied, draw).and_then(creator),
        Form::Withdraw => creator(CreatorCommand::WithdrawInvitation {
            programme: programme(request)?,
            invitation: InvitationId::from_raw(id_at(request, "invitation")?),
        }),
        Form::Acknowledge => {
            let key = request
                .get("warning")
                .and_then(Value::as_str)
                .ok_or_else(bad)?;
            let parsed = fstp_json::parse(key.as_bytes()).map_err(|_| bad())?;
            if fstp_json::to_canonical(&parsed).ok().as_deref() != Some(key) {
                return Err(bad());
            }
            let v = tagged(
                "AcknowledgeWarning",
                vec![
                    (
                        "programme",
                        Value::String(programme(request)?.raw().to_string()),
                    ),
                    ("revision", put_revision(revision_at(request, "revision")?)),
                    ("warning", parsed),
                ],
            );
            decode(&v).and_then(creator)
        }
        Form::RequestActivation => creator(CreatorCommand::RequestActivation {
            programme: programme(request)?,
            revision: revision_at(request, "revision")?,
        }),
        Form::ApproveActivation => {
            let programme = programme(request)?;
            let revision = revision_at(request, "revision")?;
            creator(CreatorCommand::ApproveActivation {
                programme,
                revision,
                decision: DecisionId::from_raw(draw()?),
            })
        }
        Form::SaveAsTemplate => {
            let programme = programme(request)?;
            creator(CreatorCommand::SaveAsTenantTemplate {
                programme,
                template: TemplateId::from_raw(draw()?),
            })
        }
        Form::Upload => upload(request, supplied, draw),
        Form::Resolve => resolve(request),
    }
}

/// The starting point of `creator.apply_start`.
fn start(v: &Value) -> Result<StartingPoint, ApiError> {
    let kind = v
        .as_object()
        .and_then(|o| o.get("kind"))
        .and_then(Value::as_str)
        .ok_or_else(bad)?;
    match kind {
        "blank" => {
            exact(v, &["kind"])?;
            Ok(StartingPoint::Blank {
                profile: default_profile()?,
            })
        }
        "template" => {
            let o = exact(v, &["kind", "template", "version"])?;
            let version = o
                .get("version")
                .and_then(Value::as_number)
                .and_then(|n| n.as_u64())
                .and_then(|n| u32::try_from(n).ok())
                .filter(|n| *n >= 1)
                .ok_or_else(bad)?;
            Ok(StartingPoint::Template {
                template: TemplateId::from_raw(id_at(o, "template")?),
                version,
            })
        }
        "clone" => {
            let o = exact(v, &["kind", "source"])?;
            Ok(StartingPoint::Clone {
                source: ProgrammeId::from_raw(id_at(o, "source")?),
            })
        }
        "import" => {
            let o = exact(v, &["kind", "document"])?;
            Ok(StartingPoint::Import {
                document: fstp_creator::ImportDocumentId::from_raw(id_at(o, "document")?),
            })
        }
        _ => Err(bad()),
    }
}

/// The `SaveFields` of `creator.save_fields`: one manual edit per field,
/// each with its value's canonical text and the SHA-256 of that text.
fn save_fields(request: &Object) -> Result<CreatorCommand, ApiError> {
    let fields = request
        .get("fields")
        .and_then(Value::as_array)
        .ok_or_else(bad)?;
    if fields.is_empty() || fields.len() > MAX_EDITS {
        return Err(bad());
    }
    let mut seen = BTreeSet::new();
    let mut edits = Vec::with_capacity(fields.len());
    for f in fields.iter() {
        let o = exact(f, &["field", "value"])?;
        let key = o.get("field").and_then(Value::as_str).ok_or_else(bad)?;
        if !seen.insert(key.to_owned()) {
            return Err(bad());
        }
        let (text, digest) = value_text(o.get("value").ok_or_else(bad)?)?;
        let mut e = Object::new();
        let _ = e.insert("field", Value::from(key));
        let _ = e.insert("value", Value::String(text));
        let _ = e.insert("digest", hex32(digest));
        let _ = e.insert("provenance", tagged("Manual", Vec::new()));
        edits.push(Value::Object(e));
    }
    let v = tagged(
        "SaveFields",
        vec![
            (
                "programme",
                Value::String(programme(request)?.raw().to_string()),
            ),
            ("base", put_revision(revision_at(request, "base")?)),
            ("fields", Value::Array(edits.into_iter().collect())),
        ],
    );
    decode(&v)
}

/// The `Invite` of `creator.invite`: a drawn invitation for the email as
/// a pending invitee, whose contact is a text reference (ADR-007).
fn invite(
    request: &Object,
    supplied: &Supplied,
    draw: &mut dyn FnMut() -> Result<u128, ApiError>,
) -> Result<CreatorCommand, ApiError> {
    let programme = programme(request)?;
    let email = request
        .get("email")
        .and_then(Value::as_str)
        .filter(|s| plausible_email(s))
        .ok_or_else(bad)?;
    let role = request
        .get("role")
        .and_then(Value::as_str)
        .and_then(invited_role)
        .ok_or_else(bad)?;
    let organisation = match request.get("organisation") {
        None | Some(Value::Null) => None,
        Some(Value::String(s)) => Some(OrganisationId::from_raw(canonical_id(s).ok_or_else(bad)?)),
        Some(_) => return Err(bad()),
    };
    let contact = supplied
        .contact
        .unwrap_or_else(|| crate::forms::text_ref(0, email));
    Ok(CreatorCommand::Invite {
        programme,
        invitation: match supplied.link {
            Some(t) => link_invitation(&crate::action::hex(&t)),
            None => InvitationId::from_raw(draw()?),
        },
        role,
        invitee: Invitee::Pending { contact },
        organisation,
    })
}

/// The label of the link token digest (ADR-007 `SecretDigest`, J2).
const LINK_LABEL: &[u8] = b"fstp:j2:invitation-link:v1:";

/// The invitation a link token names (J2, ADR-007, lane inv): the first
/// 16 bytes of the labelled SHA-256 of the token in its link spelling.
///
/// Interim, pending Daniel: the invitation id is the token's digest, so
/// the ledger holds the digest of the drawn token and never the token.
/// No record shape changes, and a restarted core finds the invitation by
/// its token. A token is 256 random bits, so the 128-bit digest names no
/// other invitation, and the id, which the admin pages show, does not
/// give the token back.
pub(crate) fn link_invitation(token: &str) -> InvitationId {
    let mut text = LINK_LABEL.to_vec();
    text.extend_from_slice(token.as_bytes());
    let digest = fstp_crypto::sha256(&text);
    let mut head = [0u8; 16];
    for (slot, b) in head.iter_mut().zip(digest.iter()) {
        *slot = *b;
    }
    InvitationId::from_raw(u128::from_be_bytes(head))
}

/// The media type of an upload.
fn media(request: &Object) -> Result<ImportMedia, ApiError> {
    request
        .get("media")
        .and_then(Value::as_str)
        .and_then(ImportMedia::from_mime)
        .ok_or_else(bad)
}

/// The normalised text of an upload, under the standard limits (Q24).
pub(crate) fn extracted(request: &Object) -> Result<fstp_import::ExtractedText, ApiError> {
    let text = request
        .get("text")
        .and_then(Value::as_str)
        .ok_or_else(bad)?;
    let limits = ImportLimits::standard().map_err(|_| bad())?;
    fstp_import::normalise(text.as_bytes(), media(request)?, limits).map_err(|_| bad())
}

/// The `RegisterDocument` of `import.upload`.
fn upload(
    request: &Object,
    supplied: &Supplied,
    draw: &mut dyn FnMut() -> Result<u128, ApiError>,
) -> Result<Command, ApiError> {
    let programme = programme(request)?;
    let media = media(request)?;
    let text = extracted(request)?;
    let (blob, digest) = supplied.upload.unwrap_or((
        BlobAddress::from_bytes([0; 32]),
        TextDigest::from_bytes([0; 32]),
    ));
    Ok(Command::Import(ImportCommand::RegisterDocument(
        ImportDocument {
            id: ImportDocumentId::from_raw(draw()?),
            programme: ProgrammeRef::from_raw(programme.raw()),
            blob,
            media,
            digest,
            text_bytes: text.byte_len(),
            uploaded_by: AccountRef::from_raw(supplied.actor.raw()),
        },
    )))
}

/// The `ResolveImport` of `import.resolve`. A confirmed or edited value
/// carries the SHA-256 of its normal text, which the creator's save
/// records as its value digest (I-65).
fn resolve(request: &Object) -> Result<Command, ApiError> {
    let programme = programme(request)?;
    let proposal = ImportProposalId::from_raw(id_at(request, "import_proposal")?);
    let shown = request
        .get("shown")
        .and_then(Value::as_str)
        .and_then(crate::action::from_hex::<32>)
        .map(SaltedDigest::from_bytes)
        .ok_or_else(bad)?;
    let conflict_acknowledged = request
        .get("conflict_acknowledged")
        .and_then(Value::as_bool)
        .ok_or_else(bad)?;
    let r = request.get("resolution").ok_or_else(bad)?;
    let kind = r
        .as_object()
        .and_then(|o| o.get("kind"))
        .and_then(Value::as_str)
        .ok_or_else(bad)?;
    let valued = |r: &Value| -> Result<(UntrustedValue, ValueDigest), ApiError> {
        let o = exact(r, &["kind", "value"])?;
        let value = UntrustedValue::new(o.get("value").ok_or_else(bad)?).map_err(|_| bad())?;
        let digest = ValueDigest::from_bytes(fstp_crypto::sha256(value.as_data().as_bytes()));
        Ok((value, digest))
    };
    let resolution = match kind {
        "confirm" => {
            let (value, digest) = valued(r)?;
            ClientResolution::Confirm { value, digest }
        }
        "edit" => {
            let (value, digest) = valued(r)?;
            ClientResolution::Edit { value, digest }
        }
        "dismiss" => {
            exact(r, &["kind"])?;
            ClientResolution::Dismiss
        }
        _ => return Err(bad()),
    };
    Ok(Command::Bridge(BridgeCommand::ResolveImport {
        programme,
        proposal,
        shown,
        resolution,
        conflict_acknowledged,
        base: revision_at(request, "base")?,
    }))
}

// ---------------------------------------------------------------------------
// Read models
// ---------------------------------------------------------------------------

/// The wire key of a report row: the canonical JSON text of the creator
/// codec's key form (module documentation). An acknowledgement names it.
pub(crate) fn warning_key(programme: ProgrammeId, row: &CheckResult) -> Option<String> {
    let cmd = CreatorCommand::AcknowledgeWarning {
        programme,
        revision: DraftRevision::new(0, Seq::ZERO),
        warning: row.key(),
    };
    let v = cmd.to_json();
    fstp_json::to_canonical(v.get("warning")?).ok()
}

/// One row of a validation report as `web/src/creator/model.ts` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReportRow {
    /// The check's catalogue name.
    pub check: &'static str,
    /// `failure` or `warning`.
    pub severity: &'static str,
    /// Whether a live acknowledgement holds for the row.
    pub acknowledged: bool,
    /// The key an acknowledgement names.
    pub key: String,
    /// The field key the row is about, if any.
    pub field: Option<String>,
    /// What the row says beyond its check: string values only. It never
    /// names an account (R-CF-03).
    pub detail: BTreeMap<&'static str, String>,
}

/// The row of one check result.
pub(crate) fn report_row(
    programme: ProgrammeId,
    r: &CheckResult,
    acknowledged: bool,
) -> Option<ReportRow> {
    let mut detail = BTreeMap::new();
    let mut field = None;
    match &r.subject {
        CheckSubject::Draft => {}
        CheckSubject::Field(f) => field = Some(f.key()),
        CheckSubject::Invitation(i) => {
            let _ = detail.insert("invitation", i.raw().to_string());
        }
        CheckSubject::Probe(p) => {
            let _ = detail.insert("probe", p.name().to_owned());
        }
        CheckSubject::Colour { mode, role } => {
            let _ = detail.insert("colour", format!("{mode:?} {role:?}"));
        }
        CheckSubject::Element(e) => {
            let _ = detail.insert("element", format!("{e:?}"));
        }
        CheckSubject::CallPackage(e) => {
            let _ = detail.insert("element", e.name().to_owned());
        }
        CheckSubject::GuideSection(h) => {
            let _ = detail.insert("section", h.clone());
        }
        CheckSubject::Placeholder(p) => {
            let _ = detail.insert("placeholder", p.clone());
        }
        CheckSubject::FlowDown(o) => {
            let _ = detail.insert("obligation", o.clone());
        }
    }
    match &r.detail {
        CheckDetail::None => {}
        CheckDetail::Cap { p05, p58 } => {
            let _ = detail.insert("p05", p05.clone());
            let _ = detail.insert("p58", p58.clone());
        }
        CheckDetail::Rule(rule) => {
            let _ = detail.insert("rule", crate::dispatch::rule_text(*rule).to_owned());
        }
        CheckDetail::NotChecked => {
            let _ = detail.insert("status", "not_checked".to_owned());
        }
        CheckDetail::Unavailable(why) => {
            let _ = detail.insert("unavailable", (*why).to_owned());
        }
        CheckDetail::Probe(outcome) => {
            let _ = detail.insert("outcome", outcome.name().to_owned());
        }
    }
    Some(ReportRow {
        check: r.check.name(),
        severity: match r.severity {
            Severity::Failure => "failure",
            Severity::Warning => "warning",
        },
        acknowledged,
        key: warning_key(programme, r)?,
        field,
        detail,
    })
}

/// The rows of `report`, with the live acknowledgements `acks`.
pub(crate) fn report_rows(
    report: &ValidationReport,
    acks: &BTreeSet<fstp_creator::WarningKey>,
) -> Result<Vec<ReportRow>, ApiError> {
    report
        .results()
        .iter()
        .map(|r| {
            let acknowledged = r.severity == Severity::Warning && acks.contains(&r.key());
            report_row(report.programme(), r, acknowledged).ok_or(ApiError::NotImplemented(
                "a report row with no canonical key",
            ))
        })
        .collect()
}

/// One invitation of a draft as `web/src/people/model.ts` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvitationRow {
    /// The invitation.
    pub id: InvitationId,
    /// The invited email.
    pub email: String,
    /// The role, as the wire spells it.
    pub role: &'static str,
    /// `invited`, `accepted`, `verified` or `granted`.
    pub state: &'static str,
    /// `pass`, `fail` or `unchecked` (D3).
    pub sod: &'static str,
    /// The rule of a failed check, never an account (R-CF-03).
    pub rule: Option<&'static str>,
}

/// One import proposal as `web/src/creator/model.ts` reads it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProposalView {
    /// The proposal.
    pub id: ImportProposalId,
    /// The field key.
    pub field: String,
    /// The proposed value, as data.
    pub value: Value,
    /// The salted digest of the stored value, which a resolution names.
    pub digest: [u8; 32],
    /// The evidence texts, as data.
    pub evidence: Vec<String>,
    /// Whether the value conflicts with the funder profile.
    pub flagged: bool,
    /// `confirmed`, `edited` or `dismissed`, once resolved.
    pub resolution: Option<&'static str>,
}

/// One row of the approval inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ApprovalRow {
    /// The draft programme whose activation is requested.
    pub programme: ProgrammeId,
    /// The revision of the live request.
    pub revision: DraftRevision,
    /// Whether the viewer may approve it: a tenant admin outside the
    /// builder set (I-67).
    pub approvable: bool,
}

/// One impact row of R-PG-04: a call of the programme and what an edit
/// does to it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImpactRow {
    /// The call.
    pub call: fstp_domain::id::CallId,
}

/// A read model of the creator pages (lane m4wire).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CreatorModel {
    /// `creator.open_draft`: the drawn programme.
    Opened {
        /// The new draft.
        programme: ProgrammeId,
    },
    /// `creator.get_draft`.
    Draft {
        /// The `fstp.programme/1` spec, with `null` for a gap.
        spec: Value,
        /// The draft's revision.
        revision: DraftRevision,
        /// Whether the programme is active.
        active: bool,
        /// Template narrative not yet accepted, by field key (TH-49).
        pending_narratives: BTreeMap<String, String>,
        /// Whether an activation request is live.
        requested: bool,
    },
    /// `creator.get_report`.
    Report {
        /// The revision the report was computed at.
        revision: DraftRevision,
        /// Every row.
        results: Vec<ReportRow>,
    },
    /// `creator.invitations`.
    Invitations(Vec<InvitationRow>),
    /// `import.list`.
    Proposals(Vec<ProposalView>),
    /// `creator.list_programmes`.
    Programmes(Vec<ProgrammeId>),
    /// `creator.list_templates`.
    Templates(Vec<(u128, u32, String)>),
    /// `admin.approvals`.
    Approvals(Vec<ApprovalRow>),
    /// `creator.impact`.
    Impact(Vec<ImpactRow>),
    /// `creator.preview`: one preview of a draft as text blocks, never
    /// markup, from `fstp-guide` and `fstp-public` (R-PG-01, I-51).
    Preview {
        /// The preview kind: `guide` or `public`.
        kind: &'static str,
        /// The blocks, in order.
        blocks: Vec<fstp_guide::PreviewBlock>,
    },
}

/// The kinds of approval `admin.approvals` cannot list, which its reply
/// names as `unlisted` so the inbox never reads as complete.
///
/// Seam, for the lead and lane m4tenant: the pending SoD-07 self-grant
/// approvals live in the tenant envelope, and no port of this crate
/// lists them yet. Once one does, its rows join the reply and
/// `self_grant` leaves this list.
pub(crate) const UNLISTED_APPROVALS: &[&str] = &["self_grant"];

impl CreatorModel {
    /// Whether the model carries an email: the invitation list, whose
    /// rows name each pending invitee's address. It is served to the web
    /// only. The dispatch refuses it through any other channel, and no
    /// MCP tool reaches it (I-86, `model.rs`).
    pub fn carries_email(&self) -> bool {
        matches!(self, CreatorModel::Invitations(_))
    }
}

/// The display name of a programme in the lists: "Programme" and its id.
/// Interim, pending a read of the draft spec's name (lane m4creator).
pub(crate) fn programme_name(p: ProgrammeId) -> String {
    format!("Programme {}", p.raw())
}

fn obj(members: Vec<(&str, Value)>) -> Value {
    let mut o = Object::new();
    for (k, v) in members {
        let _ = o.insert(k, v);
    }
    Value::Object(o)
}

fn dec(x: u128) -> Value {
    Value::String(x.to_string())
}

fn list<T>(items: &[T], f: impl Fn(&T) -> Value) -> Value {
    Value::Array(items.iter().map(f).collect())
}

impl ToJson for CreatorModel {
    fn to_json(&self) -> Value {
        match self {
            CreatorModel::Opened { programme } => obj(vec![
                ("accepted", Value::Bool(true)),
                ("programme", dec(programme.raw())),
            ]),
            CreatorModel::Draft {
                spec,
                revision,
                active,
                pending_narratives,
                requested,
            } => {
                let mut pending = Object::new();
                for (k, v) in pending_narratives {
                    let _ = pending.insert(k.as_str(), Value::from(v.as_str()));
                }
                let mut members = vec![
                    ("spec", spec.clone()),
                    ("revision", Value::String(revision_text(*revision))),
                    (
                        "status",
                        Value::from(if *active { "active" } else { "draft" }),
                    ),
                    ("pending_narratives", Value::Object(pending)),
                ];
                if *requested {
                    members.push(("activation", Value::from("requested")));
                }
                obj(members)
            }
            CreatorModel::Report { revision, results } => obj(vec![
                ("revision", Value::String(revision_text(*revision))),
                (
                    "results",
                    list(results, |r| {
                        let mut detail = Object::new();
                        for (k, v) in &r.detail {
                            let _ = detail.insert(*k, Value::from(v.as_str()));
                        }
                        let mut members = vec![
                            ("check", Value::from(r.check)),
                            ("severity", Value::from(r.severity)),
                            ("acknowledged", Value::Bool(r.acknowledged)),
                            ("key", Value::from(r.key.as_str())),
                            ("field", r.field.as_deref().map_or(Value::Null, Value::from)),
                        ];
                        if !r.detail.is_empty() {
                            members.push(("detail", Value::Object(detail)));
                        }
                        obj(members)
                    }),
                ),
            ]),
            CreatorModel::Invitations(rows) => obj(vec![(
                "invitations",
                list(rows, |r| {
                    let mut members = vec![
                        ("id", dec(r.id.raw())),
                        ("email", Value::from(r.email.as_str())),
                        ("role", Value::from(r.role)),
                        ("state", Value::from(r.state)),
                        ("sod", Value::from(r.sod)),
                    ];
                    if let Some(rule) = r.rule {
                        members.push(("rule", Value::from(rule)));
                    }
                    obj(members)
                }),
            )]),
            CreatorModel::Proposals(rows) => obj(vec![(
                "proposals",
                list(rows, |r| {
                    obj(vec![
                        ("id", dec(r.id.raw())),
                        ("field", Value::from(r.field.as_str())),
                        ("value", r.value.clone()),
                        ("digest", hex32(r.digest)),
                        (
                            "evidence",
                            list(&r.evidence, |e| {
                                obj(vec![("text", Value::from(e.as_str()))])
                            }),
                        ),
                        ("flagged", Value::Bool(r.flagged)),
                        ("resolution", r.resolution.map_or(Value::Null, Value::from)),
                    ])
                }),
            )]),
            CreatorModel::Programmes(ps) => obj(vec![(
                "programmes",
                list(ps, |p| {
                    obj(vec![
                        ("id", dec(p.raw())),
                        ("name", Value::String(programme_name(*p))),
                    ])
                }),
            )]),
            CreatorModel::Templates(ts) => obj(vec![(
                "templates",
                list(ts, |(id, version, name)| {
                    obj(vec![
                        ("id", dec(*id)),
                        ("version", Value::from(*version)),
                        ("name", Value::from(name.as_str())),
                    ])
                }),
            )]),
            CreatorModel::Approvals(rows) => obj(vec![
                (
                    "approvals",
                    list(rows, |r| {
                        obj(vec![
                            ("kind", Value::from("activation")),
                            ("programme", dec(r.programme.raw())),
                            ("revision", Value::String(revision_text(r.revision))),
                            ("approvable", Value::Bool(r.approvable)),
                        ])
                    }),
                ),
                (
                    "unlisted",
                    Value::Array(UNLISTED_APPROVALS.iter().map(|k| Value::from(*k)).collect()),
                ),
            ]),
            CreatorModel::Impact(rows) => obj(vec![(
                "calls",
                list(rows, |r| obj(vec![("call", dec(r.call.raw()))])),
            )]),
            CreatorModel::Preview { kind, blocks } => obj(vec![
                ("kind", Value::from(*kind)),
                (
                    "blocks",
                    list(blocks, |b| {
                        obj(vec![
                            ("kind", Value::from(b.kind.token())),
                            ("text", Value::from(b.text.as_str())),
                        ])
                    }),
                ),
            ]),
        }
    }
}

// ---------------------------------------------------------------------------
// What this core remembers
// ---------------------------------------------------------------------------

/// The most tenant templates [`CreatorMemory`] holds.
const MAX_TEMPLATES: usize = 10_000;

/// The most uploads [`CreatorMemory`] holds the text of.
const MAX_UPLOADS: usize = 256;

/// What this core remembers of the creator operations it executed, in
/// memory only, as `content.rs` does for workspaces.
///
/// - The tenant templates saved through this core. `CreatorState` offers
///   no listing of its templates yet (lane m4creator), so the catalogue
///   lists the ones this core saw saved, each checked against the state.
/// - The normalised text of each upload, for the evidence of its
///   proposals. The text stays with the shell (design 3.3), and the blob
///   store has no read without a clearance yet (`port.rs`). A proposal
///   of a document this core did not take fails its read closed.
#[derive(Debug, Default)]
pub(crate) struct CreatorMemory {
    templates: BTreeSet<TemplateId>,
    uploads: BTreeMap<ImportDocumentId, fstp_import::ExtractedText>,
    /// The ids of `uploads`, in the order this core took them.
    order: VecDeque<ImportDocumentId>,
}

impl CreatorMemory {
    /// Remembers that `template` was saved. A full memory remembers no
    /// new template.
    pub(crate) fn saved(&mut self, template: TemplateId) {
        if self.templates.len() < MAX_TEMPLATES {
            let _ = self.templates.insert(template);
        }
    }

    /// The templates saved through this core.
    pub(crate) fn templates(&self) -> impl Iterator<Item = TemplateId> + '_ {
        self.templates.iter().copied()
    }

    /// Remembers the normalised text of `document`. A full memory drops
    /// the upload it took first. Ids are drawn, not ordered by time, so
    /// the order of taking is kept beside them.
    pub(crate) fn uploaded(
        &mut self,
        document: ImportDocumentId,
        text: fstp_import::ExtractedText,
    ) {
        if self.uploads.insert(document, text).is_some() {
            return;
        }
        self.order.push_back(document);
        while self.uploads.len() > MAX_UPLOADS {
            let Some(oldest) = self.order.pop_front() else {
                break;
            };
            let _ = self.uploads.remove(&oldest);
        }
    }

    /// The normalised text of `document`, if this core took it.
    pub(crate) fn upload(&self, document: ImportDocumentId) -> Option<&fstp_import::ExtractedText> {
        self.uploads.get(&document)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;

    /// R-PG-01, design section 3.7 step 1: a revision travels as two
    /// canonical decimals and reads back to itself. Any other spelling is
    /// refused.
    #[test]
    fn r_pg_01_revision_text_round_trips_and_is_strict() {
        let r = DraftRevision::new(3, Seq::from_raw(17));
        assert_eq!(revision_text(r), "3.17");
        assert_eq!(parse_revision("3.17"), Some(r));
        for bad in [
            "", "3", "3.", ".17", "03.17", "3.017", "3.17.1", "-3.17", "3,17",
        ] {
            assert_eq!(parse_revision(bad), None, "{bad:?}");
        }
    }

    /// R-PG-02, design section 3.3: a full upload memory drops the
    /// upload it took first, not the smallest drawn id. So the most
    /// recent upload keeps its evidence texts.
    #[test]
    fn r_pg_02_upload_memory_drops_the_oldest_upload_first() {
        let text = || {
            fstp_import::normalise(
                b"Synthetic annex",
                ImportMedia::TextPlain,
                ImportLimits::standard().unwrap(),
            )
            .unwrap()
        };
        let mut m = CreatorMemory::default();
        // Drawn ids in descending order, so the smallest id is the newest.
        let ids: Vec<ImportDocumentId> = (0..=MAX_UPLOADS)
            .map(|n| ImportDocumentId::from_raw(10_000 - u128::try_from(n).unwrap()))
            .collect();
        for id in &ids {
            m.uploaded(*id, text());
        }
        assert!(m.upload(ids[0]).is_none(), "the first upload is dropped");
        for id in &ids[1..] {
            assert!(m.upload(*id).is_some(), "{id:?} was dropped");
        }
        // Taking a held document again keeps its place and drops nothing.
        m.uploaded(ids[1], text());
        assert!(ids[1..].iter().all(|id| m.upload(*id).is_some()));
        m.uploaded(ImportDocumentId::from_raw(1), text());
        assert!(m.upload(ids[1]).is_none());
        assert!(m.upload(ImportDocumentId::from_raw(1)).is_some());
    }

    /// SoD-09, design section 3.2 step 9: the invitation form names the
    /// invitable roles by their wire names, and no other role.
    #[test]
    fn sod09_invited_roles_decode_by_wire_name_only() {
        for name in fstp_access::INVITED_ROLES {
            let r = invited_role(name).unwrap_or_else(|| panic!("{name}"));
            assert_eq!(fstp_access::role_wire_name(r), *name);
        }
        for name in [
            "tenant_admin",
            "applicant",
            "guardian",
            "ProgrammeManager",
            "",
        ] {
            assert_eq!(invited_role(name), None, "{name}");
        }
    }

    /// I-84, design section 3.7 step 1: an email needs one `@`, a dotted
    /// domain and no whitespace.
    #[test]
    fn i84_invitation_email_is_plausible_only() {
        assert!(plausible_email("m2@e2e.invalid"));
        for bad in [
            "",
            "m2",
            "@e2e.invalid",
            "m2@",
            "m2@invalid",
            "m 2@e2e.invalid",
            "a@b@c.d",
            "m2@.e2e",
            "m2@e2e.",
        ] {
            assert!(!plausible_email(bad), "{bad:?}");
        }
        assert!(!plausible_email(&format!(
            "{}@e2e.invalid",
            "a".repeat(250)
        )));
    }

    /// R-PG-01, I-66: the warning key of a report row is canonical JSON
    /// that the acknowledgement decoder reads back to the same key.
    #[test]
    fn i66_warning_key_reads_back_through_the_acknowledgement() {
        let row = CheckResult {
            check: fstp_creator::CheckId::RosterShort,
            severity: Severity::Warning,
            subject: CheckSubject::Draft,
            detail: CheckDetail::None,
        };
        let key = warning_key(ProgrammeId::from_raw(5), &row).unwrap();
        let mut request = Object::new();
        let _ = request.insert("programme", Value::from("5"));
        let _ = request.insert("revision", Value::from("1.2"));
        let _ = request.insert("warning", Value::from(key.as_str()));
        let s = Supplied::placeholder(AccountId::from_raw(1));
        let cmd = build(Form::Acknowledge, &request, &s, &mut || Ok(1)).unwrap();
        let Command::Creator(CreatorCommand::AcknowledgeWarning {
            warning, revision, ..
        }) = cmd
        else {
            panic!("{cmd:?}");
        };
        assert_eq!(warning, row.key());
        assert_eq!(revision, DraftRevision::new(1, Seq::from_raw(2)));
        let spaced = key.replace(':', ": ");
        let _ = request.insert("warning", Value::from(spaced.as_str()));
        assert!(build(Form::Acknowledge, &request, &s, &mut || Ok(1)).is_err());
    }

    /// R-PG-01, design section 3.9: the read models carry the members the
    /// creator pages read, with ids and revisions as strings.
    #[test]
    fn r_pg_01_creator_read_models_carry_the_page_members() {
        let d = CreatorModel::Draft {
            spec: Value::Object(Object::new()),
            revision: DraftRevision::new(2, Seq::from_raw(9)),
            active: false,
            pending_narratives: BTreeMap::new(),
            requested: true,
        };
        assert_eq!(
            d.to_json().to_canonical().unwrap(),
            r#"{"activation":"requested","pending_narratives":{},"revision":"2.9","spec":{},"status":"draft"}"#
        );
        let o = CreatorModel::Opened {
            programme: ProgrammeId::from_raw(7),
        };
        assert_eq!(
            o.to_json().to_canonical().unwrap(),
            r#"{"accepted":true,"programme":"7"}"#
        );
        let t = CreatorModel::Templates(vec![(1, 1, "SuperSAFE".to_owned())]);
        assert_eq!(
            t.to_json().to_canonical().unwrap(),
            r#"{"templates":[{"id":"1","name":"SuperSAFE","version":1}]}"#
        );
    }
}
