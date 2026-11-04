//! The server-rendered sign-up and agreement forms (TH-46, R-TN-01, Q22;
//! M4 design sections 1.1, 2.2 J0 and 3.5).
//!
//! Both pages go through the escaping writer of `fstp-html`, so nothing
//! is inserted raw (I-68). Every interface string is a catalogue
//! [`Label`], and every agreement text is [`ApprovedText`] that no
//! terminology override reaches (I-72).
//!
//! Each form names exactly the fields its decoder demands, so a browser
//! submission decodes:
//!
//! - a hidden `form` selector, `signup` or `agreements`;
//! - for sign-up, `legal_name` and `contracting_signatory` as text
//!   inputs and `billing_address` as the only `textarea`, because only it
//!   may hold line breaks;
//! - for the agreements, a hidden `tenant`, one required checkbox per
//!   agreement whose value is the offered version, and `accepted_by`;
//! - a submit button with no name, so it adds no field.
//!
//! Both forms post to [`SIGNUP_ACTION`] as
//! `application/x-www-form-urlencoded`.
//!
//! TODO(legal): the agreement texts are pending. Each renders as a
//! placeholder message in [`SIGNUP_MESSAGES`] until Daniel supplies the
//! SaaS terms, the data processing agreement and the sub-processor list.
//! The English interface strings are an interim reading, pending Daniel.

use fstp_html::{
    ApprovedText, CatalogueSource, Catalogues, Document, Element, EntrySource, HtmlDocument,
    HtmlError, Label, MessageKind, Node, SafeUrl,
};

use crate::form::{
    ACCEPTED_BY, AGREEMENTS, BILLING_ADDRESS, CONTRACTING_SIGNATORY, FORM, LEGAL_NAME, SIGNUP,
    TENANT,
};
use crate::text::id_hex;
use crate::types::{Agreement, AgreementVersions, TenantId};

/// The path both forms post to (M4 design section 2.2, J0).
pub const SIGNUP_ACTION: &str = "/signup";

/// The locale of [`SIGNUP_MESSAGES`].
pub const SIGNUP_LOCALE: &str = "en";

/// The form encoding both forms declare.
const ENCTYPE: &str = "application/x-www-form-urlencoded";

const fn label(id: &'static str, message: &'static str) -> EntrySource<'static> {
    EntrySource {
        id,
        kind: MessageKind::Label,
        message,
    }
}

const fn approved(id: &'static str, message: &'static str) -> EntrySource<'static> {
    EntrySource {
        id,
        kind: MessageKind::Approved,
        message,
    }
}

const TITLE_SIGNUP: &str = "signup.title";
const LABEL_LEGAL_NAME: &str = "signup.legal_name";
const LABEL_BILLING_ADDRESS: &str = "signup.billing_address";
const LABEL_SIGNATORY: &str = "signup.contracting_signatory";
const SUBMIT_SIGNUP: &str = "signup.submit";
const TITLE_AGREEMENTS: &str = "agreements.title";
const LABEL_ACCEPT_VERSION: &str = "agreements.accept_version";
const LABEL_ACCEPTED_BY: &str = "agreements.accepted_by";
const SUBMIT_AGREEMENTS: &str = "agreements.submit";

/// The message ids of one agreement: its heading label and its text.
const fn agreement_ids(a: Agreement) -> (&'static str, &'static str) {
    match a {
        Agreement::SaasTerms => ("agreements.saas_terms", "agreements.text.saas_terms"),
        Agreement::Dpa => ("agreements.dpa", "agreements.text.dpa"),
        Agreement::SubProcessors => (
            "agreements.sub_processors",
            "agreements.text.sub_processors",
        ),
    }
}

/// The English catalogue entries of both forms. A shell that renders in
/// more locales supplies the same ids with the same kinds.
pub const SIGNUP_MESSAGES: &[EntrySource<'static>] = &[
    label(TITLE_SIGNUP, "Sign up your organisation"),
    label(LABEL_LEGAL_NAME, "Legal name of the organisation"),
    label(LABEL_BILLING_ADDRESS, "Billing address"),
    label(LABEL_SIGNATORY, "Contracting signatory"),
    label(SUBMIT_SIGNUP, "Sign up"),
    label(TITLE_AGREEMENTS, "Agreements"),
    label("agreements.saas_terms", "SaaS terms"),
    label("agreements.dpa", "Data processing agreement"),
    label("agreements.sub_processors", "Sub-processor list"),
    label(LABEL_ACCEPT_VERSION, "Accept version {version}"),
    label(LABEL_ACCEPTED_BY, "Name of the person who accepts"),
    label(SUBMIT_AGREEMENTS, "Accept the agreements"),
    approved(
        "agreements.text.saas_terms",
        "TODO(legal): the text of the SaaS terms is pending.",
    ),
    approved(
        "agreements.text.dpa",
        "TODO(legal): the text of the data processing agreement is pending.",
    ),
    approved(
        "agreements.text.sub_processors",
        "TODO(legal): the sub-processor list is pending.",
    ),
];

/// The catalogue set of [`SIGNUP_MESSAGES`] in [`SIGNUP_LOCALE`] alone.
pub fn signup_catalogues() -> Result<Catalogues, HtmlError> {
    Catalogues::new(
        &CatalogueSource {
            locale: SIGNUP_LOCALE,
            entries: SIGNUP_MESSAGES,
        },
        &[],
    )
}

fn hidden(name: &'static str, value: &str) -> Element {
    Element::new("input")
        .attr("type", "hidden")
        .attr("name", name)
        .attr("value", value)
}

/// A labelled single-line text input.
fn text_row(id: &'static str, name: &'static str, label_id: &str, autocomplete: &str) -> Element {
    Element::new("div")
        .child(
            Element::new("label")
                .attr("for", id)
                .label(&Label::new(label_id), &[]),
        )
        .child(
            Element::new("input")
                .attr("type", "text")
                .attr("id", id)
                .attr("name", name)
                .attr("autocomplete", autocomplete)
                .flag("required"),
        )
}

fn form_element() -> Result<Element, HtmlError> {
    Ok(Element::new("form")
        .attr_url("action", SafeUrl::new(SIGNUP_ACTION)?)
        .attr("method", "post")
        .attr("enctype", ENCTYPE))
}

fn submit(label_id: &str) -> Element {
    Element::new("button")
        .attr("type", "submit")
        .label(&Label::new(label_id), &[])
}

fn page(locale: &str, title_id: &str, form: Element) -> Document {
    let title = Label::new(title_id);
    Document::new(locale).title(Node::label(&title, &[])).body(
        Element::new("main")
            .child(Element::new("h1").label(&title, &[]))
            .child(form),
    )
}

/// The sign-up page in `locale`, before rendering. The shell may add a
/// stylesheet to it.
pub fn signup_form_page(locale: &str) -> Result<Document, HtmlError> {
    let form = form_element()?
        .child(hidden(FORM, SIGNUP))
        .child(text_row(
            "signup-legal-name",
            LEGAL_NAME,
            LABEL_LEGAL_NAME,
            "organization",
        ))
        .child(
            Element::new("div")
                .child(
                    Element::new("label")
                        .attr("for", "signup-billing-address")
                        .label(&Label::new(LABEL_BILLING_ADDRESS), &[]),
                )
                .child(
                    Element::new("textarea")
                        .attr("id", "signup-billing-address")
                        .attr("name", BILLING_ADDRESS)
                        .attr("rows", "4")
                        .flag("required"),
                ),
        )
        .child(text_row(
            "signup-contracting-signatory",
            CONTRACTING_SIGNATORY,
            LABEL_SIGNATORY,
            "name",
        ))
        .child(submit(SUBMIT_SIGNUP));
    Ok(page(locale, TITLE_SIGNUP, form))
}

/// The agreement page of `tenant` in `locale`, before rendering.
/// `offered` is the current offer, [`crate::SignupState::offered`]. Each
/// agreement shows its `TODO(legal)` placeholder text and a required
/// checkbox whose value is the offered version.
pub fn agreement_form_page(
    locale: &str,
    tenant: TenantId,
    offered: AgreementVersions,
) -> Result<Document, HtmlError> {
    let mut form = form_element()?
        .child(hidden(FORM, AGREEMENTS))
        .child(hidden(TENANT, &id_hex(tenant.raw())));
    for (agreement, version) in offered.pairs() {
        let (heading_id, text_id) = agreement_ids(agreement);
        let name = agreement.name();
        let version = version.to_string();
        let id = match agreement {
            Agreement::SaasTerms => "agreements-saas-terms",
            Agreement::Dpa => "agreements-dpa",
            Agreement::SubProcessors => "agreements-sub-processors",
        };
        form.push_child(
            Element::new("fieldset")
                .child(Element::new("legend").label(&Label::new(heading_id), &[]))
                .child(
                    Element::new("div")
                        .attr("class", "agreement-text")
                        .approved(&ApprovedText::new(text_id), &[]),
                )
                .child(
                    Element::new("div")
                        .child(
                            Element::new("input")
                                .attr("type", "checkbox")
                                .attr("id", id)
                                .attr("name", name)
                                .attr("value", &version)
                                .flag("required"),
                        )
                        .child(Element::new("label").attr("for", id).label(
                            &Label::new(LABEL_ACCEPT_VERSION),
                            &[("version", version.as_str())],
                        )),
                ),
        );
    }
    let form = form
        .child(text_row(
            "agreements-accepted-by",
            ACCEPTED_BY,
            LABEL_ACCEPTED_BY,
            "name",
        ))
        .child(submit(SUBMIT_AGREEMENTS));
    Ok(page(locale, TITLE_AGREEMENTS, form))
}

/// Renders the sign-up form with `cats`, which must hold the ids of
/// [`SIGNUP_MESSAGES`] in `locale`.
pub fn render_signup_form(cats: &Catalogues, locale: &str) -> Result<HtmlDocument, HtmlError> {
    signup_form_page(locale)?.render(cats)
}

/// Renders the agreement form of `tenant` for the `offered` versions
/// with `cats`, which must hold the ids of [`SIGNUP_MESSAGES`] in
/// `locale`.
pub fn render_agreement_form(
    cats: &Catalogues,
    locale: &str,
    tenant: TenantId,
    offered: AgreementVersions,
) -> Result<HtmlDocument, HtmlError> {
    agreement_form_page(locale, tenant, offered)?.render(cats)
}
