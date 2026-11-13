//! The message catalogue of the vault origin's server-rendered documents
//! (R-NF-04). Every text a person reads on the release and bank details
//! documents comes from here, so a translation replaces this catalogue
//! and no renderer. English is the only locale so far.

/// The texts of the vault's documents in one locale.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Messages {
    /// The `lang` attribute of a document in this locale.
    pub lang: &'static str,
    /// An answer of yes.
    pub yes: &'static str,
    /// An answer of no.
    pub no: &'static str,
    /// The title and heading of the identity release document.
    pub release_title: &'static str,
    /// The row label of the subject's account id.
    pub account: &'static str,
    /// The row label of the proposal id.
    pub proposal: &'static str,
    /// The row label of whether the subject or the bank details are
    /// verified.
    pub verified: &'static str,
    /// The row label of a stated country, before the programme id.
    pub country_for_programme: &'static str,
    /// The title and heading of the bank details document.
    pub bank_title: &'static str,
    /// The row label of the grant id.
    pub grant: &'static str,
    /// The row label of the account holder.
    pub holder: &'static str,
    /// The row label of the IBAN.
    pub iban: &'static str,
    /// The row label of the bank details version.
    pub version: &'static str,
    /// The row label of when the bank details were written.
    pub written_at: &'static str,
    /// The row label shown when no bank details exist.
    pub bank_details: &'static str,
    /// The value shown when no bank details exist.
    pub none_entered: &'static str,
    /// The row label of whether a dispute is open.
    pub dispute_open: &'static str,
}

/// The English catalogue.
pub(crate) const EN: Messages = Messages {
    lang: "en",
    yes: "yes",
    no: "no",
    release_title: "Identity release",
    account: "Account",
    proposal: "Proposal",
    verified: "Verified",
    country_for_programme: "Country stated for programme",
    bank_title: "Bank details",
    grant: "Grant",
    holder: "Account holder",
    iban: "IBAN",
    version: "Version",
    written_at: "Written at (UTC microseconds)",
    bank_details: "Bank details",
    none_entered: "none entered",
    dispute_open: "Dispute open",
};

impl Messages {
    /// The answer for `b`.
    pub(crate) fn yes_no(&self, b: bool) -> &'static str {
        if b { self.yes } else { self.no }
    }
}
