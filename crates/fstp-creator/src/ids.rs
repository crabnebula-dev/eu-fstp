//! Identifiers the creator names (M4 design section 3.2).
//!
//! The shell draws every id and passes it in the command, as the M2 core
//! does. In JSON each id is a decimal string.
//!
//! Interim, pending Daniel: the design names these ids without a home
//! crate. The creator cannot depend on `fstp-import` (rule A3), so the
//! import ids live here as the creator's references to import documents
//! and proposals. The engine bridge maps them to the import store's ids.

macro_rules! id {
    ($($(#[$doc:meta])* $n:ident),* $(,)?) => { $(
        $(#[$doc])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $n(u128);

        impl $n {
            /// The id with raw value `r`, as drawn by the shell.
            pub const fn from_raw(r: u128) -> Self {
                Self(r)
            }

            /// The raw value.
            pub const fn raw(self) -> u128 {
                self.0
            }
        }
    )* };
}

id!(
    /// An invitation of creator step 9.
    InvitationId,
    /// A programme template: shipped, or private to the tenant (Q17).
    TemplateId,
    /// An uploaded source document of an import start.
    ImportDocumentId,
    /// One proposed value of an import.
    ImportProposalId,
);
