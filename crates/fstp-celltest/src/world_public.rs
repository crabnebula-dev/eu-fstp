//! The public identity of a world cell (lanes m4/cellpub and
//! m4/pubtext). Test only.
//!
//! A world cell makes its texts public as a production cell does: the
//! cycle's `publish-call` stores the call title and the P-09 wording in
//! the cell's own text store before the publication, and the cell copies
//! them into its public text class when the call is published
//! (`fstp_cell::public`). Each cell copies from its own store, so no text
//! of one cell can reach another cell's view (TH-06).
//!
//! A test may name the programme a cell's cycle creates and the first id
//! of its calls ([`WorldPublic::set_identity`]), so two cells of one world
//! publish distinct programmes and calls (`i87_two_cells_never_cross`).
//! Every text is synthetic.

use std::sync::{Arc, Mutex, PoisonError};

/// The public identity a cell's cycle gives its programme and calls.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WorldIdentity {
    /// The programme's public slug, `identity.public_slug`.
    pub slug: String,
    /// The programme name, `identity.name`.
    pub name: String,
    /// The id of the cell's first call. Later calls follow it.
    pub first_call: u128,
}

/// The public identity of one world cell (module documentation). Cloning
/// gives another handle on the same cell's identity.
#[derive(Clone, Debug, Default)]
pub struct WorldPublic(Arc<Mutex<Option<WorldIdentity>>>);

impl WorldPublic {
    /// Names the programme and the first call id of the cell's next
    /// `create-programme` and `publish-call` steps.
    pub fn set_identity(&self, identity: WorldIdentity) {
        *self.0.lock().unwrap_or_else(PoisonError::into_inner) = Some(identity);
    }

    /// The identity a test named, if any.
    pub fn identity(&self) -> Option<WorldIdentity> {
        self.0
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clone()
    }
}
