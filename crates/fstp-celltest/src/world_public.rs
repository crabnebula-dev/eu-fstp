//! The public texts and the public identity of a world cell (lane
//! m4/cellpub). Test only.
//!
//! The cell text store has no public class yet (`fstp_cell::public`), so
//! a production cell shows no open call on its public pages. A world cell
//! passes [`WorldPublic`] through `fstp_cell::process::StartOptions`
//! instead. The cycle's `publish-call` marks the texts of the call it
//! published as public here: the call title and the P-09 wording of its
//! frozen policy. Claims built on a world cell's public pages say so.
//!
//! Each cell holds its own [`WorldPublic`], so no text of one cell can
//! reach another cell's view through it (TH-06).
//!
//! A test may also name the programme a cell's cycle creates and the
//! first id of its calls ([`WorldPublic::set_identity`]), so two cells of
//! one world publish distinct programmes and calls (`i87_two_cells_never_cross`).
//! Every text is synthetic.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, PoisonError};

use fstp_cell::public::{PublicTextFuture, PublicTextSource};
use fstp_domain::id::TextId;

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

#[derive(Debug, Default)]
struct Inner {
    texts: BTreeMap<TextId, String>,
    identity: Option<WorldIdentity>,
}

/// The public texts and identity of one world cell (module documentation).
/// Cloning gives another handle on the same cell's texts.
#[derive(Clone, Debug, Default)]
pub struct WorldPublic(Arc<Mutex<Inner>>);

impl WorldPublic {
    fn inner(&self) -> std::sync::MutexGuard<'_, Inner> {
        self.0.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Marks `text` public as text `id` of this cell, replacing any
    /// earlier text under that id.
    pub fn publish(&self, id: TextId, text: &str) {
        let _ = self.inner().texts.insert(id, text.to_owned());
    }

    /// The public text `id` of this cell.
    pub fn text(&self, id: TextId) -> Option<String> {
        self.inner().texts.get(&id).cloned()
    }

    /// Names the programme and the first call id of the cell's next
    /// `create-programme` and `publish-call` steps.
    pub fn set_identity(&self, identity: WorldIdentity) {
        self.inner().identity = Some(identity);
    }

    /// The identity a test named, if any.
    pub fn identity(&self) -> Option<WorldIdentity> {
        self.inner().identity.clone()
    }
}

impl PublicTextSource for WorldPublic {
    fn get_public(&self, id: TextId) -> PublicTextFuture<'_> {
        let text = self.text(id);
        Box::pin(std::future::ready(text))
    }
}
