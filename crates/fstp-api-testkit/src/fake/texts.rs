//! The text store, the blob store and the sealer (ADR-004, ADR-007).
//!
//! The fakes keep plain bytes in memory. They hold synthetic text only.
//! The blob store's content address is the fake digest of
//! [`super::vault::fake_digest`], not SHA-256, because the test kit has
//! no hash dependency. The sealer keeps the plaintext beside an opaque
//! handle and never encrypts. Real sealing is M3's (I-74, I-75).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    BlobOwner, BlobRef, BlobStore, PortError, PublicTextRef, ReadClearance, SealOwner, Sealed,
    Sealer, TextClass, TextOwner, TextRef, TextStore,
};

use super::lock;
use super::vault::fake_digest;

/// The largest blob the fake stores: 1 MiB.
pub const BLOB_LIMIT: usize = 1 << 20;

#[derive(Debug, Default)]
struct Texts {
    rows: BTreeMap<u128, (TextClass, TextOwner, Vec<u8>)>,
    next: u128,
}

/// The text store. Cloning shares the texts.
#[derive(Clone, Debug, Default)]
pub struct FakeTexts {
    state: Arc<Mutex<Texts>>,
}

impl FakeTexts {
    /// The bytes behind `r`, read by a test with no clearance.
    pub fn peek(&self, r: TextRef) -> Option<Vec<u8>> {
        lock(&self.state).rows.get(&r.0).map(|(_, _, b)| b.clone())
    }

    /// How many texts are stored.
    pub fn len(&self) -> usize {
        lock(&self.state).rows.len()
    }

    /// Whether no text is stored.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The bytes of every stored text, for a test that scans the store
    /// for a secret (lane inv, the link token).
    pub fn all(&self) -> Vec<Vec<u8>> {
        lock(&self.state)
            .rows
            .values()
            .map(|(_, _, b)| b.clone())
            .collect()
    }

    /// Replaces the texts with a copy of those of `from`, each under its
    /// reference, so a ledger copied from `from`'s cell resolves every
    /// text it names. Every clone of `self` sees the copy.
    pub fn copy_from(&self, from: &FakeTexts) {
        let (rows, next) = {
            let s = lock(&from.state);
            (s.rows.clone(), s.next)
        };
        let mut s = lock(&self.state);
        s.rows = rows;
        s.next = next;
    }

    /// Every public text that is UTF-8, by id: what a published Guide may
    /// read (R-GA-01). No confidential text is ever included.
    pub fn public_texts(&self) -> BTreeMap<fstp_domain::id::TextId, String> {
        lock(&self.state)
            .rows
            .iter()
            .filter(|(_, (class, _, _))| *class == TextClass::Public)
            .filter_map(|(id, (_, _, b))| {
                let s = String::from_utf8(b.clone()).ok()?;
                Some((fstp_domain::id::TextId::from_raw(*id), s))
            })
            .collect()
    }
}

impl FakeTexts {
    /// Stores a text now, as `TextStore::put` does. The import shell,
    /// which is synchronous, stores each proposed value's text here.
    pub fn put_now(&self, class: TextClass, owner: TextOwner, bytes: &[u8]) -> TextRef {
        let mut s = lock(&self.state);
        let n = s.next;
        s.next = n.saturating_add(1);
        s.rows.insert(n, (class, owner, bytes.to_vec()));
        TextRef(n)
    }
}

/// Whether `clearance` releases a text of `class` owned by `owner`. A
/// public text is released to any cleared read. A proposal's text is
/// released only to a read cleared on that proposal, so a clearance of one
/// proposal never opens another's text (decided by Daniel on 2026-11-13).
/// Every other owner is refused until a read needs it.
fn clears(class: TextClass, owner: TextOwner, clearance: &ReadClearance) -> bool {
    match (class, owner, clearance.op().target) {
        (TextClass::Public, _, _) => true,
        (_, TextOwner::Proposal(p), fstp_access::ReadTarget::Proposal(q)) => p == q,
        _ => false,
    }
}

impl TextStore for FakeTexts {
    async fn put(
        &self,
        class: TextClass,
        owner: TextOwner,
        bytes: &[u8],
    ) -> Result<TextRef, PortError> {
        Ok(self.put_now(class, owner, bytes))
    }

    async fn get(&self, r: TextRef, clearance: &ReadClearance) -> Result<Vec<u8>, PortError> {
        match lock(&self.state).rows.get(&r.0) {
            Some((class, owner, b)) if clears(*class, *owner, clearance) => Ok(b.clone()),
            Some(_) | None => Err(PortError::Refused),
        }
    }

    async fn get_public(&self, r: PublicTextRef) -> Result<Vec<u8>, PortError> {
        match lock(&self.state).rows.get(&r.0) {
            Some((TextClass::Public, _, b)) => Ok(b.clone()),
            Some(_) | None => Err(PortError::Refused),
        }
    }
}

/// The stored blobs, by owner and content address.
type Blobs = BTreeMap<(BlobOwner, BlobRef), Vec<u8>>;

/// The blob store. Cloning shares the blobs.
#[derive(Clone, Debug, Default)]
pub struct FakeBlobs {
    rows: Arc<Mutex<Blobs>>,
}

impl FakeBlobs {
    /// The bytes stored under `r` for `owner`, read by the shell or a test
    /// with no clearance.
    pub fn peek(&self, owner: BlobOwner, r: BlobRef) -> Option<Vec<u8>> {
        lock(&self.rows).get(&(owner, r)).cloned()
    }
}

impl BlobStore for FakeBlobs {
    async fn put(&self, owner: BlobOwner, bytes: &[u8]) -> Result<BlobRef, PortError> {
        if bytes.len() > BLOB_LIMIT {
            return Err(PortError::Refused);
        }
        let r = BlobRef(fake_digest(&bytes).bytes());
        lock(&self.rows).insert((owner, r), bytes.to_vec());
        Ok(r)
    }

    async fn get(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        clearance: &ReadClearance,
    ) -> Result<Vec<u8>, PortError> {
        let _ = clearance;
        lock(&self.rows)
            .get(&(owner, r))
            .cloned()
            .ok_or(PortError::Refused)
    }
}

#[derive(Debug, Default)]
struct Seals {
    rows: BTreeMap<Vec<u8>, (SealOwner, Vec<u8>)>,
    next: u128,
}

/// The sealer. Cloning shares the sealed values.
#[derive(Clone, Debug, Default)]
pub struct FakeSealer {
    state: Arc<Mutex<Seals>>,
}

impl Sealer for FakeSealer {
    async fn seal(&self, owner: SealOwner, plaintext: &[u8]) -> Result<Sealed, PortError> {
        let mut s = lock(&self.state);
        let n = s.next;
        s.next = n.saturating_add(1);
        let mut handle = b"fake-sealed-".to_vec();
        handle.extend_from_slice(&n.to_be_bytes());
        s.rows.insert(handle.clone(), (owner, plaintext.to_vec()));
        Ok(Sealed(handle))
    }

    async fn open(
        &self,
        owner: SealOwner,
        sealed: &Sealed,
        clearance: &ReadClearance,
    ) -> Result<Vec<u8>, PortError> {
        let _ = clearance;
        match lock(&self.state).rows.get(&sealed.0) {
            Some((o, p)) if *o == owner => Ok(p.clone()),
            Some(_) | None => Err(PortError::Refused),
        }
    }
}
