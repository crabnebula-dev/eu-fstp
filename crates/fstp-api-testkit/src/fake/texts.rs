//! The text store, the blob store and the sealer (ADR-004, ADR-007).
//!
//! The fakes keep plain bytes in memory. They hold synthetic text only.
//! The blob store's content address is the fake digest of
//! [`super::vault::fake_digest`], not SHA-256, because the test kit has
//! no hash dependency. The sealer keeps the plaintext beside an opaque
//! handle and never encrypts. Real sealing is M3's (I-74, I-75).

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use fstp_api_core::display_name::{self, FINGERPRINT_LEN};
use fstp_api_core::port::{
    BlobOwner, BlobRef, BlobStore, DisplayNameSet, ErasureCause, ErasureKind, ErasureRow,
    PortError, PublicTextRef, SealOwner, Sealed, Sealer, StepUpProof, TextClass, TextOwner,
    TextRef, TextStore, WorkspaceSlot, Workspaces,
};
use fstp_domain::id::AccountId;
use fstp_domain::id::ProposalId;
use fstp_domain::time::Timestamp;

use fstp_access::ReadClearance;

use super::lock;
use super::vault::fake_digest;

/// The largest blob the fake stores: 1 MiB.
pub const BLOB_LIMIT: usize = 1 << 20;

#[derive(Clone, Debug, Default)]
struct Texts {
    rows: BTreeMap<u128, (TextClass, TextOwner, Vec<u8>)>,
    next: u128,
    /// The erasure log (ADR-007, lane m5/retention), oldest first.
    erased: Vec<ErasureRow>,
    /// Whether the store keeps no erasure log, as the production cell's
    /// text store does today: `erasures` then answers unavailable.
    no_log: bool,
    /// The display name of each account (SA-11): its text and the keyed
    /// fingerprint stored beside it (SA-11 amendment).
    display: BTreeMap<AccountId, DisplayRow>,
    /// The account of each display name fingerprint (SA-11 amendment).
    /// The cell holds one tenant, so this index is the tenant's.
    fingerprints: BTreeMap<[u8; FINGERPRINT_LEN], AccountId>,
    /// The cell's App chain `Lookup` key, drawn at the first display name,
    /// as the login email index draws its `Lookup` group at the first
    /// login email (ADR-004).
    lookup: Option<LookupKey>,
}

/// One account's display name: the text that holds it and its keyed
/// fingerprint (SA-11 amendment).
#[derive(Clone, Copy, Debug)]
struct DisplayRow {
    text: u128,
    fingerprint: [u8; FINGERPRINT_LEN],
}

/// The fake cell's `Lookup` key. Its bytes never reach a `Debug` line.
#[derive(Clone)]
struct LookupKey([u8; 32]);

impl std::fmt::Debug for LookupKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LookupKey(..)")
    }
}

/// The text store. Cloning shares the texts.
#[derive(Clone, Debug, Default)]
pub struct FakeTexts {
    state: Arc<Mutex<Texts>>,
}

impl FakeTexts {
    /// Makes the store keep no erasure log, as the production cell's text
    /// store does today.
    pub fn without_log(&self) {
        let mut s = lock(&self.state);
        s.no_log = true;
    }

    /// Removes the bytes behind `r`, as an erasure without a log does: a
    /// later read of `r` is refused.
    pub fn forget(&self, r: TextRef) {
        let _ = lock(&self.state).rows.remove(&r.0);
    }

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
    /// The display names, their fingerprints and the `Lookup` key are
    /// copied too, as a restarted cell keeps its keystore.
    pub fn copy_from(&self, from: &FakeTexts) {
        let copy = lock(&from.state).clone();
        *lock(&self.state) = copy;
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
    /// Erases every text that account `a` owns, as an account erasure
    /// does (ADR-007, cause 2), each with one log row. Its display name is
    /// among them (SA-11). Returns how many texts it erased.
    pub fn erase_account(&self, a: AccountId, at: Timestamp) -> usize {
        let mut s = lock(&self.state);
        let owned: Vec<u128> = s
            .rows
            .iter()
            .filter(|(_, (_, owner, _))| *owner == TextOwner::Account(a))
            .map(|(id, _)| *id)
            .collect();
        let name = s.display.get(&a).map(|r| r.text);
        for id in &owned {
            let kind = if name == Some(*id) {
                ErasureKind::DisplayName
            } else {
                ErasureKind::Text
            };
            erase(&mut s, *id, at, kind);
        }
        // SA-11 amendment: the fingerprint goes with the name.
        if let Some(row) = s.display.remove(&a) {
            s.fingerprints.remove(&row.fingerprint);
        }
        owned.len()
    }

    /// The text that holds the display name of `a`, if any (SA-11).
    pub fn display_text(&self, a: AccountId) -> Option<TextRef> {
        lock(&self.state).display.get(&a).map(|r| TextRef(r.text))
    }

    /// The keyed fingerprint stored beside the display name of `a`, if
    /// any (SA-11 amendment).
    pub fn display_fingerprint(&self, a: AccountId) -> Option<[u8; FINGERPRINT_LEN]> {
        lock(&self.state).display.get(&a).map(|r| r.fingerprint)
    }

    /// How many display name fingerprints the tenant's index holds (SA-11
    /// amendment).
    pub fn fingerprint_count(&self) -> usize {
        lock(&self.state).fingerprints.len()
    }

    /// The owner of the text `r`, if it is stored.
    pub fn owner(&self, r: TextRef) -> Option<TextOwner> {
        lock(&self.state).rows.get(&r.0).map(|(_, o, _)| *o)
    }
}

/// Removes text `id` and logs its erasure at `at`, at the person's
/// request (ADR-007, cause 2), naming no grant.
fn erase(s: &mut Texts, id: u128, at: Timestamp, kind: ErasureKind) {
    if s.rows.remove(&id).is_some() {
        s.erased.push(ErasureRow {
            text: TextRef(id),
            cause: ErasureCause::ErasureRequest,
            grant: None,
            requested_at: at,
            completed_at: Some(at),
            kind,
            destroyed_epoch: None,
            by_system: false,
            reason: None,
        });
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
/// released only to a read cleared on that proposal, or on one of its
/// assignments, so a clearance of one proposal never opens another's
/// text (decided by Daniel on 2026-11-13). A programme's text is released
/// only to a read cleared on that programme or on one of its calls, never
/// to a read of one proposal. Every other owner is refused until a read
/// needs it.
fn clears(class: TextClass, owner: TextOwner, clearance: &ReadClearance) -> bool {
    use fstp_access::ReadTarget;
    match (class, owner, clearance.op().target) {
        (TextClass::Public, _, _) => true,
        (_, TextOwner::Proposal(p), _) => clearance.proposal() == Some(p),
        (_, TextOwner::Programme(p), ReadTarget::Programme(_) | ReadTarget::Call(_)) => {
            clearance.programme() == Some(p)
        }
        // SA-11: an account's display name opens to the team and member
        // reads, and to the account's own display name read. No other read
        // shows it (I-17, P-11, I-27).
        (_, TextOwner::Account(a), _) => match clearance.op().kind {
            fstp_access::ReadKind::ListTeam | fstp_access::ReadKind::ListMembers => true,
            fstp_access::ReadKind::GetMyDisplayName => clearance.account() == Some(a),
            _ => false,
        },
        // ADR-007 (Daniel, 2026-11-23; lane L39): the reason a tenant
        // admin stated for an erasure opens to the erasure log read only,
        // which the read rule admits for tenant admins.
        (_, TextOwner::Tenant, _) => clearance.op().kind == fstp_access::ReadKind::ListErasures,
        _ => false,
    }
}

impl TextStore for FakeTexts {
    /// Replaces the account's display name text, erasing the old one
    /// (SA-11, ADR-007), unless another account of the tenant holds the
    /// name (SA-11 amendment).
    async fn set_display_name(
        &self,
        a: AccountId,
        name: Option<String>,
        at: Timestamp,
    ) -> Result<DisplayNameSet, PortError> {
        self.set_display_now(a, name, at)
    }

    /// The display names under `clearance`, which must open each
    /// account's texts (SA-11). Otherwise the whole read is refused.
    async fn display_names(
        &self,
        accounts: Vec<AccountId>,
        clearance: &ReadClearance,
    ) -> Result<BTreeMap<AccountId, String>, PortError> {
        self.display_names_now(&accounts, clearance)
    }

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

    async fn erasures(&self) -> Result<Vec<ErasureRow>, PortError> {
        let s = lock(&self.state);
        if s.no_log {
            return Err(PortError::Unavailable);
        }
        Ok(s.erased.clone())
    }

    /// Erases every text the grant owns at once: its bytes leave the
    /// store, so every later read is refused, and each text gets one log
    /// row completed at the request instant (ADR-007). A grant that owns
    /// no live text is refused.
    async fn request_erasure(
        &self,
        by: AccountId,
        cause: ErasureCause,
        grant: ProposalId,
        at: Timestamp,
        proof: StepUpProof,
    ) -> Result<(), PortError> {
        let _ = (by, proof);
        let mut s = lock(&self.state);
        let owned: Vec<u128> = s
            .rows
            .iter()
            .filter(|(_, (_, owner, _))| *owner == TextOwner::Proposal(grant))
            .map(|(id, _)| *id)
            .collect();
        if owned.is_empty() {
            return Err(PortError::Refused);
        }
        for id in owned {
            s.rows.remove(&id);
            s.erased.push(ErasureRow {
                text: TextRef(id),
                cause,
                grant: Some(grant),
                requested_at: at,
                completed_at: Some(at),
                kind: ErasureKind::Text,
                destroyed_epoch: None,
                by_system: false,
                reason: None,
            });
        }
        Ok(())
    }
}

/// SA-11: the display name methods of the text store.
impl FakeTexts {
    /// The uniqueness check and the write, under one lock, so two
    /// accounts cannot take one name at once (SA-11 amendment).
    fn set_display_now(
        &self,
        a: AccountId,
        name: Option<String>,
        at: Timestamp,
    ) -> Result<DisplayNameSet, PortError> {
        let mut s = lock(&self.state);
        let fingerprint = match &name {
            Some(name) => {
                let lookup = match &s.lookup {
                    Some(k) => k.0,
                    None => {
                        let k = fstp_crypto::random_array::<32>()
                            .map_err(|_| PortError::Unavailable)?;
                        s.lookup = Some(LookupKey(k));
                        k
                    }
                };
                let key =
                    display_name::fingerprint_key(&lookup).map_err(|_| PortError::Unavailable)?;
                let fingerprint = display_name::fingerprint(&key, name);
                if s.fingerprints.get(&fingerprint).is_some_and(|b| *b != a) {
                    return Ok(DisplayNameSet::Taken);
                }
                Some(fingerprint)
            }
            None => None,
        };
        if let Some(old) = s.display.remove(&a) {
            s.fingerprints.remove(&old.fingerprint);
            erase(&mut s, old.text, at, ErasureKind::DisplayName);
        }
        if let (Some(name), Some(fingerprint)) = (name, fingerprint) {
            let n = s.next;
            s.next = n.saturating_add(1);
            s.rows.insert(
                n,
                (
                    TextClass::Confidential,
                    TextOwner::Account(a),
                    name.into_bytes(),
                ),
            );
            s.display.insert(
                a,
                DisplayRow {
                    text: n,
                    fingerprint,
                },
            );
            s.fingerprints.insert(fingerprint, a);
        }
        Ok(DisplayNameSet::Set)
    }

    fn display_names_now(
        &self,
        accounts: &[AccountId],
        clearance: &ReadClearance,
    ) -> Result<BTreeMap<AccountId, String>, PortError> {
        let s = lock(&self.state);
        let mut out = BTreeMap::new();
        for a in accounts {
            if !clears(TextClass::Confidential, TextOwner::Account(*a), clearance) {
                return Err(PortError::Refused);
            }
            let Some((_, _, b)) = s.display.get(a).and_then(|r| s.rows.get(&r.text)) else {
                continue;
            };
            let name = String::from_utf8(b.clone()).map_err(|_| PortError::Refused)?;
            out.insert(*a, name);
        }
        Ok(out)
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

    /// Replaces the blobs with a copy of those of `from`, as a restarted
    /// cell keeps its blob store. Every clone of `self` sees the copy.
    pub fn copy_from(&self, from: &FakeBlobs) {
        let rows = lock(&from.rows).clone();
        *lock(&self.rows) = rows;
    }
}

impl BlobStore for FakeBlobs {
    async fn put(&self, owner: BlobOwner, bytes: &[u8]) -> Result<BlobRef, PortError> {
        if bytes.len() > BLOB_LIMIT {
            return Err(PortError::Refused);
        }
        // A brand asset is served by the SHA-256 its record names (ADR-030),
        // as the port documents every address.
        let r = match owner {
            BlobOwner::Brand => BlobRef(fstp_crypto::sha256(bytes)),
            BlobOwner::Programme(_) => BlobRef(fake_digest(&bytes).bytes()),
        };
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

    async fn get_brand(&self, r: BlobRef) -> Result<Vec<u8>, PortError> {
        lock(&self.rows)
            .get(&(BlobOwner::Brand, r))
            .cloned()
            .ok_or(PortError::Refused)
    }

    /// ADR-007 (lane L39): an import document's blob leaves the store at
    /// once. A brand asset is refused, and a blob already gone is a no-op.
    async fn erase(
        &self,
        owner: BlobOwner,
        r: BlobRef,
        by: AccountId,
        reason: TextRef,
    ) -> Result<(), PortError> {
        let _ = (by, reason);
        if matches!(owner, BlobOwner::Brand) {
            return Err(PortError::Refused);
        }
        lock(&self.rows).remove(&(owner, r));
        Ok(())
    }

    /// Whether no owner's blob is stored under `r` (lane L39).
    async fn erased(&self, r: BlobRef) -> Result<bool, PortError> {
        Ok(!lock(&self.rows).keys().any(|(_, k)| *k == r))
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

impl FakeSealer {
    /// Replaces the sealed values with a copy of those of `from`, as a
    /// restarted cell keeps its sealed store. Every clone of `self` sees
    /// the copy.
    pub fn copy_from(&self, from: &FakeSealer) {
        let (rows, next) = {
            let s = lock(&from.state);
            (s.rows.clone(), s.next)
        };
        let mut s = lock(&self.state);
        s.rows = rows;
        s.next = next;
    }
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

/// The sealed workspaces, by proposal and slot.
type WorkspaceRows = BTreeMap<(ProposalId, WorkspaceSlot), Sealed>;

/// The workspace store (lane W6): sealed bytes by proposal and slot,
/// kept as given. Cloning shares the rows.
#[derive(Clone, Debug, Default)]
pub struct FakeWorkspaces {
    rows: Arc<Mutex<WorkspaceRows>>,
    /// The proposals whose workspace was erased (F-017).
    erased: Arc<Mutex<std::collections::BTreeSet<ProposalId>>>,
    /// Whether every call fails as unavailable, for a test of a port that
    /// cannot answer.
    down: Arc<Mutex<bool>>,
}

impl FakeWorkspaces {
    /// Replaces the rows with a copy of those of `from`, as a restarted
    /// cell keeps its workspace store. Every clone of `self` sees the copy.
    pub fn copy_from(&self, from: &FakeWorkspaces) {
        let rows = lock(&from.rows).clone();
        *lock(&self.rows) = rows;
        let erased = lock(&from.erased).clone();
        *lock(&self.erased) = erased;
    }

    /// The slots stored for `proposal`, in order.
    pub fn slots(&self, proposal: ProposalId) -> Vec<WorkspaceSlot> {
        lock(&self.rows)
            .keys()
            .filter(|(p, _)| *p == proposal)
            .map(|(_, s)| *s)
            .collect()
    }

    /// Makes every later call fail as unavailable, or answer again.
    pub fn set_down(&self, down: bool) {
        *lock(&self.down) = down;
    }

    fn up(&self) -> Result<(), PortError> {
        if *lock(&self.down) {
            Err(PortError::Unavailable)
        } else {
            Ok(())
        }
    }
}

impl Workspaces for FakeWorkspaces {
    async fn put(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
        sealed: Sealed,
    ) -> Result<(), PortError> {
        self.up()?;
        // F-017: an erased workspace takes no new value, as the cell's
        // sealer refuses one.
        if lock(&self.erased).contains(&proposal) {
            return Err(PortError::Unavailable);
        }
        lock(&self.rows).insert((proposal, slot), sealed);
        Ok(())
    }

    async fn get(
        &self,
        proposal: ProposalId,
        slot: WorkspaceSlot,
    ) -> Result<Option<Sealed>, PortError> {
        self.up()?;
        Ok(lock(&self.rows).get(&(proposal, slot)).cloned())
    }

    /// F-017: every slot of `proposal` leaves at once. The fake holds no
    /// keys, so the rows going stands in for the key's destruction. A
    /// proposal erased before answers `true` again.
    async fn erase(
        &self,
        proposal: ProposalId,
        cause: ErasureCause,
        by: AccountId,
    ) -> Result<bool, PortError> {
        let _ = (cause, by);
        self.up()?;
        let mut erased = lock(&self.erased);
        let mut rows = lock(&self.rows);
        let before = rows.len();
        rows.retain(|(p, _), _| *p != proposal);
        if rows.len() != before {
            erased.insert(proposal);
        }
        Ok(erased.contains(&proposal))
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_rt::future::block_on;

    const ANNA: AccountId = AccountId::from_raw(9_101);
    const BERG: AccountId = AccountId::from_raw(9_102);
    const AT: Timestamp = Timestamp::from_micros(1_000);

    fn set(t: &FakeTexts, a: AccountId, name: Option<&str>) -> DisplayNameSet {
        block_on(t.set_display_name(a, name.map(str::to_owned), AT)).unwrap()
    }

    /// SA-11 amendment: a name another account of the tenant holds is
    /// taken, also in another case or spacing, and nothing changes.
    #[test]
    fn sa11_unique_taken_name_is_refused_in_any_case_or_spacing() {
        let t = FakeTexts::default();
        assert_eq!(
            set(&t, ANNA, Some("Synthetic Anna Berg")),
            DisplayNameSet::Set
        );
        let held = t.display_text(ANNA).unwrap();
        for other in [
            "Synthetic Anna Berg",
            "synthetic anna berg",
            "  SYNTHETIC   anna\u{a0}Berg ",
        ] {
            assert_eq!(
                set(&t, BERG, Some(other)),
                DisplayNameSet::Taken,
                "{other:?}"
            );
        }
        assert!(t.display_text(BERG).is_none());
        assert_eq!(t.display_text(ANNA), Some(held));
        assert_eq!(t.fingerprint_count(), 1);
        assert_eq!(
            set(&t, BERG, Some("Synthetic Anna Bergh")),
            DisplayNameSet::Set
        );
    }

    /// SA-11 amendment: the own current name again, or in another case,
    /// is no conflict. The old text is erased and the fingerprint kept.
    #[test]
    fn sa11_unique_own_name_again_is_set() {
        let t = FakeTexts::default();
        assert_eq!(set(&t, ANNA, Some("Synthetic Anna")), DisplayNameSet::Set);
        let fp = t.display_fingerprint(ANNA).unwrap();
        let first = t.display_text(ANNA).unwrap();
        assert_eq!(set(&t, ANNA, Some("Synthetic Anna")), DisplayNameSet::Set);
        assert_eq!(set(&t, ANNA, Some("SYNTHETIC  anna")), DisplayNameSet::Set);
        assert_eq!(t.display_fingerprint(ANNA), Some(fp));
        assert!(
            t.peek(first).is_none(),
            "ADR-007: the replaced text is erased"
        );
        assert_eq!(t.fingerprint_count(), 1);
    }

    /// SA-11 amendment, ADR-007: a replace, a clear and an account
    /// erasure each erase the fingerprint with the name, so the name is
    /// free again.
    #[test]
    fn sa11_unique_replace_clear_and_erasure_free_the_name() {
        let t = FakeTexts::default();
        set(&t, ANNA, Some("Synthetic One"));
        set(&t, ANNA, Some("Synthetic Two"));
        assert_eq!(t.fingerprint_count(), 1);
        assert_eq!(set(&t, BERG, Some("Synthetic One")), DisplayNameSet::Set);
        assert_eq!(set(&t, BERG, Some("Synthetic Two")), DisplayNameSet::Taken);
        set(&t, ANNA, None);
        assert!(t.display_fingerprint(ANNA).is_none());
        assert_eq!(set(&t, BERG, Some("Synthetic Two")), DisplayNameSet::Set);
        assert_eq!(t.fingerprint_count(), 1);
        assert_eq!(t.erase_account(BERG, AT), 1);
        assert_eq!(t.fingerprint_count(), 0);
        assert_eq!(set(&t, ANNA, Some("synthetic two")), DisplayNameSet::Set);
    }

    /// SA-11 amendment, I-20: two tenants (two cells, two `Lookup` keys)
    /// may use the same name, and their fingerprints differ, so none links
    /// the two accounts.
    #[test]
    fn sa11_unique_i20_two_tenants_may_use_the_same_name() {
        let one = FakeTexts::default();
        let two = FakeTexts::default();
        assert_eq!(
            set(&one, ANNA, Some("Synthetic Shared")),
            DisplayNameSet::Set
        );
        assert_eq!(
            set(&two, BERG, Some("Synthetic Shared")),
            DisplayNameSet::Set
        );
        assert_ne!(one.display_fingerprint(ANNA), two.display_fingerprint(BERG));
    }

    /// SA-11 amendment, ADR-029, lane L26: two encodings of one accented
    /// name, and a look-alike with a zero width joiner, are one name, so
    /// the second account is refused.
    #[test]
    fn sa11_unique_adr029_variants_of_one_name_are_taken() {
        let t = FakeTexts::default();
        assert_eq!(
            set(&t, ANNA, Some("Jos\u{e9} Synthetic")),
            DisplayNameSet::Set
        );
        for other in ["Jose\u{301} Synthetic", "Jos\u{e9} Synth\u{200d}etic"] {
            assert_eq!(
                set(&t, BERG, Some(other)),
                DisplayNameSet::Taken,
                "{other:?}"
            );
        }
    }

    /// SA-11 amendment: a restarted cell keeps its `Lookup` key and its
    /// index, so a copy still refuses a taken name.
    #[test]
    fn sa11_unique_copy_keeps_the_key_and_the_index() {
        let t = FakeTexts::default();
        set(&t, ANNA, Some("Synthetic Anna"));
        let copy = FakeTexts::default();
        copy.copy_from(&t);
        assert_eq!(
            set(&copy, BERG, Some("synthetic anna")),
            DisplayNameSet::Taken
        );
        assert!(
            format!("{t:?}").contains("LookupKey(..)"),
            "the key bytes stay out"
        );
    }

    /// SA-11 amendment: the check and the write are one atomic step. Many
    /// accounts set one name at once, and exactly one wins.
    #[test]
    fn sa11_unique_concurrent_sets_of_one_name_have_exactly_one_winner() {
        for round in 0..20u64 {
            let t = FakeTexts::default();
            let n = 8u64;
            let gate = Arc::new(std::sync::Barrier::new(8));
            let threads: Vec<_> = (0..n)
                .map(|i| {
                    let t = t.clone();
                    let gate = Arc::clone(&gate);
                    let a = AccountId::from_raw(u128::from(9_200 + i));
                    let name = if i % 2 == 0 {
                        "Synthetic Race".to_owned()
                    } else {
                        " synthetic  RACE ".to_owned()
                    };
                    std::thread::spawn(move || {
                        gate.wait();
                        block_on(t.set_display_name(a, Some(name), AT)).unwrap()
                    })
                })
                .collect();
            let got: Vec<DisplayNameSet> = threads.into_iter().map(|h| h.join().unwrap()).collect();
            let won = got.iter().filter(|g| **g == DisplayNameSet::Set).count();
            assert_eq!(won, 1, "round {round}: {got:?}");
            assert_eq!(t.fingerprint_count(), 1, "round {round}");
            let named = (0..n)
                .filter(|i| {
                    t.display_text(AccountId::from_raw(u128::from(9_200 + i)))
                        .is_some()
                })
                .count();
            assert_eq!(named, 1, "round {round}");
        }
    }

    /// F-017: erasing a workspace removes every slot of that proposal and
    /// no other, refuses a later save of it, and answers `true` again on a
    /// repeat. A proposal with no workspace answers `false`.
    #[test]
    fn m10_f017_fake_workspace_erase_removes_every_slot() {
        let w = FakeWorkspaces::default();
        let p = ProposalId::from_raw(17);
        let q = ProposalId::from_raw(18);
        let plan = fstp_domain::id::PlanVersionId::from_raw(3);
        for (proposal, slot) in [
            (p, WorkspaceSlot::Draft),
            (p, WorkspaceSlot::Submitted(plan)),
            (q, WorkspaceSlot::Draft),
        ] {
            block_on(w.put(proposal, slot, Sealed(b"sealed".to_vec()))).unwrap();
        }
        let erase = |x| block_on(w.erase(x, ErasureCause::RetentionExpiry, ANNA));
        assert_eq!(erase(ProposalId::from_raw(19)), Ok(false));
        assert_eq!(erase(p), Ok(true));
        assert!(w.slots(p).is_empty());
        assert_eq!(w.slots(q), vec![WorkspaceSlot::Draft]);
        assert_eq!(erase(p), Ok(true), "a repeat");
        assert!(block_on(w.put(p, WorkspaceSlot::Draft, Sealed(b"late".to_vec()))).is_err());
    }
}
