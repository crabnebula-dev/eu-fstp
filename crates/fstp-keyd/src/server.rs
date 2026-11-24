//! The custody server: the state of one key volume and the socket loop.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use fstp_crypto::aead;
use fstp_crypto::sig::EcdsaP256KeyPair;
use fstp_custody::keyd::{
    MAX_USAGE_RECORDS, Request, RequestId, Response, RootHandle, SignKeyReceipt,
};
use fstp_custody::{Chain, Epoch, Refusal};
use fstp_obs::LogEvent;
use fstp_obs::assurance::{
    Assurance, DeploymentMode, HostCheck, ReducedReason, deployment_mode_from_env,
};
use zeroize::Zeroizing;

use crate::access::{ClientRole, ClientSocket};
use crate::receipt::Receipt;
use crate::table::{EpochKey, KeyTable, SignKeyName, TableStore};
use crate::usage::{self, UsageLog};
use crate::{KeydError, Passphrase, RootMaterial, epoch, sign_key};

/// The label bound into every wrap, beside the root and the caller's AAD.
const WRAP_LABEL: &[u8; 17] = b"fstp-keyd-wrap-v1";
/// Length of a wrapped seal key: nonce, key and tag.
const WRAPPED_LEN: usize = aead::NONCE_LEN + 32 + aead::TAG_LEN;
/// How long a connection may take to send its whole request, counted
/// from accept, and again to take its response, in seconds.
const CONNECTION_TIMEOUT_SECS: u64 = 5;
/// The most connections one socket serves at once. One more on that
/// socket is closed at once. The other sockets are not affected.
const MAX_CONNECTIONS_PER_SOCKET: usize = 16;
/// How often the accept loop looks at its stop flag, in milliseconds.
const POLL_MILLIS: u64 = 10;
/// How often a pilot entry tries again to send an owed fresh copy to its
/// custodian (ADR-004 "The custodian's copy").
const COPY_RETRY: Duration = Duration::from_secs(600);
/// How long [`stop`] waits for a server to end, in seconds.
const STOP_WAIT_SECS: u64 = 30;

/// Where [`serve_sockets`] reads the passphrase of the key table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PassphraseSource {
    /// The systemd credential [`crate::PASSPHRASE_CREDENTIAL`] only.
    Credential,
    /// The systemd credential, or else the operator through
    /// `systemd-ask-password` on a host without a TPM (ADR-004 part 2
    /// "Unattended boot"). The start waits until the operator answers.
    CredentialOrAsk,
}

/// What the key table says of one root.
enum Status<'a> {
    /// The root is live, with its `K(e)`.
    Live(&'a EpochKey),
    /// The root is destroyed. A root whose entry was reclaimed is older
    /// than the chain's newest epoch, so it counts as destroyed too.
    /// That holds because a chain's epochs are created from 1 on with no
    /// gap ([`Server::create`]), so every epoch below the newest existed.
    Destroyed,
    /// No root of this chain and epoch was ever created.
    Unknown,
}

fn status(table: &KeyTable, handle: RootHandle) -> Status<'_> {
    match table.get(handle.chain, handle.epoch) {
        Some(e) => e.key.as_ref().map_or(Status::Destroyed, Status::Live),
        None if handle.epoch.0 == 0 => Status::Unknown,
        None if table.newest(handle.chain).is_some_and(|n| n > handle.epoch) => Status::Destroyed,
        None => Status::Unknown,
    }
}

/// The state of one key volume.
pub(crate) struct Server {
    pub(crate) volume: PathBuf,
    pub(crate) table: TableStore,
    roots: BTreeMap<RootHandle, (RootMaterial, aead::Key)>,
    usage: UsageLog,
    /// Records written in the current window, per client code: the window
    /// start, the count, and whether the first refusal was logged.
    windows: BTreeMap<u8, (Instant, u32, bool)>,
    log_max: u64,
    rate_max: u32,
    /// Whether the volume is held after an import (ADR-004 record of
    /// lane L16 rule 2).
    held: bool,
    /// The guard of this entry's key copies, on a pilot entry with a
    /// second custodian (ADR-004 record of lane `m10/guard-key`).
    pub(crate) guard: Option<crate::guard::GuardLink>,
    /// The passphrase, kept in wiped memory on a pilot entry with a
    /// custodian, so the entry can make the custodian's fresh copy after
    /// each rotation (ADR-004 "The custodian's copy").
    pub(crate) copy_passphrase: Option<Passphrase>,
    /// The exclusive lock of the volume, held for the server's lifetime.
    _lock: crate::export::VolumeLock,
}

impl Server {
    /// Whether a request of client `client` and operation `op` may write
    /// a usage record (L13, ADR-024). It refuses a request over the
    /// per-client rate, and every request but create and destroy at the
    /// size bound. Twice the size bound refuses create and destroy too,
    /// so the log is never unbounded. A refusal writes no record except
    /// the first of a client in a window.
    pub(crate) fn admit(&mut self, client: u8, op: u8) -> bool {
        let size = self.usage.len();
        let over_size = if usage::exempt_from_bound(op) {
            size >= self.log_max.saturating_mul(2)
        } else {
            size >= self.log_max
        };
        let now = Instant::now();
        let window = Duration::from_secs(usage::USAGE_WINDOW_SECS);
        let entry = self.windows.entry(client).or_insert((now, 0, false));
        if now.duration_since(entry.0) >= window {
            *entry = (now, 0, false);
        }
        let over_rate = !usage::exempt_from_bound(op) && entry.1 >= self.rate_max;
        if !over_size && !over_rate {
            entry.1 = entry.1.saturating_add(1);
            return true;
        }
        let first = !entry.2;
        entry.2 = true;
        if first && !over_size {
            // The first refusal of a client in a window leaves one record.
            let _ = self.usage.append_from(
                client,
                RequestId([0u8; 16]),
                op,
                None,
                Refusal::LimitReached.code(),
            );
        }
        false
    }

    /// Opens the key volume under `passphrase`, creating an empty key
    /// table on first start.
    pub(crate) fn open(volume: &Path, passphrase: &Passphrase) -> Result<Server, KeydError> {
        let lock = crate::export::lock_volume(volume, crate::export::LOCK_WAIT)?;
        let table = TableStore::open_or_create(volume, passphrase)?;
        Ok(Server {
            volume: volume.to_path_buf(),
            table,
            roots: BTreeMap::new(),
            usage: UsageLog::open(volume)?,
            windows: BTreeMap::new(),
            log_max: usage::USAGE_LOG_MAX_BYTES,
            rate_max: usage::USAGE_RECORDS_PER_CLIENT_MINUTE,
            held: crate::export::is_held(volume),
            guard: None,
            copy_passphrase: None,
            _lock: lock,
        })
    }

    /// Serves one request outside any socket, with no chain check. Only
    /// the unit tests call it. Every socket request goes through
    /// [`Server::handle_as`].
    #[cfg(test)]
    pub(crate) fn handle(&mut self, request: &Request) -> Response {
        self.serve_logged(usage::CLIENT_NONE, request)
    }

    /// Serves one request that came in on a socket of `role`. A request
    /// for a chain or key outside the role's set is refused with
    /// [`Refusal::NotPermitted`] (ADR-004 part 2, R-NF-08). Every request
    /// is logged with its outcome and client.
    pub(crate) fn handle_as(&mut self, role: ClientRole, request: &Request) -> Response {
        if !self.admit(role.code(), op_and_root(request).0) {
            return Response::Refused(Refusal::LimitReached);
        }
        let held_out = self.held && !crate::export::held_permits(request);
        if role.permits(request) && !held_out {
            return self.serve_logged(role.code(), request);
        }
        let (op, root) = op_and_root(request);
        let refusal = Refusal::NotPermitted;
        if self
            .usage
            .append_from(role.code(), request.id(), op, root, refusal.code())
            .is_err()
        {
            return Response::Refused(Refusal::Internal);
        }
        Response::Refused(refusal)
    }

    fn serve_logged(&mut self, client: u8, request: &Request) -> Response {
        let (op, root) = op_and_root(request);
        let response = match self.serve_request(request) {
            Ok(r) => r,
            Err(r) => Response::Refused(r),
        };
        let outcome = match &response {
            Response::Refused(r) => r.code(),
            _ => usage::OUTCOME_SERVED,
        };
        if self
            .usage
            .append_from(client, request.id(), op, root, outcome)
            .is_err()
        {
            // An operation that cannot be logged is not answered as
            // served: reconciliation would miss it (ADR-004).
            return Response::Refused(Refusal::Internal);
        }
        response
    }

    fn serve_request(&mut self, request: &Request) -> Result<Response, Refusal> {
        match request {
            Request::CreateRoot { chain, epoch, .. } => self.create(*chain, *epoch),
            Request::Wrap { root, aad, key, .. } => self.wrap(*root, aad, key),
            Request::Unwrap {
                root, aad, wrapped, ..
            } => self.unwrap(*root, aad, wrapped),
            Request::Destroy { id, root } => {
                if matches!(status(&self.table.table, *root), Status::Unknown) {
                    return Err(Refusal::UnknownRoot);
                }
                self.guarded(*id, |s| s.destroy(*root))
            }
            Request::Sign { key, digest, .. } => self.sign(key, digest),
            Request::DestroySignKey { id, key } => {
                let known = SignKeyName::from_handle(key)
                    .is_some_and(|n| self.table.table.sign_key(n).is_some());
                if !known {
                    return Err(Refusal::NoSignKey);
                }
                self.guarded(*id, |s| s.destroy_sign_key(key))
            }
            Request::CreateSignKey { key, .. } => self.create_sign_key(key),
            Request::UsageSince { root, cursor, .. } => {
                let (records, next) = self
                    .usage
                    .since(*root, *cursor, MAX_USAGE_RECORDS)
                    .map_err(|_| Refusal::Internal)?;
                Ok(Response::Usage { records, next })
            }
        }
    }

    /// Creates the root of `chain` and `epoch`, or returns the live one,
    /// so a retried create after a lost reply finds the same root.
    ///
    /// Epochs are created from 1 on with no gap: "Provisioning creates
    /// epoch 1 of each chain", and each rotation goes from `e` to `e + 1`
    /// (ADR-004 part 2 "Epochs" and "Erasure construction"). A create
    /// that would skip an epoch is refused with
    /// [`Refusal::BadRequest`]. So every epoch below a chain's newest one
    /// existed, and a destroy of an epoch that never existed answers
    /// [`Refusal::UnknownRoot`], not a receipt.
    fn create(&mut self, chain: Chain, epoch: Epoch) -> Result<Response, Refusal> {
        let handle = RootHandle { chain, epoch };
        if epoch.0 == 0 {
            return Err(Refusal::BadRequest);
        }
        if let Some(e) = self.table.table.get(chain, epoch) {
            return if e.is_live() {
                Ok(Response::Root(handle))
            } else {
                Err(Refusal::Destroyed)
            };
        }
        match self.table.table.newest(chain) {
            Some(n) if n > epoch => return Err(Refusal::StaleEpoch),
            Some(n) if n.0.checked_add(1) != Some(epoch.0) => return Err(Refusal::BadRequest),
            None if epoch.0 != 1 => return Err(Refusal::BadRequest),
            _ => {}
        }
        let k = EpochKey::generate().map_err(|_| Refusal::Internal)?;
        let root = RootMaterial::generate().map_err(|_| Refusal::Internal)?;
        #[cfg(feature = "test-needles")]
        crate::test_needles::record(&self.volume, root.bytes());
        let sealed = epoch::seal(&k, chain, epoch, &root).map_err(|_| Refusal::Internal)?;
        epoch::write_new(&self.volume, chain, epoch, &sealed).map_err(|_| Refusal::Internal)?;
        self.table
            .insert(chain, epoch, k)
            .map_err(|_| Refusal::Internal)?;
        let key = aead::Key::from_bytes(root.bytes()).map_err(|_| Refusal::Internal)?;
        self.roots.insert(handle, (root, key));
        Ok(Response::Root(handle))
    }

    /// The live root of `handle`, opened from its epoch file on first use.
    fn root(&mut self, handle: RootHandle) -> Result<&aead::Key, Refusal> {
        let k = match status(&self.table.table, handle) {
            Status::Live(k) => k,
            Status::Destroyed => {
                self.roots.remove(&handle);
                return Err(Refusal::Destroyed);
            }
            Status::Unknown => return Err(Refusal::UnknownRoot),
        };
        if !self.roots.contains_key(&handle) {
            let bytes = epoch::read(&self.volume, handle.chain, handle.epoch)
                .map_err(|_| Refusal::Internal)?
                .ok_or(Refusal::Internal)?;
            let root = epoch::open(k, handle.chain, handle.epoch, &bytes)
                .map_err(|_| Refusal::Internal)?;
            let key = aead::Key::from_bytes(root.bytes()).map_err(|_| Refusal::Internal)?;
            self.roots.insert(handle, (root, key));
        }
        self.roots
            .get(&handle)
            .map(|(_, key)| key)
            .ok_or(Refusal::Internal)
    }

    fn wrap(
        &mut self,
        handle: RootHandle,
        aad: &[u8],
        key: &[u8; 32],
    ) -> Result<Response, Refusal> {
        let full = wrap_aad(handle, aad);
        let root = self.root(handle)?;
        let sealed = aead::seal(root, &full, key).map_err(|e| match e {
            fstp_crypto::CryptoError::SealLimitReached => Refusal::LimitReached,
            _ => Refusal::Internal,
        })?;
        let mut out = Vec::with_capacity(WRAPPED_LEN);
        out.extend_from_slice(&sealed.nonce);
        out.extend_from_slice(&sealed.body);
        Ok(Response::Wrapped(out))
    }

    fn unwrap(
        &mut self,
        handle: RootHandle,
        aad: &[u8],
        wrapped: &[u8],
    ) -> Result<Response, Refusal> {
        let full = wrap_aad(handle, aad);
        let root = self.root(handle)?;
        if wrapped.len() != WRAPPED_LEN {
            return Err(Refusal::UnwrapFailed);
        }
        let (nonce, body) = wrapped
            .split_first_chunk::<{ aead::NONCE_LEN }>()
            .ok_or(Refusal::UnwrapFailed)?;
        let opened = aead::open(root, nonce, &full, body).map_err(|_| Refusal::UnwrapFailed)?;
        let key = fstp_custody::key_box(&opened).map_err(|_| Refusal::UnwrapFailed)?;
        Ok(Response::Unwrapped(key))
    }

    /// Destroys the root of `handle`, in the steps of ADR-004 part 2, and
    /// returns the receipt. A destroyed root gets its receipt again once
    /// the read back passes again. Once the read back passes, the older
    /// destroyed entries of the chain are reclaimed.
    fn destroy(&mut self, handle: RootHandle) -> Result<Response, Refusal> {
        match status(&self.table.table, handle) {
            Status::Unknown => return Err(Refusal::UnknownRoot),
            Status::Destroyed => {}
            Status::Live(_) => {
                // Steps 1 and 2: overwrite K(e) in its slot of the key
                // table, in place, and fsync. K(e) leaves memory only
                // once the write is durable.
                self.roots.remove(&handle);
                self.table
                    .mark_destroyed(handle.chain, handle.epoch)
                    .map_err(|_| Refusal::Internal)?;
            }
        }
        // A slot whose write failed may still hold a copy of K(e). It is
        // overwritten too, on every try, before the read back.
        self.table
            .scrub_blocked(handle.chain, handle.epoch)
            .map_err(|_| Refusal::Internal)?;
        // Steps 3 and 4: unlink the epoch file and fsync the directory.
        epoch::unlink(&self.volume, handle.chain, handle.epoch).map_err(|_| Refusal::Internal)?;
        epoch::sync_dir(&self.volume).map_err(|_| Refusal::Internal)?;
        // Step 5: read the table and the directory back.
        let gone = self
            .table
            .read_back_gone(handle.chain, handle.epoch)
            .map_err(|_| Refusal::Internal)?;
        let file =
            epoch::read(&self.volume, handle.chain, handle.epoch).map_err(|_| Refusal::Internal)?;
        if !gone || file.is_some() {
            return Err(Refusal::Internal);
        }
        self.table.reclaim(handle.chain);
        Ok(Response::Destroyed(
            Receipt::full(handle.chain, handle.epoch).encode(),
        ))
    }
}

// ---------------------------------------------------------------------------
// The guard of the key copies (ADR-004 record of lane `m10/guard-key`,
// F-018, I-81).

impl Server {
    /// Runs the destroy `destroy` of request `id` under the guard. On a
    /// pilot entry with a custodian, the request id is first recorded as
    /// the owed event, so a crash after the local destroy still owes the
    /// rotation. After the local destroy has read back, the custodian
    /// replaces the guard. Only then does the receipt go out. While the
    /// custodian does not answer, the destroy answers
    /// [`Refusal::GuardPending`] and the event stays owed: the erasure
    /// waits and is never reported complete while the old guard lives.
    fn guarded(
        &mut self,
        id: RequestId,
        destroy: impl FnOnce(&mut Server) -> Result<Response, Refusal>,
    ) -> Result<Response, Refusal> {
        if self.guard.is_none() {
            return destroy(self);
        }
        let mut st =
            crate::guard::state::read_state(&self.volume).map_err(|_| Refusal::Internal)?;
        if st.owed.is_none() {
            st.owed = Some(id.0);
            crate::guard::state::write_state(&self.volume, &st).map_err(|_| Refusal::Internal)?;
        }
        let response = destroy(self)?;
        self.settle_guard()?;
        Ok(response)
    }

    /// Replaces the guard for the owed event, if one is owed.
    ///
    /// # Errors
    ///
    /// [`Refusal::GuardPending`] while the custodian does not answer or
    /// refuses, and [`Refusal::Internal`] when the state does not write.
    pub(crate) fn settle_guard(&mut self) -> Result<(), Refusal> {
        let Some(link) = self.guard.as_ref() else {
            return Ok(());
        };
        let mut st =
            crate::guard::state::read_state(&self.volume).map_err(|_| Refusal::Internal)?;
        let Some(event) = st.owed else {
            self.retry_copy();
            return Ok(());
        };
        let rotated = link
            .client
            .rotate(link.entry, event)
            .map_err(|_| Refusal::GuardPending)?;
        st.generation = rotated.generation;
        st.rotated = crate::guard::state::now();
        st.owed = None;
        st.copy_owed = true;
        crate::guard::state::write_state(&self.volume, &st).map_err(|_| Refusal::Internal)?;
        // The fresh copy is a follow-up, never part of completion: the old
        // guard is destroyed already (ADR-004 "The custodian's copy").
        if let Ok(public) = fstp_crypto::hybrid_kem::HybridPublicKey::from_bytes(&rotated.public) {
            self.send_copy(rotated.generation, &public);
        }
        Ok(())
    }

    /// Sends a fresh copy owed to the custodian, if one is owed. A failure
    /// leaves it owed for the next try.
    pub(crate) fn retry_copy(&mut self) {
        let Some(link) = self.guard.as_ref() else {
            return;
        };
        let owed = crate::guard::state::read_state(&self.volume)
            .is_ok_and(|s| s.copy_owed && s.owed.is_none());
        if !owed {
            return;
        }
        if let Ok((generation, public)) = link.client.public(link.entry) {
            self.send_copy(generation, &public);
        }
    }

    /// Makes a copy of this volume under the lock the server holds, seals
    /// it to the guard `generation` with `public`, and sends it to the
    /// custodian. On success the copy is no longer owed.
    fn send_copy(&mut self, generation: u32, public: &fstp_crypto::hybrid_kem::HybridPublicKey) {
        let (Some(link), Some(pass)) = (self.guard.as_ref(), self.copy_passphrase.as_ref()) else {
            return;
        };
        let Ok((header, inner, _)) = crate::export::make_copy(&self.volume, pass) else {
            return;
        };
        let guarded = crate::guard::copy::GuardedHeader {
            entry: link.entry,
            generation,
            id: header.id,
            created: header.created,
        };
        let Ok(outer) = crate::guard::copy::seal(&guarded, public, &inner) else {
            return;
        };
        if link.client.put(link.entry, &outer).is_err() {
            return;
        }
        if let Ok(mut st) = crate::guard::state::read_state(&self.volume) {
            st.copy_owed = false;
            st.copied = crate::guard::state::now();
            let _ = crate::guard::state::write_state(&self.volume, &st);
        }
    }
}

// ---------------------------------------------------------------------------
// CA sign keys in sign-key slots (ADR-004 "Decided by Daniel, 2026-11-15
// (late)", lane m3/erase-prod).

impl Server {
    /// Creates the sign key `handle`, or finds the live one, and answers
    /// its public key. A handle of no known form has no key, and a
    /// destroyed key is never created again.
    fn create_sign_key(&mut self, handle: &[u8]) -> Result<Response, Refusal> {
        let name = SignKeyName::from_handle(handle).ok_or(Refusal::BadRequest)?;
        if let Some(e) = self.table.table.sign_key(name) {
            return match &e.key {
                Some(k) => {
                    let pair = self.open_sign_key(k, name)?;
                    Ok(Response::SignKey(
                        pair.spki_der().map_err(|_| Refusal::Internal)?,
                    ))
                }
                None => Err(Refusal::Destroyed),
            };
        }
        let k = EpochKey::generate().map_err(|_| Refusal::Internal)?;
        let pair = EcdsaP256KeyPair::generate().map_err(|_| Refusal::Internal)?;
        let sealed = sign_key::seal(&k, name, &pair).map_err(|_| Refusal::Internal)?;
        sign_key::write_new(&self.volume, name, &sealed).map_err(|_| Refusal::Internal)?;
        self.table
            .insert_sign_key(name, k)
            .map_err(|_| Refusal::Internal)?;
        Ok(Response::SignKey(
            pair.spki_der().map_err(|_| Refusal::Internal)?,
        ))
    }

    fn open_sign_key(&self, k: &EpochKey, name: SignKeyName) -> Result<EcdsaP256KeyPair, Refusal> {
        let bytes = sign_key::read(&self.volume, name)
            .map_err(|_| Refusal::Internal)?
            .ok_or(Refusal::Internal)?;
        sign_key::open(k, name, &bytes).map_err(|_| Refusal::Internal)
    }

    /// Signs `digest` with the live sign key `handle`. The key is opened
    /// from its file for the one signature and dropped after it.
    fn sign(&mut self, handle: &[u8], digest: &[u8; 32]) -> Result<Response, Refusal> {
        let name = SignKeyName::from_handle(handle).ok_or(Refusal::NoSignKey)?;
        let entry = self.table.table.sign_key(name).ok_or(Refusal::NoSignKey)?;
        let k = entry.key.as_ref().ok_or(Refusal::Destroyed)?;
        let pair = self.open_sign_key(k, name)?;
        let signature = pair.sign_digest(digest).map_err(|_| Refusal::Internal)?;
        Ok(Response::Signed(signature))
    }

    /// Destroys the sign key `handle` in the five steps of a root destroy:
    /// overwrite its `K` in its slot in place and fsync, unlink its file,
    /// fsync the directory, and read back. It answers the full receipt,
    /// also for a key destroyed before, once the read back passes again.
    fn destroy_sign_key(&mut self, handle: &[u8]) -> Result<Response, Refusal> {
        let name = SignKeyName::from_handle(handle).ok_or(Refusal::NoSignKey)?;
        let live = self
            .table
            .table
            .sign_key(name)
            .ok_or(Refusal::NoSignKey)?
            .is_live();
        let slot = crate::table::Slot::Sign(name);
        if live {
            self.table
                .mark_sign_key_destroyed(name)
                .map_err(|_| Refusal::Internal)?;
        }
        self.table
            .scrub_blocked_slot(slot)
            .map_err(|_| Refusal::Internal)?;
        sign_key::unlink(&self.volume, name).map_err(|_| Refusal::Internal)?;
        epoch::sync_dir(&self.volume).map_err(|_| Refusal::Internal)?;
        let gone = self
            .table
            .read_back_slot_gone(slot)
            .map_err(|_| Refusal::Internal)?;
        let file = sign_key::read(&self.volume, name).map_err(|_| Refusal::Internal)?;
        if !gone || file.is_some() {
            return Err(Refusal::Internal);
        }
        SignKeyReceipt::full(&name.handle())
            .encode()
            .map(Response::Destroyed)
            .map_err(|_| Refusal::Internal)
    }
}

/// The usage log operation and root of `request`.
fn op_and_root(request: &Request) -> (u8, Option<RootHandle>) {
    match request {
        Request::CreateRoot { chain, epoch, .. } => (
            usage::OP_CREATE,
            Some(RootHandle {
                chain: *chain,
                epoch: *epoch,
            }),
        ),
        Request::Wrap { root, .. } => (usage::OP_WRAP, Some(*root)),
        Request::Unwrap { root, .. } => (usage::OP_UNWRAP, Some(*root)),
        Request::Destroy { root, .. } => (usage::OP_DESTROY, Some(*root)),
        Request::Sign { .. } => (usage::OP_SIGN, None),
        Request::DestroySignKey { .. } => (usage::OP_DESTROY_SIGN_KEY, None),
        Request::CreateSignKey { .. } => (usage::OP_CREATE_SIGN_KEY, None),
        Request::UsageSince { root, .. } => (usage::OP_USAGE, Some(*root)),
    }
}

/// The AAD of a wrap: the label, the root and the caller's AAD.
fn wrap_aad(handle: RootHandle, aad: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        WRAP_LABEL
            .len()
            .saturating_add(fstp_custody::keyd::ROOT_LEN)
            .saturating_add(aad.len()),
    );
    out.extend_from_slice(WRAP_LABEL);
    out.extend_from_slice(&handle.encode());
    out.extend_from_slice(aad);
    out
}

/// Release of a held volume (ADR-004 record of lane L16 rule 3), under
/// the volume's lock. Every erasable chain with a live epoch must be
/// named in `current`. Every live epoch of a named chain below its
/// current one is destroyed with the steps and receipt of a destroy, and
/// logged. A named epoch that is not live gives [`KeydError::StaleCopy`]
/// after those destroys.
pub(crate) fn release(
    volume: &Path,
    passphrase: &Passphrase,
    current: &[(Chain, Epoch)],
    guard: Option<crate::guard::GuardLink>,
) -> Result<(), KeydError> {
    let mut server = Server::open(volume, passphrase)?;
    server.guard = guard;
    let live = |s: &Server, chain: Chain| -> Vec<Epoch> {
        s.table
            .table
            .entries
            .iter()
            .filter(|e| e.chain == chain && e.is_live())
            .map(|e| e.epoch)
            .collect()
    };
    for chain in crate::export::ERASABLE {
        if !live(&server, chain).is_empty() && !current.iter().any(|(c, _)| *c == chain) {
            return Err(KeydError::Malformed(
                "release must name the current epoch of every erasable chain",
            ));
        }
    }
    let mut stale = false;
    for (chain, now) in current {
        for epoch in live(&server, *chain).into_iter().filter(|e| e < now) {
            let id = RequestId(fstp_crypto::random_array().map_err(KeydError::Crypto)?);
            let root = RootHandle {
                chain: *chain,
                epoch,
            };
            match server.serve_logged(ClientRole::Console.code(), &Request::Destroy { id, root }) {
                Response::Destroyed(_) => {}
                Response::Refused(Refusal::GuardPending) => {
                    return Err(KeydError::Guard(crate::guard::GuardFault::Unreachable));
                }
                _ => return Err(KeydError::Io("destroy an epoch below the current one")),
            }
        }
        if !live(&server, *chain).contains(now) {
            stale = true;
        }
    }
    if stale {
        return Err(KeydError::StaleCopy);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The socket loop.

/// The servers running in this process, by socket path, with their stop
/// flags. A server with several sockets has one entry per socket, all
/// with the same flag.
static RUNNING: Mutex<Vec<(PathBuf, Arc<AtomicBool>)>> = Mutex::new(Vec::new());

fn running() -> std::sync::MutexGuard<'static, Vec<(PathBuf, Arc<AtomicBool>)>> {
    RUNNING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Runs the server over the key volume `key_volume` on the one socket
/// `socket`, for the `fstp-cell` client: it serves the App and CellBackup
/// chains only, and only the `fstp-keyd` OS user and root can connect
/// (mode 0600). It runs until [`stop`] is called for the socket.
///
/// It is [`serve_sockets`] with that one socket and the passphrase from
/// the systemd credential [`crate::PASSPHRASE_CREDENTIAL`].
///
/// # Errors
///
/// As [`serve_sockets`].
pub fn serve(socket: &Path, key_volume: &Path) -> Result<(), KeydError> {
    serve_sockets(
        &[ClientSocket::owner_only(socket, ClientRole::Cell)],
        key_volume,
        PassphraseSource::Credential,
    )
}

/// Runs the server over the key volume `key_volume` on every socket of
/// `sockets`, until [`stop`] is called for any one of them. Each socket
/// serves the chains and keys of its role only (ADR-004 part 2 "Access
/// to `fstp-keyd`").
///
/// It is [`serve_sockets_from`] with a named key volume.
///
/// # Errors
///
/// Refuses no socket or two sockets of one path, a missing passphrase
/// outside development mode, a key table that does not open, and a
/// socket that another server serves. A key volume outside ext4 and XFS
/// is not refused: it runs at reduced assurance ([`serve_sockets_from`]).
pub fn serve_sockets(
    sockets: &[ClientSocket],
    key_volume: &Path,
    source: PassphraseSource,
) -> Result<(), KeydError> {
    serve_sockets_from(sockets, key_volume, VolumeOrigin::Named, source)
}

/// Where the key volume of a start came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VolumeOrigin {
    /// The volume the install names.
    Named,
    /// A fresh directory under the system temporary directory, made in
    /// development mode because the named volume is missing
    /// ([`HostCheck::KeyVolumeTemporary`]).
    Temporary,
}

/// The I-81 assurance a start reports: the volume's own for a named
/// volume, and [`ReducedReason::TemporaryVolume`] for a temporary one,
/// which only development mode may use (I-81 NOTE of 2026-11-01).
pub(crate) fn start_assurance(
    mode: DeploymentMode,
    origin: VolumeOrigin,
    volume: Assurance,
) -> Result<Assurance, KeydError> {
    match (origin, mode) {
        (VolumeOrigin::Named, _) => Ok(volume),
        (VolumeOrigin::Temporary, DeploymentMode::Development) => {
            Ok(Assurance::Reduced(ReducedReason::TemporaryVolume))
        }
        (VolumeOrigin::Temporary, DeploymentMode::Production) => Err(KeydError::Volume(
            "a temporary key volume needs development mode",
        )),
    }
}

/// Logs a typed event. A log write that fails never stops custody.
fn log(event: &LogEvent) {
    let _ = fstp_obs::log_to_stderr(event);
}

/// As [`serve_sockets`], with the origin of the key volume.
///
/// It takes the deployment mode from `FSTP_DEPLOYMENT_MODE`
/// ([`fstp_obs::assurance::deployment_mode_from_env`]) and the I-81
/// assurance of the key volume ([`crate::check_key_volume`]). It starts
/// at reduced assurance as at full, and logs the level and its reason in
/// [`LogEvent::KeyCustodyStarted`] (I-81 NOTE of 2026-11-01). In
/// development mode, when no passphrase source answers, it uses the
/// ephemeral passphrase of the process ([`Passphrase::development`]) and
/// warns.
///
/// # Errors
///
/// As [`serve_sockets`], and [`KeydError::Mode`] for an unset mode in a
/// release build or a misspelt mode.
pub fn serve_sockets_from(
    sockets: &[ClientSocket],
    key_volume: &Path,
    origin: VolumeOrigin,
    source: PassphraseSource,
) -> Result<(), KeydError> {
    check_layout(sockets)?;
    let setup = crate::guard::link::setup_from_env()?;
    serve_guarded(sockets, key_volume, origin, source, setup)
}

/// As [`serve_sockets`], with the guard setup `setup` in place of the one
/// the environment names (ADR-004 record of lane `m10/guard-key`): a
/// pilot entry with its custodian, or a custodian with its listener.
///
/// # Errors
///
/// As [`serve_sockets_from`].
pub fn serve_sockets_with_guard(
    sockets: &[ClientSocket],
    key_volume: &Path,
    source: PassphraseSource,
    setup: crate::guard::link::GuardSetup,
) -> Result<(), KeydError> {
    serve_guarded(sockets, key_volume, VolumeOrigin::Named, source, setup)
}

fn serve_guarded(
    sockets: &[ClientSocket],
    key_volume: &Path,
    origin: VolumeOrigin,
    source: PassphraseSource,
    setup: crate::guard::link::GuardSetup,
) -> Result<(), KeydError> {
    check_layout(sockets)?;
    let choice = deployment_mode_from_env().map_err(KeydError::Mode)?;
    if choice.defaulted {
        log(&LogEvent::HostCheckWarned {
            check: HostCheck::DeploymentModeUnset,
        });
    }
    let assurance = start_assurance(
        choice.mode,
        origin,
        crate::volume::check_key_volume(key_volume),
    )?;
    let read = match source {
        PassphraseSource::Credential => Passphrase::from_credentials(),
        PassphraseSource::CredentialOrAsk => Passphrase::from_credentials_or_ask(),
    };
    let passphrase = match read {
        Ok(p) => p,
        Err(e) if choice.mode == DeploymentMode::Development => {
            let p = Passphrase::development().map_err(|_| e)?;
            log(&LogEvent::HostCheckWarned {
                check: HostCheck::PassphraseEphemeral,
            });
            p
        }
        Err(e) => return Err(e),
    };
    // H-22: owner and mode of the volume, before any key file is read.
    crate::volume::check_private_volume(key_volume, choice.mode == DeploymentMode::Development)?;
    let mut server = Server::open(key_volume, &passphrase)?;
    // ADR-004 record of lane `m10/guard-key`: a pilot entry names its
    // custodian, and the custodian names its listen address.
    let mut listener = None;
    let guarded = match setup {
        crate::guard::link::GuardSetup::None => false,
        crate::guard::link::GuardSetup::Pilot(link) => {
            server.guard = Some(link);
            server.copy_passphrase = Some(Passphrase::from_bytes(passphrase.bytes())?);
            // A rotation or a fresh copy owed from before a restart is
            // tried at once. A failure is not fatal: the next destroy and
            // the ten-minute retry try again.
            let _ = server.settle_guard();
            true
        }
        crate::guard::link::GuardSetup::Custodian(l) => {
            listener = Some(l);
            true
        }
    };
    drop(passphrase);
    // ADR-004 record of lane L16 rule 4: a copy that holds a key since
    // destroyed lowers a full assurance. A volume reason stays first.
    let assurance = match (
        assurance,
        crate::export::register_reason(key_volume, &server.table.table),
    ) {
        (Assurance::Full, Some(reason)) => Assurance::Reduced(reason),
        (a, _) => a,
    };
    // In production a pilot entry without a custodian runs at reduced
    // assurance: its copies are not guarded (I-81).
    let assurance = match (assurance, guarded, choice.mode) {
        (Assurance::Full, false, DeploymentMode::Production) => {
            Assurance::Reduced(ReducedReason::GuardMissing)
        }
        (a, _, _) => a,
    };
    log(&LogEvent::KeyCustodyStarted {
        mode: choice.mode,
        assurance,
    });
    run_sockets_with(sockets, server, listener.as_ref())
}

/// Refuses an empty socket list and two sockets of one path.
fn check_layout(sockets: &[ClientSocket]) -> Result<(), KeydError> {
    if sockets.is_empty() {
        return Err(KeydError::Io("no socket to serve"));
    }
    for (i, s) in sockets.iter().enumerate() {
        if sockets
            .iter()
            .skip(i.saturating_add(1))
            .any(|o| o.path == s.path)
        {
            return Err(KeydError::Io("two sockets share one path"));
        }
    }
    Ok(())
}

/// Asks the server of this process that serves `socket` to stop, and
/// waits until it has stopped and removed every one of its sockets.
///
/// # Errors
///
/// Returns [`KeydError::NotRunning`] when no server of this process
/// serves `socket`, and [`KeydError::Io`] when it does not stop in time.
pub fn stop(socket: &Path) -> Result<(), KeydError> {
    let flag = running()
        .iter()
        .find(|(p, _)| p == socket)
        .map(|(_, f)| Arc::clone(f))
        .ok_or(KeydError::NotRunning)?;
    flag.store(true, Ordering::SeqCst);
    let deadline = Instant::now()
        .checked_add(Duration::from_secs(STOP_WAIT_SECS))
        .ok_or(KeydError::Io("stop deadline"))?;
    while running().iter().any(|(_, f)| Arc::ptr_eq(f, &flag)) {
        if Instant::now() > deadline {
            return Err(KeydError::Io("the server did not stop in time"));
        }
        std::thread::sleep(Duration::from_millis(POLL_MILLIS));
    }
    Ok(())
}

/// Runs `server` on the one socket `socket` for the `fstp-cell` client.
#[cfg(test)]
pub(crate) fn run(socket: &Path, server: Server) -> Result<(), KeydError> {
    run_sockets(
        &[ClientSocket::owner_only(socket, ClientRole::Cell)],
        server,
    )
}

#[cfg(unix)]
#[cfg(test)]
pub(crate) fn run_sockets(sockets: &[ClientSocket], server: Server) -> Result<(), KeydError> {
    run_sockets_with(sockets, server, None)
}

/// As [`run_sockets`], and on a custodian the guard listener beside the
/// sockets (ADR-004 record of lane `m10/guard-key`). A listener that
/// stops stops the whole entry.
#[cfg(unix)]
pub(crate) fn run_sockets_with(
    sockets: &[ClientSocket],
    server: Server,
    listener: Option<&crate::guard::link::GuardListener>,
) -> Result<(), KeydError> {
    use std::os::unix::net::UnixStream;

    check_layout(sockets)?;
    let flag = Arc::new(AtomicBool::new(false));
    {
        let mut list = running();
        for s in sockets {
            if list.iter().any(|(p, _)| *p == s.path) {
                return Err(KeydError::AlreadyRunning);
            }
            if s.path.exists() && UnixStream::connect(&s.path).is_ok() {
                return Err(KeydError::AlreadyRunning);
            }
        }
        for s in sockets {
            if s.path.exists() {
                std::fs::remove_file(&s.path)
                    .map_err(|_| KeydError::Io("remove a stale socket"))?;
            }
        }
        for s in sockets {
            list.push((s.path.clone(), Arc::clone(&flag)));
        }
    }
    let server = Arc::new(Mutex::new(server));
    let result = std::thread::scope(|scope| {
        let guard = listener.map(|l| {
            let (server, flag) = (Arc::clone(&server), Arc::clone(&flag));
            scope.spawn(move || {
                let r = crate::guard::link::run_listener(l, &server, &flag);
                flag.store(true, Ordering::SeqCst);
                r
            })
        });
        let r = accept_loop(sockets, &server, &flag);
        flag.store(true, Ordering::SeqCst);
        match guard.map(std::thread::ScopedJoinHandle::join) {
            Some(Ok(Err(e))) => r.and(Err(e)),
            Some(Err(_)) => r.and(Err(KeydError::Io("the guard listener stopped"))),
            _ => r,
        }
    });
    for s in sockets {
        let _ = std::fs::remove_file(&s.path);
    }
    running().retain(|(_, f)| !Arc::ptr_eq(f, &flag));
    result
}

/// Gives back one connection place of a socket when its connection ends.
#[cfg(unix)]
struct Place<'a>(&'a AtomicUsize);

#[cfg(unix)]
impl Drop for Place<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

/// Binds every socket of `sockets` and serves each connection on its own
/// thread until `flag` is set, then waits for the open connections.
///
/// No client can hold up another. Each connection has one deadline for
/// its whole request, counted from accept, and one for its response
/// ([`CONNECTION_TIMEOUT_SECS`]). Each socket serves at most
/// [`MAX_CONNECTIONS_PER_SOCKET`] connections at once, and closes any
/// more at once, so a flood on one socket leaves the others free
/// (R-NF-08). The server state sits behind one mutex, held only while a
/// decoded request is handled.
#[cfg(unix)]
fn accept_loop(
    sockets: &[ClientSocket],
    server: &Mutex<Server>,
    flag: &AtomicBool,
) -> Result<(), KeydError> {
    let mut listeners = Vec::with_capacity(sockets.len());
    for s in sockets {
        let listener = bind(s)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| KeydError::Io("configure the socket"))?;
        listeners.push((listener, s.role, AtomicUsize::new(0)));
    }
    let mut last_copy_try = Instant::now();
    std::thread::scope(|scope| {
        while !flag.load(Ordering::SeqCst) {
            // ADR-004 "The custodian's copy": an owed fresh copy is tried
            // again every ten minutes, when no request holds the server.
            if last_copy_try.elapsed() >= COPY_RETRY {
                last_copy_try = Instant::now();
                if let Ok(mut s) = server.try_lock() {
                    s.retry_copy();
                }
            }
            let mut idle = true;
            for (listener, role, active) in &listeners {
                let Ok((stream, _)) = listener.accept() else {
                    continue;
                };
                idle = false;
                let accepted = Instant::now();
                if active.fetch_add(1, Ordering::SeqCst) >= MAX_CONNECTIONS_PER_SOCKET {
                    active.fetch_sub(1, Ordering::SeqCst);
                    drop(stream);
                    continue;
                }
                let role = *role;
                let spawned = std::thread::Builder::new()
                    .name(format!("fstp-keyd-{}", role.name()))
                    .spawn_scoped(scope, move || {
                        let _place = Place(active);
                        serve_connection(server, stream, role, accepted);
                    });
                if spawned.is_err() {
                    active.fetch_sub(1, Ordering::SeqCst);
                }
            }
            if idle {
                std::thread::sleep(Duration::from_millis(POLL_MILLIS));
            }
        }
    });
    Ok(())
}

/// Counts the private bind directories of this process.
#[cfg(unix)]
static BIND_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Binds the socket of `spec` with its permissions set before any client
/// can reach it. It binds inside a fresh directory of mode 0700 next to
/// the socket path, sets the socket's mode and group there, and then
/// renames it to its path. The rename keeps the bound inode, so the
/// listener serves the final path.
#[cfg(unix)]
fn bind(spec: &ClientSocket) -> Result<std::os::unix::net::UnixListener, KeydError> {
    use std::os::unix::fs::DirBuilderExt as _;

    let parent = spec
        .path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let seq = BIND_SEQ.fetch_add(1, Ordering::SeqCst);
    let dir = parent.join(format!(".kb{}-{seq}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::DirBuilder::new()
        .mode(0o700)
        .create(&dir)
        .map_err(|_| KeydError::Io("create the private bind directory"))?;
    let bound = bind_in(&dir.join("s"), spec);
    let _ = std::fs::remove_dir_all(&dir);
    bound
}

/// Binds `tmp`, sets its group and mode, and renames it to the path of
/// `spec`.
#[cfg(unix)]
fn bind_in(tmp: &Path, spec: &ClientSocket) -> Result<std::os::unix::net::UnixListener, KeydError> {
    use std::os::unix::fs::PermissionsExt as _;

    let listener = std::os::unix::net::UnixListener::bind(tmp)
        .map_err(|_| KeydError::Io("bind the socket"))?;
    if let Some(gid) = spec.group {
        std::os::unix::fs::chown(tmp, None, Some(gid))
            .map_err(|_| KeydError::Io("hand the socket to its client group"))?;
    }
    std::fs::set_permissions(tmp, std::fs::Permissions::from_mode(spec.mode()))
        .map_err(|_| KeydError::Io("restrict the socket"))?;
    std::fs::rename(tmp, &spec.path).map_err(|_| KeydError::Io("move the socket"))?;
    Ok(listener)
}

#[cfg(not(unix))]
#[cfg(test)]
pub(crate) fn run_sockets(sockets: &[ClientSocket], server: Server) -> Result<(), KeydError> {
    run_sockets_with(sockets, server, None)
}

#[cfg(not(unix))]
pub(crate) fn run_sockets_with(
    sockets: &[ClientSocket],
    server: Server,
    listener: Option<&crate::guard::link::GuardListener>,
) -> Result<(), KeydError> {
    let _ = (sockets, server, listener);
    Err(KeydError::Io("fstp-keyd needs a Unix host"))
}

/// The time left before `deadline`, if any.
#[cfg(unix)]
fn time_left(deadline: Instant) -> Option<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|d| !d.is_zero())
}

/// Fills `buf` from `stream` before `deadline`. Each read waits only for
/// the time left, so a client that sends a byte at a time still runs
/// out of time at the deadline.
#[cfg(unix)]
fn read_by(stream: &mut std::os::unix::net::UnixStream, buf: &mut [u8], deadline: Instant) -> bool {
    use std::io::Read as _;
    let mut filled = 0usize;
    while filled < buf.len() {
        let Some(left) = time_left(deadline) else {
            return false;
        };
        if stream.set_read_timeout(Some(left)).is_err() {
            return false;
        }
        let Some(rest) = buf.get_mut(filled..) else {
            return false;
        };
        match stream.read(rest) {
            Ok(0) => return false,
            Ok(n) => filled = filled.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    true
}

/// Writes all of `bytes` to `stream` before `deadline`.
#[cfg(unix)]
fn write_by(stream: &mut std::os::unix::net::UnixStream, bytes: &[u8], deadline: Instant) -> bool {
    use std::io::Write as _;
    let mut sent = 0usize;
    while sent < bytes.len() {
        let Some(left) = time_left(deadline) else {
            return false;
        };
        if stream.set_write_timeout(Some(left)).is_err() {
            return false;
        }
        let Some(rest) = bytes.get(sent..) else {
            return false;
        };
        match stream.write(rest) {
            Ok(0) => return false,
            Ok(n) => sent = sent.saturating_add(n),
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => return false,
        }
    }
    stream.flush().is_ok()
}

/// Reads one request from `stream`, serves it for `role` and writes the
/// response. The whole request must arrive within
/// [`CONNECTION_TIMEOUT_SECS`] of `accepted`, and the response must go
/// out within as long again. A connection that breaks the protocol gets
/// a refusal, and a broken or late connection is dropped. Neither stops
/// the server, and neither holds the server lock while it waits.
#[cfg(unix)]
fn serve_connection(
    server: &Mutex<Server>,
    mut stream: std::os::unix::net::UnixStream,
    role: ClientRole,
    accepted: Instant,
) {
    use fstp_custody::keyd::{FRAME_HEADER_LEN, frame_body_len};

    let limit = Duration::from_secs(CONNECTION_TIMEOUT_SECS);
    let Some(deadline) = accepted.checked_add(limit) else {
        return;
    };
    if stream.set_nonblocking(false).is_err() {
        return;
    }
    let mut header = [0u8; FRAME_HEADER_LEN];
    if !read_by(&mut stream, &mut header, deadline) {
        return;
    }
    let response = match frame_body_len(&header) {
        Err(_) => Response::Refused(Refusal::BadRequest),
        Ok(len) => {
            let mut frame = Zeroizing::new(vec![0u8; FRAME_HEADER_LEN.saturating_add(len)]);
            let Some((head, body)) = frame.split_at_mut_checked(FRAME_HEADER_LEN) else {
                return;
            };
            head.copy_from_slice(&header);
            if !read_by(&mut stream, body, deadline) {
                return;
            }
            let decoded = crate::request::decode_request(&frame);
            let mut server = server.lock().unwrap_or_else(PoisonError::into_inner);
            match decoded {
                Ok(request) => server.handle_as(role, &request),
                Err(_) => {
                    let id = RequestId([0u8; 16]);
                    if server.admit(role.code(), usage::OP_USAGE) {
                        let _ = server.usage.append_from(
                            role.code(),
                            id,
                            0,
                            None,
                            Refusal::BadRequest.code(),
                        );
                    }
                    Response::Refused(Refusal::BadRequest)
                }
            }
        }
    };
    let Some(deadline) = Instant::now().checked_add(limit) else {
        return;
    };
    if let Ok(bytes) = crate::request::encode_response(&response) {
        let bytes = Zeroizing::new(bytes);
        let _ = write_by(&mut stream, &bytes, deadline);
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        reason = "test code"
    )]

    use super::*;
    use fstp_custody::keyd::RequestId;

    const ID: RequestId = RequestId([7; 16]);

    /// I-81 NOTE (2026-11-01): a named volume starts at its own
    /// assurance in both modes, so a reduced volume never stops a start.
    /// A temporary volume reports `TemporaryVolume`, never `Full`, and
    /// only development mode may use one.
    #[test]
    fn i81_note_start_assurance_follows_the_volume_and_the_mode() {
        let reduced = Assurance::Reduced(ReducedReason::Apfs);
        for mode in [DeploymentMode::Production, DeploymentMode::Development] {
            for a in [Assurance::Full, reduced] {
                assert_eq!(start_assurance(mode, VolumeOrigin::Named, a), Ok(a));
            }
        }
        for a in [Assurance::Full, reduced] {
            assert_eq!(
                start_assurance(DeploymentMode::Development, VolumeOrigin::Temporary, a),
                Ok(Assurance::Reduced(ReducedReason::TemporaryVolume))
            );
            assert!(matches!(
                start_assurance(DeploymentMode::Production, VolumeOrigin::Temporary, a),
                Err(KeydError::Volume(_))
            ));
        }
    }

    /// Issue 6 L13 (ADR-024 "Key daemon usage log"): a client over the
    /// per-client rate is refused, the log stops growing at its size
    /// bound, and create and destroy are still served at the bound.
    #[test]
    fn issue6_l13_usage_log_is_bounded_per_client_and_in_size() {
        let dir = scratch("l13");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let root = create(&mut s, Chain::App, 1);
        let wrap_req = |k: u8| Request::Wrap {
            id: ID,
            root,
            aad: b"aad".to_vec(),
            key: Box::new(Zeroizing::new([k; 32])),
        };
        // Rate: three records per window, then a refusal.
        s.rate_max = 3;
        s.windows.clear();
        let mut served = 0;
        for k in 0..6 {
            if let Response::Wrapped(_) = s.handle_as(ClientRole::Cell, &wrap_req(k)) {
                served += 1;
            }
        }
        assert_eq!(served, 3);
        // Another client has its own budget.
        assert!(matches!(
            s.handle_as(ClientRole::Vault, &wrap_req(9)),
            Response::Refused(Refusal::NotPermitted)
        ));
        let len = s.usage.len();
        let _ = s.handle_as(ClientRole::Cell, &wrap_req(7));
        assert_eq!(s.usage.len(), len, "a refused request wrote a record");
        // Size: at the bound, wrap is refused and create and destroy serve.
        s.rate_max = u32::MAX;
        s.log_max = s.usage.len();
        assert_eq!(
            s.handle_as(ClientRole::Cell, &wrap_req(8)),
            Response::Refused(Refusal::LimitReached)
        );
        let h2 = RootHandle {
            chain: Chain::App,
            epoch: Epoch(2),
        };
        let made = s.handle_as(
            ClientRole::Cell,
            &Request::CreateRoot {
                id: ID,
                cell: None,
                chain: Chain::App,
                epoch: Epoch(2),
            },
        );
        assert!(matches!(made, Response::Root(_)), "{made:?}");
        let gone = s.handle_as(ClientRole::Cell, &Request::Destroy { id: ID, root: h2 });
        assert!(matches!(gone, Response::Destroyed(_)), "{gone:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fstp-keyd-unit-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pass() -> Passphrase {
        Passphrase::from_bytes(b"synthetic unit test passphrase").unwrap()
    }

    fn create(s: &mut Server, chain: Chain, e: u64) -> RootHandle {
        match s.handle(&Request::CreateRoot {
            id: ID,
            cell: None,
            chain,
            epoch: Epoch(e),
        }) {
            Response::Root(h) => h,
            other => panic!("create: {other:?}"),
        }
    }

    fn wrap(s: &mut Server, root: RootHandle, key: [u8; 32]) -> Response {
        s.handle(&Request::Wrap {
            id: ID,
            root,
            aad: b"aad".to_vec(),
            key: Box::new(Zeroizing::new(key)),
        })
    }

    fn unwrap(s: &mut Server, root: RootHandle, wrapped: &[u8]) -> Response {
        s.handle(&Request::Unwrap {
            id: ID,
            root,
            aad: b"aad".to_vec(),
            wrapped: wrapped.to_vec(),
        })
    }

    /// I-80, I-81, ADR-004 part 2: a root wraps and unwraps across a
    /// restart, and after destroy neither it nor a written-back copy of
    /// its epoch file opens. The volume check is skipped, so this runs
    /// on any host.
    #[test]
    fn i81_keyd_server_destroy_survives_a_restart_and_a_remnant() {
        let dir = scratch("destroy");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r1 = create(&mut s, Chain::App, 1);
        let r2 = create(&mut s, Chain::App, 2);
        let Response::Wrapped(w1) = wrap(&mut s, r1, [1; 32]) else {
            panic!("wrap 1");
        };
        let Response::Wrapped(w2) = wrap(&mut s, r2, [2; 32]) else {
            panic!("wrap 2");
        };
        let remnant = std::fs::read(epoch::path(&dir, Chain::App, Epoch(1))).unwrap();
        let receipt = s.handle(&Request::Destroy { id: ID, root: r1 });
        let Response::Destroyed(rb) = &receipt else {
            panic!("destroy: {receipt:?}");
        };
        assert_eq!(
            crate::decode_receipt(rb).unwrap().steps,
            crate::DestroyStep::ALL.to_vec()
        );
        assert_eq!(s.handle(&Request::Destroy { id: ID, root: r1 }), receipt);
        drop(s);
        std::fs::write(epoch::path(&dir, Chain::App, Epoch(1)), &remnant).unwrap();
        let mut s = Server::open(&dir, &pass()).unwrap();
        assert_eq!(
            unwrap(&mut s, r1, &w1),
            Response::Refused(Refusal::Destroyed)
        );
        assert_eq!(
            unwrap(&mut s, r2, &w2),
            Response::Unwrapped(Box::new(Zeroizing::new([2; 32])))
        );
        assert!(Server::open(&dir, &Passphrase::from_bytes(b"another").unwrap()).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// I-80, I-81, ADR-004 part 2: the socket protocol end to end, with
    /// the `KeydCustody` client of `fstp-custody`. The socket admits only
    /// its owner, a second destroy returns the same receipt, the usage
    /// log records each operation, and `stop` ends the server. The volume
    /// check and the credential lookup are skipped, so this runs on any
    /// Unix host.
    #[cfg(unix)]
    #[test]
    fn adr004_keyd_socket_round_trip_with_the_custody_client() {
        use fstp_custody::{Aad, CellId, Custody as _, RootLabel, SealKey, UsageCursor};
        use fstp_rt::future::block_on;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("socket");
        let socket = dir.join("keyd.sock");
        let volume = dir.join("keys");
        std::fs::create_dir_all(&volume).unwrap();
        let server = Server::open(&volume, &pass()).unwrap();
        let handle = {
            let socket = socket.clone();
            std::thread::spawn(move || run(&socket, server))
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "no socket");
            std::thread::sleep(Duration::from_millis(5));
        }
        let mode = std::fs::metadata(&socket).unwrap().permissions().mode();
        assert_eq!(mode & 0o077, 0, "socket mode {mode:o}");
        let client = fstp_custody::KeydCustody::new(&socket).unwrap();
        let label = RootLabel {
            cell: Some(CellId([3; 16])),
            chain: Chain::App,
            epoch: Epoch(1),
        };
        let aad = Aad(b"round trip".to_vec());
        let root = block_on(client.create_root(label)).unwrap();
        let w = block_on(client.wrap(&root, &SealKey::from_bytes([5; 32]), &aad)).unwrap();
        let back = block_on(client.unwrap(&root, &w, &aad)).unwrap();
        assert_eq!(back.expose(), &[5; 32]);
        assert!(block_on(client.unwrap(&root, &w, &Aad(b"x".to_vec()))).is_err());
        let first = block_on(client.destroy(&root)).unwrap();
        let again = block_on(client.destroy(&root)).unwrap();
        assert_eq!(first, again);
        assert!(block_on(client.unwrap(&root, &w, &aad)).is_err());
        let page = block_on(client.usage_since(&root, UsageCursor::default())).unwrap();
        assert!(page.operations.len() >= 5, "{page:?}");
        stop(&socket).unwrap();
        handle.join().unwrap().unwrap();
        assert!(!socket.exists(), "the socket is left after stop");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// ADR-004 part 2: a wrapped key opens under no other root, chain or
    /// AAD, and a create of an older epoch is refused.
    #[test]
    fn adr004_keyd_server_binds_root_and_aad() {
        let dir = scratch("bind");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let a1 = create(&mut s, Chain::App, 1);
        let a2 = create(&mut s, Chain::App, 2);
        let v1 = create(&mut s, Chain::Vault, 1);
        assert_eq!(create(&mut s, Chain::App, 2), a2);
        assert_eq!(
            s.handle(&Request::CreateRoot {
                id: ID,
                cell: None,
                chain: Chain::App,
                epoch: Epoch(1),
            }),
            Response::Root(a1)
        );
        let Response::Wrapped(w) = wrap(&mut s, a1, [9; 32]) else {
            panic!("wrap");
        };
        for other in [a2, v1] {
            assert_eq!(
                unwrap(&mut s, other, &w),
                Response::Refused(Refusal::UnwrapFailed)
            );
        }
        let other_aad = s.handle(&Request::Unwrap {
            id: ID,
            root: a1,
            aad: b"other".to_vec(),
            wrapped: w.clone(),
        });
        assert_eq!(other_aad, Response::Refused(Refusal::UnwrapFailed));
        assert_eq!(
            unwrap(&mut s, a1, &w),
            Response::Unwrapped(Box::new(Zeroizing::new([9; 32])))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// I-81, ADR-004 part 2 "Epochs": "Provisioning creates epoch 1 of
    /// each chain", and a rotation goes from `e` to `e + 1`. A create
    /// that skips an epoch is refused, so a destroy receipt never
    /// confirms a root that never existed: a destroy of an epoch that
    /// was never created answers `UnknownRoot`, before and after a
    /// restart.
    #[test]
    fn i81_keyd_destroy_of_a_never_created_epoch_gets_no_receipt() {
        let dir = scratch("gaps");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let mut wrong = Vec::new();
        let try_create = |s: &mut Server, chain, e| {
            s.handle(&Request::CreateRoot {
                id: ID,
                cell: None,
                chain,
                epoch: Epoch(e),
            })
        };
        let bad = Response::Refused(Refusal::BadRequest);
        if try_create(&mut s, Chain::Vault, 2) != bad {
            wrong.push("a chain started at epoch 2");
        }
        create(&mut s, Chain::App, 1);
        if try_create(&mut s, Chain::App, 3) != bad {
            wrong.push("App 1 was followed by App 3");
        }
        create(&mut s, Chain::App, 2);
        let destroy = |s: &mut Server, chain, e| {
            s.handle(&Request::Destroy {
                id: ID,
                root: RootHandle {
                    chain,
                    epoch: Epoch(e),
                },
            })
        };
        let unknown = Response::Refused(Refusal::UnknownRoot);
        for (chain, e) in [(Chain::App, 0), (Chain::App, 3), (Chain::Vault, 2)] {
            if destroy(&mut s, chain, e) != unknown {
                wrong.push("a never created epoch got an answer other than UnknownRoot");
            }
        }
        if !matches!(destroy(&mut s, Chain::App, 1), Response::Destroyed(_)) {
            wrong.push("App 1 did not destroy");
        }
        drop(s);
        let mut s = Server::open(&dir, &pass()).unwrap();
        if destroy(&mut s, Chain::App, 3) != unknown {
            wrong.push("after a restart, App 3 got an answer other than UnknownRoot");
        }
        let _ = std::fs::remove_dir_all(&dir);
        assert!(wrong.is_empty(), "{wrong:?}");
    }

    /// I-81, ADR-004 part 2 "A crash at any step loses nothing": a
    /// partial slot at the end of the key table, as a short append
    /// leaves it, does not fail a destroy's read back. The destroy still
    /// gets its receipt, and the next start overwrites that slot.
    #[test]
    fn i81_keyd_destroy_reads_back_past_a_partial_slot() {
        let dir = scratch("partial-read-back");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r1 = create(&mut s, Chain::App, 1);
        create(&mut s, Chain::App, 2);
        let table = dir.join(crate::table::TABLE_FILE);
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&table)
            .unwrap();
        std::io::Write::write_all(&mut file, &[0x77; 30]).unwrap();
        drop(file);
        let destroyed = s.handle(&Request::Destroy { id: ID, root: r1 });
        drop(s);
        let reopened = Server::open(&dir, &pass()).map(|_| ());
        let len = std::fs::metadata(&table).unwrap().len();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(matches!(destroyed, Response::Destroyed(_)), "{destroyed:?}");
        assert!(reopened.is_ok(), "{reopened:?}");
        let whole = len
            .checked_sub(u64::try_from(crate::table::PREFIX_LEN).unwrap())
            .unwrap();
        assert_eq!(
            whole % u64::try_from(crate::table::SLOT_LEN).unwrap(),
            0,
            "the partial slot was not repaired"
        );
    }

    /// R-NF-08, ADR-028 "Witness custody": the witness role has its own
    /// socket name and usage code, reaches the ControlPlane chain only, and
    /// signs and creates no CA key.
    #[test]
    fn r_nf_08_witness_role_reaches_control_plane_only() {
        let w = ClientRole::Witness;
        assert_eq!(w.chains(), &[Chain::ControlPlane]);
        assert!(w.sign_keys().is_empty() && w.creates_sign_keys().is_empty());
        let names: Vec<&str> = ClientRole::ALL.iter().map(|r| r.name()).collect();
        let codes: Vec<u8> = ClientRole::ALL.iter().map(|r| r.code()).collect();
        for (i, r) in ClientRole::ALL.iter().enumerate() {
            assert_eq!(names.iter().filter(|n| **n == r.name()).count(), 1, "{i}");
            assert_eq!(codes.iter().filter(|c| **c == r.code()).count(), 1, "{i}");
        }
        let dir = scratch("witness-role");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r = s.handle_as(
            w,
            &Request::CreateRoot {
                id: ID,
                cell: None,
                chain: Chain::ControlPlane,
                epoch: Epoch(1),
            },
        );
        assert!(matches!(r, Response::Root(_)), "{r:?}");
        let r = s.handle_as(
            w,
            &Request::CreateRoot {
                id: ID,
                cell: None,
                chain: Chain::Vault,
                epoch: Epoch(1),
            },
        );
        assert_eq!(r, Response::Refused(Refusal::NotPermitted));
    }

    /// R-NF-08, ADR-004 part 2 "Access to `fstp-keyd`": each socket role
    /// reaches only its own chains and keys. Every other request is
    /// refused with `NotPermitted` and logged with the client's role.
    #[test]
    fn r_nf_08_keyd_role_reaches_only_its_chains() {
        let dir = scratch("roles");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let mut wrong = Vec::new();
        for role in ClientRole::ALL {
            for chain in Chain::ALL {
                let r = s.handle_as(
                    role,
                    &Request::CreateRoot {
                        id: ID,
                        cell: None,
                        chain,
                        epoch: Epoch(1),
                    },
                );
                let allowed = role.chains().contains(&chain);
                if allowed != matches!(r, Response::Root(_)) {
                    wrong.push(format!("{role:?} {chain:?}: {r:?}"));
                }
                if !allowed && r != Response::Refused(Refusal::NotPermitted) {
                    wrong.push(format!("{role:?} {chain:?}: not NotPermitted"));
                }
            }
            // ADR-004 part 2 "CA keys in custody": the cell CA key sits
            // in the App custody entry, so only the cell socket signs
            // with it. Only the pgagent socket signs with a cluster CA
            // key. A handle of no known class is refused to every role.
            let cell_ca = [fstp_custody::keyd::SIGN_KEY_CELL_CA, b'c'];
            let cluster_ca = [fstp_custody::keyd::SIGN_KEY_CLUSTER_CA, b'p'];
            let cases: [(&[u8], bool); 4] = [
                (&cell_ca, role == ClientRole::Cell),
                (&cluster_ca, role == ClientRole::PgAgent),
                (b"ca", false),
                (&[fstp_custody::keyd::SIGN_KEY_CELL_CA], false),
            ];
            for (handle, allowed) in cases {
                let signed = s.handle_as(
                    role,
                    &Request::Sign {
                        id: ID,
                        key: handle.to_vec(),
                        digest: [0; 32],
                    },
                );
                let want = if allowed {
                    Refusal::NoSignKey
                } else {
                    Refusal::NotPermitted
                };
                if signed != Response::Refused(want) || role.signs_with(handle) != allowed {
                    wrong.push(format!("{role:?} sign {handle:?}: {signed:?}"));
                }
            }
        }
        let app = RootHandle {
            chain: Chain::App,
            epoch: Epoch(1),
        };
        let page = s.handle_as(
            ClientRole::Cell,
            &Request::UsageSince {
                id: ID,
                root: app,
                cursor: 0,
            },
        );
        let Response::Usage { records, .. } = page else {
            panic!("usage: {page:?}");
        };
        let clients: Vec<u8> = records.iter().filter_map(|r| r.get(36).copied()).collect();
        if !clients.contains(&ClientRole::Cell.code())
            || !clients.contains(&ClientRole::Vault.code())
        {
            wrong.push(format!("the usage log names clients {clients:?}"));
        }
        assert!(wrong.is_empty(), "{wrong:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-NF-08, ADR-004 part 2 "Access to `fstp-keyd`": one server binds
    /// the `fstp-cell` and the `fstp-vault` socket. Each serves its own
    /// chains only, both sockets admit only their owner, and one `stop`
    /// ends the server and removes both.
    #[cfg(unix)]
    #[test]
    fn r_nf_08_keyd_cell_and_vault_sockets_serve_their_own_chains() {
        use fstp_custody::{Custody as _, CustodyError, RootLabel};
        use fstp_rt::future::block_on;
        use std::os::unix::fs::PermissionsExt as _;

        let dir = scratch("two-sockets");
        let volume = dir.join("keys");
        std::fs::create_dir_all(&volume).unwrap();
        let sockets = vec![
            ClientSocket::owner_only(&dir.join("cell.sock"), ClientRole::Cell),
            ClientSocket::owner_only(&dir.join("vault.sock"), ClientRole::Vault),
        ];
        let server = Server::open(&volume, &pass()).unwrap();
        let handle = {
            let sockets = sockets.clone();
            std::thread::spawn(move || run_sockets(&sockets, server))
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !sockets.iter().all(|s| s.path.exists()) {
            assert!(Instant::now() < deadline, "no sockets");
            std::thread::sleep(Duration::from_millis(5));
        }
        for s in &sockets {
            let mode = std::fs::metadata(&s.path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "socket mode {mode:o}");
        }
        let cell = fstp_custody::KeydCustody::new(&sockets[0].path).unwrap();
        let vault = fstp_custody::KeydCustody::new(&sockets[1].path).unwrap();
        let label = |chain| RootLabel {
            cell: None,
            chain,
            epoch: Epoch(1),
        };
        let refused = Err(CustodyError::Refused(Refusal::NotPermitted));
        let app = block_on(cell.create_root(label(Chain::App)));
        let vault_by_cell = block_on(cell.create_root(label(Chain::Vault))).map(|_| ());
        let vault_root = block_on(vault.create_root(label(Chain::Vault)));
        let app_by_vault = block_on(vault.create_root(label(Chain::App))).map(|_| ());
        stop(&sockets[1].path).unwrap();
        handle.join().unwrap().unwrap();
        let left: Vec<bool> = sockets.iter().map(|s| s.path.exists()).collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(app.is_ok(), "{app:?}");
        assert!(vault_root.is_ok(), "{vault_root:?}");
        assert_eq!(vault_by_cell, refused);
        assert_eq!(app_by_vault, refused);
        assert_eq!(left, [false, false], "a socket is left after stop");
    }

    /// I-81, ADR-004 part 2: rotation after rotation, the key table keeps
    /// only the live entries and the newest destroyed one per chain. Its
    /// file stays a few slots long, an older epoch is still refused for
    /// create, and a retried destroy of any old epoch still gets its
    /// receipt.
    #[test]
    fn i81_keyd_table_reclaims_destroyed_slots() {
        let dir = scratch("reclaim");
        let mut s = Server::open(&dir, &pass()).unwrap();
        create(&mut s, Chain::App, 1);
        create(&mut s, Chain::Vault, 1);
        for e in 2..=40 {
            create(&mut s, Chain::App, e);
            let old = RootHandle {
                chain: Chain::App,
                epoch: Epoch(e - 1),
            };
            let r = s.handle(&Request::Destroy { id: ID, root: old });
            assert!(matches!(r, Response::Destroyed(_)), "destroy {e}: {r:?}");
        }
        let len = std::fs::metadata(dir.join(crate::table::TABLE_FILE))
            .unwrap()
            .len();
        let most = crate::table::PREFIX_LEN + 4 * crate::table::SLOT_LEN;
        assert!(
            len <= u64::try_from(most).unwrap(),
            "the key table grew to {len} bytes"
        );
        drop(s);
        let mut s = Server::open(&dir, &pass()).unwrap();
        let stale = s.handle(&Request::CreateRoot {
            id: ID,
            cell: None,
            chain: Chain::App,
            epoch: Epoch(3),
        });
        assert_eq!(stale, Response::Refused(Refusal::StaleEpoch));
        let again = s.handle(&Request::Destroy {
            id: ID,
            root: RootHandle {
                chain: Chain::App,
                epoch: Epoch(3),
            },
        });
        let Response::Destroyed(rb) = again else {
            panic!("a retried destroy: {again:?}");
        };
        let receipt = crate::decode_receipt(&rb).unwrap();
        assert_eq!((receipt.chain, receipt.epoch), (Chain::App, Epoch(3)));
        let live = RootHandle {
            chain: Chain::App,
            epoch: Epoch(40),
        };
        let Response::Wrapped(w) = wrap(&mut s, live, [4; 32]) else {
            panic!("the live root does not wrap");
        };
        assert_eq!(
            unwrap(&mut s, live, &w),
            Response::Unwrapped(Box::new(Zeroizing::new([4; 32])))
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-SW-02, ADR-004 "CA keys in custody", R-NF-08: a sign key destroy
    /// follows the sign rules of each socket role. The cell socket
    /// reaches cell CA handles only, the pgagent socket cluster CA handles
    /// only, and every other request is `NotPermitted`. The server holds
    /// no sign key yet, so a permitted destroy finds none. Each request is
    /// logged as a sign key destroy with its client and outcome, and no
    /// root is touched.
    #[test]
    fn r_sw_02_keyd_sign_key_destroy_follows_the_sign_rules() {
        let dir = scratch("destroy-sign-key");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let app = create(&mut s, Chain::App, 1);
        let cell_ca = [fstp_custody::keyd::SIGN_KEY_CELL_CA, b'c'];
        let cluster_ca = [fstp_custody::keyd::SIGN_KEY_CLUSTER_CA, b'p'];
        let mut want_log = Vec::new();
        for role in ClientRole::ALL {
            for handle in [&cell_ca[..], &cluster_ca[..], b"ca"] {
                let r = s.handle_as(
                    role,
                    &Request::DestroySignKey {
                        id: ID,
                        key: handle.to_vec(),
                    },
                );
                let want = if role.signs_with(handle) {
                    Refusal::NoSignKey
                } else {
                    Refusal::NotPermitted
                };
                assert_eq!(r, Response::Refused(want), "{role:?} {handle:?}");
                want_log.push((role.code(), want.code()));
            }
        }
        let log = std::fs::read(dir.join(usage::USAGE_FILE)).unwrap();
        let got: Vec<(u8, u8)> = log
            .chunks_exact(usage::RECORD_LEN)
            .filter(|r| r.get(17) == Some(&usage::OP_DESTROY_SIGN_KEY))
            .filter_map(|r| Some((*r.get(36)?, *r.get(35)?)))
            .collect();
        assert_eq!(got, want_log);
        let Response::Wrapped(_) = wrap(&mut s, app, [5; 32]) else {
            panic!("a sign key destroy touched the App root");
        };
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// R-SW-02, I-81, ADR-004 "Decided by Daniel, 2026-11-15 (late)": the
    /// console socket creates a local cluster CA key in a sign-key slot of
    /// the key table, and a retried create finds the same key. The
    /// pgagent socket signs with it, and the signature verifies under the
    /// public key the create answered. A destroy overwrites the slot in
    /// place, unlinks the sign-key file and answers the full receipt,
    /// also when retried, and after a restart. The destroyed key neither
    /// signs nor is created again, and the root slots stay usable.
    #[test]
    fn r_sw_02_keyd_sign_key_slot_is_created_used_and_destroyed_in_place() {
        let dir = scratch("sign-key-slot");
        let handle = {
            let mut h = vec![fstp_custody::keyd::SIGN_KEY_CLUSTER_CA];
            h.extend_from_slice(b"cluster1");
            h
        };
        let name = SignKeyName::from_handle(&handle).unwrap();
        let mut s = Server::open(&dir, &pass()).unwrap();
        let app = create(&mut s, Chain::App, 1);
        let create_key = |s: &mut Server, role| {
            s.handle_as(
                role,
                &Request::CreateSignKey {
                    id: ID,
                    key: handle.clone(),
                },
            )
        };
        for role in [ClientRole::Cell, ClientRole::Vault, ClientRole::PgAgent] {
            assert_eq!(
                create_key(&mut s, role),
                Response::Refused(Refusal::NotPermitted),
                "{role:?} created a cluster CA key"
            );
        }
        let Response::SignKey(spki) = create_key(&mut s, ClientRole::Console) else {
            panic!("the console created no cluster CA key");
        };
        assert_eq!(
            create_key(&mut s, ClientRole::Console),
            Response::SignKey(spki.clone()),
            "a retried create made another key"
        );
        assert!(crate::sign_key::path(&dir, name).exists());
        let message = b"tbs certificate bytes";
        let digest = fstp_crypto::sha256(message);
        let sign = |s: &mut Server| {
            s.handle_as(
                ClientRole::PgAgent,
                &Request::Sign {
                    id: ID,
                    key: handle.clone(),
                    digest,
                },
            )
        };
        let Response::Signed(sig) = sign(&mut s) else {
            panic!("the pgagent socket did not sign");
        };
        assert!(fstp_crypto::sig::ecdsa_p256_sha256_verify(&spki, message, &sig).is_ok());
        let slot_bytes = std::fs::read(dir.join(crate::table::TABLE_FILE)).unwrap();
        let destroy = |s: &mut Server| {
            s.handle_as(
                ClientRole::PgAgent,
                &Request::DestroySignKey {
                    id: ID,
                    key: handle.clone(),
                },
            )
        };
        let Response::Destroyed(receipt) = destroy(&mut s) else {
            panic!("the destroy issued no receipt");
        };
        let decoded = fstp_custody::keyd::decode_sign_receipt(&receipt).unwrap();
        assert_eq!(decoded.handle, handle);
        assert_eq!(decoded.steps, fstp_custody::keyd::DestroyStep::ALL.to_vec());
        let after = std::fs::read(dir.join(crate::table::TABLE_FILE)).unwrap();
        assert_eq!(
            after.len(),
            slot_bytes.len(),
            "the destroy did not write in place"
        );
        assert_ne!(after, slot_bytes, "the destroy left the slot as it was");
        assert!(!crate::sign_key::path(&dir, name).exists());
        assert_eq!(destroy(&mut s), Response::Destroyed(receipt.clone()));
        assert_eq!(sign(&mut s), Response::Refused(Refusal::Destroyed));
        assert_eq!(
            create_key(&mut s, ClientRole::Console),
            Response::Refused(Refusal::Destroyed)
        );
        let Response::Wrapped(_) = wrap(&mut s, app, [6; 32]) else {
            panic!("the sign key destroy touched the App root");
        };
        drop(s);
        let mut s = Server::open(&dir, &pass()).unwrap();
        assert_eq!(destroy(&mut s), Response::Destroyed(receipt));
        assert_eq!(sign(&mut s), Response::Refused(Refusal::Destroyed));
        let table = crate::table::open_key_table(&dir, &pass()).unwrap();
        assert!(table.sign_key(name).is_some_and(|e| !e.is_live()));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

/// Review reproducers (independent review of lane W2f). Each fails on
/// the current code and passes once its defect is fixed.
#[cfg(test)]
mod review {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        reason = "test code"
    )]

    use super::*;

    const ID: RequestId = RequestId([9; 16]);

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fstp-keyd-rob-review-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn pass() -> Passphrase {
        Passphrase::from_bytes(b"synthetic review passphrase").unwrap()
    }

    /// ADR-004 part 2 "Access to fstp-keyd", R-NF-08: each socket serves
    /// a fixed set of chains, so the `fstp-cell` socket reaches App and
    /// CellBackup and never Vault. Here one socket creates both an App
    /// and a Vault root for the same client, so a cell connection could
    /// unwrap the vault's `S(e)`.
    #[cfg(unix)]
    #[test]
    fn review_keyd_one_socket_serves_every_chain() {
        use fstp_custody::{Custody as _, RootLabel};
        use fstp_rt::future::block_on;

        let dir = scratch("chains");
        let socket = dir.join("keyd.sock");
        let volume = dir.join("keys");
        std::fs::create_dir_all(&volume).unwrap();
        let server = Server::open(&volume, &pass()).unwrap();
        let handle = {
            let socket = socket.clone();
            std::thread::spawn(move || run(&socket, server))
        };
        let deadline = Instant::now() + Duration::from_secs(30);
        while !socket.exists() {
            assert!(Instant::now() < deadline, "no socket");
            std::thread::sleep(Duration::from_millis(5));
        }
        let client = fstp_custody::KeydCustody::new(&socket).unwrap();
        let app = block_on(client.create_root(RootLabel {
            cell: None,
            chain: Chain::App,
            epoch: Epoch(1),
        }));
        let vault = block_on(client.create_root(RootLabel {
            cell: None,
            chain: Chain::Vault,
            epoch: Epoch(1),
        }));
        stop(&socket).unwrap();
        handle.join().unwrap().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(app.is_ok(), "the App root: {app:?}");
        assert!(
            vault.is_err(),
            "one keyd socket served both the App and the Vault chain to one client"
        );
    }

    /// ADR-004 part 2 "A crash at any step loses nothing", design section
    /// 3.5: a crash part way through the in-place rewrite of the key
    /// table, here during the create of `R(e+1)` (step 3), must not lose
    /// the live `R(e)`. `write_in_place` overwrites the only copy of the
    /// table, so a torn write leaves a table that never opens again.
    #[test]
    fn review_keyd_torn_key_table_write_loses_every_root() {
        let dir = scratch("torn");
        let mut s = Server::open(&dir, &pass()).unwrap();
        let r1 = match s.handle(&Request::CreateRoot {
            id: ID,
            cell: None,
            chain: Chain::App,
            epoch: Epoch(1),
        }) {
            Response::Root(h) => h,
            other => panic!("create 1: {other:?}"),
        };
        let wrapped = match s.handle(&Request::Wrap {
            id: ID,
            root: r1,
            aad: b"aad".to_vec(),
            key: Box::new(Zeroizing::new([1; 32])),
        }) {
            Response::Wrapped(w) => w,
            other => panic!("wrap: {other:?}"),
        };
        let table = dir.join(crate::table::TABLE_FILE);
        let old = std::fs::read(&table).unwrap();
        let created = s.handle(&Request::CreateRoot {
            id: ID,
            cell: None,
            chain: Chain::App,
            epoch: Epoch(2),
        });
        assert!(
            matches!(created, Response::Root(_)),
            "create 2: {created:?}"
        );
        let new = std::fs::read(&table).unwrap();
        drop(s);
        // The state a crash leaves half way through `write_all` of the
        // second create: the new bytes up to the cut, the old ones after.
        let cut = old.len() / 2;
        let mut torn = new[..cut].to_vec();
        torn.extend_from_slice(&old[cut..]);
        std::fs::write(&table, &torn).unwrap();
        let reopened = Server::open(&dir, &pass());
        let unwrapped = reopened.map(|mut s| {
            s.handle(&Request::Unwrap {
                id: ID,
                root: r1,
                aad: b"aad".to_vec(),
                wrapped,
            })
        });
        let _ = std::fs::remove_dir_all(&dir);
        match unwrapped {
            Ok(r) => assert_eq!(r, Response::Unwrapped(Box::new(Zeroizing::new([1; 32])))),
            Err(e) => panic!("a torn key table write lost every root: {e:?}"),
        }
    }
}
