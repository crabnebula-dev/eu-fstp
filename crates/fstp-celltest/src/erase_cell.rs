//! The cell erasure of a test world: the `erase-cell` cycle step (R-SW-02,
//! design section 3.7, ADR-004 "CA keys in custody", ADR-011). Lane
//! m3/erase-cell. Test only.
//!
//! No world part runs `fstp-control` as a process. So the harness plays
//! the control plane in the test process, with the production parts:
//!
//! - **Operators.** Two staff members, each with a software passkey
//!   pinned in an [`OperatorLogin`] for [`CONTROL_HOST`]. Each logs in and
//!   approves the cell's `erase-cell` digest with a fresh passkey
//!   assertion, in their own session. The first then asks for the job,
//!   which [`OperatorLogin::authorise_destructive`] admits.
//! - **The job.** [`fstp_control::erase::erase_cell`] destroys every live
//!   root of the cell's custody, which holds the App, Vault and CellBackup
//!   chains of the cell, and the cell CA key. Each custody call is logged
//!   in the operator login before it is made.
//! - **The control-plane key.** One composite key per process, held in
//!   the test process (`control_plane_key`). Its custody is not modelled,
//!   as for the ClusterBackup keys of [`crate::backups`].
//! - **The confirmation** is kept with the cell, and
//!   [`World::cell_erasure`] gives it with the control plane's public key.
//!
//! Interim, pending Daniel: the world runs no `fstp-pgagent` and no edge,
//! so it runs design steps 1 and 4 only, through `erase_cell`. Steps 1 to
//! 3 in order run through `fstp_control::erase::erase_cell_steps` in the
//! tests of `fstp-control`, over real agents of an application and a
//! vault cluster (lane m3/erase-cell-2). The world's cell keeps running
//! with its keys gone.

use std::sync::OnceLock;

use fstp_control::approval::DestructiveJob;
use fstp_control::erase::{ErasureConfirmation, SignKeyCustody, erase_cell};
use fstp_control::operator::{OperatorLogin, OperatorSession, Purpose, StaffCredential};
use fstp_cp_proto::{CellId, StaffRef};
use fstp_crypto::composite::{self, CompositeSigningKey};
use fstp_crypto::sig::Ed25519SigningKey;
use fstp_custody::{CustodyError, DestroyReceipt, Refusal, SignKeyRef};
use fstp_webauthn::{AssertionResponse, CoseKey};

use crate::soft_authn::{Ceremony, client_data_json};
use crate::world::{CellHandle, World, WorldCustody, WorldError};

/// The control-plane host the world's staff passkeys assert for.
pub const CONTROL_HOST: &str = "control.fstp.localhost";

fn err(what: &str, e: &dyn std::fmt::Display) -> WorldError {
    WorldError::Store(format!("erase-cell: {what}: {e}"))
}

impl SignKeyCustody for WorldCustody {
    fn destroy_sign_key(
        &self,
        key: &SignKeyRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        std::future::ready(if self.remove_sign_key(&key.handle.0) {
            Ok(DestroyReceipt(key.handle.0.clone()))
        } else {
            Err(CustodyError::Refused(Refusal::NoSignKey))
        })
    }
}

/// The control plane's composite key of this process.
fn control_plane_key() -> Result<&'static CompositeSigningKey, WorldError> {
    static KEY: OnceLock<CompositeSigningKey> = OnceLock::new();
    if let Some(k) = KEY.get() {
        return Ok(k);
    }
    let k = composite::generate().map_err(|e| err("the control-plane key", &e))?;
    Ok(KEY.get_or_init(|| k))
}

/// A software passkey of one staff member, with user verification.
struct StaffPasskey {
    staff: StaffRef,
    id: Vec<u8>,
    key: Ed25519SigningKey,
    count: u32,
}

impl StaffPasskey {
    fn new() -> Result<StaffPasskey, WorldError> {
        let rand = |what| fstp_crypto::random_array::<16>().map_err(|e| err(what, &e));
        Ok(StaffPasskey {
            staff: StaffRef(rand("a staff id")?),
            id: rand("a credential id")?.to_vec(),
            key: Ed25519SigningKey::generate().map_err(|e| err("a staff passkey", &e))?,
            count: 0,
        })
    }

    fn pinned(&self) -> StaffCredential {
        StaffCredential {
            staff: self.staff,
            credential_id: self.id.clone(),
            key: CoseKey::Ed25519 {
                x: self.key.public_key(),
            },
        }
    }

    /// An assertion over `challenge` with the UP and UV flags.
    fn assert(&mut self, challenge: &[u8; 32]) -> Result<AssertionResponse, WorldError> {
        self.count = self.count.saturating_add(1);
        let mut auth = fstp_crypto::sha256(CONTROL_HOST.as_bytes()).to_vec();
        auth.push(0x05);
        auth.extend_from_slice(&self.count.to_be_bytes());
        let client = client_data_json(Ceremony::Get, challenge, &format!("https://{CONTROL_HOST}"));
        let mut message = auth.clone();
        message.extend_from_slice(&fstp_crypto::sha256(&client));
        Ok(AssertionResponse {
            credential_id: self.id.clone(),
            client_data_json: client,
            authenticator_data: auth,
            signature: self
                .key
                .sign(&message)
                .map_err(|e| err("an assertion", &e))?
                .to_vec(),
        })
    }

    fn log_in(
        &mut self,
        login: &mut OperatorLogin,
        now: i64,
    ) -> Result<OperatorSession, WorldError> {
        let c = login
            .begin(Purpose::Login, now)
            .map_err(|e| err("a staff login", &e))?;
        let a = self.assert(&c)?;
        Ok(login
            .finish_login(c, &a, now)
            .map_err(|e| err("a staff login", &e))?
            .0)
    }

    fn approve(
        &mut self,
        login: &mut OperatorLogin,
        session: OperatorSession,
        job: &DestructiveJob,
        now: i64,
    ) -> Result<(), WorldError> {
        let c = login
            .begin_approval(session, job, now)
            .map_err(|e| err("an approval", &e))?;
        let a = self.assert(&c)?;
        login
            .finish_approval(session, c, &a, now)
            .map_err(|e| err("an approval", &e))?;
        Ok(())
    }
}

fn now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
}

/// `erase-cell`: two operators approve the cell's erasure, and the
/// control plane runs it over the cell's custody (module documentation).
///
/// # Errors
///
/// Fails when the cell was erased already, runs no custody, or a staff
/// ceremony, the two-operator check or a custody call refuses.
pub(crate) fn erase(cell: &CellHandle) -> Result<(), WorldError> {
    if cell.backups.erasure.get().is_some() {
        return Err(err("the cell", &"is erased already"));
    }
    let mut a = StaffPasskey::new()?;
    let mut b = StaffPasskey::new()?;
    let mut login = OperatorLogin::new(CONTROL_HOST, &[a.pinned(), b.pinned()])
        .map_err(|e| err("the operator login", &e))?;
    let at = now();
    let sa = a.log_in(&mut login, at)?;
    let sb = b.log_in(&mut login, at)?;
    let job = DestructiveJob::EraseCell {
        cell: CellId(cell.id()),
    };
    a.approve(&mut login, sa, &job, at)?;
    b.approve(&mut login, sb, &job, at)?;
    let approved = login
        .authorise_destructive(sa, &job, at)
        .map_err(|e| err("the two-operator check", &e))?;
    let custody = cell.custody()?;
    let keys = custody.cell_keys();
    let signer = control_plane_key()?;
    let confirmation = cell
        .block_on(erase_cell(&custody, &approved, &keys, signer, at, |id| {
            login.log_custody_call(&approved, id, at);
        }))?
        .map_err(|e| err("the job", &e))?;
    cell.backups
        .erasure
        .set(confirmation)
        .map_err(|_| err("the cell", &"is erased already"))
}

impl World {
    /// The erasure confirmation of cell `index`, once `erase-cell` ran,
    /// and the control plane's composite public key it verifies under
    /// (R-SW-02, design section 3.7 step 4, lane m3/erase-cell).
    ///
    /// # Errors
    ///
    /// Fails when the cell does not exist or the key cannot be made.
    pub fn cell_erasure(
        &self,
        index: u8,
    ) -> Result<Option<(ErasureConfirmation, Vec<u8>)>, WorldError> {
        let cell = self
            .cell(index)
            .ok_or_else(|| err("cell_erasure", &"names no cell of the world"))?;
        let pk = control_plane_key()?.public_key().to_bytes().to_vec();
        Ok(cell.backups.erasure.get().map(|c| (c.clone(), pk)))
    }
}
