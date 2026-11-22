//! A minimal in-memory custody for the backup tests: roots are random
//! AES-256-GCM keys in a map, and `destroy` removes one. It stands in for
//! the `fstp-keyd` console socket. Shared through `#[path]` with
//! `crates/fstp-celltest/tests/adr012_backup_agent_pg.rs`.

#![allow(dead_code, unreachable_pub, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::future::Future;
use std::sync::Mutex;

use fstp_crypto::aead;
use fstp_custody::{
    Aad, BackendId, Custody, CustodyError, CustodyHandle, DestroyReceipt, EcdsaSignature,
    RootLabel, RootRef, SealKey, SignKeyRef, UsageCursor, UsagePage, WrappedSealKey,
};

/// The roots by handle.
#[derive(Default)]
pub struct MemCustody {
    roots: Mutex<BTreeMap<Vec<u8>, [u8; 32]>>,
    labels: Mutex<Vec<RootLabel>>,
}

impl MemCustody {
    /// How many roots are live.
    pub fn live(&self) -> usize {
        self.roots.lock().unwrap().len()
    }

    /// The label of every root ever created (ADR-012 record of lane L16).
    pub fn labels(&self) -> Vec<RootLabel> {
        self.labels.lock().unwrap().clone()
    }

    /// The bytes of every live root, for the I-80 scans of lane L16.
    pub fn root_bytes(&self) -> Vec<[u8; 32]> {
        self.roots.lock().unwrap().values().copied().collect()
    }
}

fn gone() -> CustodyError {
    CustodyError::Transport("no such root")
}

impl Custody for MemCustody {
    fn create_root(
        &self,
        label: RootLabel,
    ) -> impl Future<Output = Result<RootRef, CustodyError>> + Send {
        let handle = fstp_crypto::random_array::<16>().unwrap().to_vec();
        let key = fstp_crypto::random_array::<32>().unwrap();
        self.roots.lock().unwrap().insert(handle.clone(), key);
        self.labels.lock().unwrap().push(label.clone());
        std::future::ready(Ok(RootRef {
            backend: BackendId::Keyd,
            cell: label.cell,
            chain: label.chain,
            epoch: label.epoch,
            handle: CustodyHandle(handle),
        }))
    }

    fn wrap(
        &self,
        root: &RootRef,
        key: &SealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<WrappedSealKey, CustodyError>> + Send {
        let out = self
            .roots
            .lock()
            .unwrap()
            .get(&root.handle.0)
            .copied()
            .ok_or_else(gone)
            .map(|k| {
                let k = aead::Key::from_bytes(&k).unwrap();
                let s = aead::seal(&k, &aad.0, key.expose()).unwrap();
                let mut w = s.nonce.to_vec();
                w.extend_from_slice(&s.body);
                WrappedSealKey(w)
            });
        std::future::ready(out)
    }

    fn unwrap(
        &self,
        root: &RootRef,
        w: &WrappedSealKey,
        aad: &Aad,
    ) -> impl Future<Output = Result<SealKey, CustodyError>> + Send {
        let out = self
            .roots
            .lock()
            .unwrap()
            .get(&root.handle.0)
            .copied()
            .ok_or_else(gone)
            .and_then(|k| {
                let k = aead::Key::from_bytes(&k).unwrap();
                let (nonce, body) = w.0.split_at_checked(aead::NONCE_LEN).ok_or_else(gone)?;
                let nonce: [u8; aead::NONCE_LEN] = nonce.try_into().map_err(|_| gone())?;
                let plain = aead::open(&k, &nonce, &aad.0, body).map_err(|_| gone())?;
                let bytes: [u8; 32] = plain[..].try_into().map_err(|_| gone())?;
                Ok(SealKey::from_bytes(bytes))
            });
        std::future::ready(out)
    }

    fn destroy(
        &self,
        root: &RootRef,
    ) -> impl Future<Output = Result<DestroyReceipt, CustodyError>> + Send {
        let out = self
            .roots
            .lock()
            .unwrap()
            .remove(&root.handle.0)
            .map(|_| DestroyReceipt(root.handle.0.clone()))
            .ok_or_else(gone);
        std::future::ready(out)
    }

    fn sign(
        &self,
        _key: &SignKeyRef,
        _digest: &[u8; 32],
    ) -> impl Future<Output = Result<EcdsaSignature, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("sign")))
    }

    fn usage_since(
        &self,
        _root: &RootRef,
        _cursor: UsageCursor,
    ) -> impl Future<Output = Result<UsagePage, CustodyError>> + Send {
        std::future::ready(Err(CustodyError::NotImplemented("usage")))
    }
}
