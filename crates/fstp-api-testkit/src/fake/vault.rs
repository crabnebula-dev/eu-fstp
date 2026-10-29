//! The synthetic vault behind the vault port and the engine's oracle
//! (design section 6.1 requirement 9).
//!
//! Both read one shared `GroundTruth` of `fstp-domain-testkit`, so the
//! vault port and the engine always agree. Each answer carries a fake
//! query digest: a deterministic 32-byte value from std's SipHash, which
//! is not cryptographic. The M3 driver computes the real digest of the
//! query's canonical encoding (`Answer::digest`, overview NOTE 5).
//!
//! Intake (`state_country`, `declare_affiliations`, `declare_minor`)
//! takes `VaultBound<T>`, which has no accessor, so the fake records only
//! that an intake of a kind arrived for an account and a proposal. It
//! never sees the fact (I-86, R-NG-01).

use std::collections::BTreeSet;
use std::hash::{DefaultHasher, Hash, Hasher};
use std::sync::{Arc, Mutex};

use fstp_api_core::port::{
    Affiliations, AsyncIdentityOracle, CountryCode, ExclusionClasses, Receipt, Vault, VaultBound,
    VerificationPurpose, VerificationRedirect,
};
use fstp_domain::id::{AccountId, ContentDigest, OrganisationId, ProgrammeId, ProposalId};
use fstp_domain::oracle::{Answer, OracleDown, Query};
use fstp_domain_testkit::vault::GroundTruth;
use fstp_engine::IdentityOracle;

use super::lock;

/// The fake digest of `q`: four SipHash values of its `Hash` form, each
/// under its own lane prefix. Deterministic and distinct per query in
/// practice. Not cryptographic, and never used outside tests.
pub fn fake_query_digest(q: &Query) -> ContentDigest {
    fake_digest(&("query", q))
}

/// The fake digest of any hashable value, as [`fake_query_digest`] builds it.
pub fn fake_digest(value: &impl Hash) -> ContentDigest {
    let mut out = [0u8; 32];
    for (lane, chunk) in out.chunks_exact_mut(8).enumerate() {
        let mut h = DefaultHasher::new();
        b"fstp-fake-digest".hash(&mut h);
        lane.hash(&mut h);
        value.hash(&mut h);
        chunk.copy_from_slice(&h.finish().to_be_bytes());
    }
    ContentDigest::from_bytes(out)
}

/// The truthful answer to `q`, with the fake digest, or `None` when the
/// vault refuses to answer (state-machine NOTE 14, overview NOTE 4).
fn answer_of(truth: &GroundTruth, q: &Query) -> Option<Answer> {
    truth.try_answer(q).map(|mut a| {
        a.digest = fake_query_digest(q);
        a
    })
}

/// The engine's oracle over the shared facts. Every answer it gives is
/// appended to `asks`, so a dry run can report what it asked.
#[derive(Clone, Debug)]
pub struct CellOracle {
    truth: Arc<Mutex<GroundTruth>>,
    down: Arc<Mutex<bool>>,
    asks: Arc<Mutex<Vec<(Query, Answer)>>>,
}

impl CellOracle {
    /// The same facts with an empty log of its own.
    pub fn with_fresh_log(&self) -> CellOracle {
        CellOracle {
            truth: self.truth.clone(),
            down: self.down.clone(),
            asks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Every answer given through this oracle's log, in order.
    pub fn asks(&self) -> Vec<(Query, Answer)> {
        lock(&self.asks).clone()
    }
}

impl IdentityOracle for CellOracle {
    fn ask(&self, q: &Query) -> Result<Answer, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        let a = answer_of(&lock(&self.truth), q).ok_or(OracleDown)?;
        lock(&self.asks).push((q.clone(), a.clone()));
        Ok(a)
    }

    fn epoch(&self) -> Result<fstp_domain::id::VaultEpoch, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        Ok(lock(&self.truth).epoch())
    }
}

/// The kind of one intake the vault received.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum IntakeKind {
    /// `state_country`.
    Country,
    /// `declare_affiliations`.
    Affiliations,
    /// `declare_minor`.
    Minor,
}

#[derive(Debug, Default)]
struct Log {
    intake: Vec<(IntakeKind, AccountId, ProposalId)>,
    verifications: Vec<(VerificationPurpose, AccountId)>,
    asks: Vec<(Query, Answer)>,
    next: u128,
}

/// The synthetic vault port. Cloning shares the facts and the log.
#[derive(Clone, Debug)]
pub struct FakeVault {
    truth: Arc<Mutex<GroundTruth>>,
    down: Arc<Mutex<bool>>,
    log: Arc<Mutex<Log>>,
}

impl FakeVault {
    /// The vault over `truth`.
    pub fn new(truth: GroundTruth) -> FakeVault {
        FakeVault {
            truth: Arc::new(Mutex::new(truth)),
            down: Arc::new(Mutex::new(false)),
            log: Arc::new(Mutex::new(Log::default())),
        }
    }

    /// The engine's oracle over the same facts, with its own log.
    pub fn oracle(&self) -> CellOracle {
        CellOracle {
            truth: self.truth.clone(),
            down: self.down.clone(),
            asks: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Changes the facts, as a vault event would.
    pub fn change(&self, f: impl FnOnce(&mut GroundTruth)) {
        f(&mut lock(&self.truth));
    }

    /// A copy of the facts.
    pub fn truth(&self) -> GroundTruth {
        lock(&self.truth).clone()
    }

    /// Makes every query fail with `OracleDown`, or answer again.
    pub fn set_down(&self, down: bool) {
        *lock(&self.down) = down;
    }

    /// Every intake the vault received: kind, account and proposal.
    pub fn intake(&self) -> Vec<(IntakeKind, AccountId, ProposalId)> {
        lock(&self.log).intake.clone()
    }

    /// Every answer the vault port gave, in order.
    pub fn port_asks(&self) -> Vec<(Query, Answer)> {
        lock(&self.log).asks.clone()
    }

    fn receipt(
        &self,
        kind: IntakeKind,
        a: AccountId,
        p: ProposalId,
    ) -> Result<Receipt, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        let mut log = lock(&self.log);
        log.intake.push((kind, a, p));
        let n = log.next;
        log.next = n.saturating_add(1);
        Ok(Receipt(n))
    }

    fn one_bit(&self, holds: bool, digest: ContentDigest) -> Result<Answer, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        let epoch = lock(&self.truth).epoch();
        Ok(Answer {
            holds,
            accounts: None,
            epoch,
            digest,
        })
    }
}

impl AsyncIdentityOracle for FakeVault {
    async fn answer(&self, q: &Query) -> Result<Answer, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        let a = answer_of(&lock(&self.truth), q).ok_or(OracleDown)?;
        lock(&self.log).asks.push((q.clone(), a.clone()));
        Ok(a)
    }
}

impl Vault for FakeVault {
    async fn state_country(
        &self,
        a: AccountId,
        p: ProposalId,
        _fact: VaultBound<CountryCode>,
    ) -> Result<Receipt, OracleDown> {
        self.receipt(IntakeKind::Country, a, p)
    }

    async fn declare_affiliations(
        &self,
        a: AccountId,
        p: ProposalId,
        _fact: VaultBound<Affiliations>,
    ) -> Result<Receipt, OracleDown> {
        self.receipt(IntakeKind::Affiliations, a, p)
    }

    async fn declare_minor(
        &self,
        a: AccountId,
        p: ProposalId,
        _fact: VaultBound<bool>,
    ) -> Result<Receipt, OracleDown> {
        self.receipt(IntakeKind::Minor, a, p)
    }

    async fn begin_verification(
        &self,
        purpose: VerificationPurpose,
        a: AccountId,
    ) -> Result<VerificationRedirect, OracleDown> {
        if *lock(&self.down) {
            return Err(OracleDown);
        }
        let mut log = lock(&self.log);
        log.verifications.push((purpose, a));
        let n = log.next;
        log.next = n.saturating_add(1);
        Ok(VerificationRedirect(format!(
            "/fake-vault/verifications/{n}"
        )))
    }

    /// The synthetic vault knows every class (Q35, synthetic vault only).
    async fn classes_defined(
        &self,
        programme: ProgrammeId,
        classes: &ExclusionClasses,
    ) -> Result<Answer, OracleDown> {
        self.one_bit(
            true,
            fake_digest(&("classes_defined", programme, &classes.0)),
        )
    }

    /// Every partner organisation declared its list (Q35, synthetic vault
    /// only).
    async fn proximity_lists_declared(
        &self,
        programme: ProgrammeId,
        orgs: &BTreeSet<OrganisationId>,
    ) -> Result<Answer, OracleDown> {
        self.one_bit(
            true,
            fake_digest(&("proximity_lists_declared", programme, orgs)),
        )
    }
}
