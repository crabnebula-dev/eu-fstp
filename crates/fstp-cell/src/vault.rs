//! The cell's vault client over the vault's internal mutual TLS listener
//! (design sections 6.1 and 6.2, NOTE 2, NOTE 4). Lane int5.
//!
//! [`HttpVaultClient`] posts the `fstp-vault-proto` requests to
//! `/v1/epoch`, `/v1/ask`, `/v1/ack` and `/v1/identity` with the cell's `cell-app`
//! certificate, and decodes the vault's canonical replies. Every fault
//! fails the command closed (NOTE 2).
//!
//! The client converts each domain query to its wire form
//! ([`wire_query`]) and each wire answer back, with the digest of the
//! wire query ([`query_digest`]). An answer that breaks the one-bit rule
//! (NOTE 5), or a reply of the wrong shape, fails closed.
//!
//! Lane F-CYCLE2 lifted the refusal of lane int5. The shipped vault
//! service still answers 503 to a call that changes its database, the
//! query log of an `ask` and an acknowledgement included, until its chain
//! writer records them (`fstp_vault::service`, lane F-VCHAIN). Against it
//! a command with vault questions still fails closed, now from the
//! vault's reply. The test world's seeded vault persists those rows
//! (`fstp_celltest::seeded_vault`).

use std::collections::{BTreeMap, BTreeSet};

use fstp_cell_core::driver::VaultFault;
use fstp_domain::id::VaultEpoch;
use fstp_domain::id::{AccountId, ContentDigest};
use fstp_domain::oracle::{Answer, Answers, Query};
use fstp_domain::time::Timestamp;
use fstp_ledger::Seq;
use fstp_rt::Runtime;
use fstp_vault_proto::{VaultRequest, VaultResponse, WireQuery, decode_response, encode_request};

use crate::engine::VaultClient;

/// The vault client of one cell (module documentation).
pub struct HttpVaultClient<R: Runtime> {
    client: fstp_http::Client<R>,
    base: String,
}

impl<R: Runtime> std::fmt::Debug for HttpVaultClient<R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpVaultClient")
            .field("base", &self.base)
            .finish_non_exhaustive()
    }
}

impl<R: Runtime> HttpVaultClient<R> {
    /// A client of the vault at `base`, such as `https://127.0.0.1:4100`,
    /// with `tls`: the vault's internal CA as the only root and the cell's
    /// `cell-app` certificate.
    pub fn new(rt: R, base: String, tls: fstp_tls::ClientConfig) -> HttpVaultClient<R> {
        let config = fstp_http::ClientConfig {
            tls: Some(tls),
            ..fstp_http::ClientConfig::default()
        };
        HttpVaultClient {
            client: fstp_http::Client::new(rt, config),
            base,
        }
    }

    async fn call(&self, path: &str, req: &VaultRequest) -> Result<VaultResponse, VaultFault> {
        let body = encode_request(req).map_err(|_| VaultFault::Refused)?;
        let url = format!("{}{path}", self.base);
        let request = fstp_http::Request::post(&url, body)
            .and_then(|r| r.try_with_header("content-type", "application/json"))
            .map_err(|_| VaultFault::Refused)?;
        let resp = self
            .client
            .send(request)
            .await
            .map_err(|_| VaultFault::Unavailable)?;
        if resp.status.as_u16() != 200 {
            return Err(VaultFault::Unavailable);
        }
        decode_response(&resp.body).map_err(|_| VaultFault::Unavailable)
    }

    /// Registers `account` with the identity of its attribute tuple `tuple`
    /// on `POST /v1/identity` (ADR-004 record of lane L13). The vault seals
    /// the account's bank details and hardship evidence under that
    /// identity's fact key from then on, and refuses them before. The reply
    /// names no identity. Open for Daniel: no cell command calls this yet.
    ///
    /// # Errors
    ///
    /// [`VaultFault::Refused`] for a tuple the vault refuses, such as one of
    /// another identity than the account's, and [`VaultFault::Unavailable`]
    /// for any other fault.
    pub async fn register_identity(
        &self,
        account: AccountId,
        tuple: &[u8],
    ) -> Result<(), VaultFault> {
        let req = VaultRequest::RegisterIdentity {
            account: fstp_vault_proto::WireAccount(account.raw()),
            tuple: tuple.to_vec(),
        };
        match self.call("/v1/identity", &req).await? {
            VaultResponse::Acked => Ok(()),
            VaultResponse::Refused(_) => Err(VaultFault::Refused),
            VaultResponse::Epoch(_) | VaultResponse::Answers(_) | VaultResponse::Masks(_) => {
                Err(VaultFault::Unavailable)
            }
        }
    }
}

/// Whether `spans` fit the text `t` and a team of `team` accounts: each
/// inside the text on character boundaries, with a person of the team
/// (ADR-033 record of lane L31). The vault's answer is checked here, so
/// a malformed mask is never applied.
fn spans_fit(t: &str, team: usize, spans: &[fstp_vault_proto::WireSpan]) -> bool {
    fstp_vault_proto::spans_lawful(spans)
        && spans.iter().all(|s| {
            (s.person as usize) < team
                && (s.end as usize) <= t.len()
                && t.is_char_boundary(s.start as usize)
                && t.is_char_boundary(s.end as usize)
        })
}

impl<R: Runtime> HttpVaultClient<R> {
    /// The name mask on `POST /v1/mask` (M7 Q4, ADR-033 record of lane
    /// L31): the spans of each text that hold a verified name or date of
    /// birth of one of `team`. An answer that does not fit the texts is
    /// refused as unavailable, so the cell fails closed.
    ///
    /// # Errors
    ///
    /// [`VaultFault::Refused`] for a request out of its bounds or one the
    /// vault refuses, [`VaultFault::Unavailable`] for any other fault.
    pub async fn mask_texts(
        &self,
        team: &[AccountId],
        texts: &[String],
    ) -> Result<Vec<Vec<fstp_vault_proto::WireSpan>>, VaultFault> {
        // The person index of each span is the position in `team`, which
        // the request names in ascending order.
        let accounts: Vec<fstp_vault_proto::WireAccount> = team
            .iter()
            .map(|a| fstp_vault_proto::WireAccount(a.raw()))
            .collect();
        if !fstp_vault_proto::mask_request_lawful(&accounts, texts) {
            return Err(VaultFault::Refused);
        }
        let req = VaultRequest::Mask {
            accounts,
            texts: texts.to_vec(),
        };
        match self.call("/v1/mask", &req).await? {
            VaultResponse::Masks(m)
                if m.len() == texts.len()
                    && m.iter()
                        .zip(texts)
                        .all(|(s, t)| spans_fit(t, team.len(), s)) =>
            {
                Ok(m)
            }
            VaultResponse::Refused(_) => Err(VaultFault::Refused),
            _ => Err(VaultFault::Unavailable),
        }
    }
}

impl<R: Runtime> VaultClient for HttpVaultClient<R> {
    async fn epoch(&self) -> Result<VaultEpoch, VaultFault> {
        match self.call("/v1/epoch", &VaultRequest::Epoch).await? {
            VaultResponse::Epoch(e) => Ok(VaultEpoch::from_raw(e)),
            VaultResponse::Refused(_) => Err(VaultFault::Refused),
            VaultResponse::Answers(_) | VaultResponse::Acked | VaultResponse::Masks(_) => {
                Err(VaultFault::Unavailable)
            }
        }
    }

    async fn ask(
        &self,
        queries: &[Query],
        reaction_for: Option<VaultEpoch>,
        at: Timestamp,
    ) -> Result<Answers, VaultFault> {
        let wire = queries
            .iter()
            .map(wire_query)
            .collect::<Result<Vec<WireQuery>, VaultFault>>()?;
        let req = VaultRequest::Ask {
            at: u64::try_from(at.micros()).map_err(|_| VaultFault::Refused)?,
            reaction_for: reaction_for.map(VaultEpoch::raw),
            queries: wire.clone(),
        };
        let answers = match self.call("/v1/ask", &req).await? {
            VaultResponse::Answers(a) => a,
            VaultResponse::Refused(_) => return Err(VaultFault::Refused),
            VaultResponse::Epoch(_) | VaultResponse::Acked | VaultResponse::Masks(_) => {
                return Err(VaultFault::Unavailable);
            }
        };
        if answers.len() != queries.len() {
            return Err(VaultFault::Unavailable);
        }
        let mut out = Answers::new();
        for ((q, w), a) in queries.iter().zip(&wire).zip(answers) {
            if !a.is_lawful() {
                return Err(VaultFault::Unavailable);
            }
            out.insert(
                q.clone(),
                Answer {
                    holds: a.holds,
                    accounts: a
                        .accounts
                        .map(|v| v.into_iter().map(|x| AccountId::from_raw(x.0)).collect()),
                    epoch: VaultEpoch::from_raw(a.epoch),
                    digest: query_digest(w),
                },
            );
        }
        Ok(out)
    }

    async fn ack(&self, epoch: VaultEpoch, seq: Seq, link: [u8; 32]) -> Result<(), VaultFault> {
        let req = VaultRequest::Ack {
            epoch: epoch.raw(),
            ledger_seq: seq.raw(),
            link,
        };
        match self.call("/v1/ack", &req).await? {
            VaultResponse::Acked => Ok(()),
            VaultResponse::Refused(_) => Err(VaultFault::Refused),
            VaultResponse::Epoch(_) | VaultResponse::Answers(_) | VaultResponse::Masks(_) => {
                Err(VaultFault::Unavailable)
            }
        }
    }
}

/// The digest of a query's canonical encoding (`fstp_domain::oracle::Answer`):
/// SHA-256 over the kind code, big-endian, and the canonical arguments.
/// The ledger keeps it in `VaultOutcome`, never the query (NOTE 5).
/// Interim reading of lane F-CYCLE2: the design names no encoding of
/// the digest, and this one is the wire query's, which the vault reads.
pub fn query_digest(q: &WireQuery) -> ContentDigest {
    let mut bytes = Vec::with_capacity(q.args.len().saturating_add(2));
    bytes.extend_from_slice(&q.kind.to_be_bytes());
    bytes.extend_from_slice(&q.args);
    ContentDigest::from_bytes(fstp_crypto::sha256(&bytes))
}

/// The wire form of the domain query `q` (`fstp_vault_proto::query`).
///
/// # Errors
///
/// [`VaultFault::Refused`] for a query with no canonical spelling, such
/// as an amount beyond the JSON integer range.
pub fn wire_query(q: &Query) -> Result<WireQuery, VaultFault> {
    use fstp_vault_proto::query::Query as W;
    use fstp_vault_proto::{
        WireAccount, WireClass, WireEvidence, WireList, WireProgramme, WireProposal,
    };
    let acc = |a: &AccountId| WireAccount(a.raw());
    let set = |s: &BTreeSet<AccountId>| s.iter().map(acc).collect::<BTreeSet<WireAccount>>();
    let committed = |m: &BTreeMap<AccountId, fstp_money::NonNegAmount>| {
        m.iter()
            .map(|(a, n)| (acc(a), n.amount()))
            .collect::<BTreeMap<WireAccount, fstp_money::Amount>>()
    };
    let w = match q {
        Query::IsVerified { account } => W::IsVerified {
            account: acc(account),
        },
        Query::SameIdentityAsAny { subject, others } => W::SameIdentityAsAny {
            subject: acc(subject),
            others: set(others),
        },
        Query::HasConflict { reviewer, team } => W::HasConflict {
            reviewer: acc(reviewer),
            team: set(team),
        },
        Query::InExcludedClass {
            account,
            programme,
            classes,
        } => W::InExcludedClass {
            account: acc(account),
            programme: WireProgramme(programme.raw()),
            classes: classes.0.iter().map(|c| WireClass(c.raw())).collect(),
        },
        Query::WithinRecipientCap {
            subject,
            amount,
            committed: c,
            cap,
        } => W::WithinRecipientCap {
            subject: acc(subject),
            amount: amount.amount(),
            committed: committed(c),
            cap: cap.amount(),
        },
        Query::AllRecipientsWithinCap { committed: c, cap } => W::AllRecipientsWithinCap {
            committed: committed(c),
            cap: cap.amount(),
        },
        Query::HasGuardianConsent { proposal } => W::HasGuardianConsent {
            proposal: WireProposal(proposal.raw()),
        },
        Query::IsVerifiedAdultAtDeadline { account, deadline } => W::IsVerifiedAdultAtDeadline {
            account: acc(account),
            deadline: deadline.micros(),
        },
        Query::DeclaresAffiliationOnList { team, list } => W::DeclaresAffiliationOnList {
            team: set(team),
            list: WireList(list.raw()),
        },
        Query::MeetsTieBreakCountry { account, programme } => W::MeetsTieBreakCountry {
            account: acc(account),
            programme: WireProgramme(programme.raw()),
        },
        Query::ChangedSince { epoch } => W::ChangedSince { epoch: epoch.raw() },
        Query::BankReleasable { grant, at, hold } => W::BankReleasable {
            grant: WireProposal(grant.raw()),
            at: at.micros(),
            hold: hold.get(),
        },
        Query::HardshipEvidenceVerified { grant, evidence } => W::HardshipEvidenceVerified {
            grant: WireProposal(grant.raw()),
            evidence: WireEvidence(evidence.raw()),
        },
        Query::ClassesDefined { programme, classes } => W::ClassesDefined {
            programme: WireProgramme(programme.raw()),
            classes: classes.0.iter().map(|c| WireClass(c.raw())).collect(),
        },
        Query::ProximityListsDeclared { programme, lists } => W::ProximityListsDeclared {
            programme: WireProgramme(programme.raw()),
            lists: lists.iter().map(|l| WireList(l.raw())).collect(),
        },
    };
    w.to_wire().map_err(|_| VaultFault::Refused)
}
