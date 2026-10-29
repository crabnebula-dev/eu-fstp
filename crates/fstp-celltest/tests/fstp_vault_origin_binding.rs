//! The vault origin's binding of a write ticket to its write (ADR-009
//! "Tickets" and "Write kinds", design sections 6.5, 6.6 and 6.8, I-04,
//! I-18).
//!
//! These tests check `reference::vault::RefVault::origin_write` against a
//! rule restated here from the ADR-009 "Write kinds" table. A ticket admits
//! one write of one kind, by its writer, for the proposal it names. A
//! withdrawal or an ended affiliation travels under the kind of the fact it
//! ends, and only the writer of that fact may end it. Any re-declaration
//! of a partner staff affiliation needs a partner staff ticket, with or
//! without a class. A country ticket names its programme in its scope (a
//! Reading of the reference).
//!
//! The production vault origin (`fstp-vault`, lane W2d) has no write path
//! yet, so these tests are reference and teeth tests only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::collections::{BTreeMap, BTreeSet};

use fstp_celltest::reference::vault::{
    Org, Person, RefEvent, RefTicket, RefVault, RefWrite, RouteKind, TicketCheck, TicketKind,
    TicketRefusal, WriteKind, country_scope, origin_binding, sign_ticket, ticket_public_key,
};
use fstp_domain::id::{AccountId, ClassId, ProgrammeId, ProposalId, ProximityListId};
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::harness::teeth::expect_prop_failure;
use fstp_prop::{Gen, prop_assert, prop_assert_eq};

const CELL: [u8; 16] = [0xCE; 16];
const KEY: [u8; 32] = [0x11; 32];
const NOW: Timestamp = Timestamp::from_micros(10_000_000_000);

const G1: AccountId = AccountId::from_raw(401);
const G2: AccountId = AccountId::from_raw(402);
const A1: AccountId = AccountId::from_raw(501);
const A2: AccountId = AccountId::from_raw(502);
const ACCOUNTS: [AccountId; 4] = [G1, G2, A1, A2];
const PROPOSALS: [ProposalId; 2] = [ProposalId::from_raw(1), ProposalId::from_raw(2)];
const ORGS: [Org; 2] = [Org(7), Org(8)];
const PROGRAMMES: [ProgrammeId; 2] = [ProgrammeId::from_raw(1), ProgrammeId::from_raw(2)];
const K1: ClassId = ClassId::from_raw(1);

/// One origin write path: the reference, or a mutant of it.
type Origin = dyn Fn(
    &mut RefVault,
    &[u8],
    RefWrite,
    &TicketCheck<'_>,
) -> Result<Vec<RefEvent>, TicketRefusal>;

/// The facts the restated rule needs, kept by the test from the writes
/// the vault took.
#[derive(Clone, Debug, Default)]
struct Kept {
    consent: BTreeMap<ProposalId, AccountId>,
    affiliations: BTreeMap<(AccountId, Org), Option<ClassId>>,
}

impl Kept {
    fn apply(&mut self, w: &RefWrite) {
        match w {
            RefWrite::GuardianConsent { proposal, guardian } => {
                self.consent.insert(*proposal, *guardian);
            }
            RefWrite::ConsentWithdrawn { proposal } => {
                self.consent.remove(proposal);
            }
            RefWrite::AffiliationDeclared {
                account,
                org,
                class,
            } => {
                self.affiliations.insert((*account, *org), *class);
            }
            RefWrite::AffiliationEnded { account, org } => {
                self.affiliations.remove(&(*account, *org));
            }
            _ => {}
        }
    }
}

/// What a lawful ticket for `w` carries, restated from the ADR-009
/// "Write kinds" table: kind, writer, proposal and scope. `None` when no
/// ticket admits `w`.
fn lawful(
    kept: &Kept,
    w: &RefWrite,
) -> Option<(WriteKind, AccountId, Option<ProposalId>, Option<String>)> {
    match w {
        RefWrite::AdultAttestation { account, .. } | RefWrite::AttestationWithdrawn { account } => {
            Some((WriteKind::AdultAttestation, *account, None, None))
        }
        RefWrite::GuardianConsent { proposal, guardian } => {
            Some((WriteKind::GuardianConsent, *guardian, Some(*proposal), None))
        }
        RefWrite::ConsentWithdrawn { proposal } => kept
            .consent
            .get(proposal)
            .map(|g| (WriteKind::GuardianConsent, *g, Some(*proposal), None)),
        RefWrite::AffiliationDeclared {
            account,
            org,
            class,
        } => Some((
            if class.is_some()
                || kept
                    .affiliations
                    .get(&(*account, *org))
                    .is_some_and(Option::is_some)
            {
                WriteKind::PartnerStaffDeclared
            } else {
                WriteKind::AffiliationDeclared
            },
            *account,
            None,
            None,
        )),
        RefWrite::AffiliationEnded { account, org } => {
            kept.affiliations.get(&(*account, *org)).map(|class| {
                (
                    if class.is_some() {
                        WriteKind::PartnerStaffDeclared
                    } else {
                        WriteKind::AffiliationDeclared
                    },
                    *account,
                    None,
                    None,
                )
            })
        }
        RefWrite::ReviewerDeclaration { reviewer, .. } => {
            Some((WriteKind::ReviewerDeclaration, *reviewer, None, None))
        }
        RefWrite::CountryStated {
            account, programme, ..
        } => Some((
            WriteKind::CountryStated,
            *account,
            None,
            Some(country_scope(*programme)),
        )),
        RefWrite::VerificationRecorded { .. }
        | RefWrite::ProximityListDeclared { .. }
        | RefWrite::Relationship { .. } => None,
    }
}

/// Whether the restated rule admits ticket `t` for `w`.
fn admits(kept: &Kept, w: &RefWrite, t: &RefTicket) -> bool {
    match lawful(kept, w) {
        Some((kind, writer, proposal, scope)) => {
            t.kind == TicketKind::Write(kind)
                && t.account == writer
                && proposal.is_none_or(|p| t.proposal == Some(p))
                && scope.is_none_or(|s| s == t.scope)
        }
        None => false,
    }
}

/// The invariant a write's binding protects, for the failure message.
fn id_of(w: &RefWrite) -> &'static str {
    match w {
        RefWrite::GuardianConsent { .. } | RefWrite::ConsentWithdrawn { .. } => "I-18",
        RefWrite::AffiliationDeclared { .. } | RefWrite::AffiliationEnded { .. } => "I-04",
        _ => "ADR-009",
    }
}

fn prefix_write(g: &mut Gen) -> RefWrite {
    match g.u8_in(0..=2) {
        0 => {
            let a = *g.pick(&[G1, G2]);
            RefWrite::VerificationRecorded {
                account: a,
                person: Person(u64::try_from(a.raw()).unwrap()),
            }
        }
        1 => RefWrite::GuardianConsent {
            proposal: *g.pick(&PROPOSALS),
            guardian: *g.pick(&[G1, G2]),
        },
        _ => RefWrite::AffiliationDeclared {
            account: *g.pick(&[A1, A2]),
            org: *g.pick(&ORGS),
            class: if g.bool() { Some(K1) } else { None },
        },
    }
}

fn origin_write_of(g: &mut Gen, kept: &Kept) -> RefWrite {
    let account = *g.pick(&ACCOUNTS);
    let classed: Vec<(AccountId, Org)> = kept
        .affiliations
        .iter()
        .filter(|(_, class)| class.is_some())
        .map(|(key, _)| *key)
        .collect();
    match g.weighted(&[3, 3, 3, 3, 1, 1, 1, 1, 1, 3]) {
        0 => RefWrite::GuardianConsent {
            proposal: *g.pick(&PROPOSALS),
            guardian: *g.pick(&[G1, G2]),
        },
        1 => RefWrite::ConsentWithdrawn {
            proposal: *g.pick(&PROPOSALS),
        },
        2 => RefWrite::AffiliationEnded {
            account: *g.pick(&[A1, A2]),
            org: *g.pick(&ORGS),
        },
        3 => RefWrite::CountryStated {
            account,
            programme: *g.pick(&PROGRAMMES),
            country: 1,
        },
        4 => RefWrite::AffiliationDeclared {
            account,
            org: *g.pick(&ORGS),
            class: if g.bool() { Some(K1) } else { None },
        },
        5 => RefWrite::AdultAttestation {
            account,
            adult_from: Timestamp::from_micros(0),
        },
        6 => RefWrite::ReviewerDeclaration {
            reviewer: account,
            employer: None,
            relatives: BTreeSet::new(),
        },
        7 => RefWrite::ProximityListDeclared {
            list: ProximityListId::from_raw(1),
            orgs: BTreeSet::from([Org(7)]),
        },
        8 => RefWrite::VerificationRecorded {
            account,
            person: Person(9),
        },
        // A re-declaration of a partner staff affiliation with no class.
        _ => {
            let (account, org) = if classed.is_empty() {
                (*g.pick(&[A1, A2]), *g.pick(&ORGS))
            } else {
                *g.pick(&classed)
            };
            RefWrite::AffiliationDeclared {
                account,
                org,
                class: None,
            }
        }
    }
}

/// A ticket for `w`: the lawful one, or the lawful one with one member
/// changed. The kinds a defect is likeliest to confuse are drawn most.
fn ticket_for(g: &mut Gen, kept: &Kept, w: &RefWrite, nonce: u8) -> RefTicket {
    let (kind, account, proposal, scope) =
        lawful(kept, w).unwrap_or((WriteKind::GuardianConsent, G1, Some(PROPOSALS[0]), None));
    let mut t = RefTicket {
        kind: TicketKind::Write(kind),
        cell: CELL,
        account,
        proposal: proposal.or_else(|| {
            if g.bool() {
                Some(*g.pick(&PROPOSALS))
            } else {
                None
            }
        }),
        scope: scope.unwrap_or_else(|| "write".to_owned()),
        issued_at: Timestamp::from_micros(NOW.micros() - 1),
        expires_at: Timestamp::from_micros(NOW.micros() + 60_000_000),
        nonce: [nonce; 16],
    };
    match g.weighted(&[3, 2, 2, 2, 1]) {
        0 => {}
        1 => {
            let near = [
                WriteKind::AffiliationDeclared,
                WriteKind::PartnerStaffDeclared,
                WriteKind::GuardianConsent,
            ];
            // An affiliation write most often gets the other affiliation
            // kind, the confusion I-04 guards against.
            let swapped = match kind {
                WriteKind::AffiliationDeclared => Some(WriteKind::PartnerStaffDeclared),
                WriteKind::PartnerStaffDeclared => Some(WriteKind::AffiliationDeclared),
                _ => None,
            };
            t.kind = TicketKind::Write(match (swapped, g.u8_in(0..=2)) {
                (Some(other), 0 | 1) => other,
                (_, 0) => *g.pick(&near),
                _ => *g.pick(&WriteKind::ALL),
            });
        }
        2 => t.account = *g.pick(&ACCOUNTS),
        3 => t.proposal = *g.pick(&[None, Some(PROPOSALS[0]), Some(PROPOSALS[1])]),
        _ => {
            t.scope = if g.bool() {
                country_scope(*g.pick(&PROGRAMMES))
            } else {
                "write".to_owned()
            };
        }
    }
    t
}

fn check_of(keys: &[[u8; 32]]) -> TicketCheck<'_> {
    TicketCheck {
        pinned: keys,
        cell: CELL,
        route: RouteKind::Write,
        now: NOW,
    }
}

/// The property: after a random effective prefix, each origin write is
/// admitted exactly when the restated rule admits its ticket. An admitted
/// write uses up its ticket and enters the NOTE 4 protocol. A refused one
/// leaves the vault as it was.
fn origin_property(g: &mut Gen, origin: &Origin) -> Result<(), String> {
    let keys = [ticket_public_key(&KEY).unwrap()];
    let check = check_of(&keys);
    let mut v = RefVault::default();
    let mut kept = Kept::default();
    for _ in 0..g.usize_in(0..=5) {
        let w = prefix_write(g);
        v.write(w.clone());
        let e = v.current();
        v.ack(e, e, [0; 32]).unwrap();
        kept.apply(&w);
    }
    for n in 1..=g.u8_in(1..=6) {
        let w = origin_write_of(g, &kept);
        let t = ticket_for(g, &kept, &w, n);
        let bytes = sign_ticket(&t, &KEY).unwrap();
        let want = admits(&kept, &w, &t);
        let before = v.clone();
        let got = origin(&mut v, &bytes, w.clone(), &check);
        let id = id_of(&w);
        prop_assert_eq!(
            got.is_ok(),
            want,
            "{id}: the origin {} {w:?} under {t:?}: {got:?}",
            if want { "refused" } else { "admitted" }
        );
        if got.is_ok() {
            prop_assert!(
                v.used_tickets().contains(&t.nonce),
                "ADR-009: an admitted write left its ticket unused: {t:?}"
            );
            kept.apply(&w);
        } else {
            prop_assert!(
                v == before,
                "ADR-009: a refused write changed the vault: {w:?} under {t:?}"
            );
        }
    }
    Ok(())
}

fn reference_origin(
    v: &mut RefVault,
    bytes: &[u8],
    w: RefWrite,
    check: &TicketCheck<'_>,
) -> Result<Vec<RefEvent>, TicketRefusal> {
    v.origin_write(bytes, w, check)
}

/// Re-signs `bytes` with one member changed by `f`, as a mutant origin
/// that reads the ticket too loosely would see it.
fn resigned(bytes: &[u8], f: impl FnOnce(&mut RefTicket)) -> Vec<u8> {
    let body = &bytes[..bytes.len() - 64];
    match RefTicket::parse(body) {
        Some(mut t) => {
            f(&mut t);
            sign_ticket(&t, &KEY).unwrap()
        }
        None => bytes.to_vec(),
    }
}

/// ADR-009 "Tickets" and "Write kinds", I-04, I-18, design sections 6.5,
/// 6.6 and 6.8: the reference vault origin admits a write exactly when its
/// ticket names the write's kind, its writer, the proposal it names and
/// the scope it needs. Withdrawals and ended affiliations need the writer
/// and the kind of the fact they end. A re-declaration of a partner staff
/// affiliation needs the partner staff kind.
#[test]
fn adr009_origin_write_binds_kind_writer_proposal_and_scope() {
    fstp_prop::check(
        "adr009_origin_write_binds_kind_writer_proposal_and_scope",
        |g: &mut Gen| origin_property(g, &reference_origin),
    );
}

/// I-18 teeth: an origin that ignores the proposal a guardian consent
/// ticket names fails the binding property.
#[test]
fn i18_teeth_origin_ignoring_the_ticket_proposal_is_caught() {
    let mutant = |v: &mut RefVault, bytes: &[u8], w: RefWrite, check: &TicketCheck<'_>| {
        let p = fstp_celltest::reference::vault::Facts::consent_proposal(&w);
        let loose = resigned(bytes, |t| {
            if p.is_some() {
                t.proposal = p;
            }
        });
        v.origin_write(&loose, w, check)
    };
    let outcome = fstp_prop::run(
        "i18_teeth_origin_ignoring_the_ticket_proposal_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| origin_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-18") {
        panic!("{e}");
    }
}

/// I-04 teeth: an origin that ends a partner staff affiliation under an
/// ordinary affiliation ticket fails the binding property.
#[test]
fn i04_teeth_origin_ending_partner_staff_under_affiliation_ticket_is_caught() {
    let mutant = |v: &mut RefVault, bytes: &[u8], w: RefWrite, check: &TicketCheck<'_>| {
        let ends = matches!(w, RefWrite::AffiliationEnded { .. });
        let loose = resigned(bytes, |t| {
            if ends && t.kind == TicketKind::Write(WriteKind::AffiliationDeclared) {
                t.kind = TicketKind::Write(WriteKind::PartnerStaffDeclared);
            }
        });
        v.origin_write(&loose, w, check)
    };
    let outcome = fstp_prop::run(
        "i04_teeth_origin_ending_partner_staff_under_affiliation_ticket_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| origin_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-04") {
        panic!("{e}");
    }
}

/// I-04 teeth: an origin that lets an ordinary affiliation ticket
/// re-declare a partner staff affiliation with no class fails the binding
/// property. That write would clear the class just as an end would.
#[test]
fn i04_teeth_origin_redeclaring_partner_staff_under_affiliation_ticket_is_caught() {
    let mutant = |v: &mut RefVault, bytes: &[u8], w: RefWrite, check: &TicketCheck<'_>| {
        let needs_staff = matches!(w, RefWrite::AffiliationDeclared { class: None, .. })
            && origin_binding(&v.latest_facts(), &w)
                .is_some_and(|b| b.kind == WriteKind::PartnerStaffDeclared);
        let loose = resigned(bytes, |t| {
            if needs_staff && t.kind == TicketKind::Write(WriteKind::AffiliationDeclared) {
                t.kind = TicketKind::Write(WriteKind::PartnerStaffDeclared);
            }
        });
        v.origin_write(&loose, w, check)
    };
    let outcome = fstp_prop::run(
        "i04_teeth_origin_redeclaring_partner_staff_under_affiliation_ticket_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| origin_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-04") {
        panic!("{e}");
    }
}

/// I-18 teeth: an origin that never admits a consent withdrawal fails the
/// binding property, so a consent stays withdrawable on the vault origin.
#[test]
fn i18_teeth_origin_refusing_every_consent_withdrawal_is_caught() {
    let mutant = |v: &mut RefVault, bytes: &[u8], w: RefWrite, check: &TicketCheck<'_>| {
        if matches!(w, RefWrite::ConsentWithdrawn { .. }) {
            return Err(TicketRefusal::WrongKind);
        }
        v.origin_write(bytes, w, check)
    };
    let outcome = fstp_prop::run(
        "i18_teeth_origin_refusing_every_consent_withdrawal_is_caught",
        fstp_prop::Config::default(),
        |g: &mut Gen| origin_property(g, &mutant),
    );
    if let Err(e) = expect_prop_failure(&outcome, "I-18") {
        panic!("{e}");
    }
}
