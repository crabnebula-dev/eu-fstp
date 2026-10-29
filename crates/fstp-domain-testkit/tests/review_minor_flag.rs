//! Review reproducers for the R-ID-04 minor flag (lane dom, spec fidelity).
//!
//! `SPEC/01-requirements/functional.md` R-ID-04 (Derivation note): no field
//! of an applicant's request sets or clears the flag. `state-machine.md`
//! NOTE 14: every proposal without an effective over-18 attestation is
//! minor-flagged and waits for its guardian consent. R-NG-01 (guardian
//! exception): collection opens once every reviewing IRC member has
//! validated a minor-flagged proposal. The guardian is the Receiving
//! account `AddGuardian` binds (design section 6.6 step 3).

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use fstp_domain::id::{AccountId, BindingId};
use fstp_domain_testkit::r#gen::review::{L1, PR1, tag};
use fstp_domain_testkit::r#gen::roster::{Backend, add_member};
use fstp_domain_testkit::mc::life_model::{Story, life_judges, story_setup};
use fstp_domain_testkit::vault::GroundTruth;

/// A guardian account outside the setup, verified in the vault.
const GUARDIAN: AccountId = AccountId::from_raw(9_901);

/// PR1 in DRAFT, with the lead's `CreateDraft` field `field` and no
/// over-18 attestation for L1, so PR1 is minor-flagged (R-ID-04).
fn draft(field: bool) -> Story {
    let setup = story_setup(vec![(L1, PR1, field)], life_judges());
    Story::new(&setup, Backend::Production, |t: &mut GroundTruth| {
        t.withdraw_attestation(L1);
        t.set_identity(GUARDIAN, tag(GUARDIAN));
        t.verify(GUARDIAN);
    })
    .unwrap_or_else(|e| panic!("{e}"))
}

/// R-ID-04, NOTE 14, R-NG-01: the actor's field must not decide whether a
/// minor-flagged proposal can get a guardian. With the field set,
/// `AddGuardian` is accepted. With it clear and no attestation, PR1 is
/// just as minor-flagged, so `AddGuardian` must be accepted too.
#[test]
fn review_r_id_04_add_guardian_ignores_the_actor_field() {
    let mut set = draft(true);
    let step = add_member(L1, PR1, GUARDIAN, BindingId::from_raw(9_902), true);
    let accepted_set = set.attempt(&step).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        accepted_set.is_some(),
        "control: AddGuardian with the field set is accepted"
    );
    let mut clear = draft(false);
    let accepted_clear = clear.attempt(&step).unwrap_or_else(|e| panic!("{e}"));
    assert!(
        accepted_clear.is_some(),
        "R-ID-04: PR1 is minor-flagged (no attestation), yet AddGuardian is \
         refused because the actor's CreateDraft field is clear, so the \
         applicant's field decides the I-18 consent path"
    );
}
