//! A fake digest-bound step-up (I-78, design section 6.1 requirement 2).
//!
//! `begin` binds a challenge to one session and one action digest.
//! `finish` takes the synthetic authenticator response, which echoes the
//! challenge, and records a proof for that session and digest at the
//! clock's instant. `take` hands out a proof for exactly this session and
//! digest that is younger than P-71, and consumes it. A proof that is
//! exactly P-71 old is stale.
//!
//! [`FakeStepUp::approve`] runs `begin` and `finish` in one call, as a
//! user completing the WebAuthn ceremony would.

use std::sync::{Arc, Mutex};

use fstp_api_core::ActionDigest;
use fstp_api_core::port::{
    PortError, SessionId, StepUp, StepUpChallenge, StepUpProof, StepUpRef, StepUpRequired,
};
use fstp_domain::time::Timestamp;

use super::{FakeClock, lock};

/// P-71 in the SuperSAFE profile: 5 minutes (`policy-parameters.md`).
pub const P71_MICROS: i64 = 300_000_000;

/// The prefix of every synthetic challenge.
const CHALLENGE_PREFIX: &[u8] = b"fstp-fake-step-up:";

/// A proof the fake holds until it is taken.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct HeldProof {
    /// The step-up.
    pub step_up: StepUpRef,
    /// The session that ran it.
    pub session: SessionId,
    /// The digest it authorises.
    pub action: ActionDigest,
    /// When it finished.
    pub at: Timestamp,
}

/// One `take` the fake answered with a proof.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    /// The proof.
    pub proof: HeldProof,
    /// When it was taken.
    pub now: Timestamp,
}

#[derive(Debug, Default)]
struct State {
    challenges: Vec<(Vec<u8>, SessionId, ActionDigest)>,
    proofs: Vec<HeldProof>,
    begun: Vec<(SessionId, ActionDigest)>,
    taken: Vec<Taken>,
    refused_takes: Vec<(SessionId, ActionDigest, Timestamp)>,
    next: u128,
}

/// The fake step-up port. Cloning shares its state.
#[derive(Clone, Debug)]
pub struct FakeStepUp {
    state: Arc<Mutex<State>>,
    clock: FakeClock,
    p71: Arc<Mutex<i64>>,
}

impl FakeStepUp {
    /// No challenge and no proof. Proofs are stamped with `clock`.
    pub fn new(clock: FakeClock) -> FakeStepUp {
        FakeStepUp {
            state: Arc::new(Mutex::new(State::default())),
            clock,
            p71: Arc::new(Mutex::new(P71_MICROS)),
        }
    }

    /// Sets P-71, the freshness window, in microseconds.
    pub fn set_p71(&self, micros: i64) {
        *lock(&self.p71) = micros;
    }

    /// P-71, in microseconds.
    pub fn p71(&self) -> i64 {
        *lock(&self.p71)
    }

    fn begin_now(&self, s: SessionId, action: ActionDigest) -> StepUpChallenge {
        let mut st = lock(&self.state);
        let n = st.next;
        st.next = n.saturating_add(1);
        let mut challenge = CHALLENGE_PREFIX.to_vec();
        challenge.extend_from_slice(&n.to_be_bytes());
        st.challenges.push((challenge.clone(), s, action));
        st.begun.push((s, action));
        StepUpChallenge { action, challenge }
    }

    fn finish_now(&self, s: SessionId, response: &[u8]) -> Result<StepUpRef, PortError> {
        let mut st = lock(&self.state);
        let at = st
            .challenges
            .iter()
            .position(|(c, sess, _)| c.as_slice() == response && *sess == s)
            .ok_or(PortError::Refused)?;
        let (_, session, action) = st.challenges.remove(at);
        let n = st.next;
        st.next = n.saturating_add(1);
        let step_up = StepUpRef(n);
        st.proofs.push(HeldProof {
            step_up,
            session,
            action,
            at: self.clock.read(),
        });
        Ok(step_up)
    }

    /// Runs the ceremony for `action` in session `s` at the clock's
    /// instant: `begin`, then `finish` with the echoed challenge.
    pub fn approve(&self, s: SessionId, action: ActionDigest) -> Result<StepUpRef, PortError> {
        let ch = self.begin_now(s, action);
        self.finish_now(s, &ch.challenge)
    }

    /// The open challenge whose wire id is `id`
    /// (`fstp_api_core::step_up_challenge_id`): its session and bytes.
    /// The e2e cell's M3 step-up route finds the challenge an assertion
    /// answers by this id.
    pub fn challenge_for(&self, id: &[u8; 16]) -> Option<(SessionId, Vec<u8>)> {
        lock(&self.state)
            .challenges
            .iter()
            .find(|(c, _, _)| fstp_api_core::step_up_challenge_id(c) == *id)
            .map(|(c, s, _)| (*s, c.clone()))
    }

    /// The proofs not yet taken, stale ones included.
    pub fn held(&self) -> Vec<HeldProof> {
        lock(&self.state).proofs.clone()
    }

    /// Every `begin`, in order: the session and the digest.
    pub fn begun(&self) -> Vec<(SessionId, ActionDigest)> {
        lock(&self.state).begun.clone()
    }

    /// Every `take` answered with a proof, in order.
    pub fn taken(&self) -> Vec<Taken> {
        lock(&self.state).taken.clone()
    }

    /// Every `take` refused, in order: session, digest and instant.
    pub fn refused_takes(&self) -> Vec<(SessionId, ActionDigest, Timestamp)> {
        lock(&self.state).refused_takes.clone()
    }

    /// Whether `proof` is younger than `p71` at `now`.
    fn fresh(proof: &HeldProof, now: Timestamp, p71: i64) -> bool {
        proof.at <= now && now.micros().saturating_sub(proof.at.micros()) < p71
    }

    fn take_now(
        &self,
        s: SessionId,
        action: ActionDigest,
        now: Timestamp,
    ) -> Result<StepUpProof, StepUpRequired> {
        let p71 = self.p71();
        let mut st = lock(&self.state);
        let Some(at) = st
            .proofs
            .iter()
            .position(|p| p.session == s && p.action == action && Self::fresh(p, now, p71))
        else {
            st.refused_takes.push((s, action, now));
            return Err(StepUpRequired);
        };
        let proof = st.proofs.remove(at);
        st.taken.push(Taken { proof, now });
        Ok(StepUpProof {
            step_up: proof.step_up,
            action: proof.action,
        })
    }
}

impl StepUp for FakeStepUp {
    async fn begin(
        &self,
        s: SessionId,
        action: ActionDigest,
    ) -> Result<StepUpChallenge, PortError> {
        Ok(self.begin_now(s, action))
    }

    async fn finish(&self, s: SessionId, response: &[u8]) -> Result<StepUpRef, PortError> {
        self.finish_now(s, response)
    }

    async fn take(
        &self,
        s: SessionId,
        action: ActionDigest,
        now: Timestamp,
    ) -> Result<StepUpProof, StepUpRequired> {
        self.take_now(s, action, now)
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

    use super::*;
    use fstp_rt::future::block_on;

    const D1: ActionDigest = ActionDigest([1; 32]);
    const D2: ActionDigest = ActionDigest([2; 32]);
    const S1: SessionId = SessionId::from_raw(1);
    const S2: SessionId = SessionId::from_raw(2);

    fn fake() -> (FakeClock, FakeStepUp) {
        let clock = FakeClock::new(Timestamp::from_micros(1_000_000_000));
        (clock.clone(), FakeStepUp::new(clock))
    }

    /// I-78, design section 6.1 requirement 2: a proof answers only its
    /// own session and digest, and is consumed by its one `take`.
    #[test]
    fn i78_fake_step_up_proof_is_bound_to_session_and_digest_and_consumed() {
        let (clock, f) = fake();
        f.approve(S1, D1).unwrap();
        let now = clock.read();
        assert!(block_on(f.take(S2, D1, now)).is_err(), "another session");
        assert!(block_on(f.take(S1, D2, now)).is_err(), "another digest");
        let proof = block_on(f.take(S1, D1, now)).unwrap();
        assert_eq!(proof.action, D1);
        assert!(block_on(f.take(S1, D1, now)).is_err(), "consumed");
    }

    /// I-78: a proof is fresh while younger than P-71. At exactly P-71 it
    /// is stale.
    #[test]
    fn i78_fake_step_up_proof_goes_stale_at_p71() {
        let (clock, f) = fake();
        f.approve(S1, D1).unwrap();
        f.approve(S1, D1).unwrap();
        clock.advance(P71_MICROS.saturating_sub(1));
        assert!(
            block_on(f.take(S1, D1, clock.read())).is_ok(),
            "1 µs short of P-71"
        );
        clock.advance(1);
        assert!(
            block_on(f.take(S1, D1, clock.read())).is_err(),
            "exactly P-71"
        );
    }

    /// I-78: `finish` needs the challenge of its own session.
    #[test]
    fn i78_fake_step_up_finish_needs_the_sessions_challenge() {
        let (_, f) = fake();
        let ch = block_on(f.begin(S1, D1)).unwrap();
        assert_eq!(ch.action, D1);
        assert!(block_on(f.finish(S2, &ch.challenge)).is_err());
        assert!(block_on(f.finish(S1, b"forged")).is_err());
        assert!(block_on(f.finish(S1, &ch.challenge)).is_ok());
        assert!(block_on(f.finish(S1, &ch.challenge)).is_err(), "used once");
    }
}
