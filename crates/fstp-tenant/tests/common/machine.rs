//! The state machine of lane W2d: the reference and the production tenant
//! state, run side by side over generated operations.
//!
//! - Postcondition: the verdict equals the reference's. A refused
//!   operation appends nothing. An accepted one appends the record that
//!   [`required_record`] names. A setting change appends that record only
//!   (design 3.5: "Every change is a ledger record").
//! - Invariant: the projection equals the reference's, and a state folded
//!   from the appended records alone shows the same projection (Q31: the
//!   admin set has the ledger's replay guarantees).

use fstp_prop::{Gen, StateMachine};
use fstp_tenant::TenantError;

use super::gens::{Focus, op};
use super::prod::{Outcome, Sut};
use super::reference::{Reference, required_record};
use super::vocab::{Env, Op, Verdict};

/// The machine over a fixed environment.
#[derive(Clone, Debug)]
pub struct TenantMachine {
    /// The environment of every case.
    pub env: Env,
    /// What the generated operations concentrate on.
    pub focus: Focus,
    /// The longest operation sequence of a case.
    pub max: usize,
}

impl StateMachine for TenantMachine {
    type Model = Reference;
    type Sut = Result<Sut, TenantError>;
    type Command = Op;
    type Output = Result<Outcome, TenantError>;

    fn init_model(&self) -> Reference {
        Reference::new(&self.env)
    }

    fn init_sut(&self) -> Result<Sut, TenantError> {
        Sut::genesis(&self.env)
    }

    fn command(&self, g: &mut Gen, model: &Reference) -> Op {
        op(g, model, self.focus)
    }

    fn run(&self, sut: &mut Result<Sut, TenantError>, cmd: &Op) -> Result<Outcome, TenantError> {
        match sut {
            Ok(s) => s.run(cmd),
            Err(e) => Err(*e),
        }
    }

    fn next_state(&self, model: &mut Reference, cmd: &Op) {
        model.apply(cmd);
    }

    fn postcondition(
        &self,
        model: &Reference,
        cmd: &Op,
        output: &Result<Outcome, TenantError>,
    ) -> Result<(), String> {
        let out = output.as_ref().map_err(|e| e.to_string())?;
        let expected = model.verdict(cmd);
        if out.verdict != expected {
            return Err(format!(
                "verdict {:?}, the reference gives {expected:?}",
                out.verdict
            ));
        }
        match out.verdict {
            Verdict::Refused if !out.records.is_empty() => {
                Err(format!("a refused operation appended {:?}", out.records))
            }
            Verdict::Refused => Ok(()),
            Verdict::Accepted => {
                let need = required_record(cmd);
                let exact = matches!(cmd, Op::SetSetting { .. });
                if exact && out.records != [need.clone()] {
                    return Err(format!(
                        "a setting change must append exactly {need:?}, got {:?}",
                        out.records
                    ));
                }
                if !out.records.contains(&need) {
                    return Err(format!(
                        "an accepted operation must append {need:?}, got {:?}",
                        out.records
                    ));
                }
                Ok(())
            }
        }
    }

    fn invariant(&self, model: &Reference, sut: &Result<Sut, TenantError>) -> Result<(), String> {
        let s = sut.as_ref().map_err(|e| e.to_string())?;
        let seen = s.observe().map_err(|e| e.to_string())?;
        let want = model.observed();
        if seen != want {
            return Err(format!(
                "projection differs from the reference\n  seen: {seen:?}\n  want: {want:?}"
            ));
        }
        let replayed = s.replayed().map_err(|e| e.to_string())?;
        if replayed != seen {
            return Err(format!(
                "a fold of the records differs from the state (Q31)\n  replayed: {replayed:?}\n  state: {seen:?}"
            ));
        }
        let config = s.publication_config().map_err(|e| e.to_string())?;
        if config != model.publication_config() {
            return Err(format!(
                "publication config {config:?}, the reference gives {:?}",
                model.publication_config()
            ));
        }
        Ok(())
    }

    fn max_commands(&self) -> usize {
        self.max
    }
}
