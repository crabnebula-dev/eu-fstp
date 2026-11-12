//! `grant.publicity.view` (M9 design section 2.2, lane P1; R-PB-02,
//! R-PB-03, I-41, I-42, I-43), after `authorize_read` cleared the caller
//! as the maker of the grant's public choices (`ReadRule::ChoiceMaker`).
//!
//! Each choice text is read through `TextStore::get_public`, which
//! refuses every text that is not a public text (R-PB-03). A text the
//! store refuses reads as empty, so the page shows that it is missing.
//! The effective level is the one the public filter applies: the lower
//! of the choice and the maximum, and hidden for a minor-flagged grant.

use fstp_domain::id::{ProposalId, TextRef};
use fstp_domain::publicity::{PublicPhase, settable_in};
use fstp_public::Level;

use super::Call;
use super::Seams;
use crate::grant::GrantModel;
use crate::publicity::{ChoiceView, DeliverableView, PhaseView, PublicityView};

/// The public text `r`, or empty when the store refuses it.
async fn public_text<P: Seams>(call: &Call<'_, P>, r: TextRef) -> String {
    use crate::port::TextStore as _;
    call.ports
        .texts()
        .get_public(crate::port::PublicTextRef(r.id().raw()))
        .await
        .ok()
        .and_then(|b| String::from_utf8(b).ok())
        .unwrap_or_default()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// The view of `p` (module documentation).
pub(super) async fn view<P: Seams>(call: &Call<'_, P>, p: ProposalId) -> GrantModel {
    let core = &call.state.core;
    let tag = fstp_domain::view::proposal_state(core, p);
    let minor = fstp_domain::view::proposal_minor_flagged(core, p);
    let programme = fstp_domain::publicity::programme_of(core, p);
    let (max_funded, max_finished) = programme.map_or((Level::Hidden, Level::Hidden), |prog| {
        fstp_public::maxima(core, prog)
    });
    let mut phases = Vec::new();
    for (phase, max) in [
        (PublicPhase::Funded, max_funded),
        (PublicPhase::Finished, max_finished),
    ] {
        let open = tag.is_some_and(|t| settable_in(phase).contains(&t));
        let choice = match core.publicity().choice(p, phase) {
            None => None,
            Some(c) => {
                let level = Level::from_domain(c.level);
                Some(ChoiceView {
                    level,
                    effective: if minor { Level::Hidden } else { level.min(max) },
                    title: public_text(call, c.title).await,
                    summary: public_text(call, c.summary).await,
                    grantee: public_text(call, c.grantee).await,
                    deliverables: c.deliverables.iter().copied().collect(),
                })
            }
        };
        phases.push(PhaseView { open, choice });
    }
    let finished = phases.pop().unwrap_or(PhaseView {
        open: false,
        choice: None,
    });
    let funded = phases.pop().unwrap_or(PhaseView {
        open: false,
        choice: None,
    });
    let deliverables = core
        .money()
        .accepted_deliverables(p)
        .into_iter()
        .map(|(id, licence, snapshot)| DeliverableView {
            id,
            licence: licence.0.clone(),
            snapshot: hex(&snapshot.bytes()),
        })
        .collect();
    GrantModel::Publicity(Box::new(PublicityView {
        proposal: p,
        state: tag.map_or("UNKNOWN", fstp_domain::StateTag::spec_name),
        minor,
        max_funded,
        max_finished,
        funded,
        finished,
        deliverables,
    }))
}
