//! R-SB-04, I-27, TH-21 (M6 design reading 4, sections 4 and 6, lane
//! L6-API): a copy request reaches the timeline as an immediate event
//! and fires one submission copy to the given address, with ids and
//! times only.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

mod common;

use common::Cell;
use fstp_cell_core::timeline::Recipient;
use fstp_domain::id::{ContentDigest, TextId, TextRef};
use fstp_domain::record::OutboxEvent;
use fstp_domain::time::Timestamp;
use fstp_domain_testkit::r#gen::review::PR1;
use fstp_mail::{LinkTarget, Slot, TemplateId, Value};
use fstp_timeline::message::MessageSpec;

const MINUTE: i64 = 60_000_000;

/// R-SB-04, I-27: the copy request fires once, to the digest of the given
/// address, from the submission copy template. Its values are the
/// proposal id, the submission instant and a link: no address, title or
/// text. A second tick fires nothing again (I-26).
#[test]
fn r_sb_04_copy_request_fires_one_message_to_the_given_address() {
    let mut c = Cell::from_engine(common::submitted().entries().unwrap());
    let at = c.state.now_floor().micros() + MINUTE;
    let digest = [0x5c; 32];
    let address = TextRef::new(TextId::from_raw(4_000), ContentDigest::from_bytes(digest));
    c.enqueue(
        at,
        OutboxEvent::CopyRequested {
            proposal: PR1,
            address,
        },
    );
    c.tick(Timestamp::from_micros(at)).unwrap();
    assert_eq!(c.bodies.len(), 1);
    let spec = MessageSpec::decode(&c.bodies[0].body).unwrap();
    assert_eq!(spec.to, Recipient::Address(digest));
    assert_eq!(spec.template, TemplateId::SubmissionCopy);
    assert_eq!(
        spec.bindings.get(Slot::Proposal),
        Some(&Value::Proposal(PR1))
    );
    assert_eq!(
        spec.bindings.get(Slot::Link),
        Some(&Value::Link(LinkTarget::Proposal(PR1)))
    );
    let submitted = fstp_domain::proposal::copy::submitted_at(&c.state.engine().core, PR1).unwrap();
    match spec.bindings.get(Slot::When) {
        Some(Value::Moment(m)) => assert_eq!(m.at(), submitted),
        other => panic!("When is {other:?}"),
    }
    assert!(
        c.tick(Timestamp::from_micros(at + MINUTE))
            .unwrap()
            .is_empty()
    );
}
