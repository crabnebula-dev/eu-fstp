//! TH-26: fuzz target `dispatch_prepare` over S2 of the dispatcher
//! (`fstp_dispatch::prepare`, M6 design section 5.1). Beyond "no panic":
//! an accepted message keeps its bytes, and its envelope recipient is a
//! mailbox `fstp-mail` accepts.

#![no_main]

use fstp_dispatch::prepare;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if let Ok(p) = prepare::prepare(data, "noreply@fund.test") {
        assert_eq!(p.body, data);
        assert!(fstp_mail::Mailbox::new(&p.envelope.to).is_ok());
        assert!(p.template_version >= 1);
    }
});
