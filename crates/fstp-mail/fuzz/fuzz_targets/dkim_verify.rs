//! Fuzz target `dkim_verify` of `fstp-mail` (TH-26, M6 design section
//! 5.3): the header parser, the DKIM tag-list reader, the `b=` stripping
//! and both canonicalisations, under a fixed Ed25519 key. Verification
//! must return a typed result without panicking, and an input this target
//! signs itself must verify unless it has no From field.

#![no_main]

use fstp_crypto::sig::Ed25519SigningKey;
use fstp_mail::MailError;
use fstp_mail::dkim::{DkimKey, DkimSigner, sign, verify};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(key) = Ed25519SigningKey::from_seed(&[9u8; 32]) else {
        return;
    };
    let Ok(signer) = DkimSigner::new("fuzz.example", "sel", DkimKey::Ed25519(key)) else {
        return;
    };
    let Ok(public) = signer.public_key() else {
        return;
    };
    let _ = verify(data, "fuzz.example", "sel", &public);
    if let Ok(signed) = sign(data, &signer) {
        // Without a From field the signature is refused as unsupported.
        // Any other failure of an own signature is a defect.
        match verify(&signed, "fuzz.example", "sel", &public) {
            Ok(()) | Err(MailError::DkimUnsupported) => {}
            Err(e) => panic!("own signature fails: {e}"),
        }
    }
});
