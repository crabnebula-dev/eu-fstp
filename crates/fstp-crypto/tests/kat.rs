//! Known-answer tests for the fstp-crypto facade.
//!
//! Every expected value below was produced at development time with the
//! OpenSSL 3.0.13 command line tool, not copied from memory. The exact command
//! sits next to each vector so that anyone can reproduce it.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::num::NonZeroU32;

use fstp_crypto::{
    HmacSha256, Sha256, constant_time_eq, hmac_sha256, hmac_sha256_verify, pbkdf2_hmac_sha256,
    random_array, random_bytes, sha256, try_pbkdf2_hmac_sha256,
};

fn hex(s: &str) -> Vec<u8> {
    let clean: Vec<u8> = s.bytes().filter(|b| b.is_ascii_hexdigit()).collect();
    assert_eq!(clean.len() % 2, 0, "odd hex length");
    clean
        .chunks(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

fn iters(n: u32) -> NonZeroU32 {
    NonZeroU32::new(n).unwrap()
}

/// Deterministic xorshift generator for chunking tests. Not cryptographic.
struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % (n as u64)) as usize
    }
}

// ---------------------------------------------------------------- SHA-256

/// `printf '' | openssl dgst -sha256 -r`
#[test]
fn sha256_empty() {
    assert_eq!(
        sha256(b"").to_vec(),
        hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    );
}

/// `printf 'abc' | openssl dgst -sha256 -r`
#[test]
fn sha256_abc() {
    assert_eq!(
        sha256(b"abc").to_vec(),
        hex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
}

/// `printf 'abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq' | openssl dgst -sha256 -r`
#[test]
fn sha256_two_blocks() {
    assert_eq!(
        sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq").to_vec(),
        hex("248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
    );
}

/// `printf 'The quick brown fox jumps over the lazy dog' | openssl dgst -sha256 -r`
#[test]
fn sha256_fox() {
    assert_eq!(
        sha256(b"The quick brown fox jumps over the lazy dog").to_vec(),
        hex("d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592")
    );
}

/// `head -c 1000000 /dev/zero | tr '\0' 'a' | openssl dgst -sha256 -r`
#[test]
fn sha256_million_a_streaming() {
    let expected = hex("cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0");
    let data = vec![b'a'; 1_000_000];
    assert_eq!(sha256(&data).to_vec(), expected);

    let mut rng = XorShift(0x5eed_0001);
    let mut ctx = Sha256::new();
    let mut rest: &[u8] = &data;
    while !rest.is_empty() {
        let n = (rng.below(4096) + 1).min(rest.len());
        let (head, tail) = rest.split_at(n);
        ctx.update(head);
        rest = tail;
    }
    assert_eq!(ctx.finish().to_vec(), expected);
}

#[test]
fn sha256_streaming_matches_one_shot_for_every_split() {
    let data: Vec<u8> = (0u16..300).map(|i| (i % 251) as u8).collect();
    let expected = sha256(&data);
    for split in 0..=data.len() {
        let (a, b) = data.split_at(split);
        let mut ctx = Sha256::default();
        ctx.update(a);
        let cloned = ctx.clone();
        ctx.update(b);
        assert_eq!(ctx.finish(), expected, "split at {split}");
        let mut again = cloned;
        again.update(b);
        assert_eq!(again.finish(), expected, "clone at {split}");
    }
}

// ----------------------------------------------------------- HMAC-SHA-256

/// RFC 4231 test case 1 inputs.
/// `printf 'Hi There' | openssl dgst -sha256 -mac HMAC -macopt hexkey:0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b -r`
#[test]
fn hmac_sha256_case_1() {
    let key = vec![0x0b; 20];
    assert_eq!(
        hmac_sha256(&key, b"Hi There").to_vec(),
        hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
    );
}

/// RFC 4231 test case 2 inputs.
/// `printf 'what do ya want for nothing?' | openssl dgst -sha256 -mac HMAC -macopt key:Jefe -r`
#[test]
fn hmac_sha256_case_2() {
    assert_eq!(
        hmac_sha256(b"Jefe", b"what do ya want for nothing?").to_vec(),
        hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    );
}

/// RFC 4231 test case 3 inputs: key is 20 bytes of 0xaa, data is 50 bytes of 0xdd.
/// `printf '\xdd' x50 | openssl dgst -sha256 -mac HMAC -macopt hexkey:aa..aa (20 bytes) -r`
#[test]
fn hmac_sha256_case_3() {
    let key = vec![0xaa; 20];
    let data = vec![0xdd; 50];
    assert_eq!(
        hmac_sha256(&key, &data).to_vec(),
        hex("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe")
    );
}

/// RFC 4231 test case 6 inputs: a 131-byte key, longer than the block size.
/// `printf 'Test Using Larger Than Block-Size Key - Hash Key First' | openssl dgst -sha256 -mac HMAC -macopt hexkey:aa..aa (131 bytes) -r`
#[test]
fn hmac_sha256_case_6_long_key() {
    let key = vec![0xaa; 131];
    assert_eq!(
        hmac_sha256(
            &key,
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        )
        .to_vec(),
        hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
    );
}

/// Empty key and empty message. HMAC pads keys with zeros, so the one-byte key
/// 0x00 gives the same tag as the empty key.
/// `printf '' | openssl dgst -sha256 -mac HMAC -macopt hexkey:00 -r`
#[test]
fn hmac_sha256_empty_key_and_message() {
    let expected = hex("b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    assert_eq!(hmac_sha256(b"", b"").to_vec(), expected);
    assert_eq!(hmac_sha256(&[0u8], b"").to_vec(), expected);
}

#[test]
fn hmac_sha256_streaming_and_verify() {
    let key = vec![0xaa; 131];
    let msg = b"Test Using Larger Than Block-Size Key - Hash Key First";
    let tag = hmac_sha256(&key, msg);
    for split in 0..=msg.len() {
        let (a, b) = msg.split_at(split);
        let mut mac = HmacSha256::new(&key);
        mac.update(a);
        mac.update(b);
        assert_eq!(mac.finish(), tag, "split at {split}");
    }
    assert!(hmac_sha256_verify(&key, msg, &tag));
    let mut bad = tag;
    bad[31] ^= 1;
    assert!(!hmac_sha256_verify(&key, msg, &bad));
    assert!(!hmac_sha256_verify(&key, msg, &tag[..31]));
    assert!(!hmac_sha256_verify(&key, msg, &[]));
    assert!(!hmac_sha256_verify(b"other key", msg, &tag));
}

// ------------------------------------------------------ PBKDF2-HMAC-SHA256

fn pbkdf2(password: &[u8], salt: &[u8], c: u32, len: usize) -> Vec<u8> {
    let mut out = vec![0u8; len];
    pbkdf2_hmac_sha256(password, salt, iters(c), &mut out);
    out
}

/// `openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:1 PBKDF2`
#[test]
fn pbkdf2_one_iteration() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 1, 32),
        hex("120FB6CFFCF8B32C43E7225256C4F837A86548C92CCC35480805987CB70BE17B")
    );
}

/// `openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:2 PBKDF2`
#[test]
fn pbkdf2_two_iterations() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 2, 32),
        hex("AE4D0C95AF6B46D32D0ADFF928F06DD02A303F8EF3C251DFD6E2D85A95474C43")
    );
}

/// `openssl kdf -keylen 32 -kdfopt digest:SHA256 -kdfopt pass:password -kdfopt salt:salt -kdfopt iter:4096 PBKDF2`
#[test]
fn pbkdf2_4096_iterations() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 4096, 32),
        hex("C5E478D59288C841AA530DB6845C4C8D962893A001CE4E11A4963873AA98134A")
    );
}

/// Output longer than one block (40 bytes), long password and salt.
/// `openssl kdf -keylen 40 -kdfopt digest:SHA256 -kdfopt pass:passwordPASSWORDpassword -kdfopt salt:saltSALTsaltSALTsaltSALTsaltSALTsalt -kdfopt iter:4096 PBKDF2`
#[test]
fn pbkdf2_multi_block_output() {
    assert_eq!(
        pbkdf2(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40
        ),
        hex("348C89DBCBD32B2F32D814B8116E84CF2B17347EBC1800181C4E2A1FB8DD53E1C635518C7DAC47E9")
    );
}

/// `openssl kdf -keylen 64 -kdfopt digest:SHA256 -kdfopt pass:passwd -kdfopt salt:salt -kdfopt iter:1 PBKDF2`
#[test]
fn pbkdf2_passwd_salt_64_bytes() {
    assert_eq!(
        pbkdf2(b"passwd", b"salt", 1, 64),
        hex(
            "55AC046E56E3089FEC1691C22544B605F94185216DDE0465E68B9D57C20DACBC\
             49CA9CCCF179B645991664B39D77EF317C71B845B1E30BD509112041D3A19783"
        )
    );
}

/// `openssl kdf -keylen 64 -kdfopt digest:SHA256 -kdfopt pass:Password -kdfopt salt:NaCl -kdfopt iter:80000 PBKDF2`
#[test]
fn pbkdf2_80000_iterations() {
    assert_eq!(
        pbkdf2(b"Password", b"NaCl", 80000, 64),
        hex(
            "4DDCD8F60B98BE21830CEE5EF22701F9641A4418D04C0414AEFF08876B34AB56\
             A1D425A1225833549ADB841B51C9B3176A272BDEBBA1D078478F62B397F33C8D"
        )
    );
}

/// Embedded NUL bytes in password and salt, 16-byte output.
/// `openssl kdf -keylen 16 -kdfopt digest:SHA256 -kdfopt hexpass:7061737300776f7264 -kdfopt hexsalt:7361006c74 -kdfopt iter:4096 PBKDF2`
#[test]
fn pbkdf2_embedded_nul() {
    assert_eq!(
        pbkdf2(b"pass\0word", b"sa\0lt", 4096, 16),
        hex("89B69D0516F829893C696226650A8687")
    );
}

#[test]
fn pbkdf2_try_form_agrees_and_prefix_property_holds() {
    let mut long = [0u8; 64];
    try_pbkdf2_hmac_sha256(b"passwd", b"salt", iters(1), &mut long).unwrap();
    // A shorter output is a prefix of a longer one with the same inputs.
    let short = pbkdf2(b"passwd", b"salt", 1, 20);
    assert_eq!(&long[..20], &short[..]);
    // A zero-length output is accepted and writes nothing.
    let mut empty: [u8; 0] = [];
    try_pbkdf2_hmac_sha256(b"passwd", b"salt", iters(1), &mut empty).unwrap();
}

// -------------------------------------------------------- constant_time_eq

#[test]
fn constant_time_eq_semantics() {
    assert!(constant_time_eq(b"", b""));
    assert!(constant_time_eq(b"abc", b"abc"));
    assert!(!constant_time_eq(b"abc", b"abd"));
    assert!(!constant_time_eq(b"abc", b"ab"));
    assert!(!constant_time_eq(b"", b"a"));
    let mut rng = XorShift(0xc0ff_ee00);
    for _ in 0..500 {
        let len = rng.below(64);
        let a: Vec<u8> = (0..len).map(|_| rng.next() as u8).collect();
        let mut b = a.clone();
        assert!(constant_time_eq(&a, &b));
        if len > 0 {
            let i = rng.below(len);
            b[i] ^= 1 << rng.below(8);
            assert!(!constant_time_eq(&a, &b));
        }
    }
}

// ------------------------------------------------------------- randomness

#[test]
fn random_bytes_fills_and_varies() {
    let mut a = [0u8; 64];
    let mut b = [0u8; 64];
    random_bytes(&mut a).unwrap();
    random_bytes(&mut b).unwrap();
    // The chance that 64 random bytes are all zero or repeat is 2^-512.
    assert_ne!(a, [0u8; 64]);
    assert_ne!(a, b);
    let c: [u8; 32] = random_array().unwrap();
    let d: [u8; 32] = random_array().unwrap();
    assert_ne!(c, d);
    let mut empty: [u8; 0] = [];
    random_bytes(&mut empty).unwrap();
}
