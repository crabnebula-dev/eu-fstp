//! ADR-012 "Container format" test vectors (R-CR-01, I-81). Lane
//! m3/erase-steps, recorded in ADR-012 "Record: container test vectors".
//!
//! `fstp_backup::seal_container` draws its container id, data key, KEM
//! randomness and chunk nonces from the generator, and no API takes them
//! from a caller (`r_nf_08_no_api_takes_a_caller_nonce`). So the vectors
//! are recorded containers, sealed once by the writer to a fixed hybrid
//! key pair. The key pair is derived from fixed seeds: the X25519 scalar
//! and the ML-KEM-768 `d` and `z` are SHA-256 of fixed labels, expanded
//! through FIPS 203 `ML-KEM.KeyGen_internal`. This crate may name the
//! single-half ML-KEM entry points for test vectors only (I-75 scan).
//!
//! Each run decodes each recorded container, checks every header field at
//! its ADR-012 offset, opens it through `fstp_backup::open_container`,
//! and opens it again by hand from the ADR-012 bytes alone: the data key
//! through `fstp_keys::envelope::open_key` under the ADR-012 seal
//! context, and each chunk under the ADR-012 AAD. The container digests,
//! container ids, data keys and the public key digest must appear in
//! ADR-012, so the record and the test cannot drift apart.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;

use fstp_backup::{BackupError, ContainerKind, decode_container, open_container};
use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_crypto::mlkem::acvp;
use fstp_crypto::x25519::StaticSecret;
use fstp_keys::envelope::{self, SEALED_KEY_LEN, SealContext, decode_sealed_key};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};

/// The label the vector key seeds are derived from.
const SEED_LABEL: &str = "fstp-adr012-vector-v1";

/// The hybrid key pair of the vectors: X25519 scalar
/// `SHA-256("fstp-adr012-vector-v1 x25519")`, ML-KEM-768 `d` and `z`
/// `SHA-256("fstp-adr012-vector-v1 mlkem d")` and `... mlkem z"`.
fn vector_key(label: &str) -> HybridSecretKey {
    let x = fstp_crypto::sha256(format!("{label} x25519").as_bytes());
    let d = fstp_crypto::sha256(format!("{label} mlkem d").as_bytes());
    let z = fstp_crypto::sha256(format!("{label} mlkem z").as_bytes());
    HybridSecretKey::from_parts(
        StaticSecret::from_bytes(&x).unwrap(),
        acvp::keygen(&d, &z).unwrap(),
    )
    .unwrap()
}

/// SHA-256 of the vector key's public key `pk_X || pk_M`.
const PUBLIC_KEY_SHA256: &str = "0304c1ef4c006f2310fa89666d06d7161bace83f4f75af95856548c6e4212e78";

/// The ADR-012 header length: 49 fixed bytes and the 1210-byte FSK1 key.
const HEADER_LEN: usize = 49 + SEALED_KEY_LEN;

/// One recorded container and the inputs it was sealed from.
struct Vector {
    name: &'static str,
    hex: &'static str,
    kind: ContainerKind,
    chain: Chain,
    owner: [u8; 16],
    group: [u8; 16],
    generation: u32,
    part: u32,
    plaintext: &'static [u8],
    container: &'static str,
    data_key: &'static str,
    sha256: &'static str,
}

const V1_HEX: &str = concat!(
    "4642433101000103031111111111111111111111111111111156ba72ac6b2081c17aceb7b1a32698c8000000",
    "000010000046534b310100010001032222222222222222222222222222222200000001ba4d9925697b1bb51e",
    "e53f01927c4db450e74a27c7806ca89008ab1c53bb9d11d3000bdbc69990e19cb7a704a53de7f63782132946",
    "bbc3a50e07cd4e1c1dca28e3c8afcf6ce2051b2ff1580153ed2ce3b3f927097c7c4c9d14d42672a7f9baae0d",
    "91d008b27eaccc6c30d9b44d95776cfbf1f78de46fe37431689579267b7ca42d8c9c3378e91da9657888bb1e",
    "8739ef878654be7735deb4f33e6dd0c2bf871c4846425a7206dc1c12adaaa79ac91e09f5898a080f94808342",
    "def123ab8bf6fa5b84b076ba31b5b17db24f6a0399cb6c1366c1f3e224d888f75942134f62ab6814a4130434",
    "34e7234c764132f442f7b9af23abf91708469542862a5d3c4abea976a4c794a3e684d57d6dd0f76e2867ff45",
    "04f9ce617ba668b9a18c883620432d3b1f0905072110803da8eb0d72b4ace1ccc16b6179251372cab1127ee8",
    "fbae37a896c7d2b2fbf03a9d69db7170deb9daa8bfd7aabcb9f813561066f3989dc31ad594d4c96d863d0618",
    "e4df08dd48274fbdc641cd774f6b67cabe6435af489c6c2cad91bd628a5cdc4343c4ff2208ecbe8a5035c7e0",
    "acae0146e146bbbcaf3cfeca354eb043a9f019bc1438aa96ae01cf748206b173f9b7d524decd306809287177",
    "4aa8a70c83baf3f50776e230cbf2d710ebfc603ed01b60f8f8c815dd4b37e3850922141b82c562243904649d",
    "641e0150b8405370a92a43bf4f4993139809f347ab51f45622852cda7be685e9767a01bbe4aaf2043f5081f3",
    "c3c86d968dce956e049188051269c59b4850ab4310a4dd137ab0cfc9137db104d555d7e0cffa9e1d8b648e21",
    "9b7cfad668b9bdd8aa8394d21b7fcea2576fa7ed0531ac786b68131795eca06a79e3a696fe33bb2b18c5a687",
    "ccf8d3efafb8e58ad0cc8cf1da5a173d850af0f3b5eb9aea0b5426b13e2a7975614535bc6229d9de840d50bf",
    "3a892dfd99737554e2c197201dc1387278e3ff17abc8b88b9150306b99b64f34c15e4b39a816c0988ab1f00c",
    "134af213cb6331c3f0f6720f198cdf2d974fc09d18150a48298068bb6c268c5c8e1bccaed773adef15b2fcf4",
    "ee95b0b90381b6d859ca1cd8999857202a910a7ff9389ea24a99e306b1dfde3ab99acb0aa9de56a584f4c3d5",
    "ce099fad9fdbd6ae5c3b70e20641d9b7c97821c23896a3dd98e8f53ad52860ea3187d5d24fe9c6fcc776daca",
    "9e8c72a00ab3e3897c743749b58c13a1d3fc9c94be3737652765bf2b8db795f78dab16aba3cd7f89426d695a",
    "32fcffc88f2c501a0bb74aab0a20e989d658723a341640b1ebcc12ce309c7e93616327083b277c48c3a30609",
    "b19682ca504574e8cc89e3e45d514a9ab9b7d38a90670ded240e6f71816dfd0072755dacf52e2f3ebc5c5473",
    "5e109ec976fc762cd8a8a876bf3603e94680a93cca0391d660042ff5b0b787b8c0485814ff9b2d8696b98d8b",
    "5a1317ace00e2434253adcd46a9f83e69b690353d0b7dbbf33e93e6fc0a7c68d14a730b8119afa1c9602b1d3",
    "3823c19939f46fdf67cec1de2b9ec5d45b020e86a02554179933d9707e865268e84d6f35166d471094110483",
    "da23f9208778f6c70b3e7e23162745a94f0306584e7d6328b7cfa4b14e0664468b11c354c102a47a8952319e",
    "87dcc5634a934b38fcf08577371fb5551097ad1e778e4369c051ec0100000000315ea47e345af5b77ebf2db6",
    "11df85eeb8d61b30514891df9c690b99",
);

const V2_HEX: &str = concat!(
    "46424331010001020433333333333333333333333333333333b3d161759f60bc6cb1769cf510998905000000",
    "020010000046534b3101000100010444444444444444444444444444444444000000079517b28615b37e52d0",
    "e624b4f54f76d58ed0b9e2803ec5a7ea795554780cfc1bc7d5e306eb87794b555c1a2f0864d74a6ea58cda1f",
    "b55b504f7545c3d607b5e604271fb17797e711c74fa884f7b3f6aacbb6d46aa55c7f405d4e8d3e1f087c9614",
    "39a7508921dccfdefbc831a2007e7fa619ab3f754e0c1a69c90d2e46d6a8d6fc0b6f8d8ededda43efa34cb07",
    "928e001f853bbcc81624981f638566679cf9d11481e57b4da9b7afca2f223d1b1eed5244157133e6c548b71b",
    "85ebb995e4f85ad3e6471cb3bc9cd08b6b1cc7820ab8a1ffdfb4271e74f70a1cf1d72500acc7d6c5a2dc4079",
    "d6cd2e416d6966361a67d7cfadf0d5b5056f835108fbb05fd0301a5a2e82fc29894f0fdedea46c4e96ee1213",
    "cb06b3f620b0c0c7d2efeef9d6276e87bcb11dd87d46544c4e4cb3c9acb54b1ed6b42c49715f329a671b78e6",
    "935587fd8c91067e0616aa7c57534f6304450024c65a119008882a4a242f824c33c039375fe657651c09e185",
    "90eb6dee76f0ab1dd252cb92511b14cdcda0aba540389b8715606e074555d2ec9730703653f5d381289676e6",
    "037feb36e23be67a30d767761eb65ef68ca8feb88fb6899dc64f97e7b9f35b71e1a46b203b690fb774f7fbef",
    "287a0cd59189ac1fbccf8deed86f95bbc466264ded8c3cd0f25ec58c8fa6f22c8ad31f73f31e985d14dc8632",
    "e8320b79c4b009febaf04f96e6bf4610984878dd8c42d1d68ff4776e7bd7ce0ab6448110c15d7ba25b0f72c2",
    "5ab8dd8f68b3a3a63f0af74186ac4e73dd71c1c1eca66919bddd59cf2af7cf8e3ff0b871bd0b7c3cc1e4b230",
    "fd56c506cbb82dd9d990448fc06a54eb1f0d34dc9e04cc2a72b8ced8f8d19022bd353a222884b2337cd13cdc",
    "29cc6e814678cfbb2c109a7eda861468e5f7d0a7bc7c07888e6c1dc302897b2c7400628e054e98a944f7fbb7",
    "1289b7a763b52876098a38919914fcdd5686dece18dd2c00eab4c57f88067a3a7708a086a8e9cf03277969a1",
    "b9da96008b60f19ddcb5a34b61159abbbcc2a5d41d04f892a62d4e7b632f564e3a62080088656763d148af1c",
    "417876ed9f11e3364e2c8bbee1b16693f96e2b35aadd86660c6965ab7fb1d634f7eead50319d2dd78aa92a97",
    "e019222fa9dd2088222a1c00fb9e4a89bc9af7774a7451d54e49637c412fc54c508fe2cc9930ca230716ee07",
    "6b388cc50097ee5d9b125e85d5f705f108af0513be2873dadc7ef827cec7e76334cfe381a56029ca3a5856e1",
    "babc704400cc62058c7f0ffda0c96b6c41298b36648633c5608c9c86c991b3878e6d619b23e63fd4ff0457e9",
    "d8146508f86802a00fc7a675e110c5100a137fa4b78e5ce2772a5fbf2772345bf8ed76557e8b9781a6fe63e1",
    "70faff3d0b960b1d30bc862e63ea3ffa8683f3156343c3432909057581647d26f69c931daaf78bc72870b158",
    "e01368c5534693f2fd0952c67e7cf54ee20de068c948fae5e9d79d14654448c349e10e9083fd5b37ca38a7fa",
    "fe24d1499ab15a2c3384a11963b143fe7e6fee74d0738b8bbb4965f8ee346a821b15a4b888b81d51a8df8e1b",
    "34822ff3a1b013b41320657ed19ddb1cbc582b3aaf4bb48925f0222a8b455a98779cad9adb0a62cb65c70457",
    "2febe89243a22a57c7327e215082e9ad4ad5e4ecaad07d4ca33303010000002721e8618b519c01e560c84680",
    "a7755eb24bb1e5acadfcbd2f71724e540d5fbe7db401c24011309dcd00d780636aba897aa233db81879eab1b",
    "e477c28a836dee1dd2c124",
);

fn vectors() -> [Vector; 2] {
    [
        Vector {
            name: "V1 empty keystore snapshot",
            hex: V1_HEX,
            kind: ContainerKind::KeystoreSnapshot,
            chain: Chain::CellBackup,
            owner: [0x11; 16],
            group: [0x22; 16],
            generation: 1,
            part: 0,
            plaintext: b"",
            container: "56ba72ac6b2081c17aceb7b1a32698c8",
            data_key: "11d1ae184bce65726ef2766bc93f968b7098f631fb6dc01ef844d7f8990c4f98",
            sha256: "4750b2152de2f8bcee455ed0f43775b91026524bb7b71dd6c580da55379a0900",
        },
        Vector {
            name: "V2 WAL segment, part 2",
            hex: V2_HEX,
            kind: ContainerKind::WalSegment,
            chain: Chain::ClusterBackup,
            owner: [0x33; 16],
            group: [0x44; 16],
            generation: 7,
            part: 2,
            plaintext: b"synthetic WAL segment, ADR-012 vector 2",
            container: "b3d161759f60bc6cb1769cf510998905",
            data_key: "a77531001dcf43265464ea9fd68cbdedbbc946a442be8a05d9f8b963f533150a",
            sha256: "fe4f9a4dc50d6be5ca06a125a8b4faca0e4a3cd8c26c0b46fdeae29d9fd6ed29",
        },
    ]
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd hex length");
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

/// The chunks of `bytes` after the header, read by the ADR-012 layout:
/// `final u8 | len u32 | nonce 12 | ciphertext len | tag 16`.
fn chunks(bytes: &[u8]) -> Vec<(bool, [u8; 12], Vec<u8>)> {
    let mut out = Vec::new();
    let mut rest = &bytes[HEADER_LEN..];
    while !rest.is_empty() {
        let last = rest[0] == 1;
        let len = u32::from_be_bytes(rest[1..5].try_into().unwrap()) as usize;
        let nonce: [u8; 12] = rest[5..17].try_into().unwrap();
        out.push((last, nonce, rest[17..17 + len + 16].to_vec()));
        rest = &rest[17 + len + 16..];
    }
    out
}

/// ADR-012 test vectors, R-CR-01: each recorded container has its
/// recorded digest, carries every header field at its ADR-012 offset,
/// decodes, and opens to its plaintext under the vector key through
/// `fstp_backup::open_container`.
#[test]
fn r_cr_01_adr012_container_vectors_open_through_the_opener() {
    let sk = vector_key(SEED_LABEL);
    assert_eq!(
        hex(&fstp_crypto::sha256(&sk.public().to_bytes())),
        PUBLIC_KEY_SHA256
    );
    for v in vectors() {
        let bytes = unhex(v.hex);
        assert_eq!(hex(&fstp_crypto::sha256(&bytes)), v.sha256, "{}", v.name);
        assert_eq!(&bytes[0..4], b"FBC1", "{}", v.name);
        assert_eq!(bytes[4], 1, "{}: version", v.name);
        assert_eq!(&bytes[5..7], &[0, 1], "{}: aead", v.name);
        assert_eq!(bytes[7], v.kind.code(), "{}: kind", v.name);
        assert_eq!(bytes[8], v.chain.code(), "{}: chain", v.name);
        assert_eq!(bytes[9..25], v.owner, "{}: owner", v.name);
        assert_eq!(hex(&bytes[25..41]), v.container, "{}: container", v.name);
        assert_eq!(bytes[41..45], v.part.to_be_bytes(), "{}: part", v.name);
        assert_eq!(bytes[45..49], 1_048_576u32.to_be_bytes(), "{}", v.name);
        assert_eq!(decode_container(&bytes).unwrap().len(), 1, "{}", v.name);
        let o = open_container(&sk, &bytes).unwrap();
        assert_eq!(o.kind, v.kind, "{}", v.name);
        assert_eq!(o.owner, v.owner, "{}", v.name);
        assert_eq!(hex(&o.container), v.container, "{}", v.name);
        assert_eq!(o.part, v.part, "{}", v.name);
        assert_eq!(o.plaintext, v.plaintext, "{}", v.name);
    }
}

/// ADR-012 test vectors, R-CR-01: each container opens again from the
/// ADR-012 bytes alone. The data key opens through the hybrid KEM under
/// the seal context (owner, chain, purpose `Backup`, group, generation,
/// container id) to its recorded value, and each chunk opens under
/// `header | index u64 | final u8`.
#[test]
fn r_cr_01_adr012_container_vectors_open_by_the_written_layout() {
    let sk = vector_key(SEED_LABEL);
    for v in vectors() {
        let bytes = unhex(v.hex);
        let sealed = decode_sealed_key(&bytes[49..HEADER_LEN]).unwrap();
        let h = sealed.header();
        assert_eq!(
            (h.chain, h.group.0, h.generation),
            (v.chain, v.group, v.generation)
        );
        let ctx = SealContext {
            cell: CellId(v.owner),
            chain: v.chain,
            purpose: Purpose::Backup,
            group: GroupId(v.group),
            generation: v.generation,
            object: ObjectId(bytes[25..41].try_into().unwrap()),
        };
        let dek = envelope::open_key(&sk, &sealed, &ctx).unwrap();
        assert_eq!(hex(dek.expose()), v.data_key, "{}: data key", v.name);
        let key = aead::Key::from_bytes(dek.expose()).unwrap();
        let mut plaintext = Vec::new();
        for (i, (last, nonce, body)) in chunks(&bytes).into_iter().enumerate() {
            let mut aad = bytes[..HEADER_LEN].to_vec();
            aad.extend_from_slice(&(i as u64).to_be_bytes());
            aad.push(u8::from(last));
            plaintext.extend_from_slice(&aead::open(&key, &nonce, &aad, &body).unwrap());
        }
        assert_eq!(plaintext, v.plaintext, "{}", v.name);
    }
}

/// ADR-012 test vectors, I-81: a recorded container does not open under
/// another key pair, nor once a header byte changes.
#[test]
fn i81_adr012_container_vectors_refuse_another_key_and_a_changed_header() {
    let sk = vector_key(SEED_LABEL);
    let other = vector_key("fstp-adr012-vector-v1 other");
    for v in vectors() {
        let bytes = unhex(v.hex);
        assert_eq!(
            open_container(&other, &bytes).unwrap_err(),
            BackupError::OpenFailed,
            "{}",
            v.name
        );
        let mut moved = bytes.clone();
        moved[41] ^= 1;
        assert!(open_container(&sk, &moved).is_err(), "{}: part", v.name);
    }
}

/// ADR-012 "Record: container test vectors": the record names every
/// container digest, container id and data key of the vectors, and the
/// public key digest of the vector key.
#[test]
fn r_cr_01_adr012_records_the_container_vectors() {
    let adr = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/adr/ADR-012-backups.md");
    let text = std::fs::read_to_string(&adr).unwrap();
    assert!(text.contains("Record: container test vectors"));
    assert!(text.contains(PUBLIC_KEY_SHA256), "public key digest");
    for v in vectors() {
        for value in [v.sha256, v.container, v.data_key] {
            assert!(text.contains(value), "{}: {value} not in ADR-012", v.name);
        }
    }
}
