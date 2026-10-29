//! The reference hybrid KEM, written from ADR-004 "Completion part 1"
//! alone (design section 3.2). The W1h test agent owns this file. The
//! reference itself never reads or calls the production
//! `fstp_crypto::hybrid_kem`; only its test module does, to compare the
//! two.
//!
//! What it holds:
//!
//! - HKDF-SHA-256 (RFC 5869) evaluated from HMAC-SHA-256 calls of
//!   aws-lc-rs, as the ADR's test vector plan, item 1, asks. Production
//!   calls the aws-lc-rs `hkdf` module instead, so the two evaluations are
//!   independent. This is test-only composition of an aws-lc-rs HMAC, not
//!   a new primitive.
//! - [`combine`], the combiner of the section "Combiner bytes", with all
//!   six inputs as parameters. [`combine_omitting`] is its teeth twin.
//! - The fixed-input vector set of item 2 ([`vector`], [`VECTOR_COUNT`]).
//! - [`RefKeyPair`] and [`encapsulate`], the whole KEM over the aws-lc-rs
//!   ML-KEM-768 and X25519 oracles, for the cross-implementation round
//!   trips of item 4.
//! - [`OracleMlKem`] and [`oracle_mlkem_encapsulate`], the bare aws-lc-rs
//!   ML-KEM-768 oracle for the differential test of item 10.
//! - [`OracleMlDsa65`] and [`oracle_mldsa65_verify`], the bare aws-lc-rs
//!   ML-DSA-65 oracle for the ACVP subset of T-CR-MLDSA (design section
//!   7.4, TH-68), with a marked slot for the moduletto run.
//! - [`FROZEN`], the frozen outputs of item 3.
//! - A test module with the reference's own checks (items 1 to 5), the
//!   cross-implementation round trips of item 4, the oracle half of item
//!   9 and the differential tests of item 10. They need the oracle and the
//!   production code in one binary. The oracle is reachable only from this
//!   crate, and `fstp-crypto` may not depend on it (design section 2.4
//!   rules 2, 6, 7 and 9), so they live here.
//!
//! aws-lc-rs is a normal dependency of this test-only crate (ADR-001 A6).
//! Its post-quantum APIs serve only as test oracles, and only from this
//! crate (layering rule 9). Nothing here ships.

use aws_lc_rs::agreement::{self, PrivateKey, UnparsedPublicKey, X25519};
use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::encoding::AsRawBytes as _;
use aws_lc_rs::hmac;
use aws_lc_rs::kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_768};
use aws_lc_rs::signature::{
    KeyPair as _, ML_DSA_65, ML_DSA_65_SIGNING, PqdsaKeyPair, UnparsedPublicKey as SigPublicKey,
};

/// The HKDF salt of the combiner: 12 ASCII bytes, no terminator.
pub const SALT: &[u8; 12] = b"fstp-hkem-v1";

/// Length of an ML-KEM-768 encapsulation key `pk_M`.
pub const MLKEM_EK_LEN: usize = 1184;

/// Length of an ML-KEM-768 expanded decapsulation key.
pub const MLKEM_DK_LEN: usize = 2400;

/// Length of an ML-KEM-768 ciphertext `ct_M`.
pub const MLKEM_CT_LEN: usize = 1088;

/// Length of a hybrid public key `pk_X || pk_M`.
pub const PUBLIC_KEY_LEN: usize = 32 + MLKEM_EK_LEN;

/// Length of a hybrid ciphertext `E || ct_M`.
pub const CIPHERTEXT_LEN: usize = 32 + MLKEM_CT_LEN;

/// The label that seeds the fixed-input vectors. Test input only.
pub const VECTOR_LABEL: &[u8] = b"fstp-hkem-v1 combiner test input";

/// The number of fixed-input vectors [`vector`] yields.
pub const VECTOR_COUNT: usize = 80;

/// A refusal of the aws-lc-rs oracle. It names the step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OracleError(pub &'static str);

impl std::fmt::Display for OracleError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "reference oracle refused: {}", self.0)
    }
}

impl std::error::Error for OracleError {}

/// HMAC-SHA-256 of `data` under `key`, from aws-lc-rs.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let tag = hmac::sign(&hmac::Key::new(hmac::HMAC_SHA256, key), data);
    to_array32(tag.as_ref())
}

/// SHA-256 of `data`, from aws-lc-rs.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    to_array32(digest(&SHA256, data).as_ref())
}

/// RFC 5869 section 2.2: `PRK = HMAC-Hash(salt, IKM)`. An empty salt is
/// HashLen zero bytes, which HMAC pads to the same key.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// RFC 5869 section 2.3: `T(i) = HMAC-Hash(PRK, T(i-1) | info | i)`, with
/// `T(0)` empty, and the first `len` bytes of `T(1) | T(2) | ...`.
///
/// Returns `None` when `len` exceeds `255 * HashLen`, as the RFC requires.
pub fn hkdf_expand(prk: &[u8; 32], info: &[u8], len: usize) -> Option<Vec<u8>> {
    if len > 255 * 32 {
        return None;
    }
    let mut okm = Vec::with_capacity(len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 0;
    while okm.len() < len {
        counter = counter.checked_add(1)?;
        let mut input = Vec::new();
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha256(prk, &input).to_vec();
        let take = len.saturating_sub(okm.len()).min(t.len());
        okm.extend_from_slice(t.get(..take)?);
    }
    Some(okm)
}

/// The combiner info: `SHA-256(ct_M) || E || pk_X || SHA-256(pk_M)`, 128
/// bytes.
pub fn combiner_info(
    ct_m: &[u8; MLKEM_CT_LEN],
    e: &[u8; 32],
    pk_x: &[u8; 32],
    pk_m: &[u8; MLKEM_EK_LEN],
) -> [u8; 128] {
    let mut info = [0u8; 128];
    let parts: [&[u8]; 4] = [&sha256(ct_m), e, pk_x, &sha256(pk_m)];
    for (dst, src) in info.iter_mut().zip(parts.iter().flat_map(|p| p.iter())) {
        *dst = *src;
    }
    info
}

/// The ADR-004 combiner:
///
/// ```text
/// prk = HKDF-SHA-256-Extract(salt = "fstp-hkem-v1", ikm = ss_M || ss_X)
/// ss  = HKDF-SHA-256-Expand(prk, SHA-256(ct_M) || E || pk_X || SHA-256(pk_M), 32)
/// ```
///
/// With `L = 32`, Expand is the single block `HMAC(prk, info || 0x01)`.
/// The reference uses that identity, so it differs in form from both the
/// production code and [`hkdf_expand`].
pub fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_m: &[u8; MLKEM_CT_LEN],
    e: &[u8; 32],
    pk_x: &[u8; 32],
    pk_m: &[u8; MLKEM_EK_LEN],
) -> [u8; 32] {
    let mut ikm = [0u8; 64];
    for (dst, src) in ikm.iter_mut().zip(ss_m.iter().chain(ss_x.iter())) {
        *dst = *src;
    }
    let prk = hkdf_extract(SALT, &ikm);
    let mut block = [0u8; 129];
    for (dst, src) in block.iter_mut().zip(
        combiner_info(ct_m, e, pk_x, pk_m)
            .iter()
            .chain([0x01u8].iter()),
    ) {
        *dst = *src;
    }
    hmac_sha256(&prk, &block)
}

/// One of the six combiner inputs ADR-004 names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CombinerInput {
    /// The ML-KEM-768 shared secret `ss_M`.
    SsM,
    /// The X25519 shared secret `ss_X`.
    SsX,
    /// The ML-KEM-768 ciphertext `ct_M`.
    CtM,
    /// The sender's ephemeral X25519 public key `E`.
    E,
    /// The recipient's static X25519 public key `pk_X`.
    PkX,
    /// The recipient's ML-KEM-768 encapsulation key `pk_M`.
    PkM,
}

impl CombinerInput {
    /// Every input, in the order of the ADR-004 input table.
    pub const ALL: [CombinerInput; 6] = [
        CombinerInput::SsM,
        CombinerInput::SsX,
        CombinerInput::CtM,
        CombinerInput::E,
        CombinerInput::PkX,
        CombinerInput::PkM,
    ];

    /// The input's length in bytes.
    pub const fn len(self) -> usize {
        match self {
            CombinerInput::SsM | CombinerInput::SsX | CombinerInput::E | CombinerInput::PkX => 32,
            CombinerInput::CtM => MLKEM_CT_LEN,
            CombinerInput::PkM => MLKEM_EK_LEN,
        }
    }

    /// Always `false`: no input is empty. Present for clippy's `len` rule.
    pub const fn is_empty(self) -> bool {
        false
    }
}

/// The teeth twin of [`combine`]: the same construction, with `omit`
/// replaced by zero bytes of its length, so it no longer binds that input.
/// A binding property that passes for this twin has no teeth.
pub fn combine_omitting(omit: CombinerInput, v: &VectorInputs) -> [u8; 32] {
    let mut w = v.clone();
    w.fill(omit, 0x00);
    w.combine()
}

/// The six combiner inputs of one vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VectorInputs {
    /// `ss_M`.
    pub ss_m: [u8; 32],
    /// `ss_X`.
    pub ss_x: [u8; 32],
    /// `ct_M`.
    pub ct_m: [u8; MLKEM_CT_LEN],
    /// `E`.
    pub e: [u8; 32],
    /// `pk_X`.
    pub pk_x: [u8; 32],
    /// `pk_M`.
    pub pk_m: [u8; MLKEM_EK_LEN],
}

impl VectorInputs {
    /// [`combine`] over these inputs.
    pub fn combine(&self) -> [u8; 32] {
        combine(
            &self.ss_m, &self.ss_x, &self.ct_m, &self.e, &self.pk_x, &self.pk_m,
        )
    }

    /// The bytes of one input.
    pub fn field(&self, input: CombinerInput) -> &[u8] {
        match input {
            CombinerInput::SsM => &self.ss_m,
            CombinerInput::SsX => &self.ss_x,
            CombinerInput::CtM => &self.ct_m,
            CombinerInput::E => &self.e,
            CombinerInput::PkX => &self.pk_x,
            CombinerInput::PkM => &self.pk_m,
        }
    }

    /// The bytes of one input, writable.
    pub fn field_mut(&mut self, input: CombinerInput) -> &mut [u8] {
        match input {
            CombinerInput::SsM => &mut self.ss_m,
            CombinerInput::SsX => &mut self.ss_x,
            CombinerInput::CtM => &mut self.ct_m,
            CombinerInput::E => &mut self.e,
            CombinerInput::PkX => &mut self.pk_x,
            CombinerInput::PkM => &mut self.pk_m,
        }
    }

    /// Sets every byte of one input to `byte`.
    pub fn fill(&mut self, input: CombinerInput, byte: u8) {
        self.field_mut(input).fill(byte);
    }

    /// Copies one input from `other`.
    pub fn set_from(&mut self, input: CombinerInput, other: &VectorInputs) {
        self.field_mut(input).copy_from_slice(other.field(input));
    }

    /// Flips bit `bit` of one input. Bits past the end are ignored.
    pub fn flip_bit(&mut self, input: CombinerInput, bit: usize) {
        if let Some(b) = self.field_mut(input).get_mut(bit / 8) {
            *b ^= 1u8 << (bit % 8);
        }
    }
}

/// `n` bytes of SHA-256 in counter mode over the label, the vector
/// index, the field tag and a 32-bit block counter. Test input only.
fn expand_label(index: u32, tag: u8, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block: u32 = 0;
    while out.len() < n {
        let mut input = Vec::new();
        input.extend_from_slice(VECTOR_LABEL);
        input.extend_from_slice(&index.to_be_bytes());
        input.push(tag);
        input.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&sha256(&input));
        block = block.wrapping_add(1);
    }
    out.truncate(n);
    out
}

fn fill_from(dst: &mut [u8], src: &[u8]) {
    for (d, s) in dst.iter_mut().zip(src) {
        *d = *s;
    }
}

/// The counter-mode vector `index` (item 2 of the test vector plan).
pub fn counter_vector(index: u32) -> VectorInputs {
    let mut v = VectorInputs {
        ss_m: [0; 32],
        ss_x: [0; 32],
        ct_m: [0; MLKEM_CT_LEN],
        e: [0; 32],
        pk_x: [0; 32],
        pk_m: [0; MLKEM_EK_LEN],
    };
    for (tag, input) in (1u8..).zip(CombinerInput::ALL) {
        let bytes = expand_label(index, tag, input.len());
        fill_from(v.field_mut(input), &bytes);
    }
    v
}

/// The fixed-input vector `n`, for `n` below [`VECTOR_COUNT`]:
///
/// | `n` | Inputs |
/// | --- | --- |
/// | 0 to 63 | [`counter_vector`] `n` |
/// | 64 to 75 | vector 0 with one input all `0x00` (even `n`) or all `0xff` (odd `n`), inputs in [`CombinerInput::ALL`] order |
/// | 76 | every input all `0x00` |
/// | 77 | every input all `0xff` |
/// | 78 | vector 1 with the last byte of `ct_M` XOR `0x01` |
/// | 79 | vector 1 with the last byte of `ct_M` XOR `0x80` |
pub fn vector(n: usize) -> Option<VectorInputs> {
    match n {
        0..64 => Some(counter_vector(u32::try_from(n).ok()?)),
        64..76 => {
            let k = n.saturating_sub(64);
            let input = *CombinerInput::ALL.get(k / 2)?;
            let mut v = counter_vector(0);
            v.fill(input, if k.is_multiple_of(2) { 0x00 } else { 0xff });
            Some(v)
        }
        76 | 77 => {
            let mut v = counter_vector(0);
            for input in CombinerInput::ALL {
                v.fill(input, if n == 76 { 0x00 } else { 0xff });
            }
            Some(v)
        }
        78 | 79 => {
            let mut v = counter_vector(1);
            let last = v.ct_m.last_mut()?;
            *last ^= if n == 78 { 0x01 } else { 0x80 };
            Some(v)
        }
        _ => None,
    }
}

/// A recipient key pair of the whole hybrid KEM over the aws-lc-rs
/// oracles: an X25519 static key and an ML-KEM-768 decapsulation key.
pub struct RefKeyPair {
    x: PrivateKey,
    m: DecapsulationKey,
    public: [u8; PUBLIC_KEY_LEN],
}

impl RefKeyPair {
    /// A fresh key pair from aws-lc-rs.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs fails to generate or export a key.
    pub fn generate() -> Result<RefKeyPair, OracleError> {
        let x = PrivateKey::generate(&X25519).map_err(|_| OracleError("X25519 keygen"))?;
        let m = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| OracleError("ML-KEM-768 keygen"))?;
        let pk_x = x
            .compute_public_key()
            .map_err(|_| OracleError("X25519 public key"))?;
        let ek = m
            .encapsulation_key()
            .map_err(|_| OracleError("ML-KEM-768 encapsulation key"))?;
        let ek_bytes = ek
            .key_bytes()
            .map_err(|_| OracleError("ML-KEM-768 key bytes"))?;
        let mut public = [0u8; PUBLIC_KEY_LEN];
        let parts: [&[u8]; 2] = [pk_x.as_ref(), ek_bytes.as_ref()];
        if parts.iter().map(|p| p.len()).sum::<usize>() != PUBLIC_KEY_LEN {
            return Err(OracleError("public key length"));
        }
        fill_from(&mut public, &parts.concat());
        Ok(RefKeyPair { x, m, public })
    }

    /// The hybrid public key `pk_X || pk_M`.
    pub fn public_key(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.public
    }

    /// Decapsulates `ct = E || ct_M` as ADR-004 "Decapsulation" says, with
    /// `pk_X` and `pk_M` taken from the stored public key.
    ///
    /// # Errors
    ///
    /// Refuses when either half fails, including an all-zero X25519
    /// result.
    pub fn decapsulate(&self, ct: &[u8; CIPHERTEXT_LEN]) -> Result<[u8; 32], OracleError> {
        let (e, ct_m) = split_ciphertext(ct)?;
        let ss_m = self
            .m
            .decapsulate(Ciphertext::from(&ct_m[..]))
            .map_err(|_| OracleError("ML-KEM-768 decapsulation"))?;
        let ss_x = agreement::agree(
            &self.x,
            UnparsedPublicKey::new(&X25519, &e[..]),
            OracleError("X25519 agreement"),
            |k| Ok(to_array32(k)),
        )?;
        let (pk_x, pk_m) = split_public(&self.public)?;
        Ok(combine(
            &to_array32(ss_m.as_ref()),
            &ss_x,
            &ct_m,
            &e,
            &pk_x,
            &pk_m,
        ))
    }
}

/// Encapsulates to the hybrid public key `pk = pk_X || pk_M` as ADR-004
/// "Encapsulation" says. Returns `(E || ct_M, ss)`.
///
/// # Errors
///
/// Refuses when aws-lc-rs refuses either half of the public key.
pub fn encapsulate(
    pk: &[u8; PUBLIC_KEY_LEN],
) -> Result<([u8; CIPHERTEXT_LEN], [u8; 32]), OracleError> {
    let (pk_x, pk_m) = split_public(pk)?;
    let ek = EncapsulationKey::new(&ML_KEM_768, &pk_m)
        .map_err(|_| OracleError("ML-KEM-768 encapsulation key"))?;
    let (ct_m, ss_m) = ek
        .encapsulate()
        .map_err(|_| OracleError("ML-KEM-768 encapsulation"))?;
    let ct_m: [u8; MLKEM_CT_LEN] = ct_m
        .as_ref()
        .try_into()
        .map_err(|_| OracleError("ML-KEM-768 ciphertext length"))?;
    let eph = PrivateKey::generate(&X25519).map_err(|_| OracleError("X25519 keygen"))?;
    let e = to_array32(
        eph.compute_public_key()
            .map_err(|_| OracleError("X25519 public key"))?
            .as_ref(),
    );
    let ss_x = agreement::agree(
        &eph,
        UnparsedPublicKey::new(&X25519, &pk_x[..]),
        OracleError("X25519 agreement"),
        |k| Ok(to_array32(k)),
    )?;
    let ss = combine(&to_array32(ss_m.as_ref()), &ss_x, &ct_m, &e, &pk_x, &pk_m);
    let mut ct = [0u8; CIPHERTEXT_LEN];
    fill_from(&mut ct, &[&e[..], &ct_m[..]].concat());
    Ok((ct, ss))
}

/// The bare aws-lc-rs ML-KEM-768 oracle, for the differential test of
/// ADR-001 Verification and the ACVP decapsulation cases.
pub struct OracleMlKem {
    dk: DecapsulationKey,
    ek: Option<Vec<u8>>,
}

impl OracleMlKem {
    /// A fresh oracle key.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs fails.
    pub fn generate() -> Result<OracleMlKem, OracleError> {
        let dk = DecapsulationKey::generate(&ML_KEM_768)
            .map_err(|_| OracleError("ML-KEM-768 keygen"))?;
        let ek = dk
            .encapsulation_key()
            .and_then(|k| k.key_bytes())
            .map_err(|_| OracleError("ML-KEM-768 encapsulation key"))?
            .as_ref()
            .to_vec();
        Ok(OracleMlKem { dk, ek: Some(ek) })
    }

    /// Imports a raw expanded decapsulation key (FIPS 203 `dk`).
    ///
    /// # Errors
    ///
    /// Refuses a key aws-lc-rs rejects.
    pub fn from_decaps_key(dk: &[u8]) -> Result<OracleMlKem, OracleError> {
        let dk = DecapsulationKey::new(&ML_KEM_768, dk)
            .map_err(|_| OracleError("ML-KEM-768 decapsulation key"))?;
        Ok(OracleMlKem { dk, ek: None })
    }

    /// The encapsulation key, when the oracle generated it.
    pub fn encaps_key(&self) -> Option<&[u8]> {
        self.ek.as_deref()
    }

    /// The expanded decapsulation key.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs cannot export it.
    pub fn decaps_key(&self) -> Result<Vec<u8>, OracleError> {
        Ok(self
            .dk
            .key_bytes()
            .map_err(|_| OracleError("ML-KEM-768 decapsulation key bytes"))?
            .as_ref()
            .to_vec())
    }

    /// Decapsulates an ML-KEM-768 ciphertext.
    ///
    /// # Errors
    ///
    /// Refuses a ciphertext of the wrong length.
    pub fn decapsulate(&self, ct: &[u8]) -> Result<[u8; 32], OracleError> {
        let ss = self
            .dk
            .decapsulate(Ciphertext::from(ct))
            .map_err(|_| OracleError("ML-KEM-768 decapsulation"))?;
        Ok(to_array32(ss.as_ref()))
    }
}

/// Encapsulates to a raw ML-KEM-768 encapsulation key with the aws-lc-rs
/// oracle. Returns `(ct_M, ss_M)`.
///
/// # Errors
///
/// Refuses a key aws-lc-rs rejects.
pub fn oracle_mlkem_encapsulate(ek: &[u8]) -> Result<(Vec<u8>, [u8; 32]), OracleError> {
    let ek = EncapsulationKey::new(&ML_KEM_768, ek)
        .map_err(|_| OracleError("ML-KEM-768 encapsulation key"))?;
    let (ct, ss) = ek
        .encapsulate()
        .map_err(|_| OracleError("ML-KEM-768 encapsulation"))?;
    Ok((ct.as_ref().to_vec(), to_array32(ss.as_ref())))
}

/// Length of an ML-DSA-65 public key (FIPS 204 Table 2).
pub const MLDSA65_PK_LEN: usize = 1952;

/// Length of an expanded ML-DSA-65 private key (FIPS 204 Table 2).
pub const MLDSA65_SK_LEN: usize = 4032;

/// Length of an ML-DSA-65 signature (FIPS 204 Table 2).
pub const MLDSA65_SIG_LEN: usize = 3309;

/// The bare aws-lc-rs ML-DSA-65 oracle (ADR-001 A6, design section 7.4).
/// It runs the ACVP subset of T-CR-MLDSA now, and the differential tests
/// against moduletto once its ML-DSA-65 lands. It is a test oracle only:
/// production never signs with it (I-75, I-90).
///
/// aws-lc-rs offers pure ML-DSA with an empty context and hedged signing
/// only. So the oracle cannot reproduce a deterministic ACVP signature,
/// and cannot verify under a non-empty context.
pub struct OracleMlDsa65 {
    kp: PqdsaKeyPair,
}

impl OracleMlDsa65 {
    /// FIPS 204 `ML-DSA.KeyGen_internal(xi)` from the 32-byte seed.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs rejects the seed.
    pub fn from_seed(seed: &[u8; 32]) -> Result<OracleMlDsa65, OracleError> {
        let kp = PqdsaKeyPair::from_seed(&ML_DSA_65_SIGNING, seed)
            .map_err(|_| OracleError("ML-DSA-65 keygen from seed"))?;
        Ok(OracleMlDsa65 { kp })
    }

    /// Imports an expanded private key (FIPS 204 `sk`).
    ///
    /// # Errors
    ///
    /// Refuses a key aws-lc-rs rejects.
    pub fn from_private_key(sk: &[u8]) -> Result<OracleMlDsa65, OracleError> {
        let kp = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, sk)
            .map_err(|_| OracleError("ML-DSA-65 private key"))?;
        Ok(OracleMlDsa65 { kp })
    }

    /// The public key `pk`.
    pub fn public_key(&self) -> Vec<u8> {
        self.kp.public_key().as_ref().to_vec()
    }

    /// The expanded private key `sk`.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs cannot export it.
    pub fn private_key(&self) -> Result<Vec<u8>, OracleError> {
        Ok(self
            .kp
            .private_key()
            .as_raw_bytes()
            .map_err(|_| OracleError("ML-DSA-65 private key bytes"))?
            .as_ref()
            .to_vec())
    }

    /// A hedged pure ML-DSA-65 signature over `message`, empty context.
    ///
    /// # Errors
    ///
    /// Refuses when aws-lc-rs fails.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, OracleError> {
        let mut sig = vec![0u8; MLDSA65_SIG_LEN];
        let len = self
            .kp
            .sign(message, &mut sig)
            .map_err(|_| OracleError("ML-DSA-65 sign"))?;
        sig.truncate(len);
        Ok(sig)
    }
}

/// Whether `signature` is a pure ML-DSA-65 signature over `message` under
/// `pk`, with an empty context, as the aws-lc-rs oracle judges it.
pub fn oracle_mldsa65_verify(pk: &[u8], message: &[u8], signature: &[u8]) -> bool {
    SigPublicKey::new(&ML_DSA_65, pk)
        .verify(message, signature)
        .is_ok()
}

fn split_public(pk: &[u8; PUBLIC_KEY_LEN]) -> Result<([u8; 32], [u8; MLKEM_EK_LEN]), OracleError> {
    let (x, m) = pk.split_at(32);
    Ok((
        x.try_into().map_err(|_| OracleError("pk_X length"))?,
        m.try_into().map_err(|_| OracleError("pk_M length"))?,
    ))
}

fn split_ciphertext(
    ct: &[u8; CIPHERTEXT_LEN],
) -> Result<([u8; 32], [u8; MLKEM_CT_LEN]), OracleError> {
    let (e, m) = ct.split_at(32);
    Ok((
        e.try_into().map_err(|_| OracleError("E length"))?,
        m.try_into().map_err(|_| OracleError("ct_M length"))?,
    ))
}

/// Copies a 32-byte output into an array. Shorter input leaves zeros,
/// which no algorithm here produces.
fn to_array32(bytes: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    fill_from(&mut out, bytes);
    out
}

/// The frozen combiner outputs of ADR-004 test vector plan item 3, hex.
///
/// `FROZEN[n]` is [`combine`] over [`vector`] `n`. The reference computed
/// them once on 2026-10-28, and they never change (ADR-004 "Freeze
/// rule"). `crates/fstp-crypto/tests/common/hybrid_vectors.rs` holds the
/// same list for the production comparison, and a test there checks the
/// two lists are equal.
///
/// Vectors 76 (every input `0x00`) and 77 (every input `0xff`) were also
/// computed outside this repository with OpenSSL 3.6.4, `openssl kdf
/// HKDF` with `digest:SHA256`, `hexsalt` the 12 bytes of "fstp-hkem-v1",
/// `hexkey` the 64 bytes `ss_M || ss_X`, and `hexinfo` the 128 bytes
/// `SHA-256(ct_M) || E || pk_X || SHA-256(pk_M)`. Both agreed with the
/// reference.
pub const FROZEN: [&str; VECTOR_COUNT] = [
    // 0
    "e2fd933743c5810adae75b263c414b03362f37cbd9bef82a84b3d6e1d953c6b0",
    // 1
    "de7a44a830fbd98729db341cfe634f692a588400b0f49ba2530f18f6418dc40d",
    // 2
    "d40f7ad774cd949cd483e7b7850e5c1f11207e3710053e3fc9e4fbe6d593f612",
    // 3
    "2d809556b7aeeb6dffcee4408c016d996a5542c2c2c51147ce672a606f391fb5",
    // 4
    "a419be3e76768ef8ee5a48aca1f6c3cdba53f85c5e792f483e1bd63811018e3f",
    // 5
    "daf72f150b7a1fb997cce978acde17673d399cc67b317d7f5592a8bebd52a594",
    // 6
    "8e7ae4ac80b53b0858d7c9ca22a7e618cde39f5e4b3094a4617e9b2f9ae407cb",
    // 7
    "58c629c8739cbbeac2e26c378837697cd7b26dab62543c7508512af4ba6db20c",
    // 8
    "de5199bbfc29b676fbe06945134ae4cafb783580c0c963cc10a8bf482aecccd5",
    // 9
    "26d55fd47729e29cae58c6416cba4f5bb16161be28363e340858bf9540eff7e8",
    // 10
    "0554cd9e676d90cb325bf31672538c1ae0969c28d1e0dc0150a13ec8af1f398d",
    // 11
    "6ff1f79a7d2b98edf669d6d3f90af0b3c500f3a1658a5b718655ab388d0914cc",
    // 12
    "351c884192570bf44d72f25bbac8bce2d30ec1760ecf034df049026093ea7336",
    // 13
    "36d4ad041641a2a956755117de3bd068b75eceac187737c0fb04458f78f02b69",
    // 14
    "fb535d827d55399538824cd59f7c4a5897abc6c449eb5844b19c66f37c54eea2",
    // 15
    "76a3918a760fdefde5deaba0c0efd62c95bc3d8ebcc8a04e93cf7d558951c495",
    // 16
    "e89d0d22d185ebf1d455c7b025da9636231a3f8b177172ccb55cff89e8fbbbca",
    // 17
    "993ea9504009b469ad148f98fde073b6797f6b0aac9019ca8770de27ce80ca1f",
    // 18
    "f142aed2098bb992520da471b7108b63494a0f1fc5d435824c5a6afa44022a8d",
    // 19
    "e13824526dac22b444546e60514a6c5ef4392a7ac0be6e9af02f7f911dfd0d9a",
    // 20
    "aa7a5cc5ceed77dc615f7753c951915ce4fd4a865b9de5120f42343b9b2a5d88",
    // 21
    "6b8c0736f8c2df6051c8783fc8b6cbe040ed92cf477bd8c782eaf305398a3f5f",
    // 22
    "5f9b1836ae13138442d976a3f85bba172856c2028605e7d47f4949dd2718f675",
    // 23
    "21817c7b8bcd983cd844fef0fdab8f8f1eeeb2ea06763ab29780ee0afc516b00",
    // 24
    "8498b96d68d486e4cd6869634f15dbdb80214cac37c4069c876a610de04c2bc1",
    // 25
    "83f31294e6e3b94f6c20194f9a1575d70bb5de6510ac8250babf532c900f7844",
    // 26
    "c0420da3e01027fbeedf8088d5306c5d3fb943cdf7bc4e8c8953070aee01b764",
    // 27
    "bcde8ff5e9c39c5da4869462ecf8b5c45bd179976a7938200ca3f6b69bb560fa",
    // 28
    "2ef62b3f2f464497e31332e8dc67965e0b369f17c14fe1247166b57e6132a004",
    // 29
    "14a2db72ba2827788b7e5e7146cebbcb1500a474dc22ec06c64cca5695e534aa",
    // 30
    "5220a40eb3f00f2ad2437846fbb64cd32b3b56a5461418996b1a9f1d551902be",
    // 31
    "1f678ebace55d8d569ec2cd5304e32b0428dd9e35ba0117e96773aa794050d59",
    // 32
    "65d10b7821a557165f06c051304c4b9db684353ec81121e42da9415162d5af14",
    // 33
    "29e8a843cdfa82f7d34bed54a19e1b3b8b329e0845a421145cca9e7d04297d9c",
    // 34
    "25dc40a034841854e8379293a5dac26730ed9f5abdd22b58f3c2662dde0331f4",
    // 35
    "d04562505416bfeed21ca153033471fdbfd63642e7e3e5d0b8ea46e4587316ee",
    // 36
    "0041b5ba3d12364e20a140120edefdf508f7cc4383c0a1ac46bfea6369629d97",
    // 37
    "717d5ce9a4d4b4dfef3ed4763a7963d7d68590a57d5e1a001dbe97d4ffa2839b",
    // 38
    "af3e80fb41c9392a9074426e2a18c21765c4d149c84158ff429160e9bde24a70",
    // 39
    "cd0b440ecdfea6fe017fd187331463afb6c9112c09085c6e8cfa52466e7c8bdf",
    // 40
    "f9e9a9fc34025e84e2a76521094af5c7436c80579b133a1ed008ee96b1f80f75",
    // 41
    "0074b38ca7bed1dfae8796941a97b6d74bd39bfad092c05d8b1e7294b9cf5080",
    // 42
    "459987837faa9ff6d4a587256da3f2aeedcf4e3bc47179613ec2f7ff8be6ad57",
    // 43
    "611942ba8c77733f0e0dab4cd0cb1388f27528474f225381800b8a8443d47ab8",
    // 44
    "359c2ba3026ccc79165f6710ba9d7df0c3e6c526177c8ab6660a564ffbf2ea16",
    // 45
    "e0e6085367e59e9a4efd7ad68ce4d41497f873129d2843e86842ced2f876e71d",
    // 46
    "70bdbe4d4224b521ef3bce0638db9ab57d04d0dc21ab2c1674f21bba1d5936fa",
    // 47
    "9bf39fb3d73ee307b3f6b4b1ad0913e6c3a5b5440efd095e1f80941a1740b0ff",
    // 48
    "5ce167e89e31211b5e4d3ff3c8c6e5aaa4c1045df43648a8f28f8f13e555765a",
    // 49
    "9f2bf6602610299451053e672e78974f677792240c688a33349733de1063cc52",
    // 50
    "6ec6bdd2694d2b7cb847a05f6e6b1e795a5747aaa825d2ec4bd6bb6e79c8082c",
    // 51
    "aff6ccbdc94b63adf27117bd59eea84d03d55ff9d2708c43423e709825c834b0",
    // 52
    "856139dead38177ec6997af9a2cc1a837da78d3ef2aa74719742ba39e1a92c46",
    // 53
    "70f000edda5d81861474c4240cf51e1bf05288c7de398d46591e534030a9ac30",
    // 54
    "47eaea14232df8497e4fe519fb0485806ccd11ec362db6410afe7418e8aa6694",
    // 55
    "b9ca9cf1f053af1f50a5a6715d82dd5d0502df3901c910571115489f2f784850",
    // 56
    "a2410e0d756bfc3946c39cdc3cc2e864a4f7b0cbc915a0511fa5eaaeb020a1f4",
    // 57
    "d0283dc205aeb790714071636ed45a5ee85f842856f51c85f6ef9f9626ce859a",
    // 58
    "3f5b7f9edd02a729181f90716a55394c2df8f58554a54c0d9b63591485361903",
    // 59
    "1dd82ebb801d9a305e356cdb76e915eb36e781ab75569b0d471364ace9888c4e",
    // 60
    "54f696a3f68e70df57fd1a90cb89a0af22d6be7b37d19fccf164bc6db0d26cba",
    // 61
    "8cf7c75534b978c5f667717cc3d6531653c3fde2b36dd57846b34180f60de160",
    // 62
    "662fdc9ef264db3d88608b05298edd2312158dfafbf8e0e6b359d387bef287b9",
    // 63
    "0b61db8e566f623bdafcdeb7d4b3695845d784ae63bd3296706c3922d4355ded",
    // 64
    "57caa32269194d71cd484ef83259dbc5c401c01033174f02d9d5de2176f8dd47",
    // 65
    "6ef8f91541f53b41c222dc9589cc7a8fc37662088dd56917a0c0a10084b37a85",
    // 66
    "67bd49f558a4f99b547974741428249aec0d8703d13b154133893ae77af5332b",
    // 67
    "550a2fe4d43f62c8e34e17e19db5bc9866c94dfd604907d10124451c36dc1d73",
    // 68
    "cc3f33fbe45edbd76ec4de534ba6224e4885a7b5f8176894e080079c9939d882",
    // 69
    "9f7fbc1743e562150adfd3c29a13d383fae5b0bb3daba01c00f2f36efa7c84f5",
    // 70
    "bebb9bf61ebaaed78e5ac7c94ec50494e6fc3b57181d8993b8ad57d70e3703f7",
    // 71
    "59fb42d58dad6c2f9a5a327b5fdce68ffc4e599a3c9e89d16fa0e3193cc8b121",
    // 72
    "c68cacd11ed55af294d6d4dced45348c9699ff8e450461a6899a703e43468901",
    // 73
    "8a4606d7593c03552d93d4f29ce259f66bbb31a24d35d1a97f0a956206518f01",
    // 74
    "94e8556ed15817d31e0b231ab3753c05159a7faecbc8d07933e43d240eda3c11",
    // 75
    "7470cbf81c29c738c927053bbb2c46af80a299bd9420b31157ac1dc13bae263b",
    // 76
    "f1a270ff8d0bbb8be24fc6358497a45702f0997845a09e3c1ed95e3cc46387e0",
    // 77
    "3ec39ac12ed83d7901eafee6d362801130c6cf487e55c986ebb52cc90b5c51fa",
    // 78
    "6b96467f30a2b32c521a591ebb909999c3e1d79ef09c47b42ebbaee9994a5812",
    // 79
    "52b52e3e2effe0f9509984bd5332536dbef0626500b4be98000a5bce978bd534",
];

#[cfg(test)]
mod tests {
    //! Checks of the reference (ADR-004 test vector plan items 1 to 5),
    //! then the comparisons that need both the aws-lc-rs oracle and the
    //! production `fstp-crypto` (items 4, 9 and 10). The oracle is
    //! reachable only from this crate (layering rule 9), so these tests
    //! live here and not in `crates/fstp-crypto/tests`.

    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use super::*;
    use fstp_crypto::hybrid_kem::{self, HybridCiphertext, HybridPublicKey};
    use fstp_crypto::mlkem::{self, MlKem768DecapsKey, MlKem768EncapsKey};
    use fstp_prop::{Config, Gen, check_with, prop_assert, prop_assert_eq, run};

    fn hex(s: &str) -> Vec<u8> {
        let clean: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        clean
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// A fresh encapsulation randomness `m`. The plain single-half
    /// `encapsulate` of `fstp_crypto::mlkem` is crate-private (I-75), so
    /// the differential tests reach moduletto through `mlkem::acvp`.
    fn random_m() -> [u8; 32] {
        fstp_crypto::random_array().unwrap()
    }

    fn range(lo: u8, hi: u8) -> Vec<u8> {
        (lo..=hi).collect()
    }

    // ------------------------------------------------ the reference itself

    /// ADR-004 test vector plan item 1: the HMAC evaluation of HKDF gives
    /// the PRK and OKM of RFC 5869 Appendix A.1 to A.3. Each value was
    /// checked on 2026-10-28 with `openssl kdf ... HKDF` (OpenSSL 3.6.4).
    #[test]
    fn t_cr_hybrid_reference_kdf_matches_rfc5869() {
        type Case = (Vec<u8>, Vec<u8>, Vec<u8>, &'static str, &'static str);
        let cases: [Case; 3] = [
            (
                range(0x00, 0x0c),
                vec![0x0b; 22],
                range(0xf0, 0xf9),
                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5",
                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf\
                 34007208d5b887185865",
            ),
            (
                range(0x60, 0xaf),
                range(0x00, 0x4f),
                range(0xb0, 0xff),
                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244",
                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c\
                 59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71\
                 cc30c58179ec3e87c14c01d5c1f3434f1d87",
            ),
            (
                Vec::new(),
                vec![0x0b; 22],
                Vec::new(),
                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04",
                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d\
                 9d201395faa4b61a96c8",
            ),
        ];
        for (n, (salt, ikm, info, prk_hex, okm_hex)) in cases.iter().enumerate() {
            let prk = hkdf_extract(salt, ikm);
            assert_eq!(prk.to_vec(), hex(prk_hex), "A.{} PRK", n + 1);
            let want = hex(okm_hex);
            assert_eq!(
                hkdf_expand(&prk, info, want.len()).unwrap(),
                want,
                "A.{} OKM",
                n + 1
            );
        }
        assert!(hkdf_expand(&[0u8; 32], b"", 255 * 32).is_some());
        assert!(hkdf_expand(&[0u8; 32], b"", 255 * 32 + 1).is_none());
    }

    /// ADR-004 "Combiner bytes": the salt bytes, and the 128-byte info with
    /// `E` and `pk_X` at bytes 32 and 64.
    #[test]
    fn t_cr_hybrid_reference_salt_and_info_layout() {
        assert_eq!(SALT.to_vec(), hex("66 73 74 70 2d 68 6b 65 6d 2d 76 31"));
        let v = vector(0).unwrap();
        let info = combiner_info(&v.ct_m, &v.e, &v.pk_x, &v.pk_m);
        assert_eq!(info[..32], sha256(&v.ct_m));
        assert_eq!(info[32..64], v.e);
        assert_eq!(info[64..96], v.pk_x);
        assert_eq!(info[96..], sha256(&v.pk_m));
    }

    /// With `L = 32` Expand is one HMAC block: the single-block combiner
    /// equals the general RFC 5869 Expand of the same PRK and info.
    #[test]
    fn t_cr_hybrid_reference_single_block_equals_rfc5869_expand() {
        for n in 0..VECTOR_COUNT {
            let v = vector(n).unwrap();
            let ikm = [v.ss_m, v.ss_x].concat();
            let prk = hkdf_extract(SALT, &ikm);
            let info = combiner_info(&v.ct_m, &v.e, &v.pk_x, &v.pk_m);
            assert_eq!(
                hkdf_expand(&prk, &info, 32).unwrap(),
                v.combine().to_vec(),
                "vector {n}"
            );
        }
    }

    /// ADR-004 test vector plan item 3: every run recomputes the frozen
    /// constants, so an edited constant fails here.
    #[test]
    fn t_cr_hybrid_reference_matches_frozen_vectors() {
        for (n, want) in FROZEN.iter().enumerate() {
            assert_eq!(
                vector(n).unwrap().combine().to_vec(),
                hex(want),
                "vector {n}"
            );
        }
        assert!(vector(VECTOR_COUNT).is_none());
        let mut seen = std::collections::HashSet::new();
        assert!(FROZEN.iter().all(|f| seen.insert(*f)), "a repeated output");
    }

    /// Vectors 76 and 77 as OpenSSL 3.6.4 computed them (see [`FROZEN`]).
    #[test]
    fn t_cr_hybrid_reference_matches_openssl_edge_vectors() {
        assert_eq!(
            vector(76).unwrap().combine().to_vec(),
            hex("F1A270FF8D0BBB8BE24FC6358497A45702F0997845A09E3C1ED95E3CC46387E0")
        );
        assert_eq!(
            vector(77).unwrap().combine().to_vec(),
            hex("3EC39AC12ED83D7901EAFEE6D362801130C6CF487E55C986EBB52CC90B5C51FA")
        );
    }

    /// ADR-004 test vector plan item 2: the edge vectors hold what the
    /// table of [`vector`] says.
    #[test]
    fn t_cr_hybrid_reference_vector_set_is_as_documented() {
        let base = vector(0).unwrap();
        for (k, input) in CombinerInput::ALL.iter().enumerate() {
            for (fill, n) in [(0x00u8, 64 + 2 * k), (0xff, 65 + 2 * k)] {
                let v = vector(n).unwrap();
                assert!(v.field(*input).iter().all(|&b| b == fill), "vector {n}");
                for other in CombinerInput::ALL.iter().filter(|i| *i != input) {
                    assert_eq!(v.field(*other), base.field(*other), "vector {n}");
                }
            }
        }
        let one = vector(1).unwrap();
        for (n, x) in [(78, 0x01u8), (79, 0x80)] {
            let v = vector(n).unwrap();
            assert_eq!(v.ct_m[..1087], one.ct_m[..1087]);
            assert_eq!(v.ct_m[1087], one.ct_m[1087] ^ x);
        }
    }

    /// ADR-004 test vector plan item 5: flipping one bit of one input
    /// changes the output of `combiner`.
    fn binding_property(
        combiner: &dyn Fn(&VectorInputs) -> [u8; 32],
        g: &mut Gen,
    ) -> Result<(), String> {
        let n = g.usize_in(0..=VECTOR_COUNT - 1);
        let input = *g.pick(&CombinerInput::ALL);
        let bit = g.usize_in(0..=input.len() * 8 - 1);
        g.note("vector", &n);
        g.note("input", &input);
        g.note("bit", &bit);
        let v = vector(n).ok_or("no vector")?;
        let mut w = v.clone();
        w.flip_bit(input, bit);
        prop_assert!(
            combiner(&v) != combiner(&w),
            "flipping bit {bit} of {input:?} left the output unchanged"
        );
        Ok(())
    }

    /// ADR-004 test vector plan item 5, for the reference.
    #[test]
    fn t_cr_hybrid_reference_binds_every_input() {
        check_with(
            "t_cr_hybrid_reference_binds_every_input",
            Config::default().with_cases(512),
            |g| binding_property(&|v: &VectorInputs| v.combine(), g),
        );
    }

    /// ADR-004 test vector plan item 5, teeth: a combiner that omits any
    /// one of the six inputs fails the binding property. Each twin runs
    /// the same property through `fstp_prop::run`.
    #[test]
    fn t_cr_hybrid_teeth_combiner_omitting_an_input_is_caught() {
        for omit in CombinerInput::ALL {
            let twin = move |v: &VectorInputs| combine_omitting(omit, v);
            let outcome = run(
                "t_cr_hybrid_teeth_combiner_omitting_an_input_is_caught",
                Config::default().with_cases(512),
                |g| binding_property(&twin, g),
            );
            assert!(!outcome.is_passed(), "passed without {omit:?}");
        }
    }

    /// The reference KEM round-trips over the aws-lc-rs oracles, and a
    /// ciphertext opens to a different secret under another key pair.
    #[test]
    fn t_cr_hybrid_reference_kem_round_trips() {
        check_with(
            "t_cr_hybrid_reference_kem_round_trips",
            Config::default().with_cases(32),
            |_g| {
                let kp = RefKeyPair::generate().unwrap();
                let other = RefKeyPair::generate().unwrap();
                let (ct, ss) = encapsulate(kp.public_key()).unwrap();
                prop_assert_eq!(kp.decapsulate(&ct).unwrap(), ss);
                prop_assert!(other.decapsulate(&ct).unwrap() != ss);
                Ok(())
            },
        );
    }

    /// ADR-004 "Inputs": the reference refuses an all-zero X25519 result.
    #[test]
    fn t_cr_hybrid_reference_refuses_all_zero_x25519() {
        let kp = RefKeyPair::generate().unwrap();
        let (mut ct, _) = encapsulate(kp.public_key()).unwrap();
        ct[..32].fill(0);
        assert!(kp.decapsulate(&ct).is_err());
    }

    // --------------------------------------------- the aws-lc-rs oracle

    struct AcvpDecaps {
        tc_id: u32,
        dk: &'static str,
        c: &'static str,
        k: &'static str,
    }

    /// Two ML-KEM-768 decapsulation cases of NIST ACVP-Server commit
    /// `975de31eb83d87039ec88934fdc47d8c312b892d`, copied from
    /// `crates/fstp-crypto/tests/data/ml_kem_768_acvp.json`. This crate
    /// has no `fstp-json` edge, so the cases are constants here, and the
    /// full group runs through moduletto in `fstp-crypto`.
    const ACVP_DECAPS: [AcvpDecaps; 2] = [
        AcvpDecaps {
            tc_id: 86,
            dk: "859384dfc0c207a6466ccbbc507c26dfeca413e06e46e30cf18528577b76c108c31e1b6efa8b41044a4fb2152d3ff391\
             bc6443b57060ae655b0efcbabc889032ecc986d2a144153c8189505c37c6bb1471e5ea8c1521770d732e88a1a3b0624e\
             5a2a42661c1743677591296b81447169635160f80d61f31c420a5d35f5adfea37e4254be39741e197056082c1bd9390a\
             030b2a63fc37dfa561ae091dd9da11649bb7406464838bc23c872423b7515e3444fb862ba7d51becabcf9b458f302905\
             cff983d00578ad89686721432221782ba7a134e052bba7879a36654c081e4c3b615a1c764c128afbd79ef0d816c7e5af\
             135a51448c14cf3c6172e022741b889da485c208899190bb2cb8090bd2b7f8213213e090b27a9c3c56bf87024bd2e300\
             1cea031be20e959bc1a75281b8a3639f487c12f40786e5458b14747d965e0e294947d6a487d44938d50829d0723a9108\
             06b9376e76480141960757cf37e2ac03b4a6767a68381a69f6b45c274c62b800403c1c992d0b84d336560d6b4bfed4a3\
             8edcca3c61699d31cb6bb88c10909cc6081d1bc9a549f604373576f2b5b14d453eec5c7673b5a39ffa8b6a223972019f\
             0ee7300bc82da77414e4413648b68fc8e7b51dc6cbf083098c1a2f2cc680e52a9e7a8964eacb2df18b8da1d603317298\
             b797bc17524ea03376ba3b410ff1b1b23526d3eb7a8255380793c5d938861e4983d4d23cad3a34bb256434dcc315c40c\
             8d0a9d2132a595b78dfbb655f9f2361a379047706400e5cfa1654ac779841c0767ac8c1dd27254599137d9f3355328cd\
             34e581e1e1bdd64c082eaa29a7f71610b65766882ca804106ce0bc5e20630a44bc5ff87db491c2cf7746b3150ba03abd\
             907096d8004fa20384fb154f553659bbc451c09c0d42a43035994cc24b4f798bc7c961c6c64c92f2c63e87149d89e982\
             21a9337f0a973226557056952bbc05abba46c7ec6ce1b2721a0487687c16cff6b50cd5bd59443ca765353848aa42323e\
             bed3776c014d60d8a6b6d6b31de26f11c15822991249f76c3130735d2c22d5d4b4550a3428004349073e3f296a286c3a\
             0d6572c383b3fd277439c85a03b42b584c97b5779a2d675b6de024949438aa8700aeebc9ffca10c8b327ca6b917b899d\
             3ed817c4543cdf288b489c2ef3aa2f95f310b0688e3e81aa83005571812a5267781ac21c92f7c41f359de74877c19124\
             fa462b3a181bd885a3c3534f16d99afea4bb6a434ce177c99020c880eb368fd211261172f0bb7ae4270fc9aa6dfdb598\
             5a1c069f1815e9277bee24cdb1ecba0cf2c3c48100f540a24e4050f9b376868098805136e673150c957b73ea3e7bbab0\
             76b459d2157e9e501734500bd2b574b9c563a7ca8ad83b6cfbec76727b1d3c61c289958fc8805ae6e4455a5257e89038\
             54e35112b7cd46185ea16339dc0838e118971cba5a78025f86749433a38ab79b58e6e6885003470e208735177f82d738\
             c3f7a52d848b742a75d115a528f4915078632fbb639145668b504c30abb96929a75fec5deae90973b2431d685f74c98d\
             36db263bbb6c73d71974993e13b50242167110262a8eb406c987481eaacd44069d53c2b967003dd2dcb979d81a97f623\
             51344bc40a6b203083918c40aa459ea2e20892514749556294534cb3e3b948f1c0f7a941fde49874c609973a4e845b11\
             2456974b3aaf9877b3159b7ed0c4c423889c8a8b1c5b33409a8c6b26f573a6668a5fe0c74ad0ca28304d1c7a498a93bc\
             08921d3943042f986438abcc61a358c6482839a524845b04ffca16cb741f7db5b0afd7b9874b6b53d156b3e036b3d41e\
             963b27ac0c87b411436471591001635e6440903a0b38302a92c8777f264de5290dd1e511bc7c0a68e3266882cedd30ac\
             a8928596b7affb28b94d8711e31a8c9e5ac2a9567b55630d5ff8627e52386408a1bb3bc2d6b90a7c33c04aaa60e9046e\
             10d89b41fbb8e3e26cbc27c1c062411436cc22d637dd021cb93b6972cb7aee5c98ad64006b0cd070b0ad99d467158c85\
             852b88666ba1de29cfa3047396a5bddc76b1afaba62d622e17f846e17487a167ca9b45070309526ee08791647cee81b7\
             aff21ca97c7d09a7b0a2880db0110461f168a8f5bafa045864373217b05ed1223fd0b00a1d7810e341c15ce69567e826\
             5110918b857f2546beb5761de3849fde971e2cc649c363c0ef296e2dc94b07499869851ba3032248e4a628294d626c6f\
             38c42530a07952d6b44b650112f77c8df5c5939102090c8188db61f3713e93c4a22a61c91fea79ea06bb1344a5ccd638\
             12f540a8907ffcf62fbdd7344a744095bc5df65047dcf8362a38bff92b5b6098893ae96286f4199f857dc5351b962204\
             807b9421602a0f00222a82b6f4785daf303354f9c097cb74a0723cbfda0553c4b0b4454e1ed11c6926396be9ad5cd160\
             11d333a1a880e123934243542776a0848b0ccc442bcb117c24982c42d10510683e7d534ac47c6631acb187039d098b7d\
             e551b868a28ffc42112253aef0f86f4c358c778017b30c0c3510254e6abf50664fb54c197bacbb790c32a935783093c8\
             8927b65c5c696c695cab4a845b262219c639c4f07dcf663914094b1db58dd04105d7c6bc32b6392d481bf954abacac75\
             70cb30bdf265e955ac1df3a356ab59c89b0cc6db7ecf4185f81ba9af7ba8ca47bf69a278681c1c8216cabb4887a36620\
             4118764669209d502be63bc8f21429e7434b381b55c95c53da864e333c13e7818644788a381215a4954cf3a038dae27c\
             a4684b130268436cc22fa100ebd843d6d9a20dd0b8c4bc8d56899fd3e4272ca1301ac9429986977a9a4910a785990629\
             dffc7ef2093aaa646741825e53ac6c43b962b5624a4d31a5e054436a2b7b880460a52062e4c5c9b2e72225dc2355d44d\
             d6b22a18ca6a05094bf8d3b2a0c58c13777bbe448fd0182b876a596e595ad4e79db6f0c1b4e1435507802e2b539edc25\
             820b23e7127655e11b34a5aaff25c11a7b617ed7083650c9030462a79ab77be63780a45f8ca96dcb15358e56aedc3136\
             0b2030010282ca67cde5169993fa808ee475bda0af49c216af9506330c9b0384bd2c3c51b814cff09b3c530ca754e679\
             66c22e44f68650b7117f78235d8425929816526b0a46f647a85a7929b49d677a38418368091590fd1276ee9629e63944\
             db4770b7c22e30b2cffba5b6d46a9a1217b7fa44b54b8266f07554b3ea970cc30d1e92c03f41ce2a2093f58a831a4353\
             e02393cb8969a582d55545ec39a61104ba2e5bf082d0d9573988cc26089b222718d29bcfb365365bd9529c55aaba5635\
             850809b305614091247e8bb47315503a07337ed40ca79d3c8b8d240d3af38c8a7a65ed18047b92600ff09eb509820f0e",
            c: "f8ffae03ca26e156af3aa562e6f84159596d3a985ae42da4e45171ba7c8a1cfee2549efddc414b27ff697920bfc8a006\
             be1651b0ecd18f91c91f1df9e6332178c3ba45407099c0c5c223e9c88d4bed9742d8a3e1251c6af4b03cf79f2671d874\
             6e7c86eb270f0c54b3362f691387539f5e7b16680ab51c1f93d098d40cb8698827ae9eb1a85f52199589d561a0fb1140\
             fad888ab0b03fce03a9d1d1069f0ffe274362f3f1b656e402e3075efc29cfdcd3d3a4163f74ce6b1566cf4626d14544a\
             2a33ddf5860612af5d337c6b55a7eae01422ca01882baa591f9edda6976e2bfdf945277b4c145cdbea5f22b636dd9761\
             f8edc518c33223fd46d771e39756b26dfd35798d3aa071f90d2250220d4869c59b3cad020b1e786eb8c856d2ab33ffa1\
             605fb61cb91c64de695fcc1d61ba06941b5336cb67e648b4197af2b297f4eed2df996e213d63e0bfb54a86c47b286a9d\
             5059580dad4007e4dc6fb944a53717f325d94eb6a514c13efc445f8e4ebffde3d7b00b955aebce826e4e9568c5e4eb69\
             e0f3be52c7b441cb7f09ee441bc01058183accde0a9473881bf09c992a86c6511319ee5af76fa80079de11ea7c8b9d09\
             47c308345a6586a8eda5d00aa7a26346c3e2c90c1709e52ee7ca292e89e1c22b5447449ae508ba0fe2c801e3a0f6d12e\
             22c93bd98d19ce199aa055d209431fddc46beab5db20fad6b53b93e1e723785ebc29d486fb240d6a4813683e2e71ff05\
             b4f53eb57c068c2c35f0b0ddabd8e17b48f8477747d1d97aff5434d1f09ce1dd325dc2bb5f79523dd4185dd38d3629b6\
             e83f76257bbbdcd6963b1edffbdf4456c6a6d2641f035d08a7ee3a7f1c046cd3be550ab93853fc689913e0e136a83ba1\
             5f948d8f229cfd6e12d19c2fddc9f17dfde4b28a7eac09043f1d4f37ddd4923151e837d7c9c9fc4dc9de1576686b50f6\
             934474402d53439d45a015ba6558c3032571e1b3263bc7e6cad549d1050fdd49f9b5cb2024cf543b6fb706b636106b54\
             e938f8ea664d9cbd75ff7042ed9d81546bda255d177d7335a7df06b5d0edc98c6678318f7131ed7564d5344df5480224\
             1144502eedcb057be3ca1d3ff8c65fa7487521dc9d4db49265dff8158b4ce2a1893399bcb4bbfcd2c3f7d9c2286eedcd\
             76518026d6586f10a79e02477efd8ff93931b01210c6ad0f75d23a62f68044200597dd277cebab9b5c21c74c5cd74b63\
             a8b6d59789f5c50cace6676c93990db2f7b4f39e00f455ac002c12367d7bfd0cb0327ef077c45382f0454255b2e11a94\
             2254608bc41b890172be38e3edd20ed028c37006aa6ed5907c78614748e53b7ee3242a7c1000552eddb67a5436fe8808\
             d53699e9bb3c190f5b966a1fdbb1da68e8fc630d841c63f5fbe7161baa0670bf970c3e617aaac12c83ff3c1d19761b74\
             21685f1f6c9c93eb35900e54f10744d90f4d444e06c45e2a9faef1a96f0b752d4df1df86a9503d8d99cdf8a62622184a\
             919e19df8230e7017d5f411a89da304b67e63cc3e3d901f998f563ca9bd4c9be",
            k: "34cfae7f2ca3b0b9c3e06afeed554c053f6e51d875d3bd3ff0eda2086ee79f3a",
        },
        AcvpDecaps {
            tc_id: 87,
            dk: "e5b72d1ad506add04ecef45db1147b6ff265454496fcf3ccc9826c4f7352c82a96315790a18a458c89cdfefc71f85b71\
             45eba2a4608eb039ccb215ac76e33dce848d1fa56d562b22ba208e994213ea17c4a37601c14b6d5287b37d9cc28e3b02\
             d51a6a4de282fc4babcf3badd6d978a8d89c35b37969d5bb5a8016c9c77e8b571272d28a4b8675ed17b610380f1b718f\
             a5e2c8c6807a3862bc70aa340ac11116f3718e2780e2e9897541208d5a7f5de05c4ad66a6011aa9bf72783f552b8ca76\
             7f0cc174a6204f587aef4abd35c47a2f0c8bba8b7cb5d444a1c70c752845b6ab1f653048ca65cbd4630762b2b5f4d1b1\
             d410364cd2363bd66d1f68c9b6e01f99e97a617a4a923bab6b476582e41a519269136a2cff79cf409717108a53f3d326\
             7eb1495899729b8c39dfe5517652920b8c6ec5b811d5b69b0686b538d36cc8a27d9bd81009472abd310a4e4b6b122c4e\
             3794408c892409166429d328102521a0ab175310ba0de68abfcb530d3a0e77f9ac93da9aab18aead743e01e0c044ea54\
             d5e890599b5e75032034069e3fd47db761b40a0a24c217b67c0433d1a1bd081b1d0e1a9463c82440d2c9383b5123a3c2\
             17b112be7a1af18972a97c7819241596ea3a7f6389635c685a0c2b8015a63f2032993833ccb25030098404cbb6fe3c30\
             3182c6b21223cc7c816702acf0504eff12be05712833710634453f9a0ace1ac29194f99539741c9a314074db7dd8e34f\
             6c7981fd93ba2bb745bb13acb7209edce87ff62b30f799b6c6525d9e03a418e750ee12bea4709898120301c829272b3d\
             debaac6bda7d4ee56364e32e40cb7f37a059a9fc49753620e0eccc25022d1e308f5cf94721330035f98b78d15f898279\
             9bf34eb7d54d774660d5c010173307e62b969cf5701d91a8703225bed2c67c99020e005ddea17c3a60b7874b382e5b7e\
             4f963ce0e841dca75ed9500e340704aee68c89b117d23c3f044536df9970fe2849eebabdf4b958b7a47b4e3848f1992c\
             fae4826b218d953974a432a1868a7600ac767d89ceca0433c20045dd637369b06b5f6182cfd7c3c9b475ed542daeeb76\
             e0632bac3a57e6a3364aab1c0903c0654020316c7573bba5c72a5af0e86d14074dc394399de6369360bb1eec70568801\
             093548f0698b68a7bab4184e7d82753d8c31b99c7a80837ce9a79ef22c681cb3100fc786da5192e710a45bd0860f8921\
             e4d6330e296a27739854e52a25576d19c6b127f593516bc367f56567f4695a370b3257ab74223f3f332656343502413d\
             24e70a4697b970fc00abd1575685c14816ac7902c345249dc19a54bd57b0f3d94d49a0ad80a4b76e9640bf4b499746c6\
             81b73de500b3eb896b29c241efd4c5fa8c9bcc6993691941e434bc40756a03f3158d249f86265a82e08b28dc3d7c69b3\
             cd9a3e94e3c24128958bb270b7ba1f46dc707834a648aa8d46c4c439b510828922c6f912902a284a61ab94b86b89f78a\
             8543acc1511efa2136409544eff8732c981311973b7579cacc8842a794875f619e028715dc4a2ef204b770a045a2164e\
             72851c72b13316374341b1bbe9f606bdc221a240cc045c745413256c06cfadc92d198b0d3c7000e801703ef814bb193a\
             c9f558a18202545a97a542b25aa1bbe40926ab797868045024479c3fa71d1baa9486807180a3c4b1210c5d9a10c37212\
             af528d37f12d45b3939d747d17b98f319296675834fd38afed0843c4d9bdbb95ce757c095960ae26a8abe736395f5939\
             2f08650db601e3151cd4d9c72a5371fb1331cbecacc9e36ca70574e1b88ad05ccf4aa0ca08d33d20839b261a3f4ed004\
             bd1356b90877013b005c852e165340c3f3465fe89bffb916c1a2796546090b5628f49543fc2270f5679ce4bb0d33ea5d\
             62e579a588bd90657208f80a522581a22020814318614a92c000b54697a3424b253eb0038722253cd24783e703a34aa7\
             a8d8691a6bccd514ca01e54d2ed56fee996768916781a81c2cf6c5c275bb7ee1be1ba34a5241ccef0a281ad3c3f24508\
             d7e11e687872ae0865f706bbeed1bc4bb9cb338a8337172cde084913573331b8cfa0eaa51cd11aa33584beb86e4ca641\
             bd302141515a8bb7553f2020a92c04eb079d7640b01d6c9d0c708d8bbca3160713d7368ae211a47305cc1115ad403c28\
             5f349e81546d03278989f4a010538b2d53b28c624942a410c05236bc9c8162080903897b77a3ccddac0ba490804b1a6c\
             61ec45c088a523cb8dbd2b5f4efb643eb44817882c86e729b2d6698dd19f7570c9d8dc21dd6ca8ae9697f64bbeb013cf\
             6890b5abba996e7bc06423be51113f3bc4b7cb591c02215de20b9b7710acde542202818f43657f93572c1b5aac80e98e\
             1ba51c90978c8b5c4c5df27f79d06ca111c7f5c67f6dd09ee31cc5745140ebb08b4f738180c833b42750210699a5a7bf\
             8960708c43af325628de870394b7b960abb4420a8c6bf28d25e11a8a497331a45ebea97aa0b889bdb861dcd1ba063a44\
             8e288499530c4f391f25a3593933ae65a1bb1f02b0cdc00ff3d56bd9e6b8104a5c5d6133d273a5d30c8d19b084cafa52\
             09e0c48fb0317b2133a7174b5314c06d78556697bfec0b780c0375485a6731388cc50189576976e270a160ca9abdba9d\
             83f519af20a31f27411576c9c0876478a53e5fb6086f096964f51b10fb13822883a9b8747cb57f264baf2561a70fc23f\
             6e527c1520cec706855cf9598e62c41e4604ada5046878bc49c7a05f9844848461c92240a5f817e9543c1b17912fc711\
             d0b8b0557c6c8a952610a6c495319c62ab0b9eea89b181b1cebc0bddd1bf6f0492b948c3fe8044ba3a1429a6bf31e741\
             76427017835a5eb1469007c39cd1a88dd0c179197cb1ba506a282335187bac1b8b3ce348ffcc024fe956111b92354018\
             e321b69ce22bf566a63982adde58754551627a9909fa48763559b509e240e9633b42f14ce0d25af8591531c779010705\
             d6f749ebc8a6ef090702a4bb9d572250476a02c08ef359229be38c58f78d6b4859d2e315f927109ae85e00b684aaf7af\
             58004e60e2c360806469463b3a569aa54c9100ea3c900366cb3b972f17160ae5ab3e328c60e98305797d577c6f1d2ca6\
             0ab670f793073b459b0cc70ee083418d47993fe6baf9d075fc4bbf301cc9c904a8e15a45701047e510b1ec4647941117\
             565829f13bac8ce22a7d7840508a71a82b64b5b176b94375e4384f037386628cbaab0bbc1c3c2ee693c191d59a5cb161\
             66a02bc7eafe50e2e3bc093157330621e711f3d9c0a0663ccea5c9a1ee2407e52a4e3dd905f9e307619bc884f2d05ca3\
             1e601a767537b40670a93f89d6626a6c919196def74f81f100ef038407e454063c098f37bd43f4e53acf69f1ca97a211",
            c: "d3b682c9cb59e6a0509e07679feabb08740f1c325ca5721416e1426683f766277cb3b3b875a84baf89b1ed91b6ea7fff\
             40c5fc4a5267fb90e9b21e7409d08ccf2c8c12187a3644e178493d0a3f5d6be9a9c1284a0eae2354e61ad9698ca23e5e\
             5347ae0b1b05540681ab952c171bb7835d1c03669a7fd97166192b2a49538ab983660959989940308fa30fcc1eb333fe\
             e202e0f71398fbd22ca2a7aa48f9b5ea8021ddadec5ab1c3774be7eb796b418802d5f40ea37e1e8e8ea8207e837a27fa\
             58d156fd60fd0f188b4a939dac76b55984eacd2e35d6b4bf5673f5f25396809281e6ee5336793d716f00040211c01f73\
             dbfbc55e21d8abda1b81cb0de5f742dd2016b88631386eeff7e81c66c1193df559f98bf30aeedbb3b9fc89e91113d770\
             bc32fd32bc41bdffd4bdfd3f94499d4690c955c7c1c0566b63ef4675e892d33b0884829c1f8c346500d44cd6c9c3828b\
             3142185b6b292004fcd62aa2abeae07428c8f9375b84fdc3d63c41e01527aae740d469c8e291474b15b8c145480687d8\
             a441f588f8075151d58f3f72749157c942f17608c81a5ac4a91c487121095786a7a75470099d53d8968011b66d1cc658\
             2cd9bfc658a8bf06a19ab2bded165b1839ab13675846f689cfbf63909fe04771d9cd7c6806a61c67d491f81668602eb6\
             fbaf6ac2aab35c61248617da27fabb786f936121dd49094fa1b0b370ee941eeabc6281d6c6c1690f1e0f34e4ed8a5629\
             88b4ad4969b0c442681b54897986df5c10c0ee068becf55678f3facfb4d34cb6f5a139f5234556df3fb2850089c2cbbf\
             425918c53e2762d392a6061330cb2866792097b6b42911066d57a133a731fc5d65635d56eb0551d9f3d6c31856ed5095\
             055a03aeed8f3573bff024ecca36f79ab46a7411cd5ad668947fb5aa16a0f2082011e651efd3b192e338b53a21544f26\
             6474618cf9c35f1771f97883f66e93f464c5dd814e3edd0ebf8a2021e13de8e7803437d0a9bc7b9159fc510f3f8a3c9c\
             02e25ba92979c450c37906c1a91b59f8ddce99b365c43e2bc3ff7e1ce9508cb76c1cde84ede89c2f0cdc514526b30d4f\
             396a5019a3c2a6904d8fcf28a4d93ec0c36e5fa8fc1abf3453b41c0639e2db26fc484da5beac19bd2cf4d44e1c6e7f00\
             b1856e99f6587703b3f08e0c65554d6a4a88bb7bf89c169d4ff490ee637d58f3ed5cce4185c61d9ef46a9d3184bf1c8e\
             5defe6c925e446e13fe432a236502b69a29dadc8919caa9e7f2b4c3c5266b0cb4aae56974ecda26add535c107a493641\
             c207d615c5848c0cb93eed2c73a9af4aee53ee30623d84e207d2f8a6ffecdb9665e56fc1e9a9a891dbd73d634d8eae9b\
             d1ff406404128ce914452425c895de4743c548c7ce258d6b1981a5065a9a6460805eb78b6dceba338a382aac02a15324\
             29740c2d686ca6a54dcc9719bd56d9c880af6352a2a27e90bf2d469e9e5512a7805aef46f49bf1a17e06952fb63c2117\
             2053b84a45c567ae96ca2cb00f83f6a9dc95854eb3593437f56fc4bc741d72f4",
            k: "14ab4268433ff8d0ff6036eb4057f04aaa3c282b45ed65a3f211e71f79a9457c",
        },
    ];

    /// ADR-004 test vector plan item 9: ACVP decapsulation cases through
    /// the aws-lc-rs oracle, which imports raw decapsulation keys.
    #[test]
    fn t_cr_hybrid_mlkem_acvp_decapsulation_oracle() {
        for case in &ACVP_DECAPS {
            let oracle = OracleMlKem::from_decaps_key(&hex(case.dk)).unwrap();
            let k = oracle.decapsulate(&hex(case.c)).unwrap();
            assert_eq!(k.to_vec(), hex(case.k), "tcId {}", case.tc_id);
        }
    }

    /// The oracle's ML-KEM-768 round-trips, so a differential failure
    /// points at the code under test.
    #[test]
    fn t_cr_hybrid_mlkem_oracle_round_trips() {
        let oracle = OracleMlKem::generate().unwrap();
        let ek = oracle.encaps_key().unwrap().to_vec();
        assert_eq!(ek.len(), MLKEM_EK_LEN);
        assert_eq!(oracle.decaps_key().unwrap().len(), MLKEM_DK_LEN);
        let (ct, ss) = oracle_mlkem_encapsulate(&ek).unwrap();
        assert_eq!(ct.len(), MLKEM_CT_LEN);
        assert_eq!(oracle.decapsulate(&ct).unwrap(), ss);
    }

    // ------------------------------ production against the reference

    /// ADR-004 test vector plan item 4: production encapsulates to a key
    /// pair the reference generated with the aws-lc-rs oracles, and the
    /// reference decapsulates to the same secret. 1 000 key pairs per run.
    #[test]
    fn t_cr_hybrid_cross_implementation_round_trip_production_to_reference() {
        check_with(
            "t_cr_hybrid_cross_implementation_round_trip_production_to_reference",
            Config::default().with_cases(1000),
            |_g| {
                let kp = RefKeyPair::generate().unwrap();
                let pk = HybridPublicKey::from_bytes(kp.public_key()).unwrap();
                prop_assert_eq!(pk.to_bytes(), *kp.public_key());
                let (ct, ss) = hybrid_kem::encapsulate(&pk).unwrap();
                let theirs = kp.decapsulate(&ct.to_bytes()).unwrap();
                prop_assert_eq!(*ss.expose(), theirs);
                Ok(())
            },
        );
    }

    /// ADR-004 test vector plan item 4, the reverse: the reference
    /// encapsulates to a production key pair, and production decapsulates
    /// to the same secret. 1 000 key pairs per run.
    #[test]
    fn t_cr_hybrid_cross_implementation_round_trip_reference_to_production() {
        check_with(
            "t_cr_hybrid_cross_implementation_round_trip_reference_to_production",
            Config::default().with_cases(1000),
            |_g| {
                let sk = hybrid_kem::generate().unwrap();
                let (ct, theirs) = encapsulate(&sk.public().to_bytes()).unwrap();
                let ct = HybridCiphertext::from_bytes(&ct).unwrap();
                let ours = hybrid_kem::decapsulate(&sk, &ct).unwrap();
                prop_assert_eq!(*ours.expose(), theirs);
                Ok(())
            },
        );
    }

    /// ADR-004 test vector plan items 2 and 3 from this side: production
    /// `combine` equals the reference on every fixed-input vector.
    #[test]
    fn t_cr_hybrid_production_combiner_matches_reference() {
        for n in 0..VECTOR_COUNT {
            let v = vector(n).unwrap();
            let ours =
                hybrid_kem::combine(&v.ss_m, &v.ss_x, &v.ct_m, &v.e, &v.pk_x, &v.pk_m).unwrap();
            assert_eq!(*ours.expose(), v.combine(), "vector {n}");
        }
    }

    /// ADR-001 Verification, ADR-004 item 10: the oracle encapsulates to
    /// a moduletto key, and moduletto decapsulates to the oracle's secret.
    #[test]
    fn t_cr_hybrid_mlkem_moduletto_decapsulates_aws_lc_rs_ciphertexts() {
        check_with(
            "t_cr_hybrid_mlkem_moduletto_decapsulates_aws_lc_rs_ciphertexts",
            Config::default().with_cases(256),
            |_g| {
                let dk = mlkem::generate().unwrap();
                let (ct, ss) = oracle_mlkem_encapsulate(dk.encaps_key().as_bytes()).unwrap();
                let ct: [u8; MLKEM_CT_LEN] = ct.try_into().unwrap();
                let ours = mlkem::acvp::decapsulate(&dk, &ct).unwrap();
                prop_assert_eq!(*ours.expose(), ss);
                Ok(())
            },
        );
    }

    /// ADR-001 Verification, ADR-004 item 10: moduletto encapsulates to an
    /// oracle key, and the oracle decapsulates to moduletto's secret.
    #[test]
    fn t_cr_hybrid_mlkem_aws_lc_rs_decapsulates_moduletto_ciphertexts() {
        check_with(
            "t_cr_hybrid_mlkem_aws_lc_rs_decapsulates_moduletto_ciphertexts",
            Config::default().with_cases(256),
            |_g| {
                let oracle = OracleMlKem::generate().unwrap();
                let ek = MlKem768EncapsKey::from_bytes(oracle.encaps_key().unwrap()).unwrap();
                let (ct, ss) = mlkem::acvp::encapsulate(&ek, &random_m()).unwrap();
                prop_assert_eq!(oracle.decapsulate(&ct).unwrap(), *ss.expose());
                Ok(())
            },
        );
    }

    /// The oracle imports a moduletto decapsulation key, so both use the
    /// expanded FIPS 203 encoding, and decapsulates moduletto's ciphertext.
    #[test]
    fn t_cr_hybrid_mlkem_aws_lc_rs_imports_moduletto_decapsulation_keys() {
        check_with(
            "t_cr_hybrid_mlkem_aws_lc_rs_imports_moduletto_decapsulation_keys",
            Config::default().with_cases(256),
            |_g| {
                let dk = mlkem::generate().unwrap();
                let oracle = OracleMlKem::from_decaps_key(&dk.to_bytes()[..]).unwrap();
                let (ct, ss) = mlkem::acvp::encapsulate(&dk.encaps_key(), &random_m()).unwrap();
                prop_assert_eq!(oracle.decapsulate(&ct).unwrap(), *ss.expose());
                Ok(())
            },
        );
    }

    /// moduletto imports an oracle decapsulation key, derives the same
    /// encapsulation key, and decapsulates the oracle's ciphertext.
    #[test]
    fn t_cr_hybrid_mlkem_moduletto_imports_aws_lc_rs_decapsulation_keys() {
        check_with(
            "t_cr_hybrid_mlkem_moduletto_imports_aws_lc_rs_decapsulation_keys",
            Config::default().with_cases(256),
            |_g| {
                let oracle = OracleMlKem::generate().unwrap();
                let ek = oracle.encaps_key().unwrap();
                let dk = MlKem768DecapsKey::from_bytes(&oracle.decaps_key().unwrap()).unwrap();
                prop_assert_eq!(dk.encaps_key().as_bytes().to_vec(), ek.to_vec());
                let (ct, ss) = oracle_mlkem_encapsulate(ek).unwrap();
                let ct: [u8; MLKEM_CT_LEN] = ct.try_into().unwrap();
                let ours = mlkem::acvp::decapsulate(&dk, &ct).unwrap();
                prop_assert_eq!(*ours.expose(), ss);
                Ok(())
            },
        );
    }
}

/// The ML-DSA-65 ACVP subset through the aws-lc-rs oracle (design section
/// 7.4, T-CR-MLDSA for TH-68, ADR-001 A6). Layering rule 9 keeps the
/// oracle in this crate.
///
/// The vectors come from NIST ACVP-Server commit
/// `975de31eb83d87039ec88934fdc47d8c312b892d`, `gen-val/json-files`,
/// files `ML-DSA-keyGen-FIPS204`, `ML-DSA-sigGen-FIPS204` and
/// `ML-DSA-sigVer-FIPS204` (`internalProjection.json`). Their SHA-256
/// digests on 2026-10-29 were `e67ee654..63baf`, `72dcaf5f..93af22` and
/// `47cdd631..a55437`. The subset holds:
///
/// - keyGen: all 25 ML-DSA-65 cases (tcId 26 to 50). The ACVP `pk` and
///   `sk` are pinned by their SHA-256, since `sk` alone is 4032 bytes.
/// - sigGen: the two ML-DSA-65 external pure cases with an empty context,
///   tcId 44 (deterministic) and 216 (hedged). aws-lc-rs signs hedged and
///   takes no context, so the oracle checks that each ACVP signature
///   verifies. It cannot reproduce them.
/// - sigVer: the one ML-DSA-65 external pure case with an empty context,
///   tcId 39, which must fail ("modified message").
///
/// The other cases need a context or the internal interface, which
/// aws-lc-rs does not offer. They run against moduletto once its ML-DSA-65
/// pull request (crabnebula-dev/moduletto#13) lands with deterministic
/// entry points (ADR-001 A2).
#[cfg(test)]
mod mldsa_acvp {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::panic,
        clippy::indexing_slicing,
        clippy::arithmetic_side_effects,
        reason = "test code asserts on known-good values"
    )]

    use super::*;
    use fstp_crypto::CryptoError;

    fn hex(s: &str) -> Vec<u8> {
        let clean: Vec<u8> = s.bytes().filter(u8::is_ascii_hexdigit).collect();
        clean
            .chunks(2)
            .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        digest(&SHA256, bytes)
            .as_ref()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect()
    }

    /// One ACVP keyGen case, with `pk` and `sk` pinned by SHA-256.
    struct MlDsaKeyGen {
        tc_id: u32,
        seed: &'static str,
        pk_sha256: &'static str,
        sk_sha256: &'static str,
    }

    /// One ACVP external pure case with an empty context.
    struct MlDsaSig {
        tc_id: u32,
        pk: &'static str,
        message: &'static str,
        signature: &'static str,
    }

    /// ML-DSA-65 keyGen, tcId 26 to 50.
    const KEYGEN: [MlDsaKeyGen; 25] = [
        MlDsaKeyGen {
            tc_id: 26,
            seed: "a991fd42b071d49c48ae3e75c647459e0daad1e1ba356a04801912d3294bcff8",
            pk_sha256: "b1a7d0d2f0d7a04b9d5ffccd9bd578864dab4a01cdd7f70a05cd1f4f0672e43a",
            sk_sha256: "56c53ac82fbff7d81b7a8cfbbc73011ceccad677e16dc53f2ece66d49aa11edd",
        },
        MlDsaKeyGen {
            tc_id: 27,
            seed: "494f29ad1c93abb2b9545bd14cc575a98ecd3062137b439b49eb1a8cc6652fc6",
            pk_sha256: "4f2a21f2bee92fc15c91ce7dc7d96f5dac1ee1f0f7eb7325823ea96dd12ecc84",
            sk_sha256: "bd37a2499543695d6d31afe6c5188fe18fa16f3980d2941edae7b5dbe5c71c14",
        },
        MlDsaKeyGen {
            tc_id: 28,
            seed: "c4ec434d7feddcbff68b77a80e45935f3e363289a493e49acbae366e5c6b3d01",
            pk_sha256: "01d5cc69a363d4b47fffa5a042edf4293cd5290c3f4a1b5c2f11260b6446eace",
            sk_sha256: "81f88ffe05449f6ac5370d632d6e969be6028023fb81570e62d7e0e0ee963269",
        },
        MlDsaKeyGen {
            tc_id: 29,
            seed: "37eb816d244578e6de586ad200bca1da2acfa6b0443e024b1a94e43ab08f8794",
            pk_sha256: "f885f9844ac4f3c6012b4c0fffcfa6edbc236cc4f7e8dfca711b820e9b133d00",
            sk_sha256: "24fbcecf15dbf3acae3de3bc95cf41d61c4fe7dfbb161112a79038682e8d0e32",
        },
        MlDsaKeyGen {
            tc_id: 30,
            seed: "f7ba5bee3e1ef18905c788fc6f9fb838b3e346f4b2908e8585269297098caffb",
            pk_sha256: "6e31747d8ae9f9cdd2ae76fffc55247a9e4ffaf7e369e84dee896a6937bce700",
            sk_sha256: "22b6248af2b16ed3396e52ae0c6456f229216a0e004043433426ecc00757126e",
        },
        MlDsaKeyGen {
            tc_id: 31,
            seed: "3caf99a3e33b5bf5bf133760dcb35e79d7c7f542126da7a8e50f1f8ee32eafd4",
            pk_sha256: "fffc8dd40daf58cb3858be08a178cbe0e792b3cf0bb6221e705423ebaa9494fa",
            sk_sha256: "e065a2582b58297103f304381f69bfb4ed8734a92651ec47c3a361a1f0ec77eb",
        },
        MlDsaKeyGen {
            tc_id: 32,
            seed: "d315e80bd75df48cb68b90968739ea0d2a341dd744f195bd160571b414931fa7",
            pk_sha256: "a09c492b49bade3dd0c7a64359e7e67cac7c569bcc6cb773e7ce6700d45eee97",
            sk_sha256: "c683ea03f37a3e8db0004c95640c7923398820824bc8809eb8c91ae0633023f3",
        },
        MlDsaKeyGen {
            tc_id: 33,
            seed: "910b4e8bae0ca006a536502938a5552aa0f363c6a5410712bb5f6814bde0782b",
            pk_sha256: "0dff0715954ef9d2efc88fcc11ccda02adf55c088ef35fa2e6bc68281cc4d903",
            sk_sha256: "2dca799d7dfc43b974f9145504ad3846c4188730b2ec962e8be99d7780bdf4e8",
        },
        MlDsaKeyGen {
            tc_id: 34,
            seed: "73eb59029cc39c4afd32e675b302ecf6ef79a61d22a96c3dd94ca6181e02f07e",
            pk_sha256: "044fd8b0e4f899e1aea1b6e78933a35294179b2ceff1f64910411e7a944a70cf",
            sk_sha256: "8491d0b4ac22bd5ea68a830df2c9dc066cc6f0394a2e24e7b4760459b7513a1e",
        },
        MlDsaKeyGen {
            tc_id: 35,
            seed: "71fce07ae3cb11b522af23931b0ed0dba1054c5441c4aaa9f050ef54738eb286",
            pk_sha256: "fcfa1339bd9b14f7f6fbe69d3b048be9eed66416259019d4c876896ae5433a11",
            sk_sha256: "1e3e7943ffda945604521d5aff7c06e23eb050a88c6101031783b6673d54242c",
        },
        MlDsaKeyGen {
            tc_id: 36,
            seed: "074750305d5d6013d0cf39561a7208a52ea98e742c5dc77610692d83ab78ecb7",
            pk_sha256: "1ad749dba56d69712628afc07bfebcce926407ab1bf3b69d2968c8632871be98",
            sk_sha256: "481ce10bfda21789f8955b70400161b7a65337b96f6d5d50161358abcd429489",
        },
        MlDsaKeyGen {
            tc_id: 37,
            seed: "c32fb05c74b63b42db3313ca83521c0f536753c1f05b76a816d0a57a60ccbc18",
            pk_sha256: "5fd8e37e4e9d46df0f892ebba5c23c47032fd7424f47b4af5f8155cfe708d892",
            sk_sha256: "70a6f02e0d6cb3134d9f77d6f8178d5b63e064422fc4b461aa818cb53d414502",
        },
        MlDsaKeyGen {
            tc_id: 38,
            seed: "20003875c4d1f9ff6a4d621a0645b247b20d50052dbd546f60463e1e44e23441",
            pk_sha256: "1a7c15214302265023b48e721dee9f557739df14ec74386b94771ed751f4d53a",
            sk_sha256: "56989d7b19d88f7b0988c9a8adce56e6a228201e369f0e1938991da76828b1c2",
        },
        MlDsaKeyGen {
            tc_id: 39,
            seed: "1c8eb5a91d831a988d8f80164fe96ffde6e22b58c3442509a4f5a84a9c555f82",
            pk_sha256: "143a572772712eafb52552b9f72a15316a1ee1f65398c3039b75d9032b4de132",
            sk_sha256: "576db4bb0fd0046d259d3c97992bf3176a21265d39e693a555ff6943ec65f071",
        },
        MlDsaKeyGen {
            tc_id: 40,
            seed: "9f70809cfa4fe387292c7d192d6f14d0e49c16cf86d9449724f5bf278c5c4141",
            pk_sha256: "efec28828169df113525b3bfec0409ef2f80bb0932300f417a62f368619981ab",
            sk_sha256: "2f3ce7e6a0a62555289a3bc7f776516875c87f66204b6d09d63cf9e7fb651d0e",
        },
        MlDsaKeyGen {
            tc_id: 41,
            seed: "223ae03541db28e5c41d163cc1014fc8c00ac8fb5a72c837f21bad9f017e7c69",
            pk_sha256: "c82cb1da93263824832bf5e105bed88aab9b8545cdcaab1c4d0d45f906f34c6a",
            sk_sha256: "b4ea8d10817613b7d2f343c10c9364623d2fe760a290313bfdf441367edd08be",
        },
        MlDsaKeyGen {
            tc_id: 42,
            seed: "ad7ea54db9597933af241d03287c3daf2ae9cfb50e3a08f1d62c9b209f858907",
            pk_sha256: "dadda043bd30c004fb31d2223dfa278195d2a09dc2eb35a3da764e4ac137975b",
            sk_sha256: "fb65d9a82c260a1132fccc92bdbb448bbcc34e9cbef0860cc744ac06bc96c452",
        },
        MlDsaKeyGen {
            tc_id: 43,
            seed: "61671db7d80e55b58b8db6be1f71492bbda55055b0b07db5eeb86c78fdf03ac7",
            pk_sha256: "295df72185ccb42efe66cf401b6ec8e6016fd7b993d670deca2b7337990e6fe6",
            sk_sha256: "4ac308f9fbfae46a172cf226c55c2a9ef2917180a92e061c8ae9f606cbf5dcd3",
        },
        MlDsaKeyGen {
            tc_id: 44,
            seed: "1ca2a77bba4831c2be03d74e86e83786f439b746fa12cf58e87cf76b18613fa6",
            pk_sha256: "5688a3d6ef7e17377a8fe6faf53474c649eadd7ac6ab31deeb3f1037e13a6bf8",
            sk_sha256: "90041d20e02b145c9a5ca1007ffa76b912fe0e62df8bd2a88cb6dd26ad71f656",
        },
        MlDsaKeyGen {
            tc_id: 45,
            seed: "7168ce15c6ab96c3febd63ac5bca2c08a24d81401086bcf132c67f86c3d3b951",
            pk_sha256: "e6f339be5823ee16b2ead0d83f5fb9228cc27e99793ab0840d7d0670358d3b78",
            sk_sha256: "03b1fa3b241996a78b6250ebcb9405f99550560e14bbde2b477a97191c9c1461",
        },
        MlDsaKeyGen {
            tc_id: 46,
            seed: "ced0bdb68764542083119deec6abb4597db8926f40beee6b342cb10d79fd444c",
            pk_sha256: "030adf9b90197bb344832e34cabcf2bdcce2609d89205e6ac10ec365e60fd045",
            sk_sha256: "3bb6e64b27c007370607afca6c9ac9090abdeb855dd35562fa280859e91bd918",
        },
        MlDsaKeyGen {
            tc_id: 47,
            seed: "08f819f6eaaa10fd7ab8753da446f3b581acd2c45f1874ef1189a9b30310d5f0",
            pk_sha256: "bd8ea4493b56f25274b847079e55e2c10da60a8ad40710b1507bec9baafd9a59",
            sk_sha256: "2bfd6f7402505b33605c364765db289258d78aa733a3cbd44084d8a38b0bd0e0",
        },
        MlDsaKeyGen {
            tc_id: 48,
            seed: "567d2f49919d74b28ac41016adce8637a83db24cba95edd8da8fdf25235f6058",
            pk_sha256: "977ac7f04d79ba4f3609bf7fff8ec28dda906fe43cfda9af6a6d33e7aad7633d",
            sk_sha256: "d0ae83950483c53efb6eaf91b2fdc129a00e0eb02a495596f856a328e705c68d",
        },
        MlDsaKeyGen {
            tc_id: 49,
            seed: "56bdd9d2771bb95e53af1196ab46dc13637af61361100ef07b2a3dd5292a00ea",
            pk_sha256: "cd18da3552ffed77184c17b955a95523bd1b68831f1e33540b18ace853c4aab5",
            sk_sha256: "f7e8eaa5389a1131a0009d5618bf48c2cf6903b60df24bebee9a95b5ba92b7ac",
        },
        MlDsaKeyGen {
            tc_id: 50,
            seed: "d40a2d14c087dc931760453dbe3f7ec376a318aadc164c1282051243959cf453",
            pk_sha256: "c0813ee668138504f78a6629d7d5e94ba9d801d49b066532646f9e4a64f173be",
            sk_sha256: "55cd3d8cdd53d42124024812d9a78aaf945ef3517ccd4573ec68dba62af787dc",
        },
    ];

    /// ML-DSA-65 sigGen, external pure, empty context: tcId 44 and 216.
    const SIGGEN: [MlDsaSig; 2] = [
        MlDsaSig {
            tc_id: 44,
            pk: "878098482f0f9ca3fae55be06bf51fe534dca59c5e46c96d497e324eadbdde663d46433b6c19e799cdb37e005893bd29\
             6cecbbf23d0133d79695c6f98215ab4c5ce3b2d4d19d5fb35594ad1a84b8cc6ecd7f7e280145cd72c3b56ebe14f16ed9\
             868f2865b4628b0460e4b14b6abac876d3ec879851ae119e7ececb4c4e38becb6c84bb61d5b6fd6464a806a3fac6fded\
             d349dfb236f824294429d79d805800422f540fb89b62b2d8d655f1a5d623a1b9af23515e266c8f48a1c7547cddc597d7\
             9d45688e49c340ff2d8abe915a29aa623ad4a7dcefd94934d95faec94576a611cf604654c77767277f82426f59612c14\
             08809df47ae9eb4bfd8ec8a12390bf4c4691f40f32c8e045a4c82f49de998729d18106f61d99dfdca5eb8fb4e0980f77\
             70fc0ab92040c18f75fab6722da043f66c830d5fa87a0b23f0bc60d026db7cc0ec106665b2ab62572e364eec7af7d583\
             53ada642e0e929c4cb14a344a864cb35c5294cd0102e75b61604bcd4bdf855f6dae0db355e76b6beadeb51845d7e42f9\
             5624657a72c4895481ee6043c7f40b75f335efed1ac0a1f032dd4f33c0dd3c6640bf86e89c1e23dea74936fec404a756\
             c45f554a9eab7c3ce64c8661382d75a98eeced7197ae1bc69b9daf73f2d3e0a5b15d373c75c62061e0d04e556d480454\
             0cfffe75e60db11cbefd4de0de06fb72e5fa6790f0b111e8f382194719ecefc29ca5fdac42616f1df4c7d383309b4f0e\
             4a75f46874a87cfb8fd679829ae1d19860cc80f329861552bde0f239705917f9480a48379bcfa6d9e91b05531bfb2b10\
             5c401c5ceaf2538cc7366913a1831922364581f17a0bda343e38fa9653c1ece25b7d65568e99495b1ed57a7c8dccc502\
             0a2ce49a0df5288ae65d02eaa4272991090fe377b79a0c94dea5b29afcb70f731bf19f63ba9e3e8a453c7a1d37040723\
             e2f2c7cf8e8debfd10d59830a98fb9292147495a5f3eeffc2ff27bc1232f2234a372e59677ecb442a76a22dc61302a6b\
             2924b6fe8d3891f058c9586f4f07cd2d3c9bd1599ad6c011b50b17c78ec87d5b1ece5130dbe01ef55f5882c3c16f6479\
             19247b90c44e1e7e75984bea63a4c1a9421e1463c48f7c85b4fa3003978966efeb3e2047a91b0dc5e28757f2cbb70431\
             fd27c756b8266c206ea1da4ab4b187517d800289da882b2a7eca3d5dac3062da62f8e0635d5a655fbab8cbeca4ed5afa\
             453f51877239538818c530eb17bf256089e017b2d59c7bb5ce5474500fe23283ad48d8af98906609087fabee75f1f8b9\
             01381a835df2b2af1585ce64b7f07e1f81856402a890019ad91b878584ee1219a341edda555c8ed8e160f0b0f8ddadd5\
             1434de4486f764319b8eeb60efe037607576b09dfc468bb00cd53229a16dcb1ca5031838861b9976bfc4f3ff81ed987e\
             2e7d4332196d8008c1d8d30d4f0b0c636d1780020a1c64bedef3de78a061d3467fe32c58473184e6e895dd1f05744839\
             d2b422545185dd70a63050f9b6b303624a88b11c7de6492eb417157f1fec183328a9fe679fa1a6e06b45dd7d6608d59c\
             82eb8ca5f053283905b2d0d9713290d75cf1431b5fbfc316460439697da392387fb47cbb3a2ab3ee407c158f1ae26b60\
             77858d47068bfeadb2e42d7779b421c60294f49a81caf966e21fcd3a92620457e924ca4cd783991c06e7eed25ebf5f7f\
             a82835d6775bcb0af2aca41c7469974a46ed081b7367eed3e977e675d0b44e3a3c5e49971a7931cd256c042857caf0a2\
             bad7ab68767105f3388c7ccbdc0d0a9a342084f75162c0c203bada78d2b071977e1cd53257e1c37502523fe147607a54\
             7b632c4fa86f715a904bb90f948a51a9db61bf671e7ce808a55d3a3650669f38196d2e4c8f7a2061d6867521e54a9b1d\
             8ef2f2e556e50e2549374cafe1599a64e4e370828d6571683384c7556f61e0246af26294d69600ce33966dc250729142\
             c563b3bea6bd8eee7247d275f804c3bc6cda96250ca02611cc26566d12be51e066eb9f87a584b04ddc6c0fe1452c0f35\
             78e270da172bfef4be90e8901da894b9830586f9ca9cd3f51962cd9dae2a28a5805392d0ce5ee2fe1d5cc652ccb72c0f\
             a810c0d57fab1f9edd7863d37dbf3cbee5ebda506484e14b8b2871892dc75553c27dbe3f0f59ff1e6aff60070e87fd92\
             8205ed595998aceffab4ba6095cb3ff0e8bf76ca8ef4b49ea63249a4d11421c1f9104c6a72313dba745328c41e358e53\
             ed0724e4bfb59e64b57810d0822cd1320d1f12dc3e2cefad246977e776ae8d1402446a19f4e322c89b3e7aa4bec1d456\
             287b61bcbacfc7214efe3876837fd8f5aea012019c6ceb2c991285db915e1c1584bd19d6d3114a5644ab34f8a83aa7e1\
             468c61d8463faa831f442dda2d0d94b135324adf7bcf05033241e6f5113dbc6a94350312caa1da01bde001e3c4e21bfa\
             9d727614999657dfe68fa499e26cecb961dc6000aaed8359f328fd0f46262e1840a35fb7aa99df0675115bf5e7845a52\
             50b75bf98829e603ac445d2b09f7056596502269143a1b3e3a9d7e2a55abe79c74cba6eecaf63293c6c23babe8ec66ae\
             523e8d11e46fdb2d90ed0b773bb1d1428771d3a6f3beb95e001f45b737636c85af75ab5bbd0f1cc85774cf078c0f3565\
             a1e4bbe690a566b1c81a874046b3639b5b793285fb247aa59297db2968eabc6252a0b492e3cbd6262a6e6ef8e16a98ab\
             7e7af545f75cbead4422ba02d113e106d52e0d77e0efdc1e837a17c409e359de",
            message: "2342dd3477966f160b2c06fbf98da96de8012c2b631be1ae92e0b5c7ee066c6a5db55301672d57bbd95f4c3a596c9e4f\
             774233822d54d076434562ce52487657665f6898dd21b01b83597f349225f3f5af070f645ed2cac64e30221849da1458\
             93de604c624d5687a79155f71a1ea7665daca967a00a35c6accbe533a957add8509a53398c50a2586eb06e9499779134\
             63cc70f7b365f2e717ec9d04a6c4381525ee6eac520b33cda35ccc93f14db34ad08cf8e26dd3c7bf46a544bf1e45b53b\
             445fe24dc161c05caedeca7b25398c5cabbc4a5c007c75073c300d1367e1ab6ed8f2cd7eaa5e071ae8f85ee3db03f054\
             b9aca1cab38d2d11dd8cacc97ca8550dc1a67e158d46094c87fee92e8e5394e8f989bcbcef6d1456085bc4b4ab8e18d2\
             26ed3770ebe9de75699038c8e4366ca2405757957b7cfaf8166aff6bbb73dcbfc6ce64faf5d53f511e3738e9662ac107\
             c67f27884ddfa08be72c452b3bfcaca2799ef2a53e332168e0a5741b07e2255c963a686815565db874a22e173d20f693\
             5240cb8b8657422fe83cdfab98142d1544834b3190ffe2452978fd80620aa4bf510c3035f769dfe16cf867f89c873171\
             239021e2e047a08275c3f46639af2850347b33ca8550a665662b79308258091edf36308b5ad93b84d7b5859ecf460de6\
             28ea50a5a611a7531b7cbc1bcc7738fb61c4ad4695513a8421dadb2da4c2e2224746a7ba536ae38c7dc5dc945e5c5eb2\
             e22960b169552dd0a4a310899d2418f8101a782b291b25c275169cc221df2831637951bcbaf23dc072d0d6782d59a319\
             88fd73878ec22c34e61ba4a7159fa07b1c3de2413ea1f584a207ee55500cdd1abeb262c25a456f46ba8f5eaf76e0c760\
             2626850b7361cbeabfcdccfd09e6c445cb1b87dd00c7a1a14955a2098cb4526f05f73c1551a935468f6289fce7b89c5d\
             99ea64c94fcd58633bd6b4a8a75b4d48cab4b6a5435e2f2fe4d7aa582bdd78fdfe4964d9fd1c23bb9d807381d8191d3a\
             bbb4d960b69aa6fec462e57289f5e3af588dc2c49509fda4146c40ea5cf491c949334e0f8cd18ac00efae2fbc03728dd\
             6bd0756ae3666e0ac36631415bb5f9a75da5aab1d24f7fcef8a52b0413c10a46ad9b9f559bef6ff3e5215e0ca0836639\
             fef6bdcb7dd6790b26115a525a532b2273d1c4c2eff89d1a7127874c5aa5e052f886583fe37e18715d8f4e380ae01b6c\
             6db8b280d55ebf5735a1499547d79a744a653276c099db25519920ae4fd2bcbabdcf23f41a2ab72bfc18d8bfa46a0b7e\
             3e9d0bc69bd93c90adccaa8d89bc700d60edff5355d811552bcd4ffd2a88f2fc27aa6bbfe01ca8bd2279cd2b80e3f94b\
             16034796663229a95cece243965f0a7af82b7182078611a88466867f816d420e11e65c3403ea27982d7345f1c42c23a9\
             f84e99c2f20a3172374b808ecb571ca1dda770ba0802c991ed638d39f948f305f551d69e0f20b682a06537cd7b15fbbb\
             ad3e3ab83218faceeda8e2a88cd2d76f18fca4c712c9e0185fa2d303d1b63ad00b1a0cd0b80c029918e867ef38152574\
             680984b6e607d5b90ff2c434b213b754981bbeb24640789db28acee782ef0b24d78516890bd2ebcacc521030a9b523e7\
             cfeadf433afcf97e929088d2d2a10c20226ee9d6fb873f775ff8ae40be0a2d3b5ca0898f0f2e92c05b11104b494bc27a\
             93cf3ad7f08088597aef71cdbc5590a2dbd21d941c9ff05d46d95683e0b966d1c56b954fac090e7a35a62f008bd99ab2\
             95f105b01c88e6291fe7e1fefbbeffa9effda657082593e182391d02c90f4427d85241e06355ce6cc29e7540ea90b453\
             a9f810cf007205d7d16806eaf4a8c79527cb8faf11a8a1ffcca7c90dfd6549892412ab90a46bf36801538904559a138c\
             ab72a53319d8655488b43af3da062b5b6c5b8408347307cdffa98877fd2ab4079aa41428c0b6e4a91adf03ac38f2118a\
             cb862e09a1ae30c09b66eafe8180338c6173e6ec90f6e19b6426b66533a333e9a709f730b6167a8191a51ea25149cfd0\
             44374f6cdcb993c3b7e51f1c2fc265ba083b47515078c3b1dfc2a624b999808443e527985d3b25ef5b48a97ac75a4337\
             cad83bd2cd12b66ccfada701a8ef0b605fe77773fa2f92430e156407e4935e87c44f14c5fae06bba5921c8ef7f3304bf\
             508d0e26e20886de9d35b339cd108e989c2735adaf5bee6e0d597b800e2f79c24e3117722cfbaef9fcc320e84f7813d5\
             a2d61ff9f653f167003a21910283a2bd1e02b2e0e5316fbc202b00a0c3efa82eea7d04b0ed97c40012fca49bb7cf25fc\
             64e3d8f7a7fe52a7870d90ba530464a4d5d960278007a1f6fa5adf37d8f6c9b1e654a427947e074ba584b88f8ebe5af1\
             347c9280800c51090b6c75af49f82b3f9c1e79aef598216759e134d111ac636f092830033666d05f039abfb5e6612cd9\
             56c93cf12e641a647fc8e7506c54a4ca225b1175d28109d810a81310fda0304031a025b57785cb1a9e02853f3ee00816\
             aabd5616a25e797b7eb376fa7fb86705082531746a4f887872b3d34bfd888c86a292c864a638666314900400fd3ece71\
             4e82c7cb67aba87322fc4f09c18e0c83b374384d2ab587d0f0981f12c2aa74c1bd94da090b40fbdbe0f31a2d0957fb34\
             a2c7ab72ff8c06288cd30b628788663d2a5860bdc2af4b5ee638da31de14a3fcfba69a29e89f1a1e529cb8579fe114ba\
             24f941ac53f7da3df1931119aa59c5452aaa449b428b366c05b4b49ded3cf2f852848aa459cea63f42ddb51f0b1fd306\
             3aa59491da673eaf9d9b7bfa371d1ba6b21c397d5fffeabf3c1e02813bd40780afebba08e3a4158b02eaa4438de25e44\
             5ff0f3129f82f2f5ae7836eff2419941df09dd95617a97a52fd80051f59937720ef5c2d515e6898c801c827b4a446402\
             3c99ddc4556c3a21c509f9290f721131f381345744d6dabccd32019c9c5dae28010fc406ca2bf3424c07abf0a257bf82\
             b81fd9f96d6612019fa7f048ae862971f99b80cef5ca50cc7aa2bd57d77a63be7bb022c5cfa8c482debad11bf76ee409\
             5e826a06153a32dbe5a8a132e9f1bb71c2e7b6939087f463a1960928a535741cd4a64992eb25a53244b24dc30c6618e8\
             e277506c8ab9b0a715562cbb6d778d326bad9801da9de81354414c402f09bacd51779f3368e0ca6da8232fd439fa7390\
             f37dcdc6346a6081abb94d542658cb452b65b5e10781b03974cc6c3b1f93cca1967399fb4fe5330758a7b418193e3a14\
             5f4e68059c0a048c781cac6771b9285fd26693606d2a94936b52eb0c0d28562034ddf447f39e0829d30626e3799e5944\
             b3c2416f5f6ef253965ba4a533d7929e002505cbfddb2213d6f2ce5f7e2bef10f71ee3a0c757453aa9f12316b2df1ba2\
             65a40f68ae5162976209c6a5a89b45ba7257854e7af842108db41d6073841c9d9777fbc3e561677c6c5e980a67d3eec6\
             51969acf7db21a6167f4c916cecff5fa132e78976297510c2702009559aa0557caeb2f687f30cb0f0f5e5a366e8f7f6d\
             f3f1b46c2bb9b281ff1aff48c229bfc12b38a54d3ce9ecc89aa45015185027274bc2be186b308f70396c526bf866b45f\
             73728795b6ca30b209209dbb29ebed5186f8ae76893234b2ce5b176c9cf6e8375f7a0106a2ad1ffa39484aa0e35dcb51\
             d9ee61e09d13da74792943d5c469fa54c08019f53dc63fe8d94c8a63a7aedc1131dbd6964aa9b8786f3ecde196f846c3\
             abf24ebf6ffd2daf84ac8a568c49b2470bd9cd0b2da6460f4088f26a76c49463a217ad5af5e7ebffe6033c91b8f80162\
             a843a62b5be9da584c43a65afc14b2c13e434e8eac5b8ab10429f407fe9253e6e3ee7e2886d3a6f1a559b58099f028db\
             0b3b240cdfe551266b2dfe02da80b201c33f4a24efbdfd624f2d74fd82f6df022bcf88b19417262e136ee58335f51e1a\
             57377678f254ab93edb8230514659551b133f7f99a09393ab83d799a51ea1b723388621748903623c823bbce51de6c8d\
             09376e506852a2b94fbe08297773b7a88774e481f29e881f845f4b3dc389f9c067f10e0893a2e7180954b5d0afba8314\
             607e574a9fd47e173f01f34f6aac0e048fb8e4fa881827debf845570b6c82178afb6e9d28d89784bec9721ba81a79c5e\
             c56b99d13332ca4a51e5d3181f6aaf60bc75f7070ad3702989172d536378c4939c74da6529ddeda6bdf4a6feb2026319\
             ea8432453b39d39fd0c2ae20d9883ff7e3861a828399e5eeba3240de7341eb383706dba26fa71ab7f75eff0ecca7d8fe\
             d2193f9e3a9a20c626a2ed55f1cbfdd0d17bc7b28611102324551da45f0b91a78732a97111bdb3ffb862b380cb3e0c15\
             025f1a5d4f60307c8b515bee9ad928da22b893fde0002febd91712b78d9b757f44b77d88e5b4601b2f897140a98c16cb\
             19411c40bd51cc80e70011b07c6005fd92057bb0a4421c3ff9514fad8016eceac78e1893980784bf6822ca01f35a6c7f\
             37f2579577de5a31d5b548421035a2b102040ae9df3cefe99af28fff73f1f442945fe222c8eeefd278f7d088f11fb2f7\
             213ef3e79c01de19151f8367b0d229a63d3962c22dc3f0f5eba7eabe5604091e593fd19d98317cf62210e6b8e3db7962\
             b5278dfb3d0c37f3db8b1919f7012afbd867422934dfceca359fcf64b6cc8105c0e1bf8100e2859c68067c66fcb195f1\
             759c8465e03a4475a98dddc2a89ff958f215ca8df29f985dcc23647954775812627804b024741a8b6fb220983f52bfcc\
             7fd1de55c4f869794ca9d9fbc5b327ca261d14686c792ad06b8f855c18e506a61e292c7c417f3077e071294f44861af4\
             0e397e46f8def6ac4d1fd4f56f4aea76f81e81e0a83603a4640d46632578f04084f4a7035bffc4a00ad5b24524948427\
             d44ec734c69ee9b63dda46bd7e00810064f989f371bfc5c053477e92ec417faacbc464a77855390de819c320c018e789\
             679f86a33f4fec39f54089ffacd2cf00fa06d56589e99feb9cc8435ef8ba01dd462b64bc4279b0a02aee901840d5d62c\
             77bbdbc1f52eb4cc5bc91df0f017278659cad483fe46bcd6c7cb943eb5fab4b9b934751f415aa81baf6302ff50786cbf\
             2c4613f58f8f60ecdb1c1b9d4a63305ec86d685dd653cc6cc063135f3398f3e369dfa2e6587d2621914c730dc6687fc2\
             c33697435bd69ece2c6c72b6b1f1384f2ae106ca26f39560b0c4337522f8d83319c5506ce81dc46fa9c8d9edddd7e6c4\
             c196069f9b998714a3806020454797065a508d97b6fae63080a263ae0738e011e478bcbaff3283a75d0666ce4d45120c\
             76e126bde8cb3d7d5005d11f41e41b0a4eae6657540ee7800d7662f377373652c1a59322432ebf4bd011c8e6b3911dc0\
             fade058398d4b209036aeca7160e8e19eb85b15ea515e95432fe2b0617ebebfa1e7901065022d8730338372c83f14afc\
             17e0d19e8c3b39fce556a67047b5413b967099600ba6fabd243d9ade11ceabd86f73bc5926816ab7da0cad4adffcb09e\
             1649fb2ec9ba6fd43af820f6f3130892a1856df7545884919e631a7b7a34b545338df21a604c5ddd6a11b1ab13091af5\
             87277f9441e42c09635c7b2797dae5eca334ff0e0990ba211aafdb8061e8ed1a8ab25560205979339bfbab1b6d788c46\
             9213940124a5a7dd889feebb17c8040e77e99f232177ff373623b3b06e42c1086af34965f765042ad576d72091b0574f\
             ab195d2f80f63adb798b6728d07d545fc07f6b6f18b027d418201a5b5278c39d4c842dc2a28187d66361161f3a1d4bef\
             d22a98544ea4d4d9dbffb008cc9d3c8faba1451b6c268958d3b913ec8903d4c829e6f98f076f3f91a09ae92bda5b8f77\
             4d9f230fe674d6cbb9a0c48d357473c52b8a645c158a2eceb02b9043f243f998464960fdc800538d430e1a363defbd30\
             dddc6fd3f3d6c0ae9ceb0f39021adad3d6017cf3a551a19b5d5833d639cbbabf64925dcd17d09ac33d054e6a9bb0e576\
             e45301f8af22c33ba986a38d99feb4ea56abeae790bf27d8fa2b16688c4b2100e5cdd4eeb6106b4f79ee8c3ea894ef53\
             6edab5bdb1cb44b941b7081a713d2936c54b22895122c50b689cb2d478698f034687a5b581e64c085625107b1bd3eb2c\
             c305a8389735db139036a3fed39ade523224ee5c69ec3b6d83b9bf2c3655410c9a866f57bcc22834e40fa2bd54d0c215\
             5247d05ddf85b3325c64fabf6abf2232f3f8cf95b0319a0382cde21c1f98d27e7929ec59883504691c1f8856c6aa02c7\
             2cc255264f3b3e3ea05893e3efcf52e4bbc06a6c874ef5481e1ed1ef6f3a5c16b1d1ec727d8d3fe49673a77d7e2287ed\
             0ef89022c1b3991834d2b38e20d5b148d6120677bc61dd4be32b1f2067291bd2adf1c421823228b749a8d35ad82310b5\
             930fa699f434dfd2191354e96ae2c1072c8cb1308a45577cacfaac9b33f65e38158a022831475e5f214e66daafd5b2f5\
             440750375b25409637d7e1539400217fed03be1cd7050e7cc30d55cbdb8f548d4d409c55754b3cd4a7da2e3fc4226c77\
             1a416903620035e15cc68397fae8716617a57500783cc15607211d0de76b4247a450b34cf56c33c340159137a243f6c4\
             e815ab076911c7cd8e5f7096c376f6eefd26dbf0ac597bc3acdf11400a4fb578b8e083de59406d804060a5712fe0a252\
             559b8658bbaea56bf30447d791082e33d09f7665c84c8a847e979f52c46fc7f4b6a348388386172f464c2ae3c4ec17df\
             b26ae1f7d459f59dd40adfd3ddebb81ee80bc3a8e7e09eb2974bbfbeea5e8e5e6a7d3d7d8db0ff7a4b30182139ae7a05\
             0b1441524a815cefe76fa7d3d440ceed2b188258f1c3332a5d0e2944d085213e1f93ffb84bba76edd52e40c1da5d8975\
             74e9a75aed9a980acd8d0cc16e321e283082315db643d6d37370f38ace00b76acf9877efad51c150f0b5fb218de95dc8\
             b80ec192c7580eecd854acafeb89c0c8ae99aaccfbd736f214f8b5c42fae281f1fde138ec966047a6572c6e443d549a6\
             7a2bd0b5097da7cc9d8bf8cbd3735f9e39f084342f3af47f4fb449a2a3d47d0dc489388e4d6110a41243c8bde6532faf\
             156ab8c0e30d2fb2b91e171921b90f6648de1f02237408f2b168415fedad9e66ce6b5cb33ac5ece38b5c035654c10d54\
             a2b66b84bafd1a711df386d0f1bb0ebc756bdb2e0eb21cb363d9003ee626e63838321afb6a13d1aa996a6557794fbc8b\
             9ae97d3af94587bdb2d5988ba8b4dc824aff1fad46a9a6f2a5d574956fce89fb64a8f3c2a9313858e061a4100677800e\
             ffd525024a21338dac266b319e671e57e69e0228c3dc5770026acf7a365218110712fd8d25709967d0b69e00a23ac2b0\
             dbdb631f888720fc624b73e48904444b270d6c6018f9324abd8bafe3d9babc764e597e7b9e401f7473158758ba57f380\
             9a77bb5eb111095957015fa7fc9312eaa32e3b7c84dec3e26c1d722253894c1d33ab77eba560a48ad6025961228b92e5\
             37dae20674262b116360be559ce05cb06282328e794ac58634b0a3b0ef26432a730f02b03aaf9f653af0356ae6d93b79\
             b2498866b605f53a8b1cb5148c660299cba52ed7590ff9ebe8e9946e8450a3eac42f16f2c00ed0a1e75cbf349a884fce\
             5fbaba89c300a9c93b487586a7dc964b51509cdb356253852ff2d802d835335e6f3b4b1b9bf43a610a4b541494ff93bf\
             5f9869cde6bf0aaad5567efe61b3148f5c0a863b9bf6e3ba1d839a3f0c29dcadf039b6edc58f68f677e6117fae58e4a5\
             8a613d71ac84f916852e5d4fb58191e7d52c5646599ff09a7b32bf940c69e97bd24fc19e11b2da4780108cb52ae32836\
             7b1de898d3b7f54bff4f2386cc792612e48732ddb80d05bec52afe4febf0e99eb98b0e327bcd02052d79ab16709f727e\
             5f77a51382e2c289506465d5bd23c5aa6593253ef7868a8a9ab4c07a9655222a00bb72b09a4e32dfc905b805589dbaee\
             f3416c93c97239d1284062b4c18b8f0969be737711b8ecd126efb03157b2cbfc688206255f8ce873338369872058cf7a\
             3710b8239a2370f967cb1fb2e66c5592c8820c9006c61a22e10d9b81b2549d46a2969ead44937f75120ceb79aeca80ce\
             041cdbbe9e7111d5befcb7199982065345cd7d663b5aaea340ab02179bd81e98263404b9a7e3141ffdd907f337c02115\
             248752cd63a70309d582a1b3910eaec5efefdaba982ada989be00e3e638426e25e94264a9e0e8701ef9de4827baf000c\
             176a775ea280aa4ad2f0dceba9f2a6ba051c62921ac630674d7c3b4274ac8877cbb730093e2bfec1264111ce76d57e2a\
             df582f0327ccc34874b58aa142d08be3bf52c0271d86123420895ede0fa51cd71d7d13ff9047c98cde4e8f51601e4b84\
             1f217392ad9ba8f358bf4bf058a2970406eac08d55aa0532e56dc2c5796bf46c7ab681a6a923c2dd0a68aa957aaffaa1\
             1308bc548bc53aa1c81db66f79b25b0355c6a05244aa0dc33e4b53904ccd509bdd3c78d46e49321a08c551b7e601295d\
             f8f763cb4ad7de8cdd2b9dbde0436719d59d71a21054fab891ea2a2237ebeedc0833d3b3e726384edf88286902c40532\
             e888a2d5dd3191ccaa4af18326be150694a081e5764fa278724ed4a120a503836e51e04cf2837d8a194a028a9eab9db4\
             2a490e06487384c9d595595bbcaa16add4902fc4723f50a3a6ca59fa18780dccaa914b3652d8149d15538b4227245472\
             441b02ac784745768060de5c11991c61d7807f111d5ac8d73da70cb7b5d00485276a9434d9e44d29a268911aaf514522\
             0b41122ba97cddd84fdb91c571e7df117b8eae56bb27a3e9ac298dfa3318b2ce6d7e9f95e17f13d6c04f5b7ccef9522f\
             63c5326220b2a0aad7f4abbd529d28ab585fbfc41742d7adf0cf085bd17add57e6df975cc30b2d2c42b7d7b82d04a5c9\
             ab2df6ab51390ffb21f66d4ddee262afadd8c1f767d4d94f0b10fd263df8a35e1ce73e34298a30a7d6ff309c5a393c40\
             de15b1d162c2b1ea62203681e0e5fa5292c7861b2341c45eaa23b918be3b6f4291de0c374b3626a3036275ede9dacb8f\
             17efd7c97bce1feb4dfc088866b44cd70d205bab7512416a9102e9422c115bb2ac1fcc0b127d62ed8a824a8ca1b7a6ec\
             a4a1fe448c77aee4faea46ddbba96d9789a9400ca1f1790c65e82324f73c55d7dfa5eb9aa8e55bed2b6dfd8c89c7d5ad\
             a641c9f68f8592903ba72ae865da52f777d0a4915614d852a0d0913382b5b48fd088fe4934cca8833642ae8138fcbdbc\
             a17f413e56a636a58afdc33708c9d3ea2962e52297f377b80efa378cba635064089afd559fdef1b5ab953dab85b77e6e\
             cf68e58860c5569ed4e11c475be13bc8a848ef8637a2530fea45e8ee924c9a2b42936ef52bf8adf72134f8f3eddcfb93\
             83cff71fe2c0013d5e11810dbc78d3cdd409245774bf979f68d14739dfb1206b53a56665196e3566eae2b4c39815c868\
             6ed7a50d484e38ea34108e1726ec2013d4192285e042a47a176ca6ada9ccaff6e96e2600c5f585762a46a7bee94cd291\
             8f5e8f480bb1d695d86a03cdc56330dcce7764f97daf7164612e37b7d77de41a396b10daa87e6d4d67a4af3759e6a562\
             fe7e3bce670bfc9f3837c679ff3d3987a25db36ac52e5a0945cc047a4faa9b28a837f510048778ecd6d5090288b3196c\
             1effe1f50e4d99f38f4055dff8d275413a4e2c19a958878352c2b85e22ea499aabfd4dc4ebd676d5509e698c0acaaf8e\
             332bedd14dc5696cc4cdcc8523e992f9cc60aaa761a86c27207ade13c44c511e47db48b4e316fa56a5ae6d58fe97502f\
             b22ed85be9f7697bdfd1e7481b0f1a3226ca1c73194427a5bb939fca244cf808c3fa22df7e77e9644e61f80bbbb6ea44\
             7992a5f79f132ad40e56d3d25cb8ddd8dca2fe065394c4cbc1bb86431935fb8f66fb820124d5abc10176734342ab20d4\
             a41241b745513ffc94c9cc4ad52b4b829a157d7c8c81ea1d5a4457939059948e065b6f64b895a5e4770f830ef3050658\
             09049cd739262f1376f94deb35b70b18d7c04fdb84558636edb7a3bc956017a72f8c4b9c716c4e5536f3b93ecc929b1b\
             cb186f0aac36e555a00e44887c66073038197dd1d3d73047cafb1169aa2745313f1f229c914fc0ad5e1e73a2b3195148\
             5d646611c4db3beeb4005a6de3437414b0f8a1cdaf64949e2b41ad0ec6e5472468f5ad1e3bf529e1edd20025eeecef0b\
             2d3987fb3db93e0a82a207edbc28c1b5254859d24fa14e38f3df87ee6e1740322f6937879a6d6dc2c8fcc08a2d1cc075\
             c06f3c2f1f1e7564c12269aa7c0607432c340a7d9e8124627779f0c4060f5b5c8a04f4765a6d6739e6d508bfd0e43bb9\
             c1c69988794a79b5e5979c87575c3ac9e2398fb8bfc80ac6bd84c7173609fa1300482040d93d9519bcb43e653325bdae\
             ec3fc9caf83c01e20772c60f63356a23fcd0ad150a2609ab0387f4c1aa113983932a4da02df7e3ad5d2b67e2e899a0b1\
             76e9766ca950d93ae0f6c1dcea5f0d6e55aea904e6e00d733c5666e361eaa1c563de20b87f8e323c2f34813b6a2004c3\
             0fc8cc8a5f049097a2f6fbdc8d086e61312cfcee231d36223908087677b0693833f3eccf4cd3f260cd44d5b6b16b4537\
             abf9ebd35837b7fb97185d52645ddb78acac48d340195b1c005526db18ce3b975b6dd4532816e47bc62ce8a7f0f2b5f4\
             1fee84ec03a0a57f4c13e93db27e2880c04e451a51fa6631984b74e599a730ea92d959404efbe5a088264e8e477dc63a\
             12824e20dd48cd792fd3e7e8412da69aa231ba79b93a020e6f22631e7495058033b5133f41d21b4d52137b510a54c2eb\
             45c2244cfefaf025c290f3f9951f8daa24f23d0318ec5cc77eb873a960c49e621bf83e01402a7270b82c2c9e9a9a05c5\
             bddb16a8b7dde383c36576716ba952ee2e8d939be54a863a9bf4e1fc70202df429de53b2b2cdf0ae93234cc7640e659a\
             289cbfc78e2fa4108ec876a78c77a7102ddb7fd0437a8aee5422ca8a5b1503119b6e7317305ad0a9ae972c3dbc45d05e\
             ada7dc681f01089cb3f0215fd853a7bb0633ed5dd655b70a449fd14c163edf7681a3dd03d0094489cb496de86414487f\
             e3437b9bbb52028baaad72648ad4e520d9857421d38bff81cea9afd8e062b7b7035b21fc5eb8fcf5c4b08ecf8b13327a\
             224d4b1bcc4cdb0540da53b848c73c397dfd78bc4e086e24a1406dae903f5b2261f7a01c9c34b47c177005cddc9e3631\
             5f1f0ee6369371c26ae75080c8f27545a730567ef99b598ce4ae4fc0cbd80bf2c135a105840253b87599b8f5c1992a67\
             30d0a6e891f767002593e9894be75c22dd121af259a5154d19e775609c7e1fcd379ba827fbe905db27faab99506c9feb\
             fa5474e1676102d9f7a1d196d38efbd12d3af5ebd2567652f381545c7f0cefeb7e48ef97504c072d877a7d723bf85c7b\
             572aa640571e34e9ebc42e6e8e895374140d8e300a52fbd37a4c09063f621721f0e3e5d28103f80c79f9ea4b20827a90\
             81bcd552194d5e3dfd2744502bade3d6104ef1081ad531e960a87d698ff9fbbe9d34b422392870e1ec00a8b2ed59b5f6\
             637a451c4117c535df0e7a8a2f4a3da6da31a9e0a34650566a3320e00b10f7db",
            signature: "2061e52770577da09b814632158a32e4d1a27dc522489f2af0c7695f5fa7f1ba8e1cee40aa0bf96238d5bb3b2053d92f\
             8d045fefd2eeb4ac68416b3b3215cafcf0959daf02e0bc6423fdb5a952bf8bcced12805ee5a86eb32763a70e6dadcbbb\
             13655908495a948714131736bef0fd67aeef4c2a641fcafed3bc24faff2b3b485997dd7c8c01ae67397de2d208d5ea8d\
             275764ff1a0b85b91741ce49cac50a15a49989bceed584e5fc507dd7b24f1fb97ce30e410c514a73998f10981faa370a\
             836ddd7604c4b5aad4b183ac73f77f48e4a908e037739a08f680c79620f3b2ca6024e4fe671ff36ec184770956d03b5e\
             51e5d890b39f9800cb1d0dc4b7c982e6e56240f2846f64df7159c8b3860cf5e0501ca1bcf9d38cb7d30e66090054a4d3\
             61a079d880fdb00418a8e7fd2193362288f509afe1d77d89573672271e99c944a602b1ceec911e9a944131ad3f4054b5\
             32ef955e4534c75a601764a02aa101e1fca05f29335bdf6fdaa203d558fd15f0e51c690ca0cf8675902afa1046596954\
             aac9642470d6115dc07087d1023499e40f5ca31caf33147f0d47d616bff14a9e9bf25f5fa6bcab9790f34d9f5ef6f4c7\
             a98ab61e4ed424d44be575dafee6af5051495ea0ec9aa2750929573da5efef3cfa4fde9078eb5de748bd33db0f66ac4b\
             18a1c6693f0148cf61ee1e5758a2709b8b033d6b0911ad0f2b370047a47f2b93d6e1c24e7a31da6c053ce24f15448e2e\
             c2e996eae468d4f9f822c5ffdb9d751b029b89a87f0f9aff0d517db6bb437ccc3dd47e194339e5d1f7dc26781c5acaa5\
             aa02eafaad166323f5b4d5a4913d8b554f2208c17e5486642c6a2a37f0c422666d5df7a87f2a729c5c11b08d504c15f7\
             16590b7d3670d46e7e596fcf740a9fb54161bb6cbf30746e3c0c07c9f014be1dcedbd6ab237177f66ec8b2ce71fd3a7d\
             fd036286218c73cb1c8bcda9ab4a13f4d8914babac252a85e3611d51e5903008871b8a0e68a64ec3c5f50bf4fd76b6ab\
             8fe91bcce84d074776e580651a2d3d13074c43a14e4712a1849d508d6ddf800fdb7356349217685b19005cadcc4ba5f4\
             8b88d5154ac858b50f3daee8c9f077cd1f8d0aaea50198c9b6ae67ace6a866e86baa74debbe001d40360d00c77074573\
             ea5cfa7ab0334844c1095e64e1e70eb114ac141810f42c462b16a8953555716cde858e49fbaa60891ccba7d63f0ffdbc\
             fd758d2533baaef5282ac726492b7cdfe3afbaa57e8a13fcb7bb1f4d530f2a552db5c8261ff02bcfc2ac081c688fda44\
             0a2f8cfda2e77278012054cc83cde67b24094e7db87d97e15ce43294e6254ec74a0d6840835ead45894ba09c251ba076\
             92adf14b9ae1568780ca60cf15bd1d50bc03d238c7f313f5ab0de8d2703a3be9b9375f2d416ba5dbb90db8f2b6c20f17\
             c21fbdbf14eef6820f6a2b14ca59d711745e7e7e8b51b1655e62cefdcc797082f69bafc63f4a5648e4443867491e2aa5\
             2b8b88e1ee7153d62213dbb946c26525acb61eeabe97dec4a0714ac8cf57104d8987008b2c74a822722289e07fc93fb0\
             568dd9f659aa08717ef665136afd393edc85ba408a13ee7cb0d68911be4ba2ae5b475ef4013c27ddf72ccc749a61d0c6\
             1c9afab5efdfa6227317c2a4c07d8c4075d08671aadb36e5a69136ac613cb0a55d81554f843c1651d542b150b4ca5b21\
             d307e17621f3edf571b6bca8cc7af4d2cf5d9e6e3a6d584123e050135e4c8ddc728075c09e4c9b049e331cc6757e716f\
             fbccd822151f8e158185e2a80d2429aa770c13c487397331d0458a099eccf21ee829408cc3464d0efdcebca181e8111e\
             1bc4233fad1b23cb3679ee51f513212b200b205ca5242a870abdb2168c9d4c618f62610f0106ee708df975009bb21055\
             1554866c533df87803bf99622f48754315481265e3290d0fda11d4235a959fa01965554cb687ba39568fe4d0cfd1e2a0\
             f592d398f585feee029f80061fb66d926aad109d6c8fe9a3e3f562c99108063bf06e1813e209e8dcf0551333c4a2b008\
             dc34f1c1585a9cc039bb42b0e11d8dc2069e8f786ff133610df262e206f8826adc5334573fa5928f6fbc00b6f670a503\
             d1924af2b24c2d202583cfc0cefec805ad7525f8e89c3224f935d9e4de7247574ac8c474a93f4273251c789bb085a898\
             4ed14dba1794e77224bfb4e1dcf137f8207aca2bbe8cdbc88979d279d64a8c600e779b195a80ddea2153c69b1ff56161\
             18e1d0a07a053ad466d63823ea18d4deb0156a98d4885686f4f04d16547c7bf6b82c298b3dec9e88813f70fc1c25c58f\
             40d087953a7e869b2978098d12bc04e4bdb0a883bef7b7abdbcd1a0d40574876659bd0f100b73d1addeb8632cc45d1f0\
             56e18bbc00a275c1a72908d70eb52186136a5ccd7a88411d9790f53c6d347ecee9e6ecb5ea0430ee45a2788f28e83e02\
             a95e7806dffd2df2da8ddf8e3bf49b2fe0f7333ce1a7f44a622c81eebd4ecde126fd73d8f2cc42e95985de3f1d2a67a3\
             e8e55cdc657d63b1d004a34cd1be4b9a8ec2a6cea8f7840b0014aaf0249866b04e72869afa7a28961b320363ac22f24f\
             b9a24bc194a37e87e968b81d34da8dc342102c159df43517b80353214103083e73cd4d5d7cbacfc95cf876f5455b40a5\
             3c6498ebaf50cbb259551bac8549725e3e5104226567968a96ff631933bcf06cb62d37b984b1b5ee0e9bdfe450219c42\
             6000623f3ce9063c3eb5a3cd844c2fceda1792d96da4fa7d6aea0ae23ea3ffb7c17436d4755b93fb283ceec9d5d6be87\
             f455255aac23f0e5e1356e4b8926987a16a51507f19a4dbc90a1ba4a7e670a8d24c454fce303563715a0ad7287b26c3f\
             0de6f8a17dcabec4e86c6030760e944713b13f8cef8879db353301c8769755462170386504e732184847991a90e21831\
             e7aa31ff345aebbff31da1523bc609a594f85a324927cec83a955b94aee21532f59ef77d0ff45797845fa4431381a882\
             4417d8a745c1f8141903c3e9b49f3e2c4551556b3e67089f329ec5b929317f8389d80b4132f93bd498b0656e3f10068b\
             906e064883031e611a87b2d6a7e40308e6fe955755610f158182be8bc42b5c594126b6e29ad00c324a0deea84fc5de20\
             c07774ce81e05eeb4d2a28a6e08991af867d7d51c8c31f54defa08e63c137662addab4109b17699991b632658cdac1a9\
             a1018fc35b69acbc29568c1dcb009e6fccc697ca43ee877898b102db171fc9a16b5b3fb690ad65aa7f9ce8959f0f1875\
             a29e10e38107b43090fa3311bf254c323a59a8c46a13e0f8c0d9285d98b2cdb6ba761b3af5c5f27604b44c81388f9a94\
             036ea4c21161f5753872c220ea1a28c6603872b82f6c0164119a1b5f9672f3a8e27db56aa93fa3457582e619baa2646d\
             79e0430232fc181679538c71ef88c1fc03f0a5a3e5d7a3fdebcf06397493a130f813ae573efb1b7b3128f2dfd3e8caef\
             4af1383ad2a98c9b4d5e0058e13c0aeaddab707baa76302bc93b125269349a9e387ba45b3472ced03498773016c3568c\
             7ebf1c312c12ddc6aee7aa618e2fb8974a4916731747736e326072dc3df745675d91e599818bcbe7f9ce8eeb384fd71c\
             f0a19cfec9d3f351f8aee1f54bf6b6b27880f8d2cdbf1a30b07730f874e42a46287dcc4ec0d831c85c9e702afff6fbf6\
             41ca5c154f0ba308db0979c93c602a8d7d7a42af402d8c2f16bd0f15839847387c6f77abddee64fdaad3934d5ba07bc0\
             97bee7be649055a9d89b2229f25adaaee12fb153cec38c3cf57bab3b06832da3ab6fac33c1bf8abc3804effe800266e5\
             d83159573a5d0af69a23e9598a3d886c95f6b92f98c8e2d4136f75a222548090c644aafd70ffcfedcfd8bd3c9143cc74\
             a89d76e2c0e879017282c7cea5f45d026648fa500c0974c3800f60a2d7be71b61a12a2d90aeb73684054191194c89abc\
             0964a6395afcd4fde25ce77e4159a658e6168190ae948e952974d68e0d9e7a36d0d7b3a505483406fb9865f512213a1c\
             4fd97d3911410ddc93323b9b1c4f887302e79b995c57159f237b489b11fce8a0612a77acbe88d960a80a57570150822f\
             f733bc18e91c691bc7cd6c0b43a5e9c9da4fe39da3269e86c93c9d47340c9a5425f451cff10204f1a5f5773a73ccdf50\
             5a7d0a1cadd157d4a233d1235a42388984a078c70b4c95b21443d967084bd1ca2d9fd37e1295e8decee55f512dce0a0f\
             cc6094932375d08eb291801d5f76803d2df9e317cfdcd82ec3f6cd9dba5294b14261e6ab157fe254191853fa0b7a4034\
             57e035ec9e8cfb0993239ce996bae9e0ecc8093055d1facba0b2bcab5f27abf56a8a0426677362ea7392a3a44b4fc0d8\
             63dc6f181bc39b6369d14ca633b1f39a6e906ed960c7357f22cdf7269c4f05b538e3d8c69e02339333270c37469cfc3d\
             694c80150a3770e049a1707c82cb19500073991f2a4416253012d51f709f43c6242a0ca74caf1fa0ed6a301d2a482a3f\
             4a834613436af7a34cae547d46327fd7d7b7559c71234e69da04811ac5f40ef5eae66fe441c22051d49f78f76df05f00\
             9a7a9803ce09966912f4157e2c12af746f1effa98f66af5c456a141b4fda61891a2861899bb6cfe51a2acf0191eb127e\
             969ba8bfc7def509142e495d7184aeb8fc7280abb4b50000000000000000000000000000000000080b0e172126",
        },
        MlDsaSig {
            tc_id: 216,
            pk: "5ab36e1499460dab17277c31440dc055346998bf5679b439c901112aeb55e37145b369beadd5996de9e1ed0882b1eebc\
             94d361cdd908e99fafd092eb9d7adfd660697fd96fe01fcbc3a4354330d7ee02adad33473b44db972b9795202b23dc60\
             76ba487f21ac3a35fde00e3bd383f1e65b66377fc9dd3834d791617482e94eeeae9897a00a7445760f56aba49ba142c3\
             17c26fc8b623a8f2ef1cdacfc11341d7f859a2c3a038fbb78317fc23f8473ad4cbfeafdc92c3dfa25e7d732dbf65efac\
             56b8f81efb8eb550fc483c92cb6e4da95e7ebc2795e6d632b10e0d249632a6170af1eb90780f748966703e5c54284ae0\
             0d06c3633cfb1c9c39975babc18b1fb77201eebb20a7c8a310524514dbb51828a220df871a2453c80589e98ff8b93903\
             3cc4a68a23ff5663f46004e6de0203015684d0bcb98f72622e10d20685a8ff402b7bcc1c71187d7d53aeebaa6555f86a\
             b67460157654c554c103a160a9b09bf4d961f632d00a3be2d2b97433978690394eeb0b6ef1d68a6433fcdbc146491eb3\
             7c9fac64c7fd360924279b62c373e5f7ad511095b91a2dcbb02d5d03656928aa90acde6c245678dd2fd07284cabb3a6f\
             06ab23bc7a21c742347c1ed266853bc0b077aa02cd8f9d0d6fd194990bcab17c4246ce7c4f08e33e2978d5c718049525\
             545189a1bd2f35863b55d1da2e791379f1b94b70d67110c0d831cf1e6550f692d7b64b1790ed988e3dcdee14e145b77a\
             3234b21e8fd62a3acbbfc6b983463d4ffb7bca23547b1ffd8354c7eddca172be86d361c752920fc207d34b0372743281\
             b74c1139f6dba0d6a9db385c34ed2c9b264d8083959917a55c7e463bc019d32d8053209c9079eee0d9b8c25994b58702\
             d415fc986c9d414dbc8f1fb5e2c673ceafb75f237e67826032bda54297d393e479e1112a8bc316ee1877a614bb217997\
             fceeda0628b0b2fa012686be554dd76f0c84e0ef9d39362d9f091b58c5169e3f51af50da06366d68dfb9a8a41247a4ce\
             15bcca22fb333bdfed7fcec87ffb8b4e68f4abd435845abf4289d5a5eef495b6eb5371c7846a49cd3299678040216510\
             7fbf83f1f8f83ff8c38eae6d61c82c6f6614e8a7338e2b11919757692099dd70ac0763fb9b51477506f4e11b9f9d4cd0\
             f060717b5a14390a733a862fdbae6b3f54fe599e5145b966ffd787fa2d7f0480e304c06dd8e19599e336528caeb3349d\
             7826136fb1ee8cf98c3c220a287805ed0d9c7984d5d557758447c8fe34643d339944c3f995643a3dae5e83887ec877fb\
             11851ae5e6ca7dfb5484f418bb3cba3dcf35c09847c72d1dc9e8031b2adb2285f6cbcedcc0b931605e486d8ee3a427fe\
             6060eb8c4e178af9dd68d2b818d171eef54660994f7990596c0f0c5d3985eb12417f30748f081beb4224e0a1bc2d9613\
             2a0390dfb092bc574155bebce479192bc8050fe0602486695191d81cefe9ff9e1ec680e67849c088d41408cd7451060a\
             088e8a6ba66cf96ec1d30d4075f901a8df3a3c41e9ac24ee5680c17eee52ae0d41f4308e764fc13016a9df9a265c7f1c\
             870214c2572eeecbf069d96f989e841a5a15ba6328ed027babcbaf53c652331b7dc53429a4f41ce6ef3b910c98119d32\
             ba31d59d1354c44b3c9a68acba7f34892865c2da05c74c1e50728aa5f1cd3c4cdaa4b024724dad6af47ed307d155aa2f\
             cac0287c018b8bc85e395835585a190c81e3b1fa629aa020d64690c5ec2318dd738c38e6df9c86beffd7896c941dffa8\
             26d34224145ba74751cd1e6956b91605f0bac42b33b680d2babbc524375e6171f65e35056e8bf58489e41e537d686597\
             d1f0b17497d8676c9dd3bfacb0aaa4d9ad9d90729af69bad7c83791e1305609af3dcbf557d92a6731cd9d8a3ddb0e641\
             28d587557234ec6b7ca8e867cb8220a223d01d0ee972776f3569fdb1e58b8ed6e31249817a52f3170656d98e4ea26820\
             3803b0697b7203722d91ce832a40cb1a090cdc3c96630dfd4d5b68b03eaa937b38faddb9234e8c7597418a79fc70dd30\
             1e737121e4bf79e416b425ea6e5d0a74d7f8311d4cb8c7fa5760c4730efc41c31e4db10f94385d6348f06bf8a95f04dd\
             93d6b65f4a225b101f4eb49af7120fd9cd273686e37f9629b4ead7802f556880a36d2d5edbdcb036380a7e6e3b59e791\
             9823f144bcd8b088c1906a34d3063e69b6ef63855921999421afc8a0f5dbadcadc9cf66d041e8f4db4dd306f95b1fa34\
             dc9fe972168402cb498cd2c77f89ef931a07a7d4911f7a31219d9d1204e9da2df965f2d4fa5e8b007bad0ba748873d4e\
             9e7233a41de90899fa28a2420a10760719104f2af81dacf106a2e540cd37710a5601cdbb4967599ad93be31afc29f5c0\
             a4859bc9716cfd4cd1e710c8228f7753c2c542b6ca125b8fceea9a8a987e58a06096a2d355168f29f17ee16285caaf37\
             e3659d17b14fa6faaf2df66eec66e05d16e773360c19d957f1a781576fbe0a6c787e08ce511a4272c4827ddf0a16b59f\
             d1b5ebecfacb3e22d37fa5fa56e77d35822a8e7b11ae7d5388a5946326e393a04ad794488601776e0c1936145f3dc811\
             c684dc226b8a75bdf210f3c83f42546121a2ee49140e2c36def8e24d33737d5b01ff68991d22c7b6b3f085a8466f38dd\
             296d2fa84088b8cd17fe5964bdb105eac1436e3219931e81f873251242f401f5b7aa8125668233dcebc309ddc29b73bf\
             48ea2a12543652305be3bbf46fd351509c49802715b6688db1cd6a53728037a4",
            message: "920ed397d4d8cc25481f3d324009bb6cd9feb9f94f2d6f14655638ffa7dbad95ffe64bef177a5b75359417bd9febbe8d\
             8366708ce1ae52ddfdeb12304e02ba60dcdd1dff973fd3498a9aa7a10b6c0078868601613b8a731de5e22eebc4e610dd\
             36232a9f63451484c8ac1654cb37c02bd6d6165fdff084077d8044acc49bf6a0ef73d9cc97d64e9ce6e052bf91f09d2a\
             8ef287ba86ff5110efc276b2e1fa651a6ca74569624f1e5e919c5e300174c9f33326a729b6624834dc3c1cb634e03944\
             1154335be4d150351c3d1dce332e4c0c78ab921b3f776ea002293ab2853a9baf6b925f4e80429ec641e6a125034b5d17\
             efa1f1d08fa5d771a2b39d8397921cbd62201a91453cad697b22c016e81154a0acd145a2f8fed08523a48a2dac1ae802\
             fd893657eb0ae93443e9cf5f2bfa152de1499d7f951a479978059b2f70f1534b82eb11fe3e35ea4a51dbbc4097488bbe\
             d3fb1fff656aee0e88748dd5543a0f002a66a8b6b9e928014903ea8328d00d05dbef6980f27eb22aa2cae86736334e3c\
             5ee510a54e66ae3d7c117e179590d970dbc409a2766ee53b0cf61d6727a412c71b80140240e9cae492e0efd7b9be21bf\
             320f0b49fb6abc73e7508f184b411e6be937d6b64f0b7fe70d040d32e2cd8b9b0e68a94510fcfff236640ec0d1d7e99f\
             13d1a5455a3027db551c45fa5cf2d7f51160f034e1323d8f7c30e777e7d50453ff6925bac39dfcff9d8a784d8b7b231e\
             dcf595d52be809398b68e2562fc466cd6ad1767f11b4eba6361c1dea6bc9f85e87163c4da26e2575e9376eae43331bba\
             74e41683daab3418433844505ef270fa17258a4a7fdab18054502a45cd2ede7a6c7bdcdcc30f841161bc2854ee79c513\
             7d3bdd22ae883651c0d9935ebc96d56b8c33ca2306ed35f54838d3b62c725ae8afe7dca29a6bae379fe2caf805cc4934\
             7255c7496274fb59dd788d5cbfd5348bd2982b06cb48c0547c2c980147136dd594938c61fe2d80daeea8ea5bbf2a6437\
             e4120c72a2dec7feb6c576e34fe901c8d34d86240d199ddf0bcde593477719f30fe7eb49dc41221bb7997a9b0c8ca8d3\
             3b31d2d91e741fd05be8b4c5f97f983061836ff7bd3dfaa626a5982ce9f9c8bf92de12dfa87a767fdea986d6e749c050\
             c66494d44c3ab24e117a5395f4fe79e1bf9b0eb9cf5f95f658bc316f8b0b207a3a8d2b63da875ba098e23e3d71cf3b10\
             1811e108c3faddf1c76f5ca7db4a304fb7c564300e92f3a1a3d1b3ad505c66b4630db9bc5bd83f9ebd39f5ce28fe724c\
             8f8f99d7849f1ed2cd3de102989a2bbd3e85a64d96c0df519ce8cf2d64c1de84d34c477c19a43a095b4f7c3a2adb868c\
             675a9007834698d70bb37cbea979224a770bde1f279217ce8c29942f98ea0418a679a6870b5690b26c6f0e3173c733ef\
             7f14252ff42d050de29c5d13f805461ae4ef85dc68a15f9c3ad34d2da0f96aea3c8c34df05e9082c550f296af2ca85ba\
             9cae2bddb1707cb3f32a18fc5a5b1c0b0750de7ebfe3c90fcd374ce55552c653d0a788bd04713a1b0bf4c2cef9d563a2\
             f47ebdb91e5561256b304fec8b87a8b6f812d2befe1189c409fcd3210835401d23d86cfd09bf65a26587ce8e364318df\
             15cb0339f2877a617cc77884f8c7ac3abe8630a366be81fc4cc5457972058c8281cce8b56ffea3537bd2bb8bbbb167ab\
             004194c2c599abfe80733895dbf634385234365f72ad7b5249f63d11bc026f845b216fa63ddeb6b72c5b62eb51ec4ab8\
             e4788d2b36c2cd70e7d2a17c51d75ae35e898225af18b0df5f6c22401d6324ea728ee816e5ce0ddd471fbfeebe16244f\
             9b804f75d7bc47cd8f73fa43a0148fa7c05f927526f563aeff59e2f6e5405259b0c354ad0ae54a04030f0c497c0d3729\
             15a52e116fd412f02d5a5b21c14adc9bbc7750d73ea54cef71024a38e591085a7ba341c2db0fd0019b925257d5bb074d\
             47f2db8567b2cd57670a2140d5ad837fb130ddc898248d97fcb88a0bfcb4fa92431fe66811b98b586bdae769a7cdba25\
             9e4e0bcf4d4a6d2e5aec3ff30a39314e74c90e8fd221cebc002a120652e8843bac94442e026e5b51afb989e0768c827e\
             e03a522c0866b9e27c0e3ea89c1de7e4ccb57f8db71288c6f517f68c034bcb3fd3af233acd50f12c21fc408b355068a5\
             458d2b41cb562d04741f7cfa92dbdfbd9973f905c32d72f8f74be3e516fde571118868e30864b2ccb4e6684048e97705\
             e256881bc17a2eae7034a67e23e2ebdc5fc5e30ae1c113228ebb7ff1dce32c9ec907c801da4536f49249a41c87418733\
             d844237587410caa586360f86ec1f815512ebfab15c421833a6a4bee6c6c86efb3eeb3d4f97ecc89b2ddc5fbc9705fde\
             3810880d303b218c181df354cabf871e5e2969ce9f3026da3cf0e6375039a02dbf15adf38ae4191cbc53041f58097a99\
             141535699e1ef3e60413f24a58dedf1d3c4b5d44589c34949308ec93162aed2e3b3f152f57dd791c5a0690be79ad25a9\
             e61b4a4537b5d82a458c47183b4eec95d16bf77d87c639869195fa30c67921da2027e102bfbe9a32bc9df690640bb154\
             3657379a8745d1c81e0a04d2e794c73b1dab23eda222ec09067fc3598f57909567e1c58eb53e8644148425abc7a0b180\
             f685e7f5a01936fce5edd90e89e64d44b5cc739915bec005a0c306d81ed1f6df8d4d3fdc9b4661db7ada4c764426081b\
             5d447dbe803fcd3661833b02f4b1d631631d359202aa88328af3d8e2f42288dcc6fb89f5025afcc2df42872479ecce53\
             bd4099cd02ce17e73a7f187c01ad78e9a7b5eec3049372fcea38601a91c3b2a370da906d0c3091b4bf8e897456e6fa3f\
             5c19e72c8f3e2d4daea5fd9482d775c3f46f63fcecd5028fe17d0231e120a1e7cce2f10686a612d3d67d420ebf7331c1\
             bf6a94f8cec7224d206ed2a21203caf0b3bd07b498342d896832c30f2222fdb41f1435ab1055a5d396893bb42f7b0599\
             8c6431bd2751d5f415a54e749bb8d65b22021d179d5655e47a2e056d29432eb6a65ec7f97d1fb63d2bd202663a20029c\
             f764f85e31acf8545eaedcdd8e01c6170c88959d54cec01a604fc495aab393570c946ef05b3b3f3bfc1cc73e3a178cf0\
             67ac1ace780f306654539970e8f47026ed17f41bf12ec426560dac8534156efabfac891bd9806f01af601e20619549a8\
             a2fc53a8114b9cf0c8f44fe710e0c67374fb06319d132240bf06678e1f8d1aa5f5bd66fb88e2f5c6de262ffcc12e0816\
             ee3dad7c3b3e6608f7dc8b07127b17f7f0101618f7b4b122774270031b191c4b0e790936840bb60bd55daf3a046d084e\
             294a16dd79168ff8743288f14a3b65a7168f751aca414207ee902e86ad26540033ba3f81c132da8393d378c612a49c04\
             e35c60596d3c0968ccd710549923ccecf99a96e63f490477e9e256d3aa0edefee5c7a979134d9bcaa07ecac5aac465e9\
             a722d5f1a381cc8dd673a70806aae7979dba18ff0c730ece8c39670cd7daeb90eb5c7d91a57bb9fec7b6ec221c270308\
             8ba19f9554514625b37b6d5d7f9344c295c33009b272383d506d505299c24af996e79f1b9d81531b663004deb8096b17\
             0986e4672199ef2abd3d16a86dac56b8592666eaab4e497a2a51a3a29df67a6615bdfeef7ba41ffdd24a69e6fb7e6d09\
             d3a2d5337080d50876600b4197c17527241227dab5295b2e59d76b8056bfda36923a64131d9e783c98b419d6d379d43d\
             cbc0a6d6b5004437b5f3d1e9bc6ebc8f36deba6bff41e7cae9dcdafa6110212bc027ef134e11144da663540568621873\
             ae7ae7f5a59564bad3f5e8c94deb9b0af83a4bd4e16b0a1ed3600163fbbbbfd1a528e5fc1a1a660cfcd07f5930e7ada8\
             c750c12733bd9b9476020f0ba1618b534e19b0fb93625ab9627f927dff8021e26ba2c5870e0deb5623785e75d4c88b8e\
             4e7ed952ca184b8cd7d0341f13bf0dd577e4d32cefdad2276b7b14deef318a979ea63d0c5699c73fcfb561e03557d138\
             574da75e5f2a348b8b30eb91581a4139b06a76e5f864231f42335624655d58570d6cf9306b3a01158b357179b80a7226\
             d9c73e8daedea4507e1299613fc0c1fca9a49bca401b00eff725c49db5a231dc9496e5275a02fba836394c6c2af83a50\
             d2261ceae606bcbeef988faa87db8acb7ec3597a109423c68e82d1fddaf08886cf4b783f6db09fee10f6bc7dc8892a07\
             36265cb27f099c4b65899a86f4ccb5ab165733b2e3c1f1da75d984ade0894f2808c5ca8f9c9edd03fd5b005f8a15c794\
             a39c0617b232cd01b5f8505d0d9aa766e8259bbc6158481d6fe6e5b0c2a7d3c636914787ef384da4822be7e4bc4ce9e3\
             0cc3065edcfd25ea24f64f00d74f2c9ddd0daaf67db32aef8378ba87436c14bee6bc00ef45b0d3e087c43b1927d11c3c\
             b32b51d00bcf9f0db24b0eb0deadaf5f1076d1f38cdfc82fddb6c61cc1dc3a92289934f2cc2435b7b08dcf0edfb1974d\
             e1fcf6616344d5e71d1df541874f9a8159ee6176fb905b07d8353862c7e64cd3f74d6c5c5e94818a0f2f83272c0eede8\
             ef96f42c858e9b4d5954f6e4cfe417a145214f74388a184e1be70496deb45bcf1a0747df8892f547c2a4e676e39c7113\
             c662dc87dd07f036757dbf7ad55df23fcad98140f8dd0422a92d7b28c08eccdb61daf3d0f426a89c483fbd8cb59e743d\
             cca704af78d3eeb933d1ae85a33976330a75194a9bbfe7cf88f914e79737f458b31f6137c1d6507b248e8fdcf631955c\
             2654c4aaf6275d2edec685c84e1248c2ada4b739959d88ce1f1071f8edc6950dc262fadffaa2fc6a58f7d449a46f8b96\
             867da28b3e58bf2134be4cf391b525b30f2938d9a9cf405030f69154bebc8c6b0403ad1379a537fa3ca3ae3af22d60e9\
             4c920630db8f9a34901b307652fbc4e3f83e21f29f7145165a13694303d16b616ce45082a085aa25f54c85bfbb920ea6\
             e6b20b5e8fcdce9c15a7b585b58f8116daec0961a1ab96049db0bf6d0e5bbd10991fd384e7464d7645f12e368947d6b4\
             b9931a78a3a8c5ba36f2a5dc43138e43dd3fcd8c443aa9f464ac096665cdf6428d02819c9e9b4f67ab18bf903bb2224f\
             589303808a63b73a30b813f20f70d2f683e08e6563e7d6e1bf57effc75daad779f19d737c379231c67e484757c0fbf9b\
             14346ae929c16930cbc7f9ad801f1fb42e9002ce0be62aedc9b827cd18a2a8b904701b958edb07a1e8e31dee67ecd58f\
             b19c1725c8c30b2fc9f9c431625213e9b5619a55aed15045b5ca921615f4e78eea8a1f2b8b5d1a9ec5c966df21bd6b7b\
             fa33e24f7bbf19d1c8a283e362d0f830d9e6efcecd0e1c98b01514c7a219e839adf5e70d25c075d958ed3aa7f5cbb4d9\
             9009f809f61971e141080ff19871be024a79af17aa8839d1efe5e73fef5da0c006ad38611b32b25c0d91965f9264bf40\
             2c2a05968cbb86c96a143ba9757e72d767a15557b2eb2c4f0f3bd33151a4e62b8f5dbd623508625c05eb4c4882c298e0\
             c2e803788f4e9dea8c3a9eef188cb4b65cbd6b0e5f35bf6b1ae5a64fd5b98aae2aebbd065b42e8fa6b1d97f5737c41ab\
             3a21010c71c3cc7fee5eba78490907242f116b5a37efd85dcadcd12bb4aec9d45def58ddddbac09645f4f5339fb3d73c\
             494ca33c519f9a93ffdfc631591274e4925a2b20455171d34ebdf9d282d83c910e2a3e29925c2f89109e2e4f8e0e543f\
             c7770cdc44e567877536988129ab312e2e553fae523b5c9e366f06acd9e60ae73f227db4066ae64dd99064eefa66f916\
             4b073698f69362442c12472a334018da2593e722c17d3664ed3642b58088b07e9a3aedf1c12f7a27453f313cced3841b\
             46e477abe4935138f9f7c870baa8845e4f16feb75b5ebe9c3eccb513b52f5bb5a6fc5d04e6009498f248507fccb9f3fa\
             52e66c2a892a17a3e85dab782c43804977942aaea2d644bb4087e27301a7faea45e1563679d24ad1ab00db2bbbd420d4\
             bc5227c7a339dca91ce5fdd3fcc3a3c489664d4c183c9b9e5bcde77f7f61a03d5bde36a56b8450932e6e721470a59e92\
             7f5b8d5b127cb3f2f7934bf4cc0a178ff96d799b55231f17c260c9cb2f9331a6c2b38a97f19aabd57a8cc98b9b13f3f7\
             3aa2a8a24c61460af27ff6be522d7fc11ee608c0025132a110c6fc9c2d1296b81e1bf9ae544f8dca738ce9233cbc9b76\
             28f79d31cc12123450fcf2d92bba96dca3327aeea4a7b8bb17d4d21486839e02a02856c4ee39ea99099e560d0ba59e46\
             a16fa6dabe3c9f7ebb8b6ab6ab1bd2a609fd7eca00384b4a0c382a43267447828b7e305829a8ff1ef357fd3a83f7d133\
             e17c81522729c4d1c7d082bd5b92d5b9c5eeae7d4eb3238b4fa6f4c50a131b8ff685d5fc2d0c7039fb7f0b4d334ec5e8\
             1c074d9e87c8b8b778ae5e9863bf51d31eb60c207af2c0138c3545076a9b3aad3f58855be7394603a550eeee20fd6f41\
             8676e96dfc0440a16334d7cdcb5e07669c7f96d201d84a07240824bb932348640311657202d72dd52b863431406a0cca\
             0b811268627252ece9eb4429da6b2797661737d72813e8afe7f84554c433f26832fe27bbbbae7c3be98e86eb8615cd71\
             daf86432d33ec9323ccd16deae3c7a6fd6ca3ea7dd0290ca4a0b16f246257cfed6f4903fa3c93371a604bd4b79c74600\
             80cc100214a4656a3708fc06b07036fa1890a5f43cfb3ce7cd524c426dc7d34711c6637d1f958f7ce8cd3adfb000c4f3\
             462a134c0e57c7e34a2f97a3214d3872e8ad0774647d242cdcb34c03df861765f66d90a53abbf4183bc7fa43c16b3035\
             d11a66c766ba61d6cf4e07027002ab4473590e5183098d4e746d2fc553f37ae4b6bd068acb8abe05bf13aec80969856a\
             8d4e373c50e6f2d8a5315224bf20e97e16116cf66d3893ab955f3876e1327fc792eee63d7190f522b374c35e365464f7\
             8990fa88301859748ba9cd4509a64c688f88792318730e109a9c0ec7ac1e5462a4421d2d9a0e4f0c12ffb17fa18fbfc2\
             3b707d8bb70839a6bd959780246b733d296ed5c96988d80c13312c521acca6311c3332205c7ed1790b86b6731b633d3e\
             51cb4c47c1dcf66e90d9098982442d7408b3e361aac50875b696a55ff669e51dbaae974740afe50094dde564f48810b0\
             e6acdc0180f8ede8138cf7a6dc8b4b753efd1192f51420e5b4645997ad1c01ad3d81ea41de231acc418c5c60949964ee\
             749381f5364d32d1eebb249bc42e756fed8b404179c008bff347df27e50ea0d9ff1ec5228bee397dc36401e7e20e1420\
             b3416f3572640d3ab60de46fcaf636f0a207a9d84e28b15cc1b3a687fabeccd8b7aa1d1bff43e1a8f7144b3d4bfa3069\
             ecfca6afe6cbcad15d6e78540c054f014a3069fb5f22ec48b78fa419fa0ecb3a07b28c4ac0160921a57d3eeb8c98389c\
             2e454b1734381c784666c5efec704e9c5a05ec45a17e4795479e337c9b33af7c7f918a48ab263ff3f82dc808ac51bfd9\
             f9da1f3c14b72db98ef63d732c15a60f6f7140ac4a48767a4101fdce37d68c8512609141421feec03dd59121a081f5f5\
             fb00de38d6d23a8b1b625b03786a8e1f18def5210aa20f4eaa177e84d392dc9c047539c6f6a46407819ce4526d99d7bb\
             5a65b37d1ef96a35c7d4dd3bd9bb2800b5c89c4f26e884cb5c131b75d7d72288535840fc929265a0c55faf7a70c11a9c\
             12bb2990212a149a61450f839a2f94774f4efdf4583abbdf58bd7a3a83e5116c96b5a56c4e72d6504c99364e71bd5e3f\
             9a3360822db152b7287802f87b603397948041f86f2faab0d02ba5abf1e3575bb6f59bb77da5edd7ae159bf823a77bf1\
             442832c819143535eadd281b8800ccc47025a0f65278bfc6495a0da565948ef9462eabbea8c78156eced2f3c6c3632bb\
             ba018cb1a0c220f0e7da8f9a6a2223191a9452bbbb87c5fdd641b87268a6a0d9f477c788ada88d98e967456dc45897a5\
             6097e30c0f273281893a592e5a0a582d4754f201c883b1fea161e2ee084f37306f137cc0d3e82de7798f0b5fa62ffacc\
             564ebcfc8807b9dc58b7f43d0eac119599005d55d6af7b04517b0881600ab5969ff19b1ae5d131cd68536f4fec7f6282\
             106b695bc59abef168a1cebad42230c806e1bc712e2101025c22ef95a1e4a61f35dda390d2bb775c63ca3ce6d48df058\
             e81134929e985fb4fc3c173cf621bca588a248c47a18d93b735b098ed6fe3f745fe6b65d892ec27da11ea9acf7ebb86c\
             5812e413024f3e9e6ebec1611601d2a5e80e27ae8e14b76db64a14b9b748f935bd1f90a8a3278387954471419c78c8b6\
             d761f4f020758ce8bb883b85d6d3e3e0ff5dd9deb8a906ddff48241bfd72f5f1d0eb8c9b28f99296fe4852aa0583cfb9\
             606fb4916a98a164fc1deab30c8b310d324008a68d4350b3ef4477590e03faeafb30a62f802832d89119df78ad82db75\
             a160ad006dcbea069e34ba9c71327edb959835e701d36edf407571774aeee8a9e0e88c8cdf8f823118a802ee08734e02\
             902967952cbb5e2eed8c8feffc02afa123c20fbf350f05fc2e61a35f015c6cd0656d79f9900b6cf0a8c29be58cb093bb\
             07034b7444b4700a23f7a198ac06f089711ca08fbdb7a46e365374a61929f3cff94f66f1e5deec06fd36b0347aa2441c\
             69b50e80808d0a6ef5315231bb6e40d42b1b3af122593e809c211cc725999f89842f1559fd1feb3440884b245e89281a\
             fed5ce1a2cc94b7e0e0c9f6cc14bf74055b0bae3883ea9fa3567ba6ed84d8c3b8ede131cd9f5393f129e98a719219cfb\
             f72372eac5b6f811f2a70f66085e1ca7b3b98e5e46ee63c89b7f9a81509ca245cdc3cdf4f440f51c3c5a0a3dbed5bead\
             1fe843bb6769bec418672abad2356bfce5cd3bc70b3c8ff775f5c705b27b2fc6396db7bb988713088ad83184376a1103\
             5fbdb8ed9bf71ad6a4dc427a71499d49eb6224e439cbba9dbbd6be261333d3b870384e50c51b285d51f0875325cfdf49\
             fe44b80a22813cae0d7d09c3556cc72b2f684951929c8ea36c46667579c81bc49a1492da5e0320ba89e1ec53bf95a4b8\
             66001b40937a5e911f170e423cc690fad1c858fa242d2c4ba8ddcbf12dadba7b89a23c0ac2ed8df30fb6078b4fc89755\
             d319017a102e5ba20bde2e216d6d4827a25d0bd31b6313d24269287fcf372ad6fe385e75d45dd99476576dd6bfcf5c37\
             36d6c2799f968d318fd5d7e9c3d1f978b4edf0c9a47efd64d7ab6aa994a3a81a52eb51c9b0dfc4ef0203f4d2c1b040e0\
             00027968eaaf23879f72596486903483a8999a03b2fa7b2e56db79c8069dd73010f039c92751b3edef03c32b0e1aca7b\
             cbfa7098e150d13acca1b99d9c128a639e677f500b007e19317b53833548d00f7815db910175978f4145caa66ae46842\
             86f874de2a4391a68c720e79df127f964723820555115c1245a9949ca70a8b3ff43395b4de1733fa1b30a25e87dd39d5\
             e271b1f6245d751cad53f55d3dacd72ed0955618e86108f81aa763cb2d0a653b07d2487e395cd54b4c7d16e7104da17e\
             fbd069ed1840a72af0ea52faa8c29ac43a06abdf2ad2fe3a836f598f8cf8e26da10c8dc7cfa041b2b27350379659baa5\
             0da3e0f2ba438a8897388d5af3599e4122e9536367a7681af86623b45a967211c94ce92b390456f56ff46f37bb3a18d5\
             28abce096a84f2f7ce1af71139f97c077048950c2fc6ecf0f2bde7599f3735f0775caed79de3595e5818f126f549b356\
             4d0e6ef02b9032d6836cecc3e34a10c040ed5aec50ca16df38c09c619d6f5cdf81caa4af",
            signature: "3bda86aa71ad6319607d95b866cd7cbf345e1189534863b2b2040e2a1cacb207a494d3f89fa857fc6eae93264fd6b625\
             30e633e6365d4b48059d3933961fbb122786f509dc3008e35794437c4ceb373c547b0cb64d4fbb29539fa748966d6047\
             2319f5aa11cae79dde371f0b6d580d831bb089b5d160172d92d4181366bf651205040870218cbdddda833e6b5dfc6057\
             0662ebadca3941a761bcee828fdb75a0fd45fa9ed46959a8aa349142f99d31c01de6fefd434686c2e4a570e720505c5f\
             66023123e2a4d2a760df0ebdae5a625b8a22b421e495986fb8ab02eb90d5a9ca1fb03f617a06c03730e52f256a3f271d\
             cb751b2930340d3756641f9f66bfb8cfd0af87f995fcb90a97d39118111d814797f8f55d1584474f589da93a79853681\
             55efbc2adde749e1489e9bf0ef2f9fd72de2e9998c7e9e4fc8971cc2f7adb4f91301cd30e7f71785f87719dcfb429913\
             7db6a7d7f166f94fddedc25c4f30cd09e1111d70811778f51abe6fc3bf950eba6a33114f961bc99f8ef81970eedf8d86\
             6dd751d52bf86d79ccc75b08bd92324eccaf1a2f035f4d498c4fe22316e9a49a04b05404dd63392af6c2bff6d57dccf9\
             f80c6477ee6a0d51582f552c6b776dd3b635272b1b5453bcf6621b5aba57a20f6afae7cb044579ed5ac35e5cbea562fb\
             2d6412e653b0788eea66e327c6ede0cf0a8d8b4beaf904e55b47b8301bcdd80315b4bb542d0507c645bc191cbe365322\
             dcacdaba46e502b4b0d62e8f20523fafa632053599945633d0fb2cef459c60e96fdd40f9ebaa2020c02eda79268e42f5\
             24bd9ddfe0a97e2dce6ff095580c0cd69cbf6b58d70588b9a1a0dfa01ca613a91bc9b1185d3ec637686c23b58cff265d\
             6645ab48dd1ca52c6b514c9911cc83e47756395c48cb04b09a291a55ee572af097f480e26fa7fc695fe4a7a06a374963\
             d659c934786de4787ac5e6e0c703f2b9c1aa8000a2b8b276d2eba6792b76f4b4f854db573a69855ecbc6ed99a2d6c4c7\
             b6febab2efaa446b2a220a952aa1ec01d274db39b48159a47c85efdd343c7f70e4953b4a23e6c4c96a8622e2d3b6bfc7\
             817f1e294ae690c6ff0ca0ac453be5706bb6f91212fa10cf7b684190f91b8ac6d21b1128d731d4c02ef1fd012f242d63\
             195f30f8dc1cf70fd497e72fcfc71efd8a082b0c835619b8d159524b520df522142be392a76543826faf7804ef47611c\
             1283833ceeaa1e49d449212dbbba85801cda26ce8a894d8744e2ea808d96c3ed6a400b2a4166374e64cd1ef8b9908e8c\
             5b335c02235748a30e563d58bd1645c4281da69d38ad3b7a3e082b14ec44c9dd31b786504998316c0a852c78dcd2a022\
             64f291d8b7c2e8b68dabc7a78d2adb1150af7cf14c32b5f958b9248fde567da72baa62c0b6bfcbf93c99210a76fb273e\
             2fa7b6704babfdd8b50d65aba9a3e44e28ef7fde8716eb2fb987f1f741c70496aa4196dc4ecf846c8b0a135d437eb1b8\
             2210de427688579041a8bf511bd3f97599ab4848e9d9d9b4d34d62105cb9ce4fedfea27261421e683a7b2b5ec7b1104d\
             84dce347478b165cef950a8b1eb0739eb6efb9d387ab1e67467085fb8ddf10f5e0eb818dc3d1315d99bc64c0e364cdd0\
             81050ca476c14da06d3ea61674a903a13d3b2e1e732a581968f1d07efe26999cfd2a3a94245c757791b9d38db2dec799\
             cf094d4db5fab68f329bc4270693195641c74ab43d7e00135667a8dd2daf6dc86fc62b1f271a7edf33ddc4043253ac9e\
             ea4a9ba345780659e94168dcc50bf23c3d8cc46b6f1ef7d21c6bd4c14bc52b88e5ba135b0bcadc5c5bc9d5a844a3e62f\
             fcaafc1c68af8415c2862b39bdf69fb0efc73970a74d5f8f5d455cd0cafaf11d33944e60a2b26ac55dcd6c423276545b\
             032262d25af5e00fea2499d09115a42a519ed7d14ad8201ca33a8816f75cfeaa0a753516930a9bc3c16bc099da218a45\
             ccb33047a9cd89a877cd2d2b4f622eef5a3a38ffd0f7afbf97a95bbc40d5edf852f4c7fbe54582dd53ba3db9ea30d35e\
             6ba46c0d0bfdfd9f84efe59cf8b41ac36f601422e27f134e0bdfd5dff49bdae24b5ccca8c71163aa338f7a902403e9a9\
             45b671a1531a9c5c1f8bf5dd31377130b0741adf6043171763e2e77258d8f86d350fb1a7d972dbb312d2dde8429bf519\
             6bc1034de4bb88fc21918c33bd27a6a2365c178d97554d2433244f187ab15c7809f05e08701dc75258d3e0a955753657\
             cb6e56eb54bc669178b5e3279feb719fb39a170dcd8f9bc833ccd724555a574141847711a1d8d0d7d16076af897cbe10\
             9010379cf0694f36a4aab90ee15aa269a94792fae84210a40c288862140ba1224bff2f8a41da5b69902b0767689cbe54\
             947d7cb2f469b8698ef726914fa669d582e4ba47aa34d6cf82ba9c38633e11b78249fdec8c2c1b137d0cc279c0274247\
             bb80f093027150c8ff9c8315d1cd83fa45d5a48a4bffeb78254aa3d8646b834352ecc951721fadc3e3c0bdc52da52a7b\
             2efb47deb820615a894a49c5aa1578bbb998721c2a3766f8847abf412aa7b58fde9d77956448d187a372a9fb7afd661d\
             c6986c185a5900b211962847b61909c7a2df115c0d571e4dc279cff09fbdece158d77e849d1888ed4219a56b6672aa09\
             2476f0b5e6d682bdff979bba646ac8f8091e3924a31505435e6a7e3191687410f886c8f9e42c0e44b8554ff60e694dfb\
             f6327b494ebc7a18237f6586496c23d60b252716bb30453cc9dd85751c47d0812c45b7eea263f3c1ad85dcde95654696\
             242d34f8673be69e8f8728c529bfbe179d4bbecae4cb563a433e27be943a8cae2a319d4c49d4161917b492eb5b7947d8\
             95b22f79c939520ba967ee42a95514c8c6ec78980c62d38f442c4c51382d7ab7c710315884488853b4f26cd947fba6b2\
             b89796675c7dd4362dc63a4b12bc6e5095b754bb081fbe5806af359cbec8d315183d6fd38dd6cd788e117a29b1c48c80\
             20dbd7742a8dc0780973905f97ec071acb734aeeea479a8842c024678819eab8e663b4b3f326adc1ef2b7297113247fc\
             f4f07957294326fa9c416fa0abe8c0681c5d80164c08c5a7c02f2ded27331b9c395b68e1e1b05671974ec19cb69372ee\
             eca628c08785dc29639c8f7578f92f49c5a76f2312ab4f491fc27ea9034adc24260cc29ee4a05af2273fe346ea06540f\
             a3b9d39f8dad9d06c7306e0ab1da7b2a8c24ec949bc49ee248aa94f4614304b1124b8decdba0a53718cbd751d0d0d117\
             b947fa8c105fce3300ff4dec3f14a962a757803dfcb0008452e7b3f90ceffecf96758e12051ad140e34e17ecbb023769\
             b87081f04298313ae4b20bc3a6787abac3677bb04a9e55d21e4088bd02da0db28186f037f335146aa5294c17001e8d45\
             cb8ee540c99842eb80db267c5e484b15123cebef791b35ae5ed8f3e01ce9888e9e4713f20f62385e73e1decc5900f7f7\
             a120b767541081d112012c8ef726db45c5d3e71aa96917c0318f9aa7002d9a1f4a9ef4785706ccceea8d999be7886ba1\
             17ecaa79619e15709f3de4f375319337fc85b329b95ac89a64d5d9a4afc8b3c4f64baa660a0266796a76b39e2b846011\
             7fd95cb08c08f966f5b4d98d890cbbb73944bd396e89a6098694498162ce6e40f4132353a1301dd450b39f7d9b4ce678\
             1a17bb7ba1a1d46f19dd9ef7210a4bc3b290e717a8477ac877ad48f5819d5c60bd8e1a34733c7842fa2437a7a31fb658\
             d5d9b8e8005f5f7408ddcee40ab0762e5f87b346e7448b2afe667ad7374dce195cd9c533c0be15097f2890a60f838823\
             f6ad25498a13e1c89f0566759bc1f4a665eed9f69e35490a44cfeb265c7b10fdf0bebf914f18ee4bf22c6855215da9c0\
             8287ad32c40deb12c9981ed87d3a3d0b4de0791fc75063d608d528f9fe361a8abdbf0742d6dc5bbbdc261a24871c4a32\
             0c1a1906613362d69c3badcedcfbcc88c329aabb6c4bf3e02417b7edde37110d887b5393b03cd5b33f36e88acbe477cc\
             d77739cdd2462f90705fc9947faab643faaf94234ed5a1eb487d4dbcaf77012be0e0430749bd34f506aa866918495f01\
             ddc0463bdc62ee357564b9ed2ac98f2c77d30a20463eb6e2e30cf63a2b56130ba6f1d78e79624d99ce7fbb44197172f0\
             a2a4b760da4352669502e620ce647adcff63987c5d6d5b9bfff36933f4ca3dd166aa9f6336ac83dc0f2ee801775b5ce4\
             95798cf2393d70a0c39423f3c760ffa23dc9a5f2e368822a992b4a1250bc92211afd330a975294543ae77bd2dcb7975a\
             a2ca16815b007c584f085d7891355cc6ba5a855f12aff1610e0b6a5eb94b65493aa0a17ddae898c23efb7a93052110cc\
             b49ae3635ae8fd903a9848de0e725e7c0c532cddafc83887197d10733a400fd1b8458f8629133061e534877ec31328ff\
             8d18e0f25fd64800711ae290b04592d46a3bbdd9d59f23c61943920ae8ceed008eb22e27bfa5fc0465ebb74a0a01658b\
             8eecd0716f3f0b782c8f46a5b46bcb2843395c325bdbbc4f42facc1d71d20b1f2fae822f6e64b3a065a299d3ddbccdb2\
             70bfede194d1d61b23edb0033f5c7fb7a9d37423e3b526122ebc4af68e48a460237020aac7cbf2f6319396d2d6f3010e\
             97a32e696a70abacb7d45ebbe8000000000000000000000000000000000000000000000000000002080e121a1d",
        },
    ];

    /// ML-DSA-65 sigVer, external pure, empty context: tcId 39, which the
    /// ACVP marks `testPassed: false` ("modified message").
    const SIGVER_FAIL: [MlDsaSig; 1] = [MlDsaSig {
        tc_id: 39,
        pk: "2c547c19098bb03b22d8706d0c78cdeb67f46b5f344908346c641e4a55d5cc0d2c80e43d55e84813c88176cde54929fb\
             00491792940de70f14761d94c3136ba537b0ae549f091a1014fb09522d27651e1dcc2c6a73cfe8facee66d2e14465467\
             4be8a3394c53b895fe162e6b11296412a2414d5bbce2f7e977193614d359f807c0b3aa7a1f64fd561529ed659cb85645\
             f919b1a0117cb14ec23f3449cd1b8fde38e5dfc493312ae79a27f0d5ba6521592f412a18ca228eec3aa53ea37fec882d\
             5ee29b61b1a813ea0b56f17b33efea199e9f89766addaad41f03f1e8715098a7812c51ea526e887399fdabb64c128c34\
             a92a39d0604d910ee2ae42cd52330ee0a0ef42a7134ee7d9d452b55c1cf02e7cd1e8424576d8f4cbfc1e0c4e7c3cef61\
             e5da3515c3a7cadd1a6ee0e915fd7274ee66aa825250e2e180229e5af249d344a87fac7f280f862bcf5345f26f2c843c\
             7573da5a13300594abca04f7f9fb00ad6456fbbd1d1b9810b3f64f25d1e52f0d7b655648b6d6911ee9699524ea831c4f\
             c84a0f051084fea606101abd2f574984bd041326350da57089f6ff8816649d6a249fcd641874bcb2511cbbeae8c70c2e\
             7c22e1062b1dab8c2ab597bef9b9691b5017d9165abd435a762ba91af014acd0b1cedbb3d18bd278b3fd3e3a7a01fb16\
             ab0fbb4832d244dc38f8ab1a2fdd7b81c513adde45535bc2e78c4429f0643c556946156270e4a66e6454eef041771075\
             5fec61d36c677b0325348424b437ba6101a56e1497c90c2dd69ba60f421d356064382f14179c66f07c78267490accecd\
             9a12044a17c160db26bfe005e431e9fd414170d99f6c4a60bbde42583010cc3fed91d961e604c848beb2fdf9546427c3\
             590e2aa4a710677843d4a9d5e7f9bbe269cba067cc03c0e13b513d7319b4a534b2516a1b7eed40d7501913927ff11ccd\
             bf0f9346bcdc60ca78ebb2ee3b629ffb5d28272a459cb7132db0135cd631aecedd409a1ea35da2cc2e99aefe867fa7e3\
             e36cb163e70f22af94e1528cedf2413ffcb6eb00e67c1dd8f1134eb28744abf09ef19b6a480bc9a33b95d42117673419\
             475632d8c652d7d1385730e7c0fd742fbc58b01b2b21a33986b6b9e19a630b8b5555bc0f8b9b2834be8a45de20d181d7\
             176009bd681e1173c982371568b8cadbcf47049762cc76e3a301598ce6819f84a62495203a1b37672d77d92905e6367d\
             11f37260f2faac9f27537880388aaa9c0ca53e522ac8a40d7bfb9fc7b3168b8cc00087b8fe834c8bc5c84bd8c787310c\
             9fcbefb46f61d455eb249a833313b455b195fe130388d4a00e8e7df920bbe06969a8168bfac737e54993f0e6255150cc\
             02466eed0ed0bba8210580852acaa3c60d35235e254d2a56ac5fdf32373a9b6b36752308dab078bc319efb54ab69ad8d\
             0f1001827d0cc2386387f60b5f918492262c215697bde3f60ecf347647a0c0a7fcbcd95faad5d7b3c40d892e7713e9c1\
             cb8eaea226cdce9e7226f9ff26f09ca47adcae74e72d90f6a7da980fb666504a1c3063e425cf5bbe15dbc18bb0984859\
             0ad6cc519d02ae3787df6838d0ab3ff591a1faad0245019c7aa638ce4bc29f7cfd844d194df122d8feec46fe28fda2c3\
             ba2f8e82987edc5e0519167e175d4e0203e1aa107c99b0de3f1ed68ebfa2a483cbd5aa758b0f5ba225b5956fed64c6c6\
             36180b7cdf56d58ade343450c55a372fefb2ad457c9a0721e0c362ab9496890111bd610e63c11a5105718add9a181b38\
             3390cf8ba0be72f9679aea6d32d77cbfe28a0601363b2c2e535e393294a159142aac259777f20139a933e03bfb6a736a\
             42e925e16e291a33c4ac22ce526109812ebd08272c0a1eb0e4ef3ebd9c01fa46c1e84ac0ac847cffd09f405a0abe8f95\
             f8cfb256da68bd2f1067fc2189a3b5fd95387eec170ab94e4c00020d294c24ad419f4fa59546f0e43cd9be1790d3b6a8\
             0f8c5501507a346d65390e4654190319080e794ecb292708f8e2877a534192d0eb9e328b10c0c20a728a79c5f00d12d3\
             95ced8ec306dd1708dcf21f3337f64b588a99fbf4733f4906bfa0c9fc56142785b4a62e1862ec78daa0ad608b5c26a7e\
             20270329063eabaf0c5a28036f133a055d279da25f811459fcc203a86142631adf75a1dea819fcd2db0945bb1be5ab2f\
             77dd0f22bb330acd415c6290ef0fff03bf7fb0ae5ae07afd6c5253603993b996dfae651851d177290f8f005623379f9e\
             68038a4650b9dd5e5b4222c02de770689746e8eb57be6a7951b564f23dcc5f97b4654f315375d6995dcb83b2e73bde1b\
             1429c2da8b58d886fca0743b53bb0551f46c0e86aa3d7b128dd4ff1048a0fb0fae1b82d26dd499918cf5bda53e1df8fc\
             a04df4edd3dfbcba78596a35af1c0695bf21fc9cec4fbe0871f6e19bf13753b041b36c983128d95d2e8b18e9d5beb431\
             242c71750e40f260caa40c94cb15b40c4f5484ec5741c916faac261dc97161a0a9a5286a97dd9ecaf5428022e29c932f\
             68c4711248799f5382d1f53144294f66752ef6764b12f10a28f7986a64d558c32b4cc9aa3bc25bdd24632ce67bf0b5dc\
             833f3e71726c3aa3203a2db544aa1d067e30f08718230add93c30268d90059985847e0869b6b9a9a2eed253f5791f062\
             c262bef0b29e903ccea17edc177688780e066d49b55356fea49ad1f38dc0da29957a293852010f0ef88efbc2474b3e47\
             70dbda9ce57e6289c7f4e9a1cb314d358993db1792f12250fe3e66fb0555e282",
        message: "efa4f725bedd0d239303c709089a1e11b6208bf2d4be6d9ba3267fd92a3be242b1ce9e5cab27b52aa94735720ebcc1ab\
             e65d1dd25516f18e01a34c7407b76ac976d5c5ca45046fd3f2e009c54c6e3eef9a8790940558187798e4611bfaa80bb2\
             0c82e04cab5c3277f2222b6d8d897262be471c1369774c57227126787b62f61d4e964ebfd0fc37b79afa0c51b03ae8bf\
             5cdd7df1c65a495b42b149e314cd72fe74dba87649ce3f3b39e36db3d28e096c543b45ed616bf9f70d988d1038709a08\
             aedfdfb9a63dfaa1cbde5dbf5156f3d0c28254aed520de54944fb343700a1a96a2bf0ac65ecbeea9ea1b0e3fbf8d46c0\
             dbfe1b52073dc7b9a53e8495e6e4bdd91d1c4d9817cfceddd55bec9dda839219e49a282de438b3ef5722952da9c305d6\
             b8e8c352a72b5b042bff8abb2c1edc3b6b2d58ebbb75c2e06ff4c372d3fadd5f1619bbb6bffe473d86e3a3a61822e41a\
             95692786231bef749f8250ee68e1e8cfa6a3dd113971a592b47b07aaea6163c0e22b54bcc98403f42af5276491fbb88d\
             8d8e087ce3c646e925f10a26101969c6e6e2e9216f765daf20c0d77f5bca84bfa218c354284aa2cb4cc332273323b501\
             74832f15ba5ba651e230c6859293ad57183e4ac61bde4a16f8a37c15c73fdfe6466a1208229cfdeddede3272609a6fc8\
             d8f967130afc6c868c52b2b748853014a32620025c85517f5155c28764d668aa5bc49af854830d676c6e8e741c4e42a1\
             669749c945ca8d73f1bb961763d8f51ac6cf058a2697abecf066cce9f8433be76c265f5af02f79614fc08f0070fdcd39\
             5887b75836afc7c6f13af8bf2bdd3380bc071531114da17e273c3aee5d9d27e925f8c62cc4f7ee825771a792aea19d89\
             afec9d97e6f2311eb37c4f25311f3798cca760c966e26d599efc24436c55fa77616b0e9535f49085c12d0f31508d7e7b\
             b413e8a818fef5bd81d38b7778f34cc3ada0b2b09becacb54f79c75ca0ee2c2a739c37b819a818141ca981e2a9e0ff89\
             89af207db7f218ebcc01503012116603b53557777cd673ce1e6aa2b4d878b6a0a9d96d07f2e25fca14b48e8c76367ebf\
             5e595a6080a962f7b7125f17bd2d9f5b8ec76791d0c55c1095d820dfcd2ae07e8260e178d34568116b3ecc4ff2f4a235\
             935cb756b4001f40d22ea5e8bacd368361520c606333b7451d1b92f0052f3f3bc1dbad04ad42d08ec045ac8b8b852cfd\
             2fd17e3130631041606598858edf857eba316ee7cb6555df843cc3747518aab6a121cf8aadf96c2fc27869032155ca84\
             b921a4363cce1efe5c2b2b9c93d2baca68bada59633e9f5e67abb5e963b10ab0d8574630e313717c7a32c94c58d3db77\
             62cdb42c05a2db00518749ae4a98312578846f6f4a1d981ce7e0fb3f3ef1e6b05a008295d7833448c7914d7b2f595c75\
             71083e3e833577e4638bb03aeaa2919f027908a70ea32db6c3f3a4c201fba8971be6e1d090e82962a890380439f83b6b\
             534e76d8f1775c53d8cf27ad971f759b90e933260ee5ed7851f91f6af70686eba03ce2769638814e0cf0b57e617a5bc7\
             fb300abfe3dca835c50d1073c669448d4d8928f3e770cb9ba91603b71ab386626ce5d33b93d374c930c9e762d32b6510\
             a8d031e7dcc8adcf6b9e9357a5d8ffac70e49e2b79ec5d7f7005bb943f37393d6ea9901a60f6460a104d28f153e4ceeb\
             5e269a0d68d3b938ea92dd23d3be1c948fe73c74c45dd30af207ff322547114e288e535ccbc924ab1d55783301391210\
             7f4d396533f77ab18366d78d7fd68d62c5df5ce5ce9be1c84c706b3f0f5671c9947e09b2aad72d857421f8ad92711c89\
             94878a7202a68e8800e33c617deed27b1469fe9b6022e950515f8c5d24e1ac89d2e92ee2d18532931a69d594287fe500\
             7e1c8f3efbee72c36a5cf8353aa9f2d57764e162ef5198a3a8f98ad3e654ad4a94c60617b724eeb34b1d336a29db8da5\
             3dbbe8d5c979c785344762e9a1bee19dc62110c84e30915f39abdcb6d6ccea0ae32c92c7f2736ba48e55484984285e27\
             d40a3714e571d1cf83da48351e55da7d90e61200e6b5a8fd35f63920ff153a82e1fa0cb14a7af1f52c787d9a71a19bc7\
             75485ebeab3f22e0bc818ed766fd470174b9d7ba1d50c5eea5bd400896657ec4cea01e4716af3cb8b429020f6996b36c\
             8114fff06669679390746de7f8d70abe91f76e1a6ac81574aa3d2385e4556212a538e0a0230fbc3cba88102c23e6f6d8\
             afe765cba958a561b4230022a5211ca1a191ceeeafb9a6f6c31772102aca98aa60c9a701f604a473278f59ca0680542c\
             993bf6bc9056a156e85cd04dccccf00eed06a3fa4eb6dc974d5f45500f8e5394653edc1bd885b104c3f5b7d39bf1d26c\
             e069585a14ba6a7656ce41415a644ca02f6b3f9e38d1774661b8b4b92c32668fa1a0b55c2f83ffa5dd15ec4fcc12bc77\
             afe3050281740c95c588dd145f488b421e0e5417dcfb84356ec01244663cce3ecc1301b775849df5b79157b3b86e65f0\
             5a538c9b50898ab09b7a871e69c3261d3b9582c438e596aaa9a4a066ac1fb0f5df7c088d5a0ad34fd83a9d0b2f469957\
             f804d26863456c63e1e7a524d862eb3886b765031b1f210dfde60aa54977924ec879c9975836ac457f24ac7c18d136e2\
             dfe682c19562d1c19b2a9e108aeb878e63bdf50e44ca1f0978fa66ece0bd389cf69491d005f50bbe880e61773f253fe5\
             118d39506d2c7670b688b7a02159d0fda2de35cad1981c9c0e633bbb3bd6912f9b8746b1badb7a2c5e626821911922c3\
             c99d4ed155db6c573ff42ce858d5d31faa49ba431d9a9af1af8aa53eef5b903a4c94900ef63b7955cb644b55cc2ab604\
             a1587d22536e585aab440dce3038bb8a49f9130fd97478276b0eb275f54535bd59d676abe6d93360a36a826e63e4637d\
             da409b01e810db170463fc87cefcc52eb270b394b595cbe4fbfb1fb58c7c8a68958072ba74e82d0c6b2b41b1be2e5cc3\
             1f0eeaed4df9fd4cfb0fea161c46434614bab62abfe53d9d5d008db3e1c6f3e5123cfbcfc29e234bab319fb1858b0df9\
             de2377b1136e001bdead8c7044a97e9bc16fa1293f21698c6cc998c0011b4bea71d25c6061b554b3663bf12c2b901544\
             f2a1cdd0757ecb3b83d96768216657cfd9b7015aed703c8f4017a80b5ced65d332ba2758ea24a1722c4ad09e4495cb0f\
             464d19916447ff19f9b8f517f1f8855377abfded759e1df34865a1ec893647362e9a04e141dd7f2fa89cf60817e9d8ce\
             365ad48bcbfaa94b2f5a6ee377a7b6f0c00d00c9c7bbad4b37c8e71fe94d4db64819933f2608432f64cb9dee29b6f88f\
             bcdf5565a020e7ca99fa940e290d16cd4998996f3672d01572a0eaaf864746cbd7102cff1a964fe288cab2f61eb6cf4e\
             7a24366f82d0a0e9df70fcef0370954cf1b2c5f85b91f280081b40d65baf856f90ed201b94377d9d0988910c1657fec9\
             a10ea6a4255f3b9b40cba7006da971717d1346013a365a9756eb58972c324baf1bae80cd210382d6ee5a52eecfd48862\
             20be3f6207197721dbc7a7a7362af592ba77d4f60b922fbc754d1ab158365ffd938fc221c50526f0a48b5f50bff72409\
             0cab252ed21cf1e3e004672d0a1cad3b18669f5b34013ddfa6a612fc750fc0dd7b25ce0571776432eaf62303e4cc96b7\
             88d55f7fd4a02edab096a6364edbd903074cfaa1d4351077e674fb62dbee764cdc61d84f12c72976c6a23b82ef4aa6e5\
             59fef25a19731960247247fd16f47cec199580f5c03202f9a61414ed9634e92d72115758db8fe25d57988214c1d08adb\
             90d1b7d87819f7b057cdeafbd171f9a68708cea1cf0cbdd06ef80fb8e359c6910fe65e8fdb703640b32764995f505566\
             51656e88619ac1ee609249af59aad7bb66494c27d74a0bf5902f3b90fb1e62b7a76862bb152dda5c0d36d9e666c76fef\
             b760b7c208fdcfb32183b53cf7ce253a79af77c9998f1c1e0c5524a7fe2d79466b325f2158db671e31fc4b314be7b132\
             ddd714df0edb211781109e701c00b06cb50123a80003128d8e85a4bba69d2faac541a7ae9a2e478edb5f256a69f6a4d6\
             b7f2cf7b9177738586ae0d556afd76a67b0766c0d7685f857cb4207489983c9cdb0fb91d44abb12b027f16f9b3c443fc\
             d4ae03a5927fe67110142642a376049da8c11aaefa4a557facf840bdd96f99a2f7c3ea8e35e45ef5bdb3689a2a5e2442\
             3cf0694d663abfbe3c398af074a32478ae50a1c8b9418d120f80e8ba0992b837e9b561fee848f3988ba3cfc3f66d76a6\
             6d712ce2950ef79dee519559d34b620cfc815eea4a92eadb3337d6b1de7c64a5dabc056b9eb5b848a0ab90d32426cf62\
             54ae405b12506373ddcb984e5798497f25ba80a3aeb6ba3cdc703bad05c8a7cb852d4928fc895f5b5fb32259f294b8db\
             59969bcbf255909dd63ce471acc32700258ae30f73a316c08672f83e549179c0e2e7712dc8cc55683dbccb1249e5cd58\
             f277ea6b559bc3cac4639847bece5aa24f2d57791c197710f638ab376eda241ebab60caf33c8ee39618d4640dd4ba1e9\
             f439ed6d04880ffe261d3443d425580aa375935fb74edb3c9b5b012b189e2e2a7c805cc6e5c8944e16c3fd0e05899463\
             b95fde0b761e695000d33598d626c2242c3acd6988116a8280097d209fdb10d0f3d852dbc25a6449e9e4d7504a155894\
             e49dea155a883b0b3ba165da675235d72380ae2ebba7c1175027f1c41da523e6e4e573d4b33351a2060d828472b471db\
             a9f4f56efc3c7a58719e49ab2a4219be25d88fd82edecc18eeaa6b35ff33b599d21c06366349bf74bea2b2804c3f4c71\
             4282b7284e43f7af2a59b7bbb138fa241e95ea77b35c40dc00dd1c268df772a5661c6efa57d42fbd93ba92a425bf51db\
             c84077bee5b38eb17c0efd7d018b69bdfddd7b0313c2659653d02a420dbdebfd5a1db2f7b56f82e11f82bcbc6b828dbe\
             fc9f6111bdacf87a372c2d6794ae3339cb68008e4a655d5fee39b00c3d9cc38138bff040f7b6665aacfc5c12cf711bcf\
             8ffa592f04c57dece059c82407a577943ffdd9af7dc23424970454c7523db8b65db7b2b531027e116f6e032bdbfe5f01\
             c4ae508727788741af8a3283d6ed5ae384a32267a63b438f8401280504e4afc9882bb5ad213d5a7f1f59f17493",
        signature: "962404cab51de91b31f7c95ba91d5aa91a5723016e4eba3150eafe7e3078f0e1fc65338431599a2192c47bdfa37552bb\
             8799ebaf67fd0166667a31281f8f11a78a807170f0be33276cee3ac9973256be96a198edb470aa0eea8e2cf6e9a8ede8\
             63726d0f6ae3dea2744b94c0b86376fe81e8464dfc8dbc2bd71ab6cdb36f9167ff5d3490085a42de3eed41f09570287a\
             22159c2a9b8c22c9da46190e57d89ca5e71173473db9e73822f12cd36d9bc6fb0906c8ca97ad085f2ee49eb0da257f75\
             55b77e59c4dd92db6f88717d4a368f7d29daae6c152ab99cdb4925db45de12ef90dd8e1c6f3fe910ecf86f2f4cdaca93\
             7aed248f721735d692cc62cc6611e82bdf018a326e0d5dad4ebd3e00db299d1d6219777b4f1fd42c93355edae20c26dc\
             6e0fd16929d8f2a7336a952c63d13dffb370d4bea93e9782246031dc2887b701ffb765a806ea9672dc759ec44fd9bf82\
             a26ccd4effaf8deb886291810018d0f97ee22037cd63f69f8572801c84ceaf09c6274defd074bd835336dd9b67db43e0\
             b416925c0e5c195e5439bcd31d5fc71b1512487ebab00c5edecde1732ae2c1adf622b570d7cdd717eada9301570829c6\
             c1750eb172639292d27dba0b97b01dddfb75e427b4e5a9739ca8a4c3e1e6911685342435a6fcddec74d29acb1c9de050\
             32cef19614dc29ae518ffb499c5141e996f44aa072efc56713a0f2dd99f21942d1f0abe56e1fb4f9dee028bae619ac1d\
             6867db6ee792cc521f0c2d90e428b875499c27af6e5e75ed6bd829c24e83a6853659a53dff1efc4624c92728bf3785c3\
             eb886366977fdb497776ca0bd39f4cf6496d1af84d87a0be26808484a4be13ef28a9435e9de41cbad57af943209b5809\
             27c1c4d0e95f1685d4fdfb30da406064101915e6d299af8531b97932152c7206c1c34c7adaf66f8fae9379c9d2906c74\
             b8d39c537c8e50a7025f9460a8eeb9628426a544de28e3ccc528d545d2e4ee72e9cfdfd9b276785e2ce39a9d4c9cddcd\
             6a072b5f8d3fedd523f3cdc6979fe615343fa1c20729970793689b52bb30ce412c35b44a5d34dcb4911a4a253bfca37a\
             dff999f62afcbfa6884d72e53af0e18551c91a70630082cfd8fbd04cc1044f5d0b94abccceebcb6679385a99f972644e\
             4ae6c4a746359bb22b687f3cba14dd59b38ee0483760ee85254a25c27f45a90a543b782b2c71877437ee381c510412ed\
             a90096bbab56771152b684213cb6c485c4af82439c529489738192bb272679214fa376182a8cc03bb83a998fd34ce17e\
             4678eb5d255068a299a1d2786c8c4cb0f1300c2198f6c586517d34563aa3c0795b754850f3abfff2c707478cf09c9a6f\
             69135c757de244fd43818d3d1391a67e22bf79c101f68d68e3f2e0e15b7130b2f8c5cb4bb7a7fbe00e5e48e79d84c8c6\
             44133cd307ff060baba1100290aa2ff5ccb9b879f81f512634b191e94dbc0a5e6d37d21bbe72850df855ae3382aca160\
             f4a9486cfa29bf06c45e65a1366fd9a38a8573260caf1eaa7662da360ac681a3da6eff34301251f8fd45ec9aa3089eed\
             3399f458cedf1f4a79092c5cf3e844a305077b21679910b67443cd433c84dc4396ffeb455cffc93a117bbd6e778a0563\
             a3fef00b6caca4a4974869c7db45bca2b8b8ec153938987c5be4d45dca575ff73cc2afdec872cbf34efdc9dc1d73c0d6\
             b3af5f43a08fa78042d7cd47bc00fd64f048228166b8f761fa7043fa0a6f3e0dcc417a1a31761d68d2298f8f126f3507\
             f99ac6565ef48d412a4837d66adc511059411ade2c6a7264f94482eb62130ffea522107081326e12bf36ca0c9b6b0077\
             435dee161db25a5d463637f5bbd8c6d409f2f27118cf1af10a62292a36e7250e13fdf04884ff3ddf2d8e162167bdd544\
             faa1b712bb720a74ce74542e584a7932f6110925537d0635345ea0f9ca1a68ecad1e121be229972e00ac6982d49518d4\
             c6287d4f1790c15c5d7740ac11234d1c3dbcbf1acb102aadabd28d725347053e6c1669d3fd41caa3c1951dbb56894881\
             e3cdd1f716a2c13f8f3a3db5d68bbfd503f8b766784bfb68a90d7c2e8359aa33eb67a6fa3c173db6b42d5cd8e6360853\
             7976cefe4904afcf29d33427ebac45d893cf1778ae457072073353db2cc0f4a07a3c1f0cecdca063af5e8284057afeec\
             6bc03c7acf849af776ddb78e7344e2cc004f56bb48ac3251f041c89f35494a41d85052e8cfb80a1b0f190623b574c947\
             a06b70e9f6530620cfcfa721f3159315b184875fff396af91434d1e8e70b3019b9a41dbe2d9d144a46f111d4e762abe4\
             b160462e8651d3a38b11781a024caedd9a654c79e4254d7b9c945ea236c7f845eb5c195a4960b40019f5c9d5adbf5125\
             96ba89eedf92e78393dafa2548ce838585c69f2585d901cb241bd7e3e5f705e4afab62fd2f4f7dcbcfaf1f4e7d062489\
             363f2b074ddbed00e1e6e2f17dca5bdf002c16477c26a78b11a0d48c2304c8fb011fdef8df74776a796849aa4509535d\
             bd7a91baecca8f9aee05d8471aff66a3dc26862ca155d66d45bcecd174827bbb80d7cae6e3932bbb41434a8974588beb\
             a47da79da4f01b332bb94a563ac6690ff90d8aafb61cb5d1acdb73eebd7dc2adcf39884852acbea446f5b4e3db5a1413\
             b624e00fbaee11726c4c997c666fe2689c6120668d1414cc8ecad79edb170f38108e6335a15cbe693249b3c31d29eebd\
             9024a4eb07f4db56bd38e103dac80cbd2a487e736eb6205adca6d937d6debf08b54de279a6575c29c76ccd0ceb5781dd\
             86eda51507b59ceb1523810df5277f3d1ececabe9941f80db23cd26f17e0777c91c04d3b4527d2e3ae663da062674f60\
             715bdd89bcdaf2629fcb3d917885eedcf3b193cf0e85f8f2297bdf6f96eb804d1679194fcb192e0ff9c4ffc4ede56705\
             82ca25560bd242115890bef2dd009fbea4a95e5596cd42289272539dfbedbc24b0ea1239442ce36cbe9c5601b8cc4017\
             10838d45b8f75d97ab3798a96731cb475478b0b9850ac0368f535e8168561ad003474e9a25b4c87a7a8cc64a6f8e47e8\
             c3a6d59331baacead41c4b33930a31375da96d765313c73731ed18b52f297125c7e2a78320f655936aaa06ac0a2aa559\
             191cc866626ad2154b6a7e893ecae98ba0e91aa33fb8711e38eda3e27bf05a21fc88ae70b9fc50fbcf2f47af67e4d45f\
             523fe28dc00b3323a42bf126be44dc1e745940658f51b294eb5792b472443ed294e25b21000fe1aa62c70f97c075cd31\
             75ee82e845dda277be6b9afa5dc305153ac991c9d0583cedd96c58f433c0dca8ec5e6df1ff0d41c41c647e103185524c\
             334bd369e55490621929312e60f5fad49a3c1457818a1f09cc09ed29cdc06c8f7dbc25cc89e3a819615b3585bad41e5f\
             24155a48789471dca45edf32667b33eb18f25abe8fd3e75d77ef17bebbd513c180d036d3a22bf70c365eb50532e8540a\
             977ebbc97850628d4638e88caa134f0bb33c4cd0692671f7acb46bdc280eddb6c9f9e3a5e8ee04cd5e62429b5828367d\
             eb4a4807c690b16d9a8749a5c4d5460a1d3ac64c06653ed692ab2bb907fd52c872f96a0231ae021c99ecba684f2b6345\
             0f01056d944d8d1d9e58ece096045087daebc5b7ded71ac89e19a9c3698e81fd6639b2605f526c3b47783e27b6a6eb3b\
             501904a91d6687d71ad7a0bddbbfa5bcc59a021eb0d49b61b7aa21cb8612960d9f5aa1a56e477b5d89969f8f6dbbd84f\
             6b2ffc470f508917a0597200108d055dac1552c7d163d984356273bf5df86b5ae013f05b589bf5b53502d8a9db7a1121\
             9f94a81c325351090498bb17307360a75bf7cc930d44b7870866a7e582b95d37b384b99cbb303dd7fd95bfbec9c8c972\
             8d08bb2038bd93cf4910493c76870a4cfeec7b633997af3892d3acc928df35c9268efce2cdb76b3ff5099e9bc1263dd1\
             3c35637e8f6153adca72527eaeb40d71206ea065d21dc33aa28d07261d35a21159f42eb1bea851b0f6e5ee6e33e535de\
             4ecabd1bbe1bee9c3d9364ef42ccac607409c0d3c7ab2cd69bfce853225311cc25f10a36c626238c7ccf486a81db481a\
             5fdf63524e880f1c0a3b0bf288959de588d5309ed692bba76dd3747dee24b9295e79bd1f0f56521bc5aff0c72bd8acfd\
             eb488ca9ca98c88e4f87d708294d6bddaf6c5392a3a3989afc57af9c8b357405d7551b1cd8a4cd59ca544eba7fe50d94\
             ac1aacb8569d9b7630e96d13139144f8cfe2f76623f8fb8ebd7100f1c6189167015b7078537171062007af27ea6c4b78\
             8473b2c51c03bb29a5f1f0f4dfe0de683c53a3cb7e91e366beb46a4e6658c1b046bb15f7c6317e539aed7202a4e1ba19\
             6f4f7f049e1e7be9aa17d3249eff2b2c84e53e13164291c619e2e8e9bdd721d16f12cfbbc72408f5a382e0a66dab0e73\
             180c56289e0dd1d49b377b5eb2175c99b788836a411f8223f47af5eef7babd43922f4a715a280e99ba30753aab9e2cc4\
             e56ca26f91ee4106a87b72bf4a30c669c8bd7bcd9d52d572f3a68d9db52d49a76f83f855d3d9ba31b81136a4c2ffb98c\
             7e20e905a9d70295414d7da2b151ff033cb4650c1fd95e8b9e0e805d6b956d8c0e404fbcfe3b60697a83f14647567284\
             8be1ebef0a1019647aadb2b6e25562829d9fed3dc0c5dee4000000000000000000000000000000050b141d2328",
    }];

    /// T-CR-MLDSA (TH-68): the oracle's keyGen from the ACVP seed gives the
    /// ACVP `pk` and `sk`, for all 25 ML-DSA-65 cases.
    #[test]
    fn t_cr_mldsa_acvp_keygen_oracle() {
        let mut ids = Vec::new();
        for case in &KEYGEN {
            let seed: [u8; 32] = hex(case.seed).try_into().unwrap();
            let oracle = OracleMlDsa65::from_seed(&seed).unwrap();
            let pk = oracle.public_key();
            let sk = oracle.private_key().unwrap();
            assert_eq!(pk.len(), MLDSA65_PK_LEN, "tcId {}", case.tc_id);
            assert_eq!(sk.len(), MLDSA65_SK_LEN, "tcId {}", case.tc_id);
            assert_eq!(sha256_hex(&pk), case.pk_sha256, "pk, tcId {}", case.tc_id);
            assert_eq!(sha256_hex(&sk), case.sk_sha256, "sk, tcId {}", case.tc_id);
            ids.push(case.tc_id);
        }
        assert_eq!(ids, (26..=50).collect::<Vec<u32>>());
    }

    /// T-CR-MLDSA (TH-68): each ACVP sigGen signature with an empty
    /// context verifies under the oracle, and a one-bit change to its
    /// message, signature or key does not.
    #[test]
    fn t_cr_mldsa_acvp_siggen_signatures_verify_under_the_oracle() {
        for case in &SIGGEN {
            let (pk, msg, sig) = (hex(case.pk), hex(case.message), hex(case.signature));
            assert_eq!(sig.len(), MLDSA65_SIG_LEN, "tcId {}", case.tc_id);
            assert!(
                oracle_mldsa65_verify(&pk, &msg, &sig),
                "tcId {}",
                case.tc_id
            );
            let mut m = msg.clone();
            m[0] ^= 1;
            assert!(!oracle_mldsa65_verify(&pk, &m, &sig), "tcId {}", case.tc_id);
            let mut s = sig.clone();
            s[0] ^= 1;
            assert!(!oracle_mldsa65_verify(&pk, &msg, &s), "tcId {}", case.tc_id);
            let mut k = pk.clone();
            k[0] ^= 1;
            assert!(
                !oracle_mldsa65_verify(&k, &msg, &sig),
                "tcId {}",
                case.tc_id
            );
        }
    }

    /// T-CR-MLDSA (TH-68): the ACVP sigVer case with an empty context is
    /// refused, as the ACVP expects.
    #[test]
    fn t_cr_mldsa_acvp_sigver_oracle() {
        for case in &SIGVER_FAIL {
            let (pk, msg, sig) = (hex(case.pk), hex(case.message), hex(case.signature));
            assert!(
                !oracle_mldsa65_verify(&pk, &msg, &sig),
                "tcId {}",
                case.tc_id
            );
        }
    }

    /// The oracle's own ML-DSA-65 round-trips, through a private key
    /// export and import, so a later differential failure points at the
    /// code under test.
    #[test]
    fn t_cr_mldsa_oracle_round_trips() {
        let seed: [u8; 32] = fstp_crypto::random_array().unwrap();
        let oracle = OracleMlDsa65::from_seed(&seed).unwrap();
        let again = OracleMlDsa65::from_private_key(&oracle.private_key().unwrap()).unwrap();
        assert_eq!(again.public_key(), oracle.public_key());
        let sig = again.sign(b"anchor").unwrap();
        assert_eq!(sig.len(), MLDSA65_SIG_LEN);
        assert!(oracle_mldsa65_verify(&oracle.public_key(), b"anchor", &sig));
        assert!(!oracle_mldsa65_verify(
            &oracle.public_key(),
            b"anchoR",
            &sig
        ));
    }

    /// T-CR-MLDSA slot for moduletto (I-75, I-90, ADR-001 A2): the same
    /// ACVP sigGen cases through `fstp_crypto::mldsa`. moduletto has no
    /// ML-DSA-65 at the pinned commit, so each call refuses with the typed
    /// error, and no case is accepted on a classical half.
    ///
    /// When the pin moves to a commit with crabnebula-dev/moduletto#13,
    /// this test fails on purpose. Its body then becomes the moduletto run
    /// of the whole ML-DSA-65 subset, keyGen, sigGen and sigVer, with the
    /// deterministic entry points that pull request adds.
    #[test]
    fn t_cr_mldsa_acvp_moduletto_slot_refuses_until_pr13() {
        for case in &SIGGEN {
            let (pk, msg, sig) = (hex(case.pk), hex(case.message), hex(case.signature));
            assert_eq!(
                fstp_crypto::mldsa::verify(&pk, &msg, &sig),
                Err(CryptoError::MlDsaUnavailable),
                "tcId {}",
                case.tc_id
            );
        }
        assert!(matches!(
            fstp_crypto::mldsa::generate(),
            Err(CryptoError::MlDsaUnavailable)
        ));
    }
}
