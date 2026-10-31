//! The fixed-input combiner vectors of ADR-004 test vector plan items 2
//! and 3, written again here from the ADR without reading the reference.
//!
//! `EXPECTED[n]` is `combine` over [`vector`] `n`. The reference in
//! `fstp_celltest::reference::hybrid` computed the outputs once on
//! 2026-10-28 and holds the same list as `FROZEN`. They never change
//! (ADR-004 "Freeze rule"). A change to the combiner bytes needs a new
//! `kem` code and salt label. `fstp-crypto` cannot depend on
//! `fstp-celltest` (design section 2.4), so this file regenerates the
//! inputs itself, and `hybrid_kem.rs` checks that the two lists match.
//!
//! Vectors 76 (every input `0x00`) and 77 (every input `0xff`) were also
//! computed outside this repository with OpenSSL 3.6.4, `openssl kdf
//! HKDF` with `digest:SHA256`, `hexsalt` the 12 bytes of "fstp-hkem-v1",
//! `hexkey` the 64 bytes `ss_M || ss_X`, and `hexinfo` the 128 bytes
//! `SHA-256(ct_M) || E || pk_X || SHA-256(pk_M)`. Both agreed with the
//! reference.

use fstp_prop::{Gen, prop_assert};

/// The number of frozen vectors.
pub const COUNT: usize = 80;

/// The label that seeds the inputs. Test input only.
pub const LABEL: &[u8] = b"fstp-hkem-v1 combiner test input";

/// One of the six combiner inputs ADR-004 names, in the order of its
/// input table. The tag of input `k` in the label expansion is `k + 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    SsM,
    SsX,
    CtM,
    E,
    PkX,
    PkM,
}

impl Input {
    pub const ALL: [Input; 6] = [
        Input::SsM,
        Input::SsX,
        Input::CtM,
        Input::E,
        Input::PkX,
        Input::PkM,
    ];

    pub const fn len(self) -> usize {
        match self {
            Input::CtM => 1088,
            Input::PkM => 1184,
            _ => 32,
        }
    }
}

/// The six inputs of one vector.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Inputs {
    pub ss_m: [u8; 32],
    pub ss_x: [u8; 32],
    pub ct_m: [u8; 1088],
    pub e: [u8; 32],
    pub pk_x: [u8; 32],
    pub pk_m: [u8; 1184],
}

impl Inputs {
    pub fn field_mut(&mut self, input: Input) -> &mut [u8] {
        match input {
            Input::SsM => &mut self.ss_m,
            Input::SsX => &mut self.ss_x,
            Input::CtM => &mut self.ct_m,
            Input::E => &mut self.e,
            Input::PkX => &mut self.pk_x,
            Input::PkM => &mut self.pk_m,
        }
    }

    pub fn flip_bit(&mut self, input: Input, bit: usize) {
        self.field_mut(input)[bit / 8] ^= 1 << (bit % 8);
    }
}

/// `SHA-256(LABEL || index as u32 BE || tag || block as u32 BE)` for
/// blocks 0, 1, 2 and so on, concatenated and cut to `n` bytes.
fn expand(index: u32, tag: u8, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut block = 0u32;
    while out.len() < n {
        let mut input = LABEL.to_vec();
        input.extend_from_slice(&index.to_be_bytes());
        input.push(tag);
        input.extend_from_slice(&block.to_be_bytes());
        out.extend_from_slice(&fstp_crypto::sha256(&input));
        block += 1;
    }
    out.truncate(n);
    out
}

fn counter(index: u32) -> Inputs {
    let mut v = Inputs {
        ss_m: [0; 32],
        ss_x: [0; 32],
        ct_m: [0; 1088],
        e: [0; 32],
        pk_x: [0; 32],
        pk_m: [0; 1184],
    };
    for (k, input) in Input::ALL.iter().enumerate() {
        let bytes = expand(index, k as u8 + 1, input.len());
        v.field_mut(*input).copy_from_slice(&bytes);
    }
    v
}

/// The inputs of vector `n` (ADR-004 test vector plan item 2):
///
/// - 0 to 63: the label expansion with index `n`.
/// - 64 to 75: vector 0 with input `(n - 64) / 2` all `0x00` (even `n`)
///   or all `0xff` (odd `n`).
/// - 76 and 77: every input all `0x00`, and every input all `0xff`.
/// - 78 and 79: vector 1 with the last byte of `ct_M` XOR `0x01`, and
///   XOR `0x80`.
pub fn vector(n: usize) -> Inputs {
    match n {
        0..64 => counter(n as u32),
        64..76 => {
            let mut v = counter(0);
            let fill = if n.is_multiple_of(2) { 0x00 } else { 0xff };
            v.field_mut(Input::ALL[(n - 64) / 2]).fill(fill);
            v
        }
        76 | 77 => {
            let mut v = counter(0);
            for input in Input::ALL {
                v.field_mut(input).fill(if n == 76 { 0x00 } else { 0xff });
            }
            v
        }
        78 | 79 => {
            let mut v = counter(1);
            v.ct_m[1087] ^= if n == 78 { 0x01 } else { 0x80 };
            v
        }
        _ => panic!("no vector {n}"),
    }
}

/// ADR-004 test vector plan item 5: flipping one bit of one input
/// changes the output of `combiner`.
pub fn binding_property(combiner: &dyn Fn(&Inputs) -> [u8; 32], g: &mut Gen) -> Result<(), String> {
    let n = g.usize_in(0..=COUNT - 1);
    let input = *g.pick(&Input::ALL);
    let bit = g.usize_in(0..=input.len() * 8 - 1);
    g.note("vector", &n);
    g.note("input", &input);
    g.note("bit", &bit);
    let v = vector(n);
    let mut w = v.clone();
    w.flip_bit(input, bit);
    prop_assert!(
        combiner(&v) != combiner(&w),
        "flipping bit {bit} of {input:?} left the output unchanged"
    );
    Ok(())
}

/// The expected combiner outputs, hex.
pub const EXPECTED: [&str; COUNT] = [
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
