//! ADR-012 `FBC2` container test vectors (R-CR-01, F-043, TH-51, I-81).
//! Lane m10/backup-format, recorded in ADR-012 "Record of lane
//! m10/backup-format, 2026-11-24", part "Container vectors".
//!
//! As for the `FBC1` vectors (`adr012_container_vectors.rs`), the writer
//! draws its container id, data key, KEM randomness, chunk nonces and the
//! hedged ML-DSA-65 randomness itself. So each vector is a container the
//! writer sealed once. The group key pair is the `FBC1` vector key. The
//! writer key is the composite private key
//! `SHA-256("fstp-adr012-vector-v2 writer mldsa seed") ||
//! SHA-256("fstp-adr012-vector-v2 writer ed25519 seed")`, in a writer key
//! file of cluster `55` x16.
//!
//! Each run checks each digest and each header field at its offset,
//! opens each container through `fstp_backup::open_object`, and again by
//! hand: the signature under the writer public key, the data key through
//! `fstp_keys::envelope::open_key`, and each chunk under
//! `header | index u64 | final u8`. The digests, container ids, data keys
//! and the writer public key digest must appear in ADR-012.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![allow(clippy::indexing_slicing, clippy::arithmetic_side_effects)]

use std::path::Path;

use fstp_backup::writer::{WriterKey, container_signature_verifies};
use fstp_backup::{BackupError, ContainerKind, ObjectIdent, decode_container, open_object};
use fstp_crypto::aead;
use fstp_crypto::hybrid_kem::HybridSecretKey;
use fstp_crypto::mlkem::acvp;
use fstp_crypto::x25519::StaticSecret;
use fstp_keys::envelope::{self, SEALED_KEY_LEN, SealContext, decode_sealed_key};
use fstp_keys::{CellId, Chain, GroupId, ObjectId, Purpose};

/// The `FBC1` vector key pair (ADR-012 "Record: container test vectors").
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

/// The vector writer key, from its writer key file.
fn writer_key() -> WriterKey {
    let mut file = b"FBW1".to_vec();
    file.push(1);
    file.extend_from_slice(&[0x55; 16]);
    file.extend_from_slice(&fstp_crypto::sha256(
        b"fstp-adr012-vector-v2 writer mldsa seed",
    ));
    file.extend_from_slice(&fstp_crypto::sha256(
        b"fstp-adr012-vector-v2 writer ed25519 seed",
    ));
    WriterKey::decode(&file).unwrap()
}

/// SHA-256 of the vector writer public key.
const WRITER_PUBLIC_SHA256: &str =
    "974d30f22bf806f87345ada9d43c573383e598c91aa9d83bc2e124054719c5a0";

/// The bytes of a version 2 header before its `ident`.
const FIXED_LEN: usize = 46;

struct Vector {
    name: &'static str,
    hex: &'static str,
    kind: ContainerKind,
    owner: [u8; 16],
    group: [u8; 16],
    generation: u32,
    ident: fn() -> ObjectIdent,
    ident_bytes: &'static [u8],
    plaintext: &'static [u8],
    container: &'static str,
    data_key: &'static str,
    sha256: &'static str,
}

const V3_HEX: &str = concat!(
    "464243320100010104555555555555555555555555555555554c5603a042f02f8a8c8f158f576344a7001000",
    "001577777777777777777777777777777777000000030146534b310100010001046666666666666666666666",
    "6666666666000000019104faacbb40f17ccc32ae70276daa64c5a8c41558f947212dedfd675a07085a7ca82d",
    "46ee983cac9c2c2b3db1ad58e054b1fa370e984e47d82fbc4f9aecc1ad046bc7cca9d335b724121329a0531a",
    "f4557e003f01edd5759f38c697f2fe4a0830448bcbe61209321a1a3c9537d60015046067da1d91dd33b40b7c",
    "e4cb95eb220e925f63ac4a5714ad2efac685c28d0d69a0e6d1144325211c76d2a31b4acb717d363395246c7c",
    "733ac763d328e01b22a12fb1edaec4e78383f9bf1860f3227673b532233b0da9a3873a5558ab46f3441496e3",
    "fe013e82d07d8b035a79e1dcb8efd4d35b6f6a84061002f502214782b53cf98032446c11295646ebfed2411c",
    "8cf137728415e364c18d69cae589333cce0c56b12d59227b8d66c44c470557dac8ca400c4147903b40f6073b",
    "466ecb086e7e6292c011568bb0cbc7235f50a9956b9d0caf467f77f4d7e038a5475b36a7d2ae101616dd723d",
    "455fd30987afa4c2c586980fa0fe74da61552bbe9ecd9b0eee525f15bc04143eed815d8598e8d133280a804b",
    "2ac15ba508fb2b57d9e1928979e4ed7ae4e1018a7dba4b1ba91b6ec2ad67c1ece9a10b2288826da164dce5f3",
    "65986c8401938a740e628a58c81fa525d6e71bd39664d236e5cf24f695ec0bea8a5c5f13f17b4fe097e1d32a",
    "e262a4c85963a6812d6713be35d3f8d14b938a13582799c65eb935cf525a910b61cd04e4bfbdb8a8c94eb5b0",
    "1c1bcdd3682aef0a1e09bf37bea3aa4150a7b1d0ddd8aec96e9bc21af121a3defcefa439a272a4653e107ed5",
    "7d492340b8691771321bbf7f31f8ab9edb8e67f62baa8ec659e3770f8aa1203fefb4c07b32e9455abf02e5a4",
    "06c8faf25cf89d5f5970e91dc1c9e3508b8bd9d8ba976e61988f5e1bdcd79d13d69edfde8cc85e300a70f61c",
    "307a17a8449c5c30172e6ebbaa10b551119b2b08a7250133aaf93add718a1264db71713131f8cebcde9070bf",
    "13f3ddfffc94e65cbf287a8a37a70c6d57bdd7cd993bc663b175f6c3dab0c899655ec9d3a79a298ea30a671d",
    "8690fff6a70f5ab5ab001b07d35b461e050204c2d40ca96488e0bd16b05b1053d10bb68f8bb644996ee57e5a",
    "686117d92728dd7a3cfdfe70de44a293c4647bbeb7a0cd141463da03b95657339e76407cf5171affb8a0ce25",
    "4839e1dec1a55247bae631bd825a203e53da2747c676088b319d4564e563b68d6146f20b59e1f9560efc083e",
    "3e377b4b061175c98a851d78e45086c7429831252ba8597872b2aab75d81e3bfb47640e897b750eba850337b",
    "168e36a4b3d24aafa39548ca719c87485657c775360dcae03c5a87c44ec14c4234abf17921a3eeada0f3461f",
    "fbb39af0bda5bafbc55140658a399d98c9c9e9f219648e38bc8bfeaf3b95312342925751552473e571a38c41",
    "91af04f0e59ec259ac4b5ca3818482a00c2a45c4167e7aa26f8decd9fafc9a8a723ece3c67d1485fe8d89478",
    "19d7b517ee11f15f26c46b40d5788e89051a930690865f0bbf593c4f116ecb35d5770e6c2891363e26966105",
    "93a7cabbac776b9545f507f469125e825d6ae04583743311e8da432492888aa28b8cf0f56427c9cb5eb599a0",
    "16656bc9943b73bcf840871a71c867a6feb8c8625a67ee177ee99700ed98c428723a7fcc2d32bba648141fc4",
    "8a010000002cb0eabdda79ddc286722efa17999f798767a7d22cc58a73d3d75f81b4e7d182bdb7eb917a69fa",
    "a451d881e73f9d06821c200b9941a8a11ab472e449f823f660751cb30b6af357c88ea79e67eb34e9d0906e60",
    "24a5977e066af55f4ac3f6b03aa822da165e5f8c1a4310fae29ddeadf103d6e67eef43806f1e64cc4b069a47",
    "99e216d94428440365c3beffd8b6182183df5f1be59b5bf533d65098f0f83c40ae48ee92fa8b953a93805d3e",
    "09450139f49398484d05f11706b0958ab24eb694032da5f0170fdab73ecba1a03fe137cfa53d4d4ac36dc90e",
    "bd45f13991ab07c708670706499a52356624090b9247fc4ec28047c341733bc2478cc6af4a8e568b898f15bb",
    "e6b6eb93397f0757a8981c0a1cbe16b2dca69a6de540cd51bf2bad033eea3cfdae823114fa052c0617e1bcf7",
    "94ef724331b0893dfe491f0aa35eb488767b7e7bb6fc99293be0a4c2f8ecdd687e53e635bb63d87471db42e1",
    "c41e431d701b8c4b6eac872aa439f7be035389680f1478a7a0403fcc98abf8d77058fe62f9336f76fd2c6747",
    "2ea3fe08232990c25c87b2bbe5ce4bb0efeb619f9fd612a254994adc2f1b0f5eceef2ec862b3f2c0066b1bfd",
    "3f905da5bd45252a1833ec0128ce17f8ab6b46d1005b89e86199382f2acb86732cfe5bfec3f7378997f7d045",
    "3300ee203206f8b4dd8857a2039bf75020d8559afc45898bcf9a7e3a6f9eeb2ace53ef673ba0ae2a6784b556",
    "ce22470b8e853bfd03ae786e4d416155b7c256fcda0cffeb94e70ba8c0fda9d381dc2bed10afd32d6b6820cc",
    "816cf6ab5e008253fa4fa05eefd68ef6fdc82602db31a8d71c169b7f86d886b5a6b1288c93815a8b46ea9a11",
    "5d4f15cdf1b62ca6bf26f5bba83363915cef89d52e6f8092b4b0214778e90517de9363b735ba4d8b1f20a37d",
    "05defc85a0eb418466e8c21d4860f5efdc2a9ca92cfb19cd180feb7ee51a17c076a7574ca9aef115a1d37994",
    "172cecc669c748727359ac11bd3ac0c6c71eca9ed0242421584f6fcb2a7c3eaefbb6912c6225616ed81e140f",
    "7c3a70d904de78f1bb09c9a79dfc2e04690dbb59c9a74e4e7ac6c087acc8279432f9b3342cb28e4b5e99b7a6",
    "d4bce561247f5aa34b08bd94ebfa84bc2ab7ab4709aaa4b1be1a6b3856b5302f39aef5bdd415753a682697db",
    "1fea7a355df9ca8db81ded86ea214e3f89c42c7b33baa1c038ef11b0be26bb8ef4cadb70d0ee5cf9dbc3d9c7",
    "2e9b786ac3480c0beb38defa01ba2431d7c56a92303739c27df4846815fcb7c258fda01d251fee8f050661d1",
    "0c43c1588c4bc650ba295c1d63785045a02092a2b2139fa5e87dd0b4185cbbfd662533e22cb2019549dd07ee",
    "7a6e831e1b2b70017a74d9aed31c77f7b8a9174d176e3e4ef5b848808d70f047679fd89c15135963d381272f",
    "027875310dc1fb3dc351b3dd3b8c9eb2682f823da646057abc338af05b5894066e0c58be8df909f9c0baa66e",
    "d0fec87b1475551ad650ef5e33339784ab019d92606b868944ecf9be59845d3f96febeb54f40e919096f799a",
    "0aaedc6c80f046e3d58531f67e9e5b55d29f94db7ab22728dd67a06f7ddfa7844bfb607159a517b9d4e99c6d",
    "2587ace80246d0523fc202cea7e61bccc4997ca102b092b0870da6b6a201c0c1255064c9985eb2e29acfd633",
    "6ca2876cef757650a0b83120be5abb33eb4d71cde7f108535d452704c6469cabfb75b656fdda1a7655d2a4a6",
    "81a53d2a14c7729774099020e609e61575ac7fafa72241fd1198c24dcc73f466002a306a943cbd810b6ac25d",
    "d76306fa8fbd80fa0052f85fe2f9c4efe0247459636778bee25b1bf173934732b9a4be28d4bb11c362489a91",
    "2cd7bbf3e4b920f73e11f8d53ff45734181d055893bf86030ee7ad9cf090f21a81001e8d35fe406fa5249b0f",
    "dc04da0150deff3e56a9ec85d54b3dfc07fa1925d9ade480ce305eaf6244cce490d0f489483ef49b6cc39321",
    "429877f5c9dbd5e97ab536fc47f71feb7a4e43472a7083e0a332231eabfa13d1772b9ce252b2f5ccaf33fc5f",
    "a33092e7f01c8e5850e3071a940c2ffbb77a61e432e726ff0099eaed255dc71d780ef49393b106fd9acadf4d",
    "195ab412e346f4f2416145fee0eca14c7665e19353bef05c71500bae3a3558893ee952dad879d87080e66f6a",
    "030f251c215cf8e033e20c590418656a7167fb0ac44d9ee589067e99a2910b4131ba74d570178f3af76b9131",
    "5609e264ca5699929922cc73a682496ac22d702dbddf425eaaa7d2cc26f97b00225ce552c58a9e05c42d165c",
    "afedcdc39ef1df6abe228a161d0881345bc531b951fb4b764cb28cdd83b83065eb55c1ba7ed1eeeebc123d44",
    "b25cdc73ff9824c07abe4187ae23bd53eb614daca0337bd58ffc06610f233da8a142f16277659857eb53192f",
    "60e2d6f00493198acb98ed1d931eba1f4c689c8628c1a1ecfe72372179d29e130b656a427492968c5d57f197",
    "b27ada6a01f2f7ada4aa45fb6d594aee3b1767429049c9446cdb978e6afa897fab189989d704eb1aeca477c5",
    "a33cb17e1290710753172c39f87b030cc02ed7275dba3a0d7b20fb746c45cb4432543cc9bf70b4d3d27cdfe7",
    "33fe5a768d3a9b7391b7cec33acfb9128bf7f306a2f143b4e18b0b2babfce5ca5b0c7a0630dbd3c0f5e3cbbd",
    "d7edd8aeb6e5466082e90b82a23b2b15047f087243354651071d0d3025db387e74b7efcfbeb74771eca96bab",
    "28aa5885f4c36f7895ad18b95197f32933a9a9cf0acb0ec48f8535eda363cc7a5ef6e289bb24422fbc2e5718",
    "b9dc798c99cc307e1a3c96ce183f6437f45dd30aa9006ac95fad9b54af1fcf2f6541d8bd08846e0fce325b65",
    "63c69a0c4d28a36e09e764a0d542be5d2e60c6bad6cb1e43d88f69f8e08a4522309231a45c0d066e7577799b",
    "9caca46b324dac0b3fed6d2e69608a943d03194ff681fd83e6e8c244663c6613403f28e11b71069928de71b9",
    "b295769714d4c951a11493b3c6cc591f400dc6180fcb94896912297e03ca97b421168f13fa738f217510b86e",
    "8e534e81d6c4ad0f463ccf9f2cef2178a5627775def77aa94a6585fc7792d40ff20c9a6a9251986f8d88462d",
    "f1fee35b4a9792ae5d6a6c256a664f80a12e3ceb492083b0dbfd2ecbe3870c0d80d465668bd4be37f3aa4bcf",
    "15422e2324930db640abadc12812414cd7c16a67bf83fa335c4ff62680ba70b285db571642ba0af7614b1b8e",
    "92af393a60d3fbab38faf35994132e63a04b6738c61f4f7c67e735cdc0d925aabfe7d14d9fa1293d735ffa53",
    "ad6d229b12ba88128a3cfad355d2184903df7a53ae4d5b2673da041ea91275fc76b7d00cd65435aaf432f3c6",
    "f64282b458beff05b59fff56bcb4d095b44192e042e2cfb61e2d865b9f33eb006ee52a483e9cae1902e12711",
    "53bf34b03495eae5727915700014e79e592c6139baf2fd8f45be700f5af5fa6c4f054fa22211d029d7d7645d",
    "a358ce3f3f10409951815acb83d077a334d16a7d7c16621dc5ee0a2c99568e4454039d388dd5dc9ed3454ac8",
    "2fa118775ab50b37d12c808d1b014127ff47e5164c0867a30a80d97abb3f0adf24c9e46ac0d159020e7dec9d",
    "4fe1606a1179a4427e09afe60a779a43b7da27124023e0d0957a265453cf25fb5e10709b58183a83602a4f0f",
    "685a3a76ff9327ca72d47bbe35292f751827a81be4087aa2fc13ad94539eda07c88e80405168f44acf3485b5",
    "e926d6363b7223ff545fc81b18235065462c7bec7d1b409eed82b8f52087e029ea67f4b990b00ffe30e9da13",
    "ec3efb1538c606b94d28256fb8044f85498a7279799df5f7cff958e51fab7df0e6e61344e440e9f4415c1de6",
    "db7428d369564aafbc449dfd5624da667df38448ce93fd657d3388ac19143427ff1cfcbaea22352a85c0c547",
    "fdb5686cb02e67031c6e773aabbd700f4129a4aaa530c81f81d521a40f535458b51d0b84927077f3006e4c65",
    "84029c68cc69cfd8329b74bed5676cc6a4d445115a873b08a244591200ea65e364b1caf03aa03131e25c3824",
    "68a4fb6005a8d86f219d065b1d53c41ef1aef737981fa141732ceef4af004eba85e5d1b59241033e020ab8f1",
    "c1454185a0174aeb4a987c08887b0b4a733f54d33f7c3a1eb38511099f1a69b6e2778737886f5b80a2b4dd8f",
    "2dd72d68b5d7c72c6189ab438fb9f7936f3cd295fa0dd00c5af3ebfda0ed0c3a70bf2b44b3acc5cc9bda3216",
    "713a75e7347a327c7c846f27c70e7f5328283780d1f6a617b39376c3f0aa95f1f8f5f6d52b5237058852280a",
    "21d73d6aa4cf3a889d7f9119dcf72e4dccc2c8181b813f7cf4c6195a0ecc4882c259c4f87228402a35af8ee3",
    "470f29978dbc4f3f7ed18cd3fc6f338c82342df1e1dbdbc1a7de9af8ab6c9478f3dc03cab3d64f8434e65144",
    "599f91854e595d77f4966b2a46c6bb7dfd295b1eab3cd764936e2bbe93dded90ef758e724948a77655531f20",
    "fae0cff9101a9994a4013b275d755750b41fabda3b0df4742074c03d17d631b3992adeb25a8ad76a0a8eb4d1",
    "26586d370780d81e23ba83ba5573447ea4f02145e524ef11b721f2044db79d882a6acab8f8384b6786fda1aa",
    "a21416b6ced4394b4a6f72628d462ddad3b9d076c7873da819e6843590023c2a980eb1ee30e0f6b5f55ae1c1",
    "1157e6dc3682d3188ee626765c7359f2582af1b2ec064ed17cd73d6081d3f6051c264558bac1fc0f4f73889e",
    "aeb8010d1e3946696e73c430667b7d95a5c5d2e7eb2a8fa2d4e0edf1000000000000000000050d141d272ea5",
    "3b5dcb1c0e3fbd21e9bb270b1653cf35009ed377f5d50d8864755a9c2a9803de46203183fea1a144103ee1d5",
    "3f0670c507cea5af57686be647617ca4755d0e",
);

const V4_HEX: &str = concat!(
    "4642433201000102043333333333333333333333333333333340bf35a091981469e808612c61fb8248001000",
    "001830303030303030313030303030303030303030303030303246534b310100010001044444444444444444",
    "444444444444444400000007c13f0a8a7f3865ec6473c9e401c3d2f687f37af45e83023ef0c2a80b2597cf71",
    "a653f97ee5e51f138e9a895f2f584381cec5ad2b0e03731db8afaaf1b617b45d4b910852e7efdbf75fd9ef6e",
    "051edee30b3beb64d94dfcc28d6ccc8368e817f002e9bdb13544cb3cbaf046149c7cb634140c8364adddaf90",
    "6c34a09b4902c870a109ed9f7733876845cf043afcb00836b44a670276a6b9f460da10f5bf0317d82760316c",
    "10600fc5f7bd8978476dbe10e14bf3aed8b90d9789c3dc1315da652de60af1625733083d288d7583fbd27b28",
    "caa12b0d02f7ccc3df4e0e890d824100ebddc6cc23e8186a27fe023e794e1affb2831f1e3b3792d2e713812a",
    "5ff53ff7586d19afa9367e2b40cebeb7557adf8a49da8896f59bfd6e7a8ef1e081f62c5ef8286821ba698f8f",
    "7e2aa9925f4f355efd703818402e7403d934e5b80a6550307f970dfab17fdf3eb4fdef3f3c698f72c4adcfa2",
    "a4bd5e550ff043ed0239b2104d4f20906d760c1ddd5912cce2907ec7a274768a66586a804f23c59ba582821c",
    "d077f1d0c7d5f2d19c52aee360ddc4015ef4cbcaeb4629ded497182c0246f20376e423d201cefe69b8e7183c",
    "e42c9733e4c95ed550cfe05e042a8d4873adc86927134b70f1409783309aea7f225c445be47dbdce3f098eb2",
    "ddfeeac62a11dafc95ea494fccf6c46f2b7f71da59b8d19419606a731e9491da585abafb86d1ad266a53aa2e",
    "d51202d8aab618060f0ec89feb5bd70f81df31aa1bfc41171404285ad20f86cebfdb3f9c4970d1722cdc7d92",
    "5b74618e70192766c1d4e02274228f9c3842f167d6e6da0f5f8e0e142ac933a4a94f2bfcb63016b215a5de77",
    "8c7fa9f784f7e9360f69ae773bb1a9ce2c139691ee6e227a7f64e2048803269bb0ab4d55f5370ad82abda4cc",
    "ef7c9e0f417c2e9c84675626071f7366bb452c2c90da5b598c6975f350aa935feefb8da0b0721fa2a52bc108",
    "c7dd85b9228789d08446a0c0b17f30a6e33525b8c411b87a8a63ad819bf9f6b9b6599d1b062babfc20a54c65",
    "db200d945ed39d70a674c6d1e3a9bfecdec1424c7ac13eabf0547bb5a44eee9825c63f9570ef3349da272d4c",
    "6529fe0c9ccd0c17bc22d924e88c3d28fbd308beb9e47bc9f03752aed734d60faf298c77456f1cfd79260cf3",
    "d0ccb34e70b2f52bc6a9507f958327fee381c65765ed9c626978cd41597d98699475a27c70075199864ff20f",
    "1d2f3a43fab0bdd381fd6deedad5d84b78dec31858f2f2fd905c04f9c85f75031aef806d2e0ef7216a089f39",
    "e021b85211d947bc0217d95ba5c4dc90e82e06d5eda6e3cc07fb249ba35420db10b83670d0d63c7cc73aae9e",
    "47991fa356a46a4358121a33322ce0dbdfb70067aedcfa85ce544a48925579fac42c039495e579706b9d6c6d",
    "7819c9dbea4c072d2deb92fb213d8639307ce444ae50d447fd52f40b28c2940a9aeed18d0af3128e40f48934",
    "3dae2f0125212d0de386c0fb46433b67aea2d9e7dbb35e7965b9f8637f547c1bbefb6bca097c943df140a1aa",
    "da0c7f2ba096fd4cf15fa83ff3459d6ff05163daa37c626079036ab944208c1ccbffe703938ebe9be00b5619",
    "c814e4147ce85fca6cb956daaea33ba9eebea62ae54fc4bf35707126528555defc7a3ebd3d90482f27325501",
    "4080b0c301000000277d658ce1f7ef716320532d2d36bf547b06d92fb35b0c1fdf4d8f0f52a30fbd3b59a7fc",
    "6407c5e4443abbafb490bfdcabad6b86f93f2afe17ec4aeefb2ef51a18e6a802ae7f7e02d6a6b3bf097f0dd1",
    "b3865381f478ed6baa13450b50e7ab000c55103bebde6f19fb0eb5102bf1617abe8ad69d8b68bb8713db0693",
    "9fa4f3fbc69b9dab6d1eff6d5e0fae350549ce3f883c5cedd501ca9a6f0f1c17784e854a08c1433f3ce6cf1e",
    "a83c2f7eda4aa91e3ce1354dfb7937642a2771cea5b4c7f332b707a64e13b81088e9d732132223d66ac6f859",
    "b96c3468ef7bc48f6cd37b85f4921fa8d8df3ec863a12b23cf33b8af9d6100634cb044479fb8ca01947d9988",
    "04568a1de3a00a4291f88a3bffe77933b34934431af5ed8ffb6d6ab65c94d890083195754688633b36bccc17",
    "963b49eececd6b34268385898f4ec0b2550a2c8bcb52300ecb2d65d82aeeb517c2bc85702062d7f67a336284",
    "1204a16a59053cee9b98027afc44aeeb939decd579174037d969574aa47a4d41f9b518843ce0a55bf5acfa1c",
    "acd1a5bcea111fc5140e0af8f1d99c8864b793c804f6d9c5fe36b76d24cf1828de66d8a65b4623cd9cb27cb2",
    "b366913e323b1d534cedfeec4a5dce469d746b9a62dbb3aa784bc639e8e097179f731651655dcadb91058540",
    "8f6ed19c7642dbea63192e511f8c571b4216fbb4207aa63bf879ebe1798b6037dee2e16ca260a25ec4d308c6",
    "e37f0bcec2918aef59a95d56acb74de5ecda130fb9abfa6b47653b7e44530d2a33e6bb4c301dcf325f8db4d0",
    "c8549fbd00019675881659ad935fa930c94a2e8175876e13e162debd3c93e9c8c29ab982a923b5a0325300b1",
    "9400fb07a9bf6b42220392d24758e419755f0953691d7665a74b16d90bfb7704c5155dc7089b86bb2aed4430",
    "c3b19ea157a2101e15e6df2c497ed5601bfebd536008fc0c9a9f3bac6ea4f3954ecf76eefe4c5254667391bd",
    "131f7bce5d5a7f8af387fa102f49fba9ccbbef7f66b2c1855945c7a9ef072a5cf8b2a09cc5186ed4333cfaff",
    "85c9fe0bb9c35e9f553dd2d41b28228e760d8b70b13f80aa608c5591193765bac6e3139ad96db09cdd7cdea9",
    "b437674b560e2526fc67f7746ae686df33272b11d042d2306acce0cc3ddec4a742930e7fda20313abedb8392",
    "51ecd08a3b38d22a5ef3eef5172da20ff91b40021305fe662d7e82e497c560aaea79ad0133b0cb8265a0c8ef",
    "c4bcb185af81c5aafbc7a8346d87d7b5501df7fdc0607cd86f2d5632890143b13aafc6516dd5c3a14682cb20",
    "c4b7b8c4bbaff3a31287f98e1ca7b21d6d363278f325941ff263b9bdf945ceff90790e927985e9751b437ede",
    "16d6e298dcdd444d4dd2941ca72f8c277564f25cac5c3093f3fb17de236e94a8d2a19666fa1ee48d78d64f20",
    "326f0104b74bff546580e89eab2c7444a4e528a0269d8c7cace5d23fbc6e749324eb07a321fc1a553c665063",
    "86fd754013c945767c22f72cccf3ba411fbdd9af3469825efc87049d77479c8a8d8f57d1d28c190873701315",
    "af3235cc50b2cf3ed6df38dda0dc5f96cd68320575812ae69103f762cecf5ad2a573691d3479e1a7a94bb033",
    "ea9b89f5a5259012c8be727081b786000758c7fb4b72230962d2fc615525696e30c6961b24a0350945ac5819",
    "eeb38de7f0666397ea3beeef5fa5bde7023e642b330ab3237fd7f06d48f509db5430e0a0782635b3947d7622",
    "8a0c6c610076996ce9191927042b68803587a4993236bf96a1830b8a7725d5bdd30db4fce5e76cbb439fc31a",
    "c525ee86febbf22c075744ec93e0bbdee31645fc72b3731030cf4aa53987925c5d6c22333d4eb7ca57f82277",
    "1da7b6a75bea99f0305c66fad349b00a75b18d9b2573d609cc5e2bead0f5f3c07810df15ef0fd12ec5ed5cfc",
    "72e82f6312bdcffb9d01599d111fce51e5830919de014f820c9d4f152e3d9fed3a8f0acb3d36d2f8443919c9",
    "514baa9e7b94fa8f1fd82f6edbda83df249061bb2f0f6c7b5d20204af487a6c6e7532034dd4390efe2df5623",
    "752b4f55ac5f1d4421ce065f5264ecc941be8a426bf7e4787a50cb2690bd7d63f3c42b80e9aac344b53eb737",
    "453a54f402d9ace447e51698818512063f547555c67c3b7824fef5ac58410e8a723d8a58b11be954db5fc703",
    "fe4529f3e49061c85043409e6e897341fa0f9c31905abf2bdbb863feca584ad242f8b37186e1001a68ed7279",
    "d41b698b8d0d4fab63178915b222f669f11a32ecb2d2b3440497d3cc3527becd79de1dae537010728b5fc82e",
    "41fb827e31277b1028bba00f1e8911affd075fa0590991d8741c958c910473c0bf305401110dddf947ecbb55",
    "79e7b00f54ecffecdca1a3cd39f7a183d9007e5b925b83df1461a6c5749594e965443487067d8e866a9db06d",
    "638e46836a5175b418b78639a10138b586e4d050e368c6b81560291a31cdd14f20670aa8350236e761e30bc8",
    "9ba6ca507fda6f9a80e2e6c5e289d4986e59d086e10f6420037ad21fb9063e6e896900600483f71cd72ab2bf",
    "1fcf038a22173bfa23123860312005a308d08e9f0419070915da3100346d77fc53803ffd56700b24f2f09f31",
    "91361373ae3c43b6b40fce42814ca25d6555852d4f8eccc04e6a5ed79dfd1ba279c9b16b7c70ffbcb3f12f31",
    "25a6414f7b723d4168c475c2d5c498ddd45575cee44b4f99158116cd6d557750d75026d4a090076ab2d67863",
    "e4d9647f75794332ba422ba71660615c0e44b8339810d4d7733e56bf919474bb5abdd63e1b36d5de6efe11b9",
    "decdc01f8aac04bf8cb18a158313bef8a66c446fe492dd79fc613e8b33489f840394c71e4bf10d7dbbe37133",
    "a4358a1326a47894b502ca11333d9cbe892f6ed827348346a1f8b74700dc4d333780784846820199e5918013",
    "64531e6e112192e1cf1a309e7002040bf4a854d36522f35e91bc534a1ab1a2faa45d7a09d8e3cd7ec32fd006",
    "07d8ac5c9a096a49bd4d8fff0bec6921ad126dcb649e0d05838abe5ec02809a7fb6de004479aa31d6447bf86",
    "2e4d1374cb8947c529c538d237bc3f56eb617dc666682ef5be8ee1dc34d32dc2638ddb4b7800766330abe55f",
    "696ba88a947d416d56f66d9665a885f7104612e2bc2a197605e7842967930193404c3b7de141706a6d353ca1",
    "e0b16fd9b76f329fbf37c0a73baf20feb3f92a26c14abc84985b9f21561dde2364d91000de365cf5135ddb5e",
    "0eb971e20adcf7c094ac68531382680de324f71ecdcc3aa4cede40205517b4b60b2fc752bb8bbe22a22b32c3",
    "814306b6a17de29b43cf75d262f70310b191d6f2749245cad6f2a97bd7c763526eb063a62a71d2cfc29c8d92",
    "191be334e222609f749d09dfa43eed3b3464f45fb33d5e0e7b4ca0b045a205cb8225594a709534a2582e45dc",
    "400a62a97b0ca18bfa7afb0e10de69cf554dd6faed0e67e5f4e3e679f958204b26ff190b0554cf4607d502dc",
    "d098936bfc8259573ce86c9b9bdeb87ad0c16b61ecd1bf62acecba17614dbafe6055b171d41864472f1eb70e",
    "718ba6d71e8de1ca3b789fa85fa1dab4bff260438da8ee9e224a645b346301a36e7cb4fff891f83c77e03bbd",
    "958c62669726e5898dfcf1d2f280944c0cc3c3891e8faebc95c286a9502fceef74ea32ac1d484134fd356d9d",
    "2794c15a4b7c87ae7551f43fa831f11876cd658539cab555e7210d473b0fe65c268ede8741002f5af9116d1c",
    "8490a6de627e1915d72e42478ee69bcfcc3738aaf0c8f07e001087b9c6d8c490dc8e93125310bb3cfbd835d9",
    "cc8393dcb7a611a0d1374878f0cb19130b61be3ac7e444db1e32e104c905a824faae5c3fa5e7a5b79003aa57",
    "cef33b3adf63577c3af6de8946b74d6f05263ed9891340fd3b68760f0eeb977d075a4be4453ae05a687a2336",
    "1330723994d9294d93fe6ff0dd1f74bb2bc67a0df8cdd01c4bd83023eaaa0d4d543bd87cc8a142c6ee37c239",
    "1fab4828344e11cabc40b3084ea35c2c29358ba624b0780c9613d6aa77c1ce4a6b224cae6626003d61a8c073",
    "0d4d9122685261896853e098eb6c1b9c65c0ddc96d8bc2506f960cc3e878367209b9decc5948c5c91130ca8c",
    "e9b8df5f8302bedc0b97d8c3337adf71fe581bcce66b18a281384e8926413a099138b3d593f8f8ec96eeea57",
    "08cda869d9d67900d3c00be2f2374897a2242d00fc3af3e1560adff9331063e30120d4acaa053275479c882f",
    "eb37d1a8276b73c93a8b0c3d7effaa1c71a23a8f099699c7782e46345b1f8af56dfa860f37da1c25a913ddb1",
    "9f79ddb2e9865385e3f8df59d602f2a3030be971307bed7e24a28d2c93fd263f9c5eefa6098a588ac6502594",
    "13f57220f31b593b6480a5aa670d1319c1863aeb67597087307b0783686f1293ce251593f07855b5b5b6219f",
    "6a91758a68553b8af94bc2e874632d7b0e58f969b225e40cc86cf44cf6662320a7e4d5fb3c5b097c69b14b9f",
    "74e21c3e677930db25a11ac63862bdbf4f7906554dcd597108b6576ad0ba3a74b8aeb08e586f0655c38903d2",
    "d507e4b0a964131cecd4a9ecdb241c69b7d9e8c5fc7506dcedbd41e0bf68ca1ad12e302c3b9e84983548c156",
    "b08f06d96b817534aa8e29fe4f81f55bbdf2b9b878d2d5f92398cd82015800667fa1583cf36c392d18dd65d6",
    "f48d9e915afaa98f2dda3b45214f61652a271482df675c682e2fcd151d4b75b4d9e2063ae4ff42505b6cb9c0",
    "01090c3437a4aa383a9f00000000000000000000000000000000000000000000000000030a0e141b1e55d25e",
    "11d73ca0f2d73bc73814fbb0b9a93c1bf62cb2f285001a7ad29998f7e1476df692e4d2af02c601936ca0e269",
    "494e8fa7b3d70dfa590297d3127f7efa0d",
);

fn vectors() -> [Vector; 2] {
    [
        Vector {
            name: "V3 base backup part 3, the last",
            hex: V3_HEX,
            kind: ContainerKind::BaseBackup,
            owner: [0x55; 16],
            group: [0x66; 16],
            generation: 1,
            ident: || ObjectIdent::Base {
                backup: [0x77; 16],
                part: 3,
                last: true,
            },
            ident_bytes: &[
                0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77, 0x77,
                0x77, 0x77, 0, 0, 0, 3, 1,
            ],
            plaintext: b"synthetic base backup part, ADR-012 vector 3",
            container: "4c5603a042f02f8a8c8f158f576344a7",
            data_key: "b9dcf7872e5c68d1fada18aec4fd527af32f51f601d98d0d38b0005030561fad",
            sha256: "3871e3a520c60bee6cc07018e26248e587b6e421aa45f1c158db58237a66cf93",
        },
        Vector {
            name: "V4 WAL segment 000000010000000000000002",
            hex: V4_HEX,
            kind: ContainerKind::WalSegment,
            owner: [0x33; 16],
            group: [0x44; 16],
            generation: 7,
            ident: || ObjectIdent::Wal("000000010000000000000002".to_owned()),
            ident_bytes: b"000000010000000000000002",
            plaintext: b"synthetic WAL segment, ADR-012 vector 4",
            container: "40bf35a091981469e808612c61fb8248",
            data_key: "7b25ec400ccbbb53de589298b2c63cd666b3902b8294c43184f548d94748370b",
            sha256: "65965db5f92ad2e367ce3fc442103f3acd87595a3ff76ffcf684a01975be3ec5",
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

/// F-043, R-CR-01: each recorded `FBC2` container has its recorded
/// digest, carries every header field at its offset, decodes, and opens
/// to its plaintext and object through `fstp_backup::open_object` under
/// the vector keys.
#[test]
fn f043_adr012_fbc2_vectors_open_through_the_opener() {
    let sk = vector_key("fstp-adr012-vector-v1");
    let w = writer_key();
    assert_eq!(hex(&fstp_crypto::sha256(&w.public())), WRITER_PUBLIC_SHA256);
    for v in vectors() {
        let bytes = unhex(v.hex);
        let n = v.ident_bytes.len();
        assert_eq!(hex(&fstp_crypto::sha256(&bytes)), v.sha256, "{}", v.name);
        assert_eq!(&bytes[0..4], b"FBC2", "{}", v.name);
        assert_eq!(bytes[4], 1, "{}: version", v.name);
        assert_eq!(&bytes[5..7], &[0, 1], "{}: aead", v.name);
        assert_eq!(bytes[7], v.kind.code(), "{}: kind", v.name);
        assert_eq!(bytes[8], Chain::ClusterBackup.code(), "{}: chain", v.name);
        assert_eq!(bytes[9..25], v.owner, "{}: owner", v.name);
        assert_eq!(hex(&bytes[25..41]), v.container, "{}: container", v.name);
        assert_eq!(bytes[41..45], 1_048_576u32.to_be_bytes(), "{}", v.name);
        assert_eq!(usize::from(bytes[45]), n, "{}: ident length", v.name);
        assert_eq!(
            &bytes[FIXED_LEN..FIXED_LEN + n],
            v.ident_bytes,
            "{}",
            v.name
        );
        assert_eq!(decode_container(&bytes).unwrap().len(), 1, "{}", v.name);
        let o = open_object(&sk, &w.public(), &bytes).unwrap();
        assert_eq!(o.owner, v.owner, "{}", v.name);
        assert_eq!(o.ident, (v.ident)(), "{}", v.name);
        assert_eq!(o.plaintext, v.plaintext, "{}", v.name);
    }
}

/// F-043, R-CR-01: each container opens again from the recorded layout
/// alone. The signature verifies under the writer public key over every
/// byte before it, the data key opens through the hybrid KEM under the
/// seal context (owner, chain, purpose `Backup`, group, generation,
/// container id) to its recorded value, and each chunk opens under
/// `header | index u64 | final u8`.
#[test]
fn f043_adr012_fbc2_vectors_open_by_the_written_layout() {
    let sk = vector_key("fstp-adr012-vector-v1");
    let w = writer_key();
    for v in vectors() {
        let bytes = unhex(v.hex);
        let header_len = FIXED_LEN + v.ident_bytes.len() + SEALED_KEY_LEN;
        let signed = bytes.len() - fstp_backup::writer::SIGNATURE_LEN;
        assert!(
            container_signature_verifies(&w.public(), &bytes[..signed], &bytes[signed..]),
            "{}: signature",
            v.name
        );
        let sealed = decode_sealed_key(&bytes[header_len - SEALED_KEY_LEN..header_len]).unwrap();
        let h = sealed.header();
        assert_eq!(
            (h.chain, h.group.0, h.generation),
            (Chain::ClusterBackup, v.group, v.generation)
        );
        let ctx = SealContext {
            cell: CellId(v.owner),
            chain: Chain::ClusterBackup,
            purpose: Purpose::Backup,
            group: GroupId(v.group),
            generation: v.generation,
            object: ObjectId(bytes[25..41].try_into().unwrap()),
        };
        let dek = envelope::open_key(&sk, &sealed, &ctx).unwrap();
        assert_eq!(hex(dek.expose()), v.data_key, "{}: data key", v.name);
        let key = aead::Key::from_bytes(dek.expose()).unwrap();
        // One final chunk: final u8, len u32, nonce 12, body and tag.
        let c = &bytes[header_len..signed];
        assert_eq!(c[0], 1, "{}: final", v.name);
        let len = u32::from_be_bytes(c[1..5].try_into().unwrap()) as usize;
        assert_eq!(c.len(), 17 + len + 16, "{}", v.name);
        let nonce: [u8; 12] = c[5..17].try_into().unwrap();
        let mut aad = bytes[..header_len].to_vec();
        aad.extend_from_slice(&0u64.to_be_bytes());
        aad.push(1);
        let plaintext = aead::open(&key, &nonce, &aad, &c[17..]).unwrap();
        assert_eq!(&plaintext[..], v.plaintext, "{}", v.name);
    }
}

/// F-043, TH-51, I-81: a recorded container does not open under another
/// writer key or another group key pair, nor once an identity byte or a
/// signature byte changes.
#[test]
fn f043_adr012_fbc2_vectors_refuse_another_key_and_a_changed_identity() {
    let sk = vector_key("fstp-adr012-vector-v1");
    let other = vector_key("fstp-adr012-vector-v1 other");
    let w = writer_key();
    let w2 = WriterKey::generate([0x55; 16]).unwrap();
    for v in vectors() {
        let bytes = unhex(v.hex);
        assert_eq!(
            open_object(&sk, &w2.public(), &bytes).unwrap_err(),
            BackupError::Malformed("writer signature"),
            "{}",
            v.name
        );
        assert_eq!(
            open_object(&other, &w.public(), &bytes).unwrap_err(),
            BackupError::OpenFailed,
            "{}",
            v.name
        );
        for i in [
            FIXED_LEN,
            FIXED_LEN + v.ident_bytes.len() - 1,
            bytes.len() - 1,
        ] {
            let mut moved = bytes.clone();
            moved[i] ^= 1;
            assert!(
                open_object(&sk, &w.public(), &moved).is_err(),
                "{}: {i}",
                v.name
            );
        }
    }
}

/// ADR-012 record of lane m10/backup-format: the record names every
/// container digest, container id and data key of the `FBC2` vectors,
/// and the writer public key digest.
#[test]
fn f043_adr012_records_the_fbc2_vectors() {
    let adr = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/adr/ADR-012-backups.md");
    let text = std::fs::read_to_string(&adr).unwrap();
    assert!(text.contains("Record of lane m10/backup-format"));
    assert!(
        text.contains(WRITER_PUBLIC_SHA256),
        "writer public key digest"
    );
    for v in vectors() {
        for value in [v.sha256, v.container, v.data_key] {
            assert!(text.contains(value), "{}: {value} not in ADR-012", v.name);
        }
    }
}
