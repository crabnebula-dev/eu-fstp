//! The theme checks of I-69 and I-70 (M4 design section 3.2, rule A10).
//!
//! WCAG luminance needs the sRGB transfer function, which has a power of
//! 2.4. The crate has no floats. So two `const` tables of 256 entries hold
//! a lower and an upper bound of each channel's linear value, as integers
//! scaled by 10^12. Each bound lies at least 2 * 10^-9 from the exact
//! value. Luminance is the integer weighted sum with the WCAG weights
//! scaled by 10^4. A pair passes AA only if `(L1 + 0.05) * 2 >= 9 * (L2 +
//! 0.05)` holds with the lighter colour's lower bound and the darker
//! colour's upper bound. So it passes only if the exact value passes.
//!
//! The tables were computed once with `f64` outside this crate. The test
//! `i70_contrast_bounds_enclose_f64_values` of design 8.8 recomputes them
//! in `fstp-api-testkit`, outside the float lint, through
//! [`linear_bounds`]. It lives in `fstp_api_testkit::reference::creator`.
//!
//! Interim, pending Daniel: the M4 default theme tokens are defined here,
//! because no other crate holds them yet. The web lanes take the same
//! values for their CSS tokens.

use std::collections::BTreeSet;

/// An sRGB colour with 8-bit channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Rgb {
    /// Red.
    pub r: u8,
    /// Green.
    pub g: u8,
    /// Blue.
    pub b: u8,
}

impl Rgb {
    /// The colour `0xRRGGBB`.
    pub const fn hex(v: u32) -> Rgb {
        let [_, r, g, b] = v.to_be_bytes();
        Rgb { r, g, b }
    }
}

/// A theme mode (I-70: light and dark).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ThemeMode {
    /// The light theme.
    Light,
    /// The dark theme.
    Dark,
}

/// What a text colour is used for.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum TextRole {
    /// Body text on the page background.
    Body,
    /// Secondary text on the page background.
    Muted,
    /// Link text on the page background.
    Link,
    /// Error text on the page background.
    Error,
    /// Text on the accent colour, such as a primary button.
    OnAccent,
}

/// One text colour pair of a theme.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ColourPair {
    /// The theme mode.
    pub mode: ThemeMode,
    /// The text role.
    pub role: TextRole,
    /// The text colour.
    pub text: Rgb,
    /// The background colour.
    pub background: Rgb,
}

/// A mandatory element of I-69.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum MandatoryElement {
    /// The funder visibility elements the funder profile requires.
    FunderVisibility,
    /// The AI assessment disclosure.
    AiDisclosure,
    /// The privacy notice.
    PrivacyNotice,
    /// The accessibility statement.
    AccessibilityStatement,
    /// The Data Act information for tenants.
    DataActInformation,
    /// The platform attribution (P-68).
    PlatformAttribution,
}

impl MandatoryElement {
    /// Every mandatory element.
    pub const ALL: [MandatoryElement; 6] = [
        MandatoryElement::FunderVisibility,
        MandatoryElement::AiDisclosure,
        MandatoryElement::PrivacyNotice,
        MandatoryElement::AccessibilityStatement,
        MandatoryElement::DataActInformation,
        MandatoryElement::PlatformAttribution,
    ];
}

/// The theme the report checks: its text colour pairs and the mandatory
/// elements it shows.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Theme {
    /// Every text colour pair, light and dark.
    pub pairs: Vec<ColourPair>,
    /// The mandatory elements the theme shows.
    pub elements: BTreeSet<MandatoryElement>,
}

const LIGHT_BG: Rgb = Rgb::hex(0xFF_FF_FF);
const DARK_BG: Rgb = Rgb::hex(0x12_12_12);

/// The M4 default theme tokens. Every pair meets AA in both modes.
pub(crate) const DEFAULT_PAIRS: [ColourPair; 10] = [
    pair(ThemeMode::Light, TextRole::Body, 0x1A_1A_1A, LIGHT_BG),
    pair(ThemeMode::Light, TextRole::Muted, 0x4A_4A_4A, LIGHT_BG),
    pair(ThemeMode::Light, TextRole::Link, 0x0B_57_D0, LIGHT_BG),
    pair(ThemeMode::Light, TextRole::Error, 0xB3_26_1E, LIGHT_BG),
    pair(
        ThemeMode::Light,
        TextRole::OnAccent,
        0xFF_FF_FF,
        Rgb::hex(0x0B_57_D0),
    ),
    pair(ThemeMode::Dark, TextRole::Body, 0xF1_F1_F1, DARK_BG),
    pair(ThemeMode::Dark, TextRole::Muted, 0xC4_C4_C4, DARK_BG),
    pair(ThemeMode::Dark, TextRole::Link, 0xA8_C7_FA, DARK_BG),
    pair(ThemeMode::Dark, TextRole::Error, 0xF2_B8_B5, DARK_BG),
    pair(
        ThemeMode::Dark,
        TextRole::OnAccent,
        0x12_12_12,
        Rgb::hex(0xA8_C7_FA),
    ),
];

const fn pair(mode: ThemeMode, role: TextRole, text: u32, background: Rgb) -> ColourPair {
    ColourPair {
        mode,
        role,
        text: Rgb::hex(text),
        background,
    }
}

impl Theme {
    /// The M4 default theme: the default tokens and every mandatory
    /// element. Branding packages arrive in M9.
    pub fn m4_default() -> Theme {
        Theme {
            pairs: DEFAULT_PAIRS.to_vec(),
            elements: MandatoryElement::ALL.into_iter().collect(),
        }
    }
}

/// 0.05 in luminance units of 10^16.
const OFFSET: i64 = 500_000_000_000_000;

/// The WCAG weights of red, green and blue, scaled by 10^4.
const WEIGHTS: [i64; 3] = [2126, 7152, 722];

fn channel(table: &[i64; 256], c: u8) -> i64 {
    table.get(usize::from(c)).copied().unwrap_or(0)
}

/// The luminance bound of `c` over `table`, scaled by 10^16, plus 0.05.
/// Every term is below 10^16, so the sum stays far below `i64::MAX`.
fn shifted_luminance(table: &[i64; 256], c: Rgb) -> i64 {
    let [wr, wg, wb] = WEIGHTS;
    let terms = [
        wr.saturating_mul(channel(table, c.r)),
        wg.saturating_mul(channel(table, c.g)),
        wb.saturating_mul(channel(table, c.b)),
        OFFSET,
    ];
    terms.iter().fold(0i64, |acc, t| acc.saturating_add(*t))
}

/// Whether `lighter` on `darker` reaches 4.5:1 by the bounds.
fn ratio_holds(lighter: Rgb, darker: Rgb) -> bool {
    let l1 = shifted_luminance(&LINEAR_LOWER, lighter);
    let l2 = shifted_luminance(&LINEAR_UPPER, darker);
    l1.saturating_mul(2) >= l2.saturating_mul(9)
}

/// Whether the text colour on the background meets WCAG 2.2 AA for
/// normal text, 4.5:1. It passes only if the exact ratio passes.
pub fn meets_aa(text: Rgb, background: Rgb) -> bool {
    ratio_holds(text, background) || ratio_holds(background, text)
}

/// The lower and upper bound of the linear value of the 8-bit channel
/// value `c`, as integers scaled by 10^12. Read-only, so that the test
/// `i70_contrast_bounds_enclose_f64_values` can recompute both tables.
pub fn linear_bounds(c: u8) -> (i64, i64) {
    (channel(&LINEAR_LOWER, c), channel(&LINEAR_UPPER, c))
}

/// The lower bound of each channel's linear value, scaled by 10^12.
const LINEAR_LOWER: [i64; 256] = [
    -2_000,
    303_524_983,
    607_051_967,
    910_578_950,
    1_214_105_934,
    1_517_632_917,
    1_821_159_901,
    2_124_686_884,
    2_428_213_868,
    2_731_740_851,
    3_035_267_835,
    3_346_533_763,
    3_676_505_324,
    4_024_715_018,
    4_391_440_037,
    4_776_951_480,
    5_181_514_702,
    5_605_389_624,
    6_048_831_022,
    6_512_088_792,
    6_995_408_187,
    7_499_030_043,
    8_023_190_985,
    8_568_123_618,
    9_134_056_702,
    9_721_215_320,
    10_329_821_029,
    10_960_092_006,
    11_612_243_179,
    12_286_486_356,
    12_983_030_342,
    13_702_081_047,
    14_443_841_596,
    15_208_512_422,
    15_996_291_365,
    16_807_373_752,
    17_641_952_488,
    18_500_218_128,
    19_382_358_956,
    20_288_561_056,
    21_219_008_376,
    22_173_882_793,
    23_153_364_178,
    24_157_630_448,
    25_186_857_627,
    26_241_219_894,
    27_320_889_639,
    28_426_037_504,
    29_556_832_437,
    30_713_441_732,
    31_896_031_073,
    33_104_764_570,
    34_339_804_808,
    35_601_312_875,
    36_889_448_401,
    38_204_369_595,
    39_546_233_276,
    40_915_194_906,
    42_311_408_620,
    43_735_027_256,
    45_186_202_385,
    46_665_084_336,
    48_171_822_226,
    49_706_563_984,
    51_269_456_374,
    52_860_645_023,
    54_480_274_442,
    56_128_488_049,
    57_805_428_191,
    59_511_236_162,
    61_246_052_231,
    63_010_015_653,
    64_803_264_692,
    66_625_936_643,
    68_478_167_844,
    70_360_093_696,
    72_271_848_682,
    74_213_566_380,
    76_185_379_481,
    78_187_419_805,
    80_219_818_314,
    82_282_705_129,
    84_376_209_544,
    86_500_460_036,
    88_655_584_285,
    90_841_709_183,
    93_058_960_846,
    95_307_464_630,
    97_587_345_141,
    99_898_726_247,
    102_241_731_088,
    104_616_482_091,
    107_023_100_978,
    109_461_708_778,
    111_932_425_836,
    114_435_371_826,
    116_970_665_758,
    119_538_425_988,
    122_138_770_229,
    124_771_815_560,
    127_437_678_435,
    130_136_474_690,
    132_868_319_553,
    135_633_327_655,
    138_431_613_032,
    141_263_289_140,
    144_128_468_858,
    147_027_264_497,
    149_959_787_810,
    152_926_149_996,
    155_926_461_707,
    158_960_833_060,
    162_029_373_639,
    165_132_192_501,
    168_269_398_189,
    171_441_098_732,
    174_647_401_655,
    177_888_413_983,
    181_164_242_249,
    184_474_992_500,
    187_820_770_300,
    191_201_680_740,
    194_617_828_441,
    198_069_317_559,
    201_556_251_794,
    205_078_734_390,
    208_636_868_145,
    212_230_755_414,
    215_860_498_113,
    219_526_197_729,
    223_227_955_316,
    226_965_871_510,
    230_740_046_524,
    234_550_580_161,
    238_397_571_812,
    242_281_120_465,
    246_201_324_707,
    250_158_282_729,
    254_152_092_330,
    258_182_850_921,
    262_250_655_529,
    266_355_602_802,
    270_497_789_013,
    274_677_310_060,
    278_894_261_476,
    283_148_738_429,
    287_440_835_726,
    291_770_647_817,
    296_138_268_798,
    300_543_792_415,
    304_987_312_069,
    309_468_920_817,
    313_988_711_375,
    318_546_776_125,
    323_143_207_112,
    327_778_096_056,
    332_451_534_346,
    337_163_613_048,
    341_914_422_908,
    346_704_054_355,
    351_532_597_500,
    356_400_142_145,
    361_306_777_783,
    366_252_593_598,
    371_237_678_474,
    376_262_120_990,
    381_326_009_432,
    386_429_431_787,
    391_572_475_749,
    396_755_228_725,
    401_977_777_832,
    407_240_209_901,
    412_542_611_483,
    417_885_068_848,
    423_267_667_986,
    428_690_494_613,
    434_153_634_174,
    439_657_171_840,
    445_201_192_516,
    450_785_780_838,
    456_411_021_180,
    462_076_997_654,
    467_783_794_112,
    473_531_494_148,
    479_320_181_100,
    485_149_938_056,
    491_020_847_847,
    496_932_993_060,
    502_886_456_032,
    508_881_318_854,
    514_917_663_376,
    520_995_571_204,
    527_115_123_705,
    533_276_402_010,
    539_479_487_012,
    545_724_459_370,
    552_011_399_512,
    558_340_387_634,
    564_711_503_704,
    571_124_827_464,
    577_580_438_429,
    584_078_415_891,
    590_618_838_919,
    597_201_786_363,
    603_827_336_855,
    610_495_568_807,
    617_206_560_419,
    623_960_389_675,
    630_757_134_346,
    637_596_871_994,
    644_479_679_970,
    651_405_635_419,
    658_374_815_279,
    665_387_296_282,
    672_443_154_957,
    679_542_467_633,
    686_685_310_435,
    693_871_759_291,
    701_101_889_932,
    708_375_777_891,
    715_693_498_506,
    723_055_126_921,
    730_460_738_090,
    737_910_406_772,
    745_404_207_540,
    752_942_214_776,
    760_524_502_675,
    768_151_145_247,
    775_822_216_317,
    783_537_789_526,
    791_297_938_332,
    799_102_736_014,
    806_952_255_669,
    814_846_570_216,
    822_785_752_396,
    830_769_874_774,
    838_799_009_740,
    846_873_229_509,
    854_992_606_124,
    863_157_211_454,
    871_367_117_198,
    879_622_394_887,
    887_923_115_881,
    896_269_351_374,
    904_661_172_391,
    913_098_649_793,
    921_581_854_277,
    930_110_856_375,
    938_685_726_457,
    947_306_534_733,
    955_973_351_249,
    964_686_245_894,
    973_445_288_398,
    982_250_548_333,
    991_102_095_113,
    999_999_998_000,
];
/// The upper bound of each channel's linear value, scaled by 10^12.
const LINEAR_UPPER: [i64; 256] = [
    2_000,
    303_528_984,
    607_055_968,
    910_582_951,
    1_214_109_935,
    1_517_636_918,
    1_821_163_902,
    2_124_690_885,
    2_428_217_869,
    2_731_744_852,
    3_035_271_836,
    3_346_537_764,
    3_676_509_325,
    4_024_719_019,
    4_391_444_038,
    4_776_955_481,
    5_181_518_703,
    5_605_393_625,
    6_048_835_023,
    6_512_092_793,
    6_995_412_188,
    7_499_034_044,
    8_023_194_986,
    8_568_127_619,
    9_134_060_703,
    9_721_219_321,
    10_329_825_030,
    10_960_096_007,
    11_612_247_180,
    12_286_490_357,
    12_983_034_343,
    13_702_085_048,
    14_443_845_597,
    15_208_516_423,
    15_996_295_366,
    16_807_377_753,
    17_641_956_489,
    18_500_222_129,
    19_382_362_957,
    20_288_565_057,
    21_219_012_377,
    22_173_886_794,
    23_153_368_179,
    24_157_634_449,
    25_186_861_628,
    26_241_223_895,
    27_320_893_640,
    28_426_041_505,
    29_556_836_438,
    30_713_445_733,
    31_896_035_074,
    33_104_768_571,
    34_339_808_809,
    35_601_316_876,
    36_889_452_402,
    38_204_373_596,
    39_546_237_277,
    40_915_198_907,
    42_311_412_621,
    43_735_031_257,
    45_186_206_386,
    46_665_088_337,
    48_171_826_227,
    49_706_567_985,
    51_269_460_375,
    52_860_649_024,
    54_480_278_443,
    56_128_492_050,
    57_805_432_192,
    59_511_240_163,
    61_246_056_232,
    63_010_019_654,
    64_803_268_693,
    66_625_940_644,
    68_478_171_845,
    70_360_097_697,
    72_271_852_683,
    74_213_570_381,
    76_185_383_482,
    78_187_423_806,
    80_219_822_315,
    82_282_709_130,
    84_376_213_545,
    86_500_464_037,
    88_655_588_286,
    90_841_713_184,
    93_058_964_847,
    95_307_468_631,
    97_587_349_142,
    99_898_730_248,
    102_241_735_089,
    104_616_486_092,
    107_023_104_979,
    109_461_712_779,
    111_932_429_837,
    114_435_375_827,
    116_970_669_759,
    119_538_429_989,
    122_138_774_230,
    124_771_819_561,
    127_437_682_436,
    130_136_478_691,
    132_868_323_554,
    135_633_331_656,
    138_431_617_033,
    141_263_293_141,
    144_128_472_859,
    147_027_268_498,
    149_959_791_811,
    152_926_153_997,
    155_926_465_708,
    158_960_837_061,
    162_029_377_640,
    165_132_196_502,
    168_269_402_190,
    171_441_102_733,
    174_647_405_656,
    177_888_417_984,
    181_164_246_250,
    184_474_996_501,
    187_820_774_301,
    191_201_684_741,
    194_617_832_442,
    198_069_321_560,
    201_556_255_795,
    205_078_738_391,
    208_636_872_146,
    212_230_759_415,
    215_860_502_114,
    219_526_201_730,
    223_227_959_317,
    226_965_875_511,
    230_740_050_525,
    234_550_584_162,
    238_397_575_813,
    242_281_124_466,
    246_201_328_708,
    250_158_286_730,
    254_152_096_331,
    258_182_854_922,
    262_250_659_530,
    266_355_606_803,
    270_497_793_014,
    274_677_314_061,
    278_894_265_477,
    283_148_742_430,
    287_440_839_727,
    291_770_651_818,
    296_138_272_799,
    300_543_796_416,
    304_987_316_070,
    309_468_924_818,
    313_988_715_376,
    318_546_780_126,
    323_143_211_113,
    327_778_100_057,
    332_451_538_347,
    337_163_617_049,
    341_914_426_909,
    346_704_058_356,
    351_532_601_501,
    356_400_146_146,
    361_306_781_784,
    366_252_597_599,
    371_237_682_475,
    376_262_124_991,
    381_326_013_433,
    386_429_435_788,
    391_572_479_750,
    396_755_232_726,
    401_977_781_833,
    407_240_213_902,
    412_542_615_484,
    417_885_072_849,
    423_267_671_987,
    428_690_498_614,
    434_153_638_175,
    439_657_175_841,
    445_201_196_517,
    450_785_784_839,
    456_411_025_181,
    462_077_001_655,
    467_783_798_113,
    473_531_498_149,
    479_320_185_101,
    485_149_942_057,
    491_020_851_848,
    496_932_997_061,
    502_886_460_033,
    508_881_322_855,
    514_917_667_377,
    520_995_575_205,
    527_115_127_706,
    533_276_406_011,
    539_479_491_013,
    545_724_463_371,
    552_011_403_513,
    558_340_391_635,
    564_711_507_705,
    571_124_831_465,
    577_580_442_430,
    584_078_419_892,
    590_618_842_920,
    597_201_790_364,
    603_827_340_856,
    610_495_572_808,
    617_206_564_420,
    623_960_393_676,
    630_757_138_347,
    637_596_875_995,
    644_479_683_971,
    651_405_639_420,
    658_374_819_280,
    665_387_300_283,
    672_443_158_958,
    679_542_471_634,
    686_685_314_436,
    693_871_763_292,
    701_101_893_933,
    708_375_781_892,
    715_693_502_507,
    723_055_130_922,
    730_460_742_091,
    737_910_410_773,
    745_404_211_541,
    752_942_218_777,
    760_524_506_676,
    768_151_149_248,
    775_822_220_318,
    783_537_793_527,
    791_297_942_333,
    799_102_740_015,
    806_952_259_670,
    814_846_574_217,
    822_785_756_397,
    830_769_878_775,
    838_799_013_741,
    846_873_233_510,
    854_992_610_125,
    863_157_215_455,
    871_367_121_199,
    879_622_398_888,
    887_923_119_882,
    896_269_355_375,
    904_661_176_392,
    913_098_653_794,
    921_581_858_278,
    930_110_860_376,
    938_685_730_458,
    947_306_538_734,
    955_973_355_250,
    964_686_249_895,
    973_445_292_399,
    982_250_552_334,
    991_102_099_114,
    1_000_000_002_000,
];
