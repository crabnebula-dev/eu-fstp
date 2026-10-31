// The countries an applicant can state as residence or establishment
// (R-NG-01, P-17). Codes only: the names come from the browser's
// `Intl.DisplayNames`, so no country name is written here.
//
// The list holds every officially assigned ISO 3166-1 alpha-2 code, and
// XK, the user-assigned code the European Commission uses for Kosovo.
// Eligibility is decided by the cell, never by this list.

/** The country codes, in code order. */
export const COUNTRY_CODES: readonly string[] = Object.freeze(
  [
    "AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ",
    "BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ",
    "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ",
    "DE DJ DK DM DO DZ",
    "EC EE EG EH ER ES ET",
    "FI FJ FK FM FO FR",
    "GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY",
    "HK HM HN HR HT HU",
    "ID IE IL IM IN IO IQ IR IS IT",
    "JE JM JO JP",
    "KE KG KH KI KM KN KP KR KW KY KZ",
    "LA LB LC LI LK LR LS LT LU LV LY",
    "MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ",
    "NA NC NE NF NG NI NL NO NP NR NU NZ",
    "OM",
    "PA PE PF PG PH PK PL PM PN PR PS PT PW PY",
    "QA",
    "RE RO RS RU RW",
    "SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ",
    "TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ",
    "UA UG UM US UY UZ",
    "VA VC VE VG VI VN VU",
    "WF WS",
    "XK",
    "YE YT",
    "ZA ZM ZW",
  ]
    .join(" ")
    .split(" "),
);

/** One country choice: its code and its name in `locale`. */
export interface CountryChoice {
  readonly code: string;
  readonly name: string;
}

/**
 * The countries with their names in `locale`, sorted by name. A code the
 * browser cannot name is shown as its code.
 */
export function countryChoices(locale: string): readonly CountryChoice[] {
  let names: Intl.DisplayNames | null = null;
  try {
    names = new Intl.DisplayNames([locale], { type: "region", fallback: "code" });
  } catch {
    names = null;
  }
  const out = COUNTRY_CODES.map((code) => {
    let name = code;
    try {
      name = names?.of(code) ?? code;
    } catch {
      name = code;
    }
    return Object.freeze({ code, name });
  });
  const collator = new Intl.Collator(locale);
  out.sort((a, b) => collator.compare(a.name, b.name));
  return Object.freeze(out);
}
