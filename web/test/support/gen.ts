// Generators for the property tests. Each one leans towards the inputs
// that the grammar under test treats specially.

import type { Rng } from "./rng.js";

const MONEY_TOKENS: readonly string[] = [
  "0",
  "1",
  "2",
  "5",
  "9",
  "00",
  "50",
  ".",
  ".",
  "-",
  "+",
  "e",
  " ",
  ",",
  "_",
  "\u0000",
  "１",
  "١",
  "9999999999999999",
];

/** A string near the ADR-006 grammar. */
export function moneyish(r: Rng): string {
  return r.stringFrom(MONEY_TOKENS, 8);
}

/** A canonical EUR amount of up to 18 digits. */
export function canonicalAmount(r: Rng): string {
  let int = r.oneIn(5) ? "0" : String(1 + r.below(9));
  if (int !== "0") {
    const more = r.below(16);
    for (let i = 0; i < more; i += 1) {
      int += String(r.below(10));
    }
  }
  return `${int}.${String(r.below(10))}${String(r.below(10))}`;
}

const URL_TOKENS: readonly string[] = [
  "/",
  "/",
  "//",
  "https://",
  "http://",
  "HTTPS://",
  "javascript:",
  "data:",
  "example.org",
  "a-b",
  "-",
  ".",
  ":",
  "8443",
  "@",
  "?",
  "#",
  "%",
  "%2F",
  "%zz",
  "\\",
  " ",
  "\t",
  "\u0000",
  "ä",
  "app",
  "x",
];

/** A string near URLs, same-origin paths and their tricks. */
export function urlish(r: Rng): string {
  return r.stringFrom(URL_TOKENS, 7);
}

const MARKUP: readonly string[] = [
  "<",
  ">",
  "&",
  "&lt;",
  '"',
  "'",
  "<script>",
  "</p>",
  "<img src=x onerror=alert(1)>",
  "javascript:",
  "{{x}}",
  "\u0000",
  " ",
  "\ud800",
  "a",
  " ",
];

/** A string full of markup, entities and odd code units. */
export function markupish(r: Rng): string {
  return r.stringFrom(MARKUP, 6);
}

const MESSAGE_TOKENS: readonly string[] = [
  "{",
  "}",
  "{{",
  "}}",
  "{name}",
  "{count}",
  "{a_1}",
  "{A}",
  "{1}",
  "{}",
  "text",
  " ",
  "é",
  "<b>",
];

/** A string near the message placeholder grammar. */
export function messageish(r: Rng): string {
  return r.stringFrom(MESSAGE_TOKENS, 6);
}

/** A path built from the given literal segments and path tricks. */
export function pathish(r: Rng, literals: readonly string[]): string {
  const segs: readonly string[] = [
    ...literals,
    "",
    ".",
    "..",
    "%2e",
    "%2F",
    "%5C",
    "%zz",
    "%C3%A9",
    "%00",
    "a%20b",
    "c1",
    "p7",
    "x",
  ];
  const n = r.below(5);
  let out = "";
  for (let i = 0; i < n; i += 1) {
    out += `/${r.pick(segs)}`;
  }
  if (out === "" || r.oneIn(8)) {
    out = r.pick(["", "/", "//", "?", "#"]) + out;
  }
  return out;
}
