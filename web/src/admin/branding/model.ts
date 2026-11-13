// The pure part of the tenant admin's branding and terminology screens
// (M9 lane P2; R-WL-03, R-WL-05, I-68, I-70, I-72; M9 design sections 2.2
// and 2.3, decisions D1 and D2).
//
// - Brand tokens are the tenant name and the brand colour family, in
//   light and dark, each colour spelt `#rrggbb` in lower case. The body
//   is `{tokens}` in the shape `fstp_brand::from_value` reads. Nothing
//   here builds CSS, markup or a URL (I-68).
// - The contrast check is the cell's: `tenant.branding.check` answers the
//   failing pairs of the I-70 table, and this module only names them.
// - A terminology body is `{labels, voyage_on}`. Labels name keys of the
//   closed list only, and never a key of fixed wording (I-72).

import { FIXED_LABEL_KEYS, PLAIN_LABELS } from "../../vocab/plain.js";

/** The colour keys of the brand family, in the order of the generated CSS (D1). */
export const COLOUR_KEYS = ["brand", "brand-hover", "brand-text", "on-brand", "focus"] as const;

/** One colour key. */
export type ColourKey = (typeof COLOUR_KEYS)[number];

/** The two modes. */
export const MODES = ["light", "dark"] as const;

/** One mode. */
export type Mode = (typeof MODES)[number];

/** A brand colour family: one `#rrggbb` per key. */
export type Palette = Readonly<Record<ColourKey, string>>;

/**
 * The platform brand family, repeating `fstp_brand::Palette::PLATFORM_LIGHT`
 * and `PLATFORM_DARK`. The screen starts from it, because no read gives
 * the tokens in force (interim, pending Daniel).
 */
export const PLATFORM: Readonly<Record<Mode, Palette>> = Object.freeze({
  light: Object.freeze({ brand: "#2563eb", "brand-hover": "#1d4ed8", "brand-text": "#1e40af", "on-brand": "#ffffff", focus: "#2563eb" }),
  dark: Object.freeze({ brand: "#3b82f6", "brand-hover": "#60a5fa", "brand-text": "#93c5fd", "on-brand": "#0f172a", focus: "#60a5fa" }),
});

/** The pair kinds of the I-70 table, in table order (`fstp_brand::PairKind`). */
export const PAIR_KINDS = ["brand-text/surface-0", "brand-text/surface-1", "on-brand/brand", "on-brand/brand-hover", "focus/surface-0"] as const;

/** Every pair of the table, as the cell names it: `light.on-brand/brand`. */
export const PAIRS: readonly string[] = Object.freeze(MODES.flatMap((m) => PAIR_KINDS.map((k) => `${m}.${k}`)));

/** The longest tenant name, in UTF-8 bytes (`fstp_brand::MAX_NAME_BYTES`). */
export const MAX_NAME_BYTES = 80;

/** The longest label, in UTF-8 bytes (`fstp_journey::vocab::MAX_LABEL_BYTES`). */
export const MAX_LABEL_BYTES = 200;

const HEX = /^#[0-9a-f]{6}$/;

// A control character: C0, DEL and C1.
const CONTROL = /[\u0000-\u001f\u007f-\u009f]/;

function bytes(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** Whether `s` is a colour as the token text spells it: `#rrggbb`, lower case. */
export function isColour(s: string): boolean {
  return HEX.test(s);
}

/**
 * Whether `s` is a tenant name `fstp_brand::BrandName` accepts: 1 to 80
 * bytes, no control character, no angle bracket, no space at either end.
 */
export function isBrandName(s: string): boolean {
  return s !== "" && bytes(s) <= MAX_NAME_BYTES && s.trim() === s && !CONTROL.test(s) && !/[<>]/.test(s);
}

/** What a person entered on the branding screen. */
export interface BrandingInput {
  readonly name: string;
  readonly light: Readonly<Record<string, string>>;
  readonly dark: Readonly<Record<string, string>>;
}

function palette(raw: Readonly<Record<string, string>>): Palette | null {
  const out: Record<string, string> = {};
  for (const k of COLOUR_KEYS) {
    const v = (raw[k] ?? "").trim().toLowerCase();
    if (!isColour(v)) {
      return null;
    }
    out[k] = v;
  }
  return out as Palette;
}

/**
 * The body of `tenant.branding.check` and `tenant.branding.set`, or null
 * when the name or a colour is not one the cell reads. Typography is
 * closed to `system` (D2).
 */
export function brandingBody(input: BrandingInput): { readonly tokens: Readonly<Record<string, unknown>> } | null {
  const light = palette(input.light);
  const dark = palette(input.dark);
  if (!isBrandName(input.name) || light === null || dark === null) {
    return null;
  }
  return { tokens: { name: input.name, typography: "system", light, dark } };
}

/** The reply of `tenant.branding.check`. */
export interface BrandingCheck {
  readonly accepted: boolean;
  readonly failing: readonly string[];
}

/** Reads a `tenant.branding.check` reply: `{accepted, failing}`, pairs of the table only. */
export function decodeCheck(v: unknown): BrandingCheck | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const o = v as Readonly<Record<string, unknown>>;
  const accepted = o["accepted"];
  const failing = o["failing"];
  if (typeof accepted !== "boolean" || !Array.isArray(failing)) {
    return null;
  }
  const names = failing as readonly unknown[];
  if (!names.every((p): p is string => typeof p === "string" && PAIRS.includes(p))) {
    return null;
  }
  // I-70: accepted exactly when no pair fails.
  if (accepted !== (names.length === 0)) {
    return null;
  }
  return { accepted, failing: names };
}

/** The mode and kind of a pair name, such as `light` and `on-brand/brand`. */
export function splitPair(name: string): { readonly mode: Mode; readonly kind: string } | null {
  const dot = name.indexOf(".");
  const mode = name.slice(0, dot);
  const kind = name.slice(dot + 1);
  if (dot < 0 || (mode !== "light" && mode !== "dark") || !(PAIR_KINDS as readonly string[]).includes(kind)) {
    return null;
  }
  return { mode, kind };
}

/** Every label key the terminology screen offers a field for: the closed list without fixed wording. */
export function editableKeys(): readonly string[] {
  return Object.keys(PLAIN_LABELS).filter((k) => !FIXED_LABEL_KEYS.includes(k));
}

/**
 * Whether `s` is a label `fstp_journey::vocab` accepts: 1 to 200 bytes,
 * no control character, no brace, no angle bracket, no space at either
 * end. A label takes no placeholder and no markup (I-68, I-72).
 */
export function isLabelText(s: string): boolean {
  return s !== "" && bytes(s) <= MAX_LABEL_BYTES && s.trim() === s && !CONTROL.test(s) && !/[{}<>]/.test(s);
}

/** The outcome of building a terminology body. */
export type TerminologyBody =
  | { readonly ok: true; readonly body: { readonly labels: Readonly<Record<string, string>>; readonly voyage_on: boolean } }
  | { readonly ok: false; readonly invalid: readonly string[] };

/**
 * The body of `tenant.terminology.set`. An empty field keeps the plain
 * label and is left out. A key outside the editable list is never sent,
 * so fixed wording and approved text stay out of reach (I-72). Fields
 * with text the cell would refuse are listed instead.
 */
export function terminologyBody(entries: Readonly<Record<string, string>>, voyage: boolean): TerminologyBody {
  const allowed = editableKeys();
  const labels: Record<string, string> = {};
  const invalid: string[] = [];
  for (const key of allowed) {
    const raw = entries[key];
    if (raw === undefined) {
      continue;
    }
    const text = raw.trim();
    if (text === "") {
      continue;
    }
    if (!isLabelText(text)) {
      invalid.push(key);
      continue;
    }
    labels[key] = text;
  }
  return invalid.length > 0 ? { ok: false, invalid } : { ok: true, body: { labels, voyage_on: voyage } };
}

/** The element id of a label key's field: dots become dashes. */
export function fieldId(key: string): string {
  return `terminology-${key.replaceAll(".", "-")}`;
}
