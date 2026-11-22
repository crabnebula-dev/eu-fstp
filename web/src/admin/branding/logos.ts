// The pure part of the logo controls of the tenant admin's branding page
// (ADR-030; I-68, R-WL-03).
//
// - The page checks a chosen file here first, so the admin reads a plain
//   message at once: too big, the wrong type, or the wrong size. The
//   cell checks again and stays the judge (`fstp_brand::image`).
// - The contrast estimate reads the pixels the browser decoded for the
//   preview. It advises and never refuses (ADR-030 section 3).
// - The body of `tenant.branding.set_logo` is `{image, mode, programme}`:
//   the file as standard base64, or null to clear the slot.

/** The largest logo, in bytes (`fstp_brand::image::MAX_LOGO_BYTES`). */
export const MAX_LOGO_BYTES = 256 * 1024;

/** The smallest and largest width or height, in pixels. */
export const MIN_DIMENSION = 16;
export const MAX_DIMENSION = 2048;

/** The two logo formats. */
export type LogoFormat = "png" | "webp";

/** The modes a logo is drawn for. */
export type LogoMode = "light" | "dark";

/** Why a chosen file is not used, in the page's words. */
export type LogoProblem = "too_big" | "wrong_type" | "dimensions" | "unreadable";

/** The format the first bytes of a file show, or null for any other. */
export function sniff(bytes: Uint8Array): LogoFormat | null {
  const png = [0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a];
  if (bytes.length >= 8 && png.every((b, i) => bytes[i] === b)) {
    return "png";
  }
  const ascii = (from: number, to: number): string => String.fromCharCode(...Array.from(bytes.subarray(from, to)));
  if (bytes.length >= 12 && ascii(0, 4) === "RIFF" && ascii(8, 12) === "WEBP") {
    return "webp";
  }
  return null;
}

/** The first problem of a file of `size` bytes and the format its bytes show, before it is decoded. */
export function fileProblem(size: number, format: LogoFormat | null): LogoProblem | null {
  if (size > MAX_LOGO_BYTES) {
    return "too_big";
  }
  return format === null ? "wrong_type" : null;
}

/** Whether a decoded image of `width` by `height` pixels lies within the bounds. */
export function sizeOk(width: number, height: number): boolean {
  const ok = (d: number): boolean => Number.isInteger(d) && d >= MIN_DIMENSION && d <= MAX_DIMENSION;
  return ok(width) && ok(height);
}

/** Standard base64 with padding of `bytes`, the form the cell reads. */
export function toBase64(bytes: Uint8Array): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  let out = "";
  for (let i = 0; i < bytes.length; i += 3) {
    const a = bytes[i] ?? 0;
    const b = bytes[i + 1] ?? 0;
    const c = bytes[i + 2] ?? 0;
    const n = (a << 16) | (b << 8) | c;
    const left = bytes.length - i;
    out += alphabet[(n >> 18) & 63];
    out += alphabet[(n >> 12) & 63];
    out += left > 1 ? alphabet[(n >> 6) & 63] : "=";
    out += left > 2 ? alphabet[n & 63] : "=";
  }
  return out;
}

/** The body of `tenant.branding.set_logo`. */
export function logoBody(
  mode: LogoMode,
  programme: string | null,
  image: string | null,
): { readonly image: string | null; readonly mode: LogoMode; readonly programme: string | null } {
  return { image, mode, programme };
}

/** An RGB colour. */
export type Rgb = readonly [number, number, number];

/** The header colours a logo sits on: `--color-surface-1` in light and dark (`web/src/site/tokens.css`). */
export const HEADER: Readonly<Record<LogoMode, Rgb>> = Object.freeze({
  light: [0xf8, 0xfa, 0xfc] as const,
  dark: [0x1e, 0x29, 0x3b] as const,
});

function channel(c: number): number {
  const s = c / 255;
  return s <= 0.04045 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
}

/** The WCAG relative luminance of `c`. */
export function luminance(c: Rgb): number {
  return 0.2126 * channel(c[0]) + 0.7152 * channel(c[1]) + 0.0722 * channel(c[2]);
}

/** The WCAG contrast ratio of two luminances. */
export function ratio(a: number, b: number): number {
  const [hi, lo] = a > b ? [a, b] : [b, a];
  return (hi + 0.05) / (lo + 0.05);
}

/**
 * The contrast of a logo against `bg`, estimated from its RGBA pixels:
 * the share of the opaque pixels that differ from the background by at
 * least 3:1 decides. It is the ratio of those pixels' mean luminance, or
 * of all opaque pixels when too few stand out. A logo with no opaque
 * pixel gives 1. Advice only (ADR-030 section 3).
 */
export function logoContrast(rgba: Uint8ClampedArray | Uint8Array, bg: Rgb): number {
  const back = luminance(bg);
  let sum = 0;
  let count = 0;
  for (let i = 0; i + 3 < rgba.length; i += 4) {
    if ((rgba[i + 3] ?? 0) < 128) {
      continue;
    }
    sum += luminance([rgba[i] ?? 0, rgba[i + 1] ?? 0, rgba[i + 2] ?? 0]);
    count += 1;
  }
  if (count === 0) {
    return 1;
  }
  return ratio(sum / count, back);
}

/** A contrast in hundredths as the ratio people read, such as "2.4". */
export function ratioText(x100: string): string {
  const n = Number.parseInt(x100, 10);
  return Number.isFinite(n) ? (Math.floor(n / 10) / 10).toFixed(1) : "";
}

/** Whether a logo of contrast `r` may be hard to see: under the 3:1 bound of non-text content. */
export function lowContrast(r: number): boolean {
  return r < 3;
}

/** One stored logo of the read `tenant.branding.logos`. */
export interface StoredLogo {
  readonly path: string;
  readonly format: LogoFormat;
  readonly width: string;
  readonly height: string;
  readonly pdf: boolean;
  readonly email: boolean;
  /** The contrast advice on the slot's top bar, in hundredths of the ratio, or null. */
  readonly contrast: string | null;
  /** Whether the cell advises that the logo may be hard to see (I-70, never a refusal). */
  readonly advice: boolean;
}

/** One owner's slots. */
export interface LogoSlots {
  readonly light: StoredLogo | null;
  readonly dark: StoredLogo | null;
}

/** A programme's row. */
export interface ProgrammeSlots extends LogoSlots {
  readonly programme: string;
  readonly name: string;
}

/** The read reply. */
export interface LogosView {
  readonly tenant: LogoSlots;
  readonly programmes: readonly ProgrammeSlots[];
}

const LOGO_PATH = /^\/brand\/[0-9a-f]{64}\.(png|webp)$/;

function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

function stored(v: unknown): StoredLogo | null | undefined {
  if (v === null) {
    return null;
  }
  const o = record(v);
  if (o === null) {
    return undefined;
  }
  const { path, format, width, height, pdf, email, contrast, advice } = o;
  if (
    typeof path !== "string" ||
    !LOGO_PATH.test(path) ||
    (format !== "png" && format !== "webp") ||
    typeof width !== "string" ||
    typeof height !== "string" ||
    typeof pdf !== "boolean" ||
    typeof email !== "boolean" ||
    (contrast !== null && (typeof contrast !== "string" || !/^[0-9]{1,5}$/.test(contrast))) ||
    typeof advice !== "boolean"
  ) {
    return undefined;
  }
  return { path, format, width, height, pdf, email, contrast, advice };
}

function slots(v: unknown): LogoSlots | null {
  const o = record(v);
  if (o === null) {
    return null;
  }
  const light = stored(o["light"]);
  const dark = stored(o["dark"]);
  return light === undefined || dark === undefined ? null : { light, dark };
}

/** The read reply, or null when it has another shape. */
export function decodeLogos(v: unknown): LogosView | null {
  const o = record(v);
  const tenant = o === null ? null : slots(o["tenant"]);
  const rows = o?.["programmes"];
  if (tenant === null || !Array.isArray(rows)) {
    return null;
  }
  const programmes: ProgrammeSlots[] = [];
  for (const r of rows) {
    const p = record(r);
    const s = slots(r);
    const programme = p?.["programme"];
    const name = p?.["name"];
    if (s === null || typeof programme !== "string" || typeof name !== "string") {
      return null;
    }
    programmes.push({ programme, name, ...s });
  }
  return { tenant, programmes };
}
