// Byte and JSON encodings shared by the auth and vault pages (M3 design
// sections 8.7 and 11.2).
//
// - The cell takes byte strings as lowercase hexadecimal (lane w3ar,
//   `fstp-cell` `http::body`), and the browser's WebAuthn `toJSON()` gives
//   base64url. Base64url and hex are decoded by the browser's own
//   `Uint8Array.fromBase64` and `Uint8Array.fromHex`, so the pages hold no
//   in-house decoder. Only the hex encoder is written here.
// - Request bodies are RFC 8785 canonical JSON, which the cell requires
//   byte for byte. The values these pages send are strings, booleans,
//   null, safe integers, arrays and objects. Any other number is refused,
//   so no float is ever sent.

/** A JSON value these pages send. */
export type Json = null | boolean | number | string | readonly Json[] | { readonly [k: string]: Json };

/** An encoding the browser does not offer, or input outside its grammar. */
export class EncodingError extends Error {
  constructor(code: string) {
    super(code);
    this.name = 'EncodingError';
  }
}

interface Base64Constructor {
  fromBase64(s: string, o: { readonly alphabet: 'base64url'; readonly lastChunkHandling: 'loose' }): Uint8Array;
  fromHex(s: string): Uint8Array;
}

function codec(): Base64Constructor {
  const c = Uint8Array as unknown as Partial<Base64Constructor>;
  if (typeof c.fromBase64 !== 'function' || typeof c.fromHex !== 'function') {
    throw new EncodingError('encoding.unsupported');
  }
  return c as Base64Constructor;
}

const DIGITS = '0123456789abcdef';

/** Lowercase hexadecimal of `bytes`. */
export function hex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) {
    out += DIGITS.charAt(b >> 4) + DIGITS.charAt(b & 15);
  }
  return out;
}

/** Whether `s` is lowercase hex of `min` to `max` bytes. */
export function isHex(s: unknown, min: number, max: number): s is string {
  return (
    typeof s === 'string' &&
    s.length % 2 === 0 &&
    s.length >= 2 * min &&
    s.length <= 2 * max &&
    /^[0-9a-f]*$/.test(s)
  );
}

/** The bytes of lowercase hex `s`, decoded by the browser. */
export function unhex(s: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})*$/.test(s)) {
    throw new EncodingError('encoding.hex');
  }
  return codec().fromHex(s);
}

/** Hex of the unpadded base64url string `s`, decoded by the browser. */
export function base64urlToHex(s: unknown): string {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new EncodingError('encoding.base64url');
  }
  return hex(codec().fromBase64(s, { alphabet: 'base64url', lastChunkHandling: 'loose' }));
}

/** `n` random bytes from the browser's CSPRNG, in lowercase hex. */
export function randomHex(n: number): string {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return hex(b);
}

/**
 * The RFC 8785 canonical text of `v`: members sorted by UTF-16 code
 * units, no white space, and the ECMAScript spelling of strings and
 * integers, which RFC 8785 adopts.
 */
export function canonical(v: Json): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') {
    return JSON.stringify(v);
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new EncodingError('encoding.number');
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return `[${(v as readonly Json[]).map(canonical).join(',')}]`;
  }
  const o = v as { readonly [k: string]: Json };
  const keys = Object.keys(o).sort();
  const parts: string[] = [];
  for (const k of keys) {
    const x = o[k];
    if (x !== undefined) {
      parts.push(`${JSON.stringify(k)}:${canonical(x)}`);
    }
  }
  return `{${parts.join(',')}}`;
}
