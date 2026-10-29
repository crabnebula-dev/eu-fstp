// Independent reference for `safeUrl` (ADR-014: same-origin paths and
// `https:` only). It follows the interim grammar in support/contract.ts,
// pending Daniel and the `fstp-oauth` URL subset of lane W1e.

function printableAscii(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || c === 0x5c) {
      return false;
    }
  }
  return true;
}

function isHex(c: string | undefined): boolean {
  return c !== undefined && /^[0-9A-Fa-f]$/.test(c);
}

function escapesWellFormed(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    if (s[i] === "%") {
      if (!isHex(s[i + 1]) || !isHex(s[i + 2])) {
        return false;
      }
      i += 2;
    }
  }
  return true;
}

const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;

function hostOk(authority: string): boolean {
  if (authority === "" || authority.includes("@")) {
    return false;
  }
  const colon = authority.indexOf(":");
  const host = colon < 0 ? authority : authority.slice(0, colon);
  const port = colon < 0 ? null : authority.slice(colon + 1);
  if (port !== null && !/^[0-9]{1,5}$/.test(port)) {
    return false;
  }
  if (host === "" || !host.split(".").every((l) => LABEL.test(l))) {
    return false;
  }
  // WHATWG URL: a host whose last label is a number is an IPv4 address.
  const last = host.slice(host.lastIndexOf(".") + 1);
  return !/^[0-9]+$/.test(last) && !/^0x[0-9a-f]*$/.test(last);
}

/** Whether `safeUrl` accepts `input`. */
export function refSafeUrl(input: unknown): boolean {
  if (typeof input !== "string" || input === "") {
    return false;
  }
  if (!printableAscii(input) || !escapesWellFormed(input)) {
    return false;
  }
  if (input[0] === "/") {
    return input[1] !== "/";
  }
  if (input[0] === "#") {
    return /^#[A-Za-z][A-Za-z0-9._-]*$/.test(input);
  }
  if (!input.startsWith("https://")) {
    return false;
  }
  const rest = input.slice("https://".length);
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  return hostOk(authority);
}

/**
 * The shape every accepted URL must have, written as a separate and
 * weaker check: a same-document fragment, a same-origin path or an
 * `https:` URL with a host.
 */
export function sameOriginOrHttps(s: string): boolean {
  if (s.startsWith("#")) {
    return !s.includes("/") && !s.includes(":") && !s.includes("\\");
  }
  if (s.startsWith("/")) {
    return !s.startsWith("//") && !s.includes("\\");
  }
  return /^https:\/\/[^/?#@\\\s]+/.test(s);
}
