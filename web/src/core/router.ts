// Client-side routes: paths against generated segments (M4 design section
// 3.9, ADR-014).
//
// A table is checked when the router is built: patterns are well formed,
// every parameter has exactly one check, and no two routes can match the
// same path. A path is decoded under the rules of the HTTP router decision
// of 2026-10-25 (HANDOFF.md). A parameter reaches a page only after its
// generated check accepted the decoded segment.
//
// Interim, pending Daniel: the route segment format of `gen/api.ts` is not
// fixed yet. This module reads it as `{name}` whole segments with one
// check function per parameter.

/** The generated check for one path segment, applied to its decoded text. */
export type SegmentCheck = (segment: string) => boolean;

/**
 * One route. `pattern` is `/` or `/seg/seg...`, where a segment is a
 * literal or a whole-segment `{name}` with `name` matching
 * `[a-z][a-z0-9_]*`. `segments` holds exactly one check per `{name}`.
 */
export interface RouteDef {
  readonly name: string;
  readonly pattern: string;
  readonly segments: Readonly<Record<string, SegmentCheck>>;
}

/** A matched route with its decoded and checked parameters. */
export interface RouteMatch {
  readonly name: string;
  readonly params: Readonly<Record<string, string>>;
}

/** The router over one checked table. */
export interface Router {
  /** The one route that `path` matches, or null. It never throws. */
  match(path: string): RouteMatch | null;
}

/** The error `createRouter` throws for a malformed or ambiguous table. */
export class RouterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RouterError";
  }
}

type Seg = { readonly lit: string } | { readonly param: string; readonly check: SegmentCheck };

interface Route {
  readonly name: string;
  readonly segs: readonly Seg[];
}

const PARAM_NAME = /^[a-z][a-z0-9_]*$/;

/**
 * Whether a UTF-16 code unit is a control character: C0, DEL or C1
 * (U+0000 to U+001F and U+007F to U+009F). This is the set that Rust's
 * `char::is_control` refuses in `fstp_http::router::is_safe_segment`.
 */
function isControl(c: number): boolean {
  return c <= 0x1f || (c >= 0x7f && c <= 0x9f);
}

/**
 * Whether a literal segment can be compared with decoded path segments.
 * Interim strict reading, pending Daniel: besides braces and dot segments,
 * a literal may not hold `%`, `?`, `#`, `\` or a control character, since
 * a path segment holding one of them is refused or decoded first.
 */
function literalAllowed(s: string): boolean {
  if (s === "" || s === "." || s === "..") {
    return false;
  }
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c === 0x7b || c === 0x7d || c === 0x25 || c === 0x3f || c === 0x23 || c === 0x5c || isControl(c)) {
      return false;
    }
  }
  return true;
}

function compile(d: RouteDef): Route {
  if (typeof d !== "object" || d === null || typeof d.name !== "string" || typeof d.pattern !== "string") {
    throw new RouterError("a route needs a name and a pattern");
  }
  const checks = d.segments;
  if (typeof checks !== "object" || checks === null) {
    throw new RouterError(`route ${d.name} has no segment checks`);
  }
  const { pattern } = d;
  if (!pattern.startsWith("/")) {
    throw new RouterError(`pattern ${JSON.stringify(pattern)} of ${d.name} does not start with /`);
  }
  const segs: Seg[] = [];
  const used = new Set<string>();
  if (pattern !== "/") {
    for (const s of pattern.slice(1).split("/")) {
      if (s.startsWith("{") && s.endsWith("}") && s.length > 2) {
        const name = s.slice(1, -1);
        if (!PARAM_NAME.test(name)) {
          throw new RouterError(`parameter ${JSON.stringify(s)} of ${d.name} is malformed`);
        }
        if (used.has(name)) {
          throw new RouterError(`parameter ${name} appears twice in ${d.name}`);
        }
        const check: unknown = Object.hasOwn(checks, name) ? checks[name] : undefined;
        if (typeof check !== "function") {
          throw new RouterError(`parameter ${name} of ${d.name} has no check`);
        }
        used.add(name);
        segs.push({ param: name, check: check as SegmentCheck });
      } else if (literalAllowed(s)) {
        segs.push({ lit: s });
      } else {
        throw new RouterError(`segment ${JSON.stringify(s)} of ${d.name} is malformed`);
      }
    }
  }
  for (const k of Object.keys(checks)) {
    if (!used.has(k)) {
      throw new RouterError(`check ${k} of ${d.name} has no parameter`);
    }
  }
  return { name: d.name, segs };
}

/** Runs a check. A check that throws or answers anything but `true` refuses. */
function passes(check: SegmentCheck, segment: string): boolean {
  try {
    return check(segment) === true;
  } catch {
    return false;
  }
}

/**
 * Whether two routes can match one path: the same segment count, and at
 * every position equal literals, two parameters, or a literal that the
 * other route's check accepts. A check that throws on a literal counts as
 * accepting it, so the table is refused rather than guessed at.
 */
function ambiguous(a: Route, b: Route): boolean {
  if (a.segs.length !== b.segs.length) {
    return false;
  }
  return a.segs.every((x, i) => {
    const y = b.segs[i];
    if (y === undefined) {
      return false;
    }
    if ("lit" in x && "lit" in y) {
      return x.lit === y.lit;
    }
    if ("lit" in x && "check" in y) {
      return mayAccept(y.check, x.lit);
    }
    if ("check" in x && "lit" in y) {
      return mayAccept(x.check, y.lit);
    }
    return true;
  });
}

function mayAccept(check: SegmentCheck, literal: string): boolean {
  try {
    return check(literal) === true;
  } catch {
    return true;
  }
}

/** Whether `s` holds `%` followed by two hex digits. */
function hasPctTriple(s: string): boolean {
  for (let i = 0; i + 2 < s.length; i += 1) {
    if (s.charCodeAt(i) === 0x25 && isHex(s.charCodeAt(i + 1)) && isHex(s.charCodeAt(i + 2))) {
      return true;
    }
  }
  return false;
}

/** Two hex digits follow each `%`. */
function escapesWellFormed(raw: string): boolean {
  for (let i = 0; i < raw.length; i += 1) {
    if (raw.charCodeAt(i) === 0x25) {
      if (!isHex(raw.charCodeAt(i + 1)) || !isHex(raw.charCodeAt(i + 2))) {
        return false;
      }
      i += 2;
    }
  }
  return true;
}

function isHex(c: number): boolean {
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

/**
 * The decoded segments of `path`, or null when the path is refused: it
 * does not start with `/`, holds `?` or `#`, has an empty segment other
 * than the root, holds a malformed escape or escapes that are not UTF-8,
 * or has a segment that is or decodes to `.` or `..`, or decodes to text
 * holding `/`, `\` or a control character (C0, DEL or C1). A segment
 * whose decoded text still holds `%` and two hex digits is refused too.
 * That is the rule of `is_safe_segment` in fstp-http: a page that decodes
 * a parameter again can never obtain `/` or `..` from it.
 */
function decodePath(path: string): string[] | null {
  if (!path.startsWith("/") || path.includes("?") || path.includes("#")) {
    return null;
  }
  if (path === "/") {
    return [];
  }
  const out: string[] = [];
  for (const raw of path.slice(1).split("/")) {
    if (raw === "" || raw === "." || raw === ".." || !escapesWellFormed(raw)) {
      return null;
    }
    let dec: string;
    try {
      dec = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (dec === "." || dec === ".." || hasPctTriple(dec)) {
      return null;
    }
    for (let i = 0; i < dec.length; i += 1) {
      const c = dec.charCodeAt(i);
      if (c === 0x2f || c === 0x5c || isControl(c)) {
        return null;
      }
    }
    out.push(dec);
  }
  return out;
}

function matchRoute(r: Route, segs: readonly string[]): RouteMatch | null {
  for (let i = 0; i < r.segs.length; i += 1) {
    const p = r.segs[i];
    if (p !== undefined && "lit" in p && p.lit !== segs[i]) {
      return null;
    }
  }
  const params: Record<string, string> = {};
  for (let i = 0; i < r.segs.length; i += 1) {
    const p = r.segs[i];
    const s = segs[i];
    if (p !== undefined && "check" in p) {
      if (s === undefined || !passes(p.check, s)) {
        return null;
      }
      params[p.param] = s;
    }
  }
  return Object.freeze({ name: r.name, params: Object.freeze(params) });
}

/**
 * Builds a router over `defs`. It throws `RouterError` for a duplicate
 * route name, a malformed pattern or brace, a parameter named twice, a
 * parameter without a check or a check without a parameter, and for two
 * ambiguous routes.
 */
export function createRouter(defs: readonly RouteDef[]): Router {
  if (!Array.isArray(defs)) {
    throw new RouterError("the route table must be an array");
  }
  const routes: Route[] = [];
  const names = new Set<string>();
  for (const d of defs as readonly RouteDef[]) {
    const r = compile(d);
    if (names.has(r.name)) {
      throw new RouterError(`route name ${r.name} appears twice`);
    }
    names.add(r.name);
    routes.push(r);
  }
  for (let i = 0; i < routes.length; i += 1) {
    for (let j = i + 1; j < routes.length; j += 1) {
      const a = routes[i];
      const b = routes[j];
      if (a !== undefined && b !== undefined && ambiguous(a, b)) {
        throw new RouterError(`routes ${a.name} and ${b.name} can match the same path`);
      }
    }
  }
  const byLength = new Map<number, Route[]>();
  for (const r of routes) {
    const list = byLength.get(r.segs.length) ?? [];
    list.push(r);
    byLength.set(r.segs.length, list);
  }
  return Object.freeze({
    match(path: string): RouteMatch | null {
      if (typeof path !== "string") {
        return null;
      }
      const segs = decodePath(path);
      if (segs === null) {
        return null;
      }
      let found: RouteMatch | null = null;
      for (const r of byLength.get(segs.length) ?? []) {
        const m = matchRoute(r, segs);
        if (m !== null) {
          if (found !== null) {
            return null;
          }
          found = m;
        }
      }
      return found;
    },
  });
}
