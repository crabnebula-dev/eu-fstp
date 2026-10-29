// Independent reference for router.ts: table validation, ambiguity and
// path matching, as support/contract.ts states them (ADR-014; the path
// rules follow the HTTP router decision of 2026-10-25 in HANDOFF.md).

import type { RouteDef, RouteMatch } from "../support/contract.js";

/** One pattern segment. */
export type PatSeg = { readonly lit: string } | { readonly param: string };

const PARAM = /^\{([a-z][a-z0-9_]*)\}$/;

/** The segments of a pattern, or null when it is malformed. */
export function patternSegments(pattern: string): PatSeg[] | null {
  if (!pattern.startsWith("/")) {
    return null;
  }
  if (pattern === "/") {
    return [];
  }
  const out: PatSeg[] = [];
  for (const s of pattern.slice(1).split("/")) {
    const m = PARAM.exec(s);
    if (m !== null && m[1] !== undefined) {
      out.push({ param: m[1] });
    } else if (s === "" || s.includes("{") || s.includes("}") || s === "." || s === "..") {
      return null;
    } else {
      out.push({ lit: s });
    }
  }
  return out;
}

/** Whether two valid routes are ambiguous by the contract's rule. */
export function ambiguous(a: RouteDef, b: RouteDef): boolean {
  const sa = patternSegments(a.pattern);
  const sb = patternSegments(b.pattern);
  if (sa === null || sb === null || sa.length !== sb.length) {
    return false;
  }
  return sa.every((x, i) => {
    const y = sb[i];
    if (y === undefined) {
      return false;
    }
    if ("lit" in x && "lit" in y) {
      return x.lit === y.lit;
    }
    if ("param" in x && "param" in y) {
      return true;
    }
    if ("lit" in x && "param" in y) {
      return b.segments[y.param]?.(x.lit) === true;
    }
    if ("param" in x && "lit" in y) {
      return a.segments[x.param]?.(y.lit) === true;
    }
    return false;
  });
}

/** Why a table is refused, or null when `createRouter` must accept it. */
export function tableFault(defs: readonly RouteDef[]): string | null {
  const names = new Set<string>();
  for (const d of defs) {
    if (names.has(d.name)) {
      return `duplicate route name ${d.name}`;
    }
    names.add(d.name);
    const segs = patternSegments(d.pattern);
    if (segs === null) {
      return `malformed pattern ${d.pattern}`;
    }
    const params = segs.flatMap((s) => ("param" in s ? [s.param] : []));
    if (new Set(params).size !== params.length) {
      return `parameter named twice in ${d.pattern}`;
    }
    const checks = Object.keys(d.segments);
    if (params.some((p) => !checks.includes(p)) || checks.some((c) => !params.includes(c))) {
      return `parameters and checks differ in ${d.pattern}`;
    }
  }
  for (let i = 0; i < defs.length; i += 1) {
    for (let j = i + 1; j < defs.length; j += 1) {
      const a = defs[i];
      const b = defs[j];
      if (a !== undefined && b !== undefined && ambiguous(a, b)) {
        return `routes ${a.name} and ${b.name} are ambiguous`;
      }
    }
  }
  return null;
}

/** The decoded segments of a path, or null when the path is refused. */
export function pathSegments(path: string): string[] | null {
  if (!path.startsWith("/") || path.includes("?") || path.includes("#")) {
    return null;
  }
  if (path === "/") {
    return [];
  }
  const out: string[] = [];
  for (const raw of path.slice(1).split("/")) {
    if (raw === "" || raw === "." || raw === "..") {
      return null;
    }
    if (/%(?![0-9A-Fa-f]{2})/.test(raw)) {
      return null;
    }
    let dec: string;
    try {
      dec = decodeURIComponent(raw);
    } catch {
      return null;
    }
    if (dec === "." || dec === ".." || /[/\\\u0000-\u001f\u007f-\u009f]/.test(dec) || /%[0-9A-Fa-f]{2}/.test(dec)) {
      return null;
    }
    out.push(dec);
  }
  return out;
}

/** Every route of a valid table that matches `path`, with its params. */
export function refMatches(defs: readonly RouteDef[], path: string): RouteMatch[] {
  const segs = pathSegments(path);
  if (segs === null) {
    return [];
  }
  const out: RouteMatch[] = [];
  for (const d of defs) {
    const pat = patternSegments(d.pattern);
    if (pat === null || pat.length !== segs.length) {
      continue;
    }
    const params: Record<string, string> = {};
    const ok = pat.every((p, i) => {
      const s = segs[i];
      if (s === undefined) {
        return false;
      }
      if ("lit" in p) {
        return p.lit === s;
      }
      if (d.segments[p.param]?.(s) !== true) {
        return false;
      }
      params[p.param] = s;
      return true;
    });
    if (ok) {
      out.push({ name: d.name, params });
    }
  }
  return out;
}

/** The single match the router must give, or null. */
export function refMatch(defs: readonly RouteDef[], path: string): RouteMatch | null {
  const all = refMatches(defs, path);
  return all.length === 1 ? (all[0] ?? null) : null;
}
