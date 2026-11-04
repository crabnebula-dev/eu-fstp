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

// ---------------------------------------------------------------------------
// In-app navigation (lane m4/site scope item 1, ADR-014, R-NF-03)
// ---------------------------------------------------------------------------
//
// One document serves every `/app/` page. A link or a call of `navigate`
// that leads to another `/app/` path changes the URL with the History API
// and renders that page into the shell, with no new document. Back and
// Forward render the page of the restored URL. A path outside `/app/`
// (the auth pages, the vault origin, public pages) or under
// `/app/assets/` is a normal navigation.
//
// After every in-app navigation, focus moves to the page's `main h1`
// (WCAG 2.2 SC 2.4.3), the page's title is spoken in the polite live
// region (SC 4.1.3), and the frames set `document.title`. The spoken
// text is the heading, with the document title beside it when that names
// more, such as a set-up step (`spokenTitle`). A page that
// replaces its heading while it loads is followed: the new heading text
// is spoken, and focus lost to the body goes back to the heading until
// the person presses a key or a pointer.
//
// The browser's own URL parser resolves each link, so this section adds
// no parser of its own. A path reaches a page only through a route table
// of `createRouter`, as before.

/** Renders the page of `path` into the shell. */
export type PageRender = (path: string) => void | Promise<void>;

/** What the navigation needs from the shell. */
export interface NavigationHooks {
  /** Renders the page of a path. */
  readonly render: PageRender;
  /** Speaks a page title in the polite live region. */
  readonly announce: (title: string) => void;
}

interface NavState {
  hooks: NavigationHooks | null;
  /** The number of the latest render. A render that a newer one replaced does nothing more. */
  seq: number;
  /** Functions a page registered to run when it is left. */
  leave: (() => void)[];
  /** Checks a page registered to run before it is left; one that answers false keeps the page. */
  holds: (() => boolean | Promise<boolean>)[];
  /** The number of the latest navigation asked for. One that a newer one replaced does nothing. */
  asked: number;
  /** The path, query and fragment of the page on show. */
  current: string;
  /** The text last spoken for the current page. */
  spoken: string;
  /** Whether the person pressed a key or a pointer since the last navigation. */
  touched: boolean;
  watch: MutationObserver | null;
}

const nav: NavState = {
  hooks: null,
  seq: 0,
  leave: [],
  holds: [],
  asked: 0,
  current: "",
  spoken: "",
  touched: false,
  watch: null,
};

/** The path below `/app/` that `href` names on this origin, with its query and fragment, or null. */
export function appPathOf(href: string, base: string): string | null {
  let u: URL;
  let b: URL;
  try {
    b = new URL(base);
    u = new URL(href, b);
  } catch {
    return null;
  }
  if (u.origin !== b.origin) {
    return null;
  }
  const p = u.pathname;
  if (!(p === "/app" || p.startsWith("/app/")) || p === "/app/assets" || p.startsWith("/app/assets/")) {
    return null;
  }
  return `${p}${u.search}${u.hash}`;
}

/** Registers `f` to run once when the current page is left by an in-app navigation. */
export function whenLeft(f: () => void): void {
  nav.leave.push(f);
}

/**
 * Registers `check` to run before the current page is left by an in-app
 * navigation. While it runs the page stays. When it answers false, the
 * navigation is dropped and the page stays, so a page can keep work that
 * is not stored yet, such as an edit whose save failed (I-21). A check
 * that throws lets the page go. The check is dropped once the page is left.
 */
export function holdLeave(check: () => boolean | Promise<boolean>): void {
  nav.holds.push(check);
}

/** Whether every check of the current page lets it go. */
async function mayLeave(): Promise<boolean> {
  for (const check of nav.holds) {
    let ok = true;
    try {
      ok = await check();
    } catch {
      ok = true;
    }
    if (!ok) {
      return false;
    }
  }
  return true;
}

/** The path, query and fragment of the current URL. */
function here(): string {
  return `${location.pathname}${location.search}${location.hash}`;
}

/** The current page's `h1`, or null. */
function pageHeading(): HTMLElement | null {
  const el = document.querySelector("main h1");
  return el instanceof HTMLElement ? el : null;
}

/** Moves focus to the page heading. */
function focusHeading(h1: HTMLElement): void {
  if (!h1.hasAttribute("tabindex")) {
    h1.setAttribute("tabindex", "-1");
  }
  h1.focus();
}

/**
 * What a navigation speaks: the heading, and the document title beside it
 * when the title names more than the heading does, such as the step of a
 * set-up whose every step shares one heading.
 */
export function spokenTitle(heading: string, title: string): string {
  const head = heading.trim();
  const full = title.trim();
  if (head === "" || full === "" || full.includes(head)) {
    return head;
  }
  return `${head}, ${full}`;
}

/** Speaks the page title when it changed since it was last spoken. */
function speak(h1: HTMLElement | null): void {
  const text = spokenTitle(h1?.textContent ?? "", document.title);
  if (text === "" || text === nav.spoken || nav.hooks === null) {
    return;
  }
  nav.spoken = text;
  nav.hooks.announce(text);
}

/** Follows the page after a navigation: its heading text, and focus lost to the body. */
function follow(seq: number): void {
  nav.watch?.disconnect();
  nav.touched = false;
  nav.spoken = "";
  const h1 = pageHeading();
  if (h1 !== null) {
    focusHeading(h1);
  }
  speak(h1);
  if (typeof MutationObserver !== "function") {
    return;
  }
  const watch = new MutationObserver(() => {
    if (seq !== nav.seq) {
      watch.disconnect();
      return;
    }
    const now = pageHeading();
    speak(now);
    const active = document.activeElement;
    if (now !== null && !nav.touched && (active === null || active === document.body)) {
      focusHeading(now);
    }
  });
  watch.observe(document.body, { childList: true, subtree: true, characterData: true });
  nav.watch = watch;
}

/** Leaves the current page and renders the one of the current URL. */
async function show(moved: boolean): Promise<void> {
  const hooks = nav.hooks;
  if (hooks === null) {
    return;
  }
  nav.seq += 1;
  const seq = nav.seq;
  const leaving = nav.leave;
  nav.leave = [];
  nav.holds = [];
  nav.current = here();
  for (const f of leaving) {
    try {
      f();
    } catch {
      // A page's leave hook never stops the next page.
    }
  }
  // An open dialog belongs to the page that is left.
  for (const d of Array.from(document.querySelectorAll("dialog[open]"))) {
    if (d instanceof HTMLDialogElement) {
      d.close();
    }
  }
  const rendered = hooks.render(location.pathname);
  if (moved) {
    follow(seq);
  }
  await rendered;
  if (moved && seq === nav.seq) {
    const h1 = pageHeading();
    speak(h1);
    const active = document.activeElement;
    if (h1 !== null && !nav.touched && (active === null || active === document.body)) {
      focusHeading(h1);
    }
  }
}

/**
 * Opens `href`. An `/app/` path of this origin renders in place and is
 * added to the history, or replaces the current entry with `replace`.
 * Anything else is a normal navigation.
 */
export function navigate(href: string, opts: { readonly replace?: boolean } = {}): void {
  const path = nav.hooks === null ? null : appPathOf(href, location.href);
  if (path === null) {
    location.assign(href);
    return;
  }
  void go(path, opts.replace === true);
}

/** Opens the in-app `path` once the current page lets it go. */
async function go(path: string, replace: boolean): Promise<void> {
  nav.asked += 1;
  const asked = nav.asked;
  if (nav.holds.length > 0 && !(await mayLeave())) {
    return;
  }
  if (asked !== nav.asked) {
    return;
  }
  if (replace) {
    history.replaceState(null, "", path);
  } else {
    history.pushState(null, "", path);
    window.scrollTo(0, 0);
  }
  await show(true);
}

/**
 * Back or Forward moved to another entry. When the current page holds
 * the navigation, the URL of the page on show comes back.
 */
async function moved(): Promise<void> {
  nav.asked += 1;
  const asked = nav.asked;
  if (nav.holds.length > 0) {
    const ok = await mayLeave();
    if (asked !== nav.asked) {
      return;
    }
    if (!ok) {
      history.pushState(null, "", nav.current);
      return;
    }
  }
  await show(true);
}

/** The element of this document that a same-page fragment link names, or null. */
function fragmentTarget(u: URL): HTMLElement | null {
  if (u.hash.length < 2) {
    return null;
  }
  let id: string;
  try {
    id = decodeURIComponent(u.hash.slice(1));
  } catch {
    return null;
  }
  const el = document.getElementById(id);
  return el instanceof HTMLElement ? el : null;
}

/** A click on an in-app link, handled in place. */
function clicked(e: MouseEvent): void {
  if (e.defaultPrevented || e.button !== 0 || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) {
    return;
  }
  const t = e.target;
  const a = t instanceof Element ? t.closest("a[href]") : null;
  if (!(a instanceof HTMLAnchorElement) || (a.target !== "" && a.target !== "_self") || a.hasAttribute("download")) {
    return;
  }
  let u: URL;
  try {
    u = new URL(a.href);
  } catch {
    return;
  }
  const here = new URL(location.href);
  if (u.origin === here.origin && u.pathname === here.pathname && u.search === here.search && u.hash !== "") {
    // A link to a part of this page, such as the skip link or an error
    // summary entry: focus that part without a history entry.
    const target = fragmentTarget(u);
    if (target !== null) {
      e.preventDefault();
      if (!target.hasAttribute("tabindex") && target.tabIndex < 0) {
        target.setAttribute("tabindex", "-1");
      }
      target.focus();
      target.scrollIntoView({ block: "start" });
    }
    return;
  }
  const path = appPathOf(a.href, here.href);
  if (path === null) {
    return;
  }
  e.preventDefault();
  navigate(path);
}

/**
 * Starts in-app navigation for the shell: renders the page of the
 * current URL, then handles in-app links, Back and Forward. Called once.
 */
export function startNavigation(hooks: NavigationHooks): Promise<void> {
  if (nav.hooks !== null) {
    return Promise.resolve();
  }
  nav.hooks = hooks;
  document.addEventListener("click", clicked);
  window.addEventListener("popstate", () => {
    void moved();
  });
  const touch = (): void => {
    nav.touched = true;
  };
  document.addEventListener("keydown", touch, true);
  document.addEventListener("pointerdown", touch, true);
  return show(false);
}

/** Renders the current URL again, in place, for a page whose fragment changed. */
export function rerender(): Promise<void> {
  return show(false);
}
