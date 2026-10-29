// Accessibility helpers (R-NF-03, WCAG 2.2 level AA; M4 design section
// 3.9, ADR-014 "Accessibility and localisation"): live regions, errors
// linked to their fields, and reduced motion.

import { h } from "./dom.js";

/** How urgently a live region speaks. */
export type Politeness = "polite" | "assertive";

/** The class that hides a live region visually but not from assistive technology. */
export const VISUALLY_HIDDEN_CLASS = "fstp-visually-hidden";

const regions = new Map<Politeness, HTMLElement>();

/** The latest message written to each region, for the delayed rewrite. */
const latest = new Map<HTMLElement, string>();

/** The page's live region of `politeness`, if it is still in the page. */
function existing(politeness: Politeness): HTMLElement | null {
  const known = regions.get(politeness);
  return known !== undefined && document.body.contains(known) ? known : null;
}

/** Creates the empty live region of `politeness` and puts it in the page. */
function create(politeness: Politeness): HTMLElement {
  const el = h("div", {
    "aria-live": politeness,
    "aria-atomic": "true",
    role: politeness === "assertive" ? "alert" : "status",
    class: VISUALLY_HIDDEN_CLASS,
  });
  document.body.appendChild(el);
  regions.set(politeness, el);
  return el;
}

/**
 * Creates both live regions, empty, unless they are already in the page.
 * Assistive technology often ignores text in a region that enters the
 * page together with it (WCAG 2.2 SC 4.1.3). So the shell calls this at
 * start-up, before any page announces. Idempotent.
 *
 * Interim, pending Daniel: the shell lane calls this once after it builds
 * the page skeleton.
 */
export function installLiveRegions(): void {
  for (const p of ["polite", "assertive"] as const) {
    if (existing(p) === null) {
      create(p);
    }
  }
}

function write(el: HTMLElement, message: string): void {
  el.textContent = "";
  el.appendChild(document.createTextNode(message));
  latest.set(el, message);
}

/**
 * Puts `message` as text into the page's one live region of that
 * politeness. The region is reused when `installLiveRegions` or an
 * earlier call made it. When this call has to create the region, the text
 * is written at once and written again one task later, unless a newer
 * message replaced it. Assistive technology then sees a change to a
 * region already in the page, so the first message is not lost.
 */
export function announce(message: string, politeness: Politeness): void {
  if (typeof message !== "string") {
    throw new TypeError("announce takes a string message");
  }
  if (politeness !== "polite" && politeness !== "assertive") {
    throw new TypeError("politeness is polite or assertive");
  }
  const known = existing(politeness);
  if (known !== null) {
    write(known, message);
    return;
  }
  const el = create(politeness);
  write(el, message);
  setTimeout(() => {
    if (latest.get(el) === message && regions.get(politeness) === el && document.body.contains(el)) {
      write(el, message);
    }
  }, 0);
}

/** HTML's ASCII whitespace: tab, line feed, form feed, carriage return and space. */
function isAsciiWhitespace(c: number): boolean {
  return c === 0x09 || c === 0x0a || c === 0x0c || c === 0x0d || c === 0x20;
}

/** The ids of an id list, which ASCII whitespace separates. */
function tokens(v: string | null): string[] {
  const out: string[] = [];
  let cur = "";
  for (const ch of v ?? "") {
    if (isAsciiWhitespace(ch.charCodeAt(0))) {
      if (cur !== "") {
        out.push(cur);
      }
      cur = "";
    } else {
      cur += ch;
    }
  }
  if (cur !== "") {
    out.push(cur);
  }
  return out;
}

/** The id of `error`, which must be non-empty and hold no ASCII whitespace. */
function idOf(error: HTMLElement): string {
  const id = error.getAttribute("id");
  if (id === null || id === "" || tokens(id).length !== 1 || tokens(id)[0] !== id) {
    throw new TypeError("an error element needs an id without spaces before a field can point at it");
  }
  return id;
}

/** The error ids `linkError` added to each control. */
const linked = new WeakMap<HTMLElement, Set<string>>();

/**
 * Marks `control` invalid and adds the id of `error` to its
 * `aria-describedby`, keeping the ids already there. It throws, and
 * changes nothing, when `error` has no id.
 */
export function linkError(control: HTMLElement, error: HTMLElement): void {
  const id = idOf(error);
  const ids = tokens(control.getAttribute("aria-describedby"));
  if (!ids.includes(id)) {
    ids.push(id);
  }
  control.setAttribute("aria-describedby", ids.join(" "));
  control.setAttribute("aria-invalid", "true");
  const set = linked.get(control) ?? new Set<string>();
  set.add(id);
  linked.set(control, set);
}

/**
 * Undoes `linkError`, keeping the other described-by ids. The control
 * stays invalid while another linked error remains.
 */
export function clearError(control: HTMLElement, error: HTMLElement): void {
  const id = idOf(error);
  const ids = tokens(control.getAttribute("aria-describedby")).filter((t) => t !== id);
  if (ids.length === 0) {
    control.removeAttribute("aria-describedby");
  } else {
    control.setAttribute("aria-describedby", ids.join(" "));
  }
  const set = linked.get(control);
  set?.delete(id);
  if (set === undefined || set.size === 0) {
    linked.delete(control);
    control.removeAttribute("aria-invalid");
  }
}

/** Whether the user asked for reduced motion (`prefers-reduced-motion: reduce`). */
export function prefersReducedMotion(): boolean {
  const mm = (globalThis as { readonly matchMedia?: unknown }).matchMedia;
  if (typeof mm !== "function") {
    return false;
  }
  const q: unknown = (mm as (query: string) => unknown).call(globalThis, "(prefers-reduced-motion: reduce)");
  return typeof q === "object" && q !== null && (q as { readonly matches?: unknown }).matches === true;
}
