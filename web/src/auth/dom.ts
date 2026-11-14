// A minimal DOM builder for the M3 auth and vault pages (M3 design
// section 11.2, ADR-014 "DOM").
//
// It follows the rules of `web/src/core/dom.ts`, which lane m4w1c builds
// in parallel, and keeps its `h(tag, attrs, children)` signature, so the
// merge can switch these pages to core by changing one import.
//
// - Elements are built with `document.createElement`, `setAttribute` and
//   text nodes only. No string ever reaches an HTML parser.
// - Tags and attributes come from allowlists. No `on*` attribute, no
//   `style` and no `srcdoc` can be set.
// - URL attributes take same-origin absolute paths only. These pages link
//   nowhere else.

/** An attribute value. `true` sets an empty attribute; `false` omits it. */
export type AttrValue = string | boolean;

/** A child of `h`: a node, or a string that becomes a text node. */
export type Child = Node | string;

/** Why `h` refused. The code names the rule, never the input. */
export class DomRefusal extends Error {
  readonly code: string;

  constructor(code: string) {
    super(code);
    this.name = 'DomRefusal';
    this.code = code;
  }
}

/** The tags these pages build. */
const TAGS: ReadonlySet<string> = new Set([
  'a',
  'aside',
  'button',
  'dialog',
  'div',
  'fieldset',
  'footer',
  'form',
  'h1',
  'h2',
  'header',
  'input',
  'label',
  'legend',
  'li',
  'main',
  'nav',
  'p',
  'section',
  'span',
  'strong',
  'time',
  'ul',
]);

/** The attributes these pages set, besides `aria-*` and `data-*`. */
const ATTRIBUTES: ReadonlySet<string> = new Set([
  'action',
  'autocomplete',
  'checked',
  'class',
  'datetime',
  'disabled',
  'for',
  'hidden',
  'href',
  'id',
  'inputmode',
  'max',
  'method',
  'min',
  'name',
  'novalidate',
  'required',
  'role',
  'spellcheck',
  'type',
  'value',
]);

/** The attributes whose value is a URL. */
const URL_ATTRIBUTES: ReadonlySet<string> = new Set(['href', 'action']);

/** `aria-*` and `data-*` names: lower-case ASCII words joined by `-`. */
const ARIA_OR_DATA = /^(?:aria|data)(?:-[a-z][a-z0-9]*)+$/;

/**
 * The input when it is a same-origin absolute path, else null: it starts
 * with one `/`, and holds printable ASCII only, with no backslash.
 */
export function samePath(input: unknown): string | null {
  if (typeof input !== 'string' || !/^\/(?!\/)[\x21-\x5b\x5d-\x7e]*$/.test(input)) {
    return null;
  }
  return input;
}

/**
 * Builds `<tag>` with `attrs` and `children`. String children become text
 * nodes. It throws `DomRefusal` for a tag or attribute outside the
 * allowlists, or a URL that is not a same-origin path.
 */
export function h(
  tag: string,
  attrs: Readonly<Record<string, AttrValue>> = {},
  children: readonly Child[] = [],
): HTMLElement {
  if (!TAGS.has(tag)) {
    throw new DomRefusal('dom.tag');
  }
  const el = document.createElement(tag);
  for (const name of Object.keys(attrs)) {
    const value = attrs[name];
    if (!ATTRIBUTES.has(name) && !ARIA_OR_DATA.test(name)) {
      throw new DomRefusal('dom.attribute');
    }
    if (value === undefined || value === false) {
      continue;
    }
    if (URL_ATTRIBUTES.has(name)) {
      const url = samePath(value);
      if (url === null) {
        throw new DomRefusal('dom.url');
      }
      el.setAttribute(name, url);
    } else {
      el.setAttribute(name, value === true ? '' : value);
    }
  }
  for (const c of children) {
    el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c);
  }
  return el;
}

/** Removes every child of `el`. */
export function clear(el: Element): void {
  while (el.firstChild !== null) {
    el.firstChild.remove();
  }
}

/** The name of the page's one Trusted Types policy (ADR-014). */
export const TRUSTED_TYPES_POLICY = 'fstp-dom';

interface PolicyFactory {
  createPolicy(name: string, rules: Readonly<Record<string, (input: string) => never>>): unknown;
}

function refuse(): never {
  throw new TypeError(TRUSTED_TYPES_POLICY);
}

let policyInstalled = false;

/**
 * Creates the policy `fstp-dom`, which refuses every HTML string, script
 * and script URL, as core's does. It does nothing in a browser without
 * Trusted Types. Idempotent.
 */
export function installTrustedTypesPolicy(): void {
  if (policyInstalled) {
    return;
  }
  const factory = (globalThis as { readonly trustedTypes?: unknown }).trustedTypes;
  if (
    typeof factory !== 'object' ||
    factory === null ||
    typeof (factory as PolicyFactory).createPolicy !== 'function'
  ) {
    return;
  }
  (factory as PolicyFactory).createPolicy(TRUSTED_TYPES_POLICY, {
    createHTML: refuse,
    createScript: refuse,
    createScriptURL: refuse,
  });
  policyInstalled = true;
}
