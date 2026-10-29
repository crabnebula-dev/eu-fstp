// The DOM builder, the URL filter and the Trusted Types policy (M4 design
// section 3.9, ADR-014 "DOM").
//
// `h` builds elements through `document.createElement`, `setAttribute`
// and text nodes only, so no string ever reaches an HTML parser. Tags and
// attributes come from allowlists. Every `on*` attribute and `style` are
// refused. URL attributes take only what `safeUrl` accepts. The page sets
// `require-trusted-types-for 'script'` with the one policy below, which
// refuses every HTML string, script and script URL.

/** An attribute value. `true` sets an empty attribute; `false` omits it. */
export type AttrValue = string | boolean;

/** A child of `h`: a node, or a string that becomes a text node. */
export type Child = Node | string;

/** Why `h` refused. */
export type DomRefusalCode = "tag" | "attribute" | "url" | "child";

/** The error `h` throws for input outside its rules. */
export class DomRefusal extends Error {
  readonly code: DomRefusalCode;

  constructor(code: DomRefusalCode, message: string) {
    super(message);
    this.name = "DomRefusal";
    this.code = code;
  }
}

/**
 * The tags pages may build. Script, frame, plugin, style, metadata,
 * template and foreign-content elements (SVG and MathML) are absent.
 *
 * Interim, pending Daniel: ADR-014 names tag allowlists but not their
 * members. This list holds the text, table, form and landmark elements
 * that pages and the accessibility rules of R-NF-03 need.
 */
const TAGS: ReadonlySet<string> = new Set([
  "a", "abbr", "article", "aside", "b", "blockquote", "br", "button", "caption", "code", "col",
  "colgroup", "dd", "del", "details", "dfn", "div", "dl", "dt", "em", "fieldset", "figcaption",
  "figure", "footer", "form", "h1", "h2", "h3", "h4", "h5", "h6", "header", "hr", "i", "img", "input",
  "ins", "kbd", "label", "legend", "li", "main", "mark", "meter", "nav", "ol", "optgroup", "option",
  "output", "p", "pre", "progress", "q", "s", "samp", "search", "section", "select", "small", "span",
  "strong", "sub", "summary", "sup", "table", "tbody", "td", "textarea", "tfoot", "th", "thead",
  "time", "tr", "u", "ul", "var", "wbr",
]);

/**
 * The attributes pages may set, besides `aria-*` and `data-*`. No event
 * handler, no `style`, no `srcdoc`, no `formaction` and no namespaced
 * name is here. `href`, `src` and `action` are the URL attributes.
 *
 * Interim, pending Daniel: ADR-014 names attribute allowlists but not
 * their members. This list holds the global, form, table and media
 * attributes that pages need. `id` and `name` values pass
 * `identifierAllowed` as well.
 */
const ATTRIBUTES: ReadonlySet<string> = new Set([
  "abbr", "accept", "action", "alt", "autocomplete", "checked", "cols", "colspan", "datetime",
  "dir", "disabled", "enctype", "for", "headers", "height", "hidden", "high", "href", "id",
  "inputmode", "class", "lang", "low", "max", "maxlength", "method", "min", "minlength", "multiple",
  "name", "novalidate", "open", "optimum", "pattern", "placeholder", "readonly", "required",
  "role", "rows", "rowspan", "scope", "selected", "size", "span", "spellcheck", "src", "start",
  "step", "tabindex", "title", "translate", "type", "value", "width", "wrap",
]);

/** The attributes whose value is a URL, filtered by `safeUrl`. */
const URL_ATTRIBUTES: ReadonlySet<string> = new Set(["href", "src", "action"]);

/** `aria-*` and `data-*` names: lower-case ASCII words joined by `-`. */
const ARIA_OR_DATA = /^(?:aria|data)(?:-[a-z][a-z0-9]*)+$/;

function attributeAllowed(name: string): boolean {
  return ATTRIBUTES.has(name) || ARIA_OR_DATA.test(name);
}

/** An `id` or `name` value: an ASCII letter, then letters, digits, `.`, `-` or `_`. */
const IDENTIFIER = /^[A-Za-z][A-Za-z0-9._-]*$/;

/**
 * Names an `id` or `name` may not take, because the element would then
 * shadow a member that code reads (DOM clobbering). A form's controls
 * shadow the members of `HTMLFormElement`, and any element's id shadows
 * a window member that `EventTarget` or `Object.prototype` gives, or a
 * global the browser lacks.
 *
 * The list holds the own members of `HTMLFormElement`, the methods and
 * tree members of `Node`, `Element` and `HTMLElement`, the members of
 * `EventTarget` and `Object.prototype`, and the globals this module and
 * a11y.ts look up. Reflected string attributes such as `title` are left
 * out, since shadowing one hides no behaviour. The HTML sink names are
 * left out too: the web scan refuses them as strings, and no code may
 * read them. `Document` is covered by
 * refusing `name` on `form` and `img` (see `h`), the only allowed tags
 * whose names it exposes.
 *
 * Interim, pending Daniel: ADR-014 does not address DOM clobbering.
 */
const RESERVED_IDENTIFIERS: ReadonlySet<string> = new Set([
  // HTMLFormElement own members.
  "acceptCharset", "action", "autocomplete", "checkValidity", "elements", "encoding", "enctype",
  "length", "method", "name", "noValidate", "rel", "relList", "reportValidity", "requestSubmit",
  "reset", "submit", "target",
  // Node, Element and HTMLElement methods and tree members.
  "after", "append", "appendChild", "attachInternals", "attachShadow", "attributes", "before",
  "blur", "childElementCount", "childNodes", "children", "classList", "className", "click",
  "cloneNode", "closest", "compareDocumentPosition", "contains", "dataset", "firstChild",
  "firstElementChild", "focus", "getAttribute", "getAttributeNS", "getAttributeNames",
  "getAttributeNode", "getBoundingClientRect", "getClientRects", "getElementsByClassName",
  "getElementsByTagName", "getRootNode", "hasAttribute", "hasAttributes", "hasChildNodes",
  "hidePopover", "id", "innerText", "insertAdjacentElement",
  "insertAdjacentText", "insertBefore", "isConnected", "isEqualNode", "isSameNode",
  "lastChild", "lastElementChild", "localName", "matches", "nextElementSibling", "nextSibling",
  "nodeName", "nodeType", "nodeValue", "normalize", "outerText", "ownerDocument",
  "parentElement", "parentNode", "prepend", "previousElementSibling", "previousSibling",
  "querySelector", "querySelectorAll", "remove", "removeAttribute", "removeChild",
  "replaceChild", "replaceChildren", "replaceWith", "requestFullscreen", "scroll",
  "scrollBy", "scrollIntoView", "scrollTo", "setAttribute", "setAttributeNS", "shadowRoot",
  "showPopover", "style", "tagName", "textContent", "toggleAttribute", "togglePopover",
  // EventTarget.
  "addEventListener", "dispatchEvent", "removeEventListener",
  // Object.prototype.
  "__defineGetter__", "__defineSetter__", "__lookupGetter__", "__lookupSetter__", "__proto__",
  "constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString",
  "toString", "valueOf",
  // Globals that core modules look up.
  "document", "matchMedia", "trustedTypes",
]);

/**
 * Whether `value` is a safe `id` or `name`: a token that holds no
 * whitespace and cannot shadow a member that code reads.
 */
function identifierAllowed(value: string): boolean {
  return IDENTIFIER.test(value) && !RESERVED_IDENTIFIERS.has(value);
}

/** The tags whose `name` becomes a named property of `document`. */
const DOCUMENT_NAMED: ReadonlySet<string> = new Set(["form", "img"]);

function describe(v: unknown): string {
  return typeof v === "string" ? JSON.stringify(v) : typeof v;
}

/**
 * Builds `<tag>` with `attrs` and `children`. String children become text
 * nodes. It throws `DomRefusal` for a tag or attribute outside the
 * allowlists, an unsafe URL, or a child that is neither a node nor a
 * string. Nothing is stringified or parsed.
 *
 * An `id` or `name` value must pass `identifierAllowed`, and `form` and
 * `img` take no `name`, so no built element can clobber a member of
 * `document`, of its form or of the window.
 */
export function h(tag: string, attrs: Readonly<Record<string, AttrValue>> = {}, children: readonly Child[] = []): HTMLElement {
  if (typeof tag !== "string" || !TAGS.has(tag)) {
    throw new DomRefusal("tag", `tag ${describe(tag)} is not allowed`);
  }
  if (typeof attrs !== "object" || attrs === null || Array.isArray(attrs)) {
    throw new DomRefusal("attribute", "attributes must be a plain object");
  }
  if (!Array.isArray(children)) {
    throw new DomRefusal("child", "children must be an array");
  }
  const set: [string, string][] = [];
  for (const name of Object.keys(attrs)) {
    const value: unknown = attrs[name];
    if (!attributeAllowed(name)) {
      throw new DomRefusal("attribute", `attribute ${describe(name)} is not allowed`);
    }
    if (name === "id" || name === "name") {
      if (name === "name" && DOCUMENT_NAMED.has(tag)) {
        throw new DomRefusal("attribute", `a ${tag} takes no name, since document would expose it`);
      }
      if (typeof value !== "string" || !identifierAllowed(value)) {
        throw new DomRefusal("attribute", `${name} value ${describe(value)} is not a safe identifier`);
      }
      set.push([name, value]);
    } else if (URL_ATTRIBUTES.has(name)) {
      const url = safeUrl(value);
      if (url === null) {
        throw new DomRefusal("url", `${name} value ${describe(value)} is not a same-origin path or https: URL`);
      }
      set.push([name, url]);
    } else if (typeof value === "string") {
      set.push([name, value]);
    } else if (value === true) {
      set.push([name, ""]);
    } else if (value !== false) {
      throw new DomRefusal("attribute", `attribute ${name} takes a string or a boolean, not ${describe(value)}`);
    }
  }
  const kids: Node[] = [];
  for (const c of children as readonly unknown[]) {
    if (typeof c === "string") {
      kids.push(document.createTextNode(c));
    } else if (c instanceof Node) {
      kids.push(c);
    } else {
      throw new DomRefusal("child", `a child must be a node or a string, not ${describe(c)}`);
    }
  }
  const el = document.createElement(tag);
  for (const [name, value] of set) {
    el.setAttribute(name, value);
  }
  for (const k of kids) {
    el.appendChild(k);
  }
  return el;
}

function isHexAt(s: string, i: number): boolean {
  const c = s.charCodeAt(i);
  return (c >= 0x30 && c <= 0x39) || (c >= 0x41 && c <= 0x46) || (c >= 0x61 && c <= 0x66);
}

/** Printable ASCII without backslash, and each `%` followed by two hex digits. */
function charactersAllowed(s: string): boolean {
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (c < 0x21 || c > 0x7e || c === 0x5c) {
      return false;
    }
    if (c === 0x25) {
      if (!isHexAt(s, i + 1) || !isHexAt(s, i + 2)) {
        return false;
      }
      i += 2;
    }
  }
  return true;
}

/** One DNS label: lower-case letters, digits and inner hyphens. */
const LABEL = /^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/;
/** A port: one to five digits. */
const PORT = /^[0-9]{1,5}$/;

/**
 * A last label that the WHATWG URL parser reads as a number, which makes
 * the whole host an IPv4 address: all digits, or `0x` and hex digits.
 */
const NUMERIC_LABEL = /^(?:[0-9]+|0x[0-9a-f]*)$/;

/**
 * A host of LDH labels and an optional port. No userinfo and no IP
 * literal: bracketed IPv6 fails the label rule, and a host whose last
 * label is numeric is refused, since the URL parser reads it as IPv4.
 */
function authorityAllowed(authority: string): boolean {
  if (authority === "" || authority.includes("@")) {
    return false;
  }
  const colon = authority.indexOf(":");
  const host = colon < 0 ? authority : authority.slice(0, colon);
  if (colon >= 0 && !PORT.test(authority.slice(colon + 1))) {
    return false;
  }
  const labels = host.split(".");
  const last = labels[labels.length - 1] ?? "";
  return host !== "" && labels.every((label) => LABEL.test(label)) && !NUMERIC_LABEL.test(last);
}

const HTTPS = "https://";
/**
 * A fragment-only link to an element of the same page, such as a skip
 * link to `#main` (WCAG 2.2 SC 2.4.1): `#` and an identifier.
 */
const FRAGMENT_LINK = /^#[A-Za-z][A-Za-z0-9._-]*$/;

/** The characters that end an authority: `/`, `?` and `#`. */
const AUTHORITY_END: ReadonlySet<number> = new Set([0x2f, 0x3f, 0x23]);

/**
 * The input itself when it is a same-origin path or an `https:` URL, else
 * null. It never normalises and never throws.
 *
 * Interim grammar, pending Daniel and the `fstp-oauth` URL subset (W1e):
 * - printable ASCII only (0x21 to 0x7E), and no backslash;
 * - each `%` followed by two hex digits;
 * - a path starts with `/` and its second character is not `/`;
 * - an `https:` URL starts with exactly `https://`, then a host of
 *   lower-case LDH labels separated by dots, an optional `:` and one to
 *   five digits, then nothing or `/`, `?` or `#` and the rest. No userinfo.
 *   A host whose last label is all digits or `0x` and hex digits is an
 *   IPv4 address to the URL parser, and is refused.
 * - a fragment-only link is `#`, an ASCII letter, then letters, digits,
 *   `.`, `-` or `_`. It stays on the same document, so it is same-origin.
 *   Interim, pending Daniel: this lets a skip link meet WCAG 2.2 SC 2.4.1.
 *   Any other text that starts with `#` is refused.
 */
export function safeUrl(input: unknown): string | null {
  if (typeof input !== "string" || input === "" || !charactersAllowed(input)) {
    return null;
  }
  if (input.charCodeAt(0) === 0x2f) {
    return input.charCodeAt(1) === 0x2f ? null : input;
  }
  if (input.charCodeAt(0) === 0x23) {
    return FRAGMENT_LINK.test(input) ? input : null;
  }
  if (!input.startsWith(HTTPS)) {
    return null;
  }
  const rest = input.slice(HTTPS.length);
  let end = 0;
  while (end < rest.length && !AUTHORITY_END.has(rest.charCodeAt(end))) {
    end += 1;
  }
  return authorityAllowed(rest.slice(0, end)) ? input : null;
}

/** The name of the page's one Trusted Types policy, as the CSP names it. */
export const TRUSTED_TYPES_POLICY = "fstp-dom";

/** The part of the Trusted Types API this module uses. */
interface PolicyFactory {
  createPolicy(name: string, rules: Readonly<Record<string, (input: string) => never>>): unknown;
}

function refuseHtml(): never {
  throw new TypeError("fstp-dom refuses every HTML string (ADR-014)");
}

function refuseScript(): never {
  throw new TypeError("fstp-dom refuses every script (ADR-014)");
}

function refuseScriptUrl(): never {
  throw new TypeError("fstp-dom refuses every script URL (ADR-014)");
}

let policyInstalled = false;

/**
 * Creates the policy `fstp-dom`, whose `createHTML`, `createScript` and
 * `createScriptURL` refuse every input. The CSP allows no other policy,
 * so no code can turn a string into trusted HTML. Idempotent. It does
 * nothing in a browser without Trusted Types.
 */
export function installTrustedTypesPolicy(): void {
  if (policyInstalled) {
    return;
  }
  const factory = (globalThis as { readonly trustedTypes?: unknown }).trustedTypes;
  if (typeof factory !== "object" || factory === null || typeof (factory as PolicyFactory).createPolicy !== "function") {
    return;
  }
  (factory as PolicyFactory).createPolicy(TRUSTED_TYPES_POLICY, {
    createHTML: refuseHtml,
    createScript: refuseScript,
    createScriptURL: refuseScriptUrl,
  });
  policyInstalled = true;
}
