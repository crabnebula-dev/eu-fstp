// A small in-house DOM for running web/src/core under Node.js.
//
// It offers the node, element, attribute and text APIs that a builder
// over `createElement`, `setAttribute` and text nodes needs. Every HTML
// parsing sink (`innerHTML`, `outerHTML`, `insertAdjacentHTML`,
// `setHTMLUnsafe`, `createContextualFragment`, `document.write`) throws
// and is recorded, so a test fails when production code reaches one.
// ADR-014: text goes in through `textContent` only.

/** Every attempt to reach an HTML sink, as `sink` names. */
export const sinkUses: string[] = [];

function sink(name: string): never {
  sinkUses.push(name);
  throw new Error(`HTML sink ${name} reached (ADR-014 forbids it)`);
}

let createdElements = 0;

/** A node of the fake DOM. */
export class FakeNode extends EventTarget {
  static readonly ELEMENT_NODE = 1;
  static readonly TEXT_NODE = 3;
  static readonly DOCUMENT_FRAGMENT_NODE = 11;
  readonly childNodes: FakeNode[] = [];
  parentNode: FakeNode | null = null;

  constructor(readonly nodeType: number) {
    super();
  }

  get firstChild(): FakeNode | null {
    return this.childNodes[0] ?? null;
  }

  get lastChild(): FakeNode | null {
    return this.childNodes[this.childNodes.length - 1] ?? null;
  }

  get parentElement(): FakeElement | null {
    return this.parentNode instanceof FakeElement ? this.parentNode : null;
  }

  get textContent(): string {
    return this.childNodes.map((c) => c.textContent).join("");
  }

  set textContent(value: string | null) {
    for (const c of this.childNodes) {
      c.parentNode = null;
    }
    this.childNodes.length = 0;
    const text = value ?? "";
    if (text !== "") {
      this.appendChild(new FakeText(text));
    }
  }

  appendChild<T extends FakeNode>(child: T): T {
    if (!(child instanceof FakeNode)) {
      throw new TypeError("appendChild takes a node");
    }
    if (child.nodeType === FakeNode.DOCUMENT_FRAGMENT_NODE) {
      for (const c of [...child.childNodes]) {
        this.appendChild(c);
      }
      return child;
    }
    child.remove();
    child.parentNode = this;
    this.childNodes.push(child);
    return child;
  }

  insertBefore<T extends FakeNode>(child: T, ref: FakeNode | null): T {
    if (ref === null) {
      return this.appendChild(child);
    }
    child.remove();
    const at = this.childNodes.indexOf(ref);
    if (at < 0) {
      throw new Error("insertBefore: reference is not a child");
    }
    child.parentNode = this;
    this.childNodes.splice(at, 0, child);
    return child;
  }

  removeChild<T extends FakeNode>(child: T): T {
    const at = this.childNodes.indexOf(child);
    if (at < 0) {
      throw new Error("removeChild: not a child");
    }
    this.childNodes.splice(at, 1);
    child.parentNode = null;
    return child;
  }

  remove(): void {
    if (this.parentNode !== null) {
      this.parentNode.removeChild(this);
    }
  }

  append(...nodes: (FakeNode | string)[]): void {
    for (const n of nodes) {
      this.appendChild(typeof n === "string" ? new FakeText(n) : n);
    }
  }

  prepend(...nodes: (FakeNode | string)[]): void {
    const first = this.firstChild;
    for (const n of nodes) {
      this.insertBefore(typeof n === "string" ? new FakeText(n) : n, first);
    }
  }

  replaceChildren(...nodes: (FakeNode | string)[]): void {
    this.textContent = "";
    this.append(...nodes);
  }

  contains(other: FakeNode | null): boolean {
    for (let n: FakeNode | null = other; n !== null; n = n.parentNode) {
      if (n === this) {
        return true;
      }
    }
    return false;
  }
}

/** A text node. Its data is never parsed. */
export class FakeText extends FakeNode {
  data: string;

  constructor(data: string) {
    super(FakeNode.TEXT_NODE);
    this.data = String(data);
  }

  override get textContent(): string {
    return this.data;
  }

  override set textContent(value: string | null) {
    this.data = value ?? "";
  }

  get nodeValue(): string {
    return this.data;
  }
}

/** A document fragment. */
export class FakeFragment extends FakeNode {
  constructor() {
    super(FakeNode.DOCUMENT_FRAGMENT_NODE);
  }
}

/** Reflected string properties and the attribute each one reads. */
const REFLECTED: Readonly<Record<string, string>> = {
  id: "id",
  className: "class",
  href: "href",
  src: "src",
  alt: "alt",
  type: "type",
  name: "name",
  htmlFor: "for",
  title: "title",
  lang: "lang",
  role: "role",
  placeholder: "placeholder",
  autocomplete: "autocomplete",
  action: "action",
  method: "method",
};

/** Reflected boolean properties. */
const REFLECTED_BOOL: readonly string[] = ["disabled", "required", "hidden", "checked", "readOnly"];

/** An element. Attribute names are stored as given, lower-cased. */
export class FakeElement extends FakeNode {
  readonly localName: string;
  /** The namespace `createElementNS` gave, or the HTML one. */
  namespaceURI = "http://www.w3.org/1999/xhtml";
  readonly attributes = new Map<string, string>();
  /** The live `value` of a form control, separate from its attribute. */
  private liveValue: string | null = null;

  constructor(tag: string) {
    super(FakeNode.ELEMENT_NODE);
    this.localName = tag.toLowerCase();
  }

  get tagName(): string {
    return this.localName.toUpperCase();
  }

  get nodeName(): string {
    return this.tagName;
  }

  get children(): FakeElement[] {
    return this.childNodes.filter((c): c is FakeElement => c instanceof FakeElement);
  }

  setAttribute(name: string, value: string): void {
    this.attributes.set(String(name).toLowerCase(), String(value));
  }

  getAttribute(name: string): string | null {
    return this.attributes.get(String(name).toLowerCase()) ?? null;
  }

  hasAttribute(name: string): boolean {
    return this.attributes.has(String(name).toLowerCase());
  }

  removeAttribute(name: string): void {
    this.attributes.delete(String(name).toLowerCase());
  }

  toggleAttribute(name: string, force?: boolean): boolean {
    const on = force ?? !this.hasAttribute(name);
    if (on) {
      this.setAttribute(name, "");
    } else {
      this.removeAttribute(name);
    }
    return on;
  }

  get value(): string {
    return this.liveValue ?? this.getAttribute("value") ?? "";
  }

  set value(v: string) {
    this.liveValue = String(v);
  }

  get tabIndex(): number {
    const t = this.getAttribute("tabindex");
    return t === null ? -1 : Number(t);
  }

  set tabIndex(n: number) {
    this.setAttribute("tabindex", String(n));
  }

  get classList(): { add(...c: string[]): void; remove(...c: string[]): void; contains(c: string): boolean } {
    const read = (): string[] => (this.getAttribute("class") ?? "").split(/\s+/).filter((c) => c !== "");
    return {
      add: (...c: string[]) => {
        const s = read();
        for (const x of c) {
          if (!s.includes(x)) {
            s.push(x);
          }
        }
        this.setAttribute("class", s.join(" "));
      },
      remove: (...c: string[]) => {
        this.setAttribute("class", read().filter((x) => !c.includes(x)).join(" "));
      },
      contains: (c: string) => read().includes(c),
    };
  }

  focus(): void {
    fakeDocument.activeElement = this;
  }

  blur(): void {
    if (fakeDocument.activeElement === this) {
      fakeDocument.activeElement = fakeDocument.body;
    }
  }

  click(): void {
    this.dispatchEvent(new Event("click", { bubbles: true, cancelable: true }));
  }

  /** Every element below this one, in document order. */
  descendants(): FakeElement[] {
    const out: FakeElement[] = [];
    const walk = (n: FakeNode): void => {
      for (const c of n.childNodes) {
        if (c instanceof FakeElement) {
          out.push(c);
        }
        walk(c);
      }
    };
    walk(this);
    return out;
  }

  getElementsByTagName(tag: string): FakeElement[] {
    const t = tag.toLowerCase();
    return this.descendants().filter((e) => t === "*" || e.localName === t);
  }

  get innerHTML(): string {
    return sink("innerHTML");
  }

  set innerHTML(_v: string) {
    sink("innerHTML");
  }

  get outerHTML(): string {
    return sink("outerHTML");
  }

  set outerHTML(_v: string) {
    sink("outerHTML");
  }

  insertAdjacentHTML(_where: string, _html: string): void {
    sink("insertAdjacentHTML");
  }

  setHTMLUnsafe(_html: string): void {
    sink("setHTMLUnsafe");
  }
}

for (const [prop, attr] of Object.entries(REFLECTED)) {
  Object.defineProperty(FakeElement.prototype, prop, {
    configurable: true,
    get(this: FakeElement): string {
      return this.getAttribute(attr) ?? "";
    },
    set(this: FakeElement, v: string): void {
      this.setAttribute(attr, String(v));
    },
  });
}
for (const prop of REFLECTED_BOOL) {
  Object.defineProperty(FakeElement.prototype, prop, {
    configurable: true,
    get(this: FakeElement): boolean {
      return this.hasAttribute(prop);
    },
    set(this: FakeElement, v: boolean): void {
      this.toggleAttribute(prop, Boolean(v));
    },
  });
}

/** The fake document. One object for the whole run, reset per test. */
class FakeDocument extends FakeNode {
  readonly documentElement = new FakeElement("html");
  readonly head = new FakeElement("head");
  readonly body = new FakeElement("body");
  activeElement: FakeElement | null = null;

  constructor() {
    super(9);
    this.documentElement.appendChild(this.head);
    this.documentElement.appendChild(this.body);
    this.appendChild(this.documentElement);
    this.activeElement = this.body;
  }

  createElement(tag: string): FakeElement {
    createdElements += 1;
    return new FakeElement(String(tag));
  }

  /** An element in namespace `ns`, as the SVG builder makes them (lane j4). */
  createElementNS(ns: string, tag: string): FakeElement {
    createdElements += 1;
    const e = new FakeElement(String(tag));
    e.namespaceURI = String(ns);
    return e;
  }

  createTextNode(data: string): FakeText {
    return new FakeText(String(data));
  }

  createDocumentFragment(): FakeFragment {
    return new FakeFragment();
  }

  getElementById(id: string): FakeElement | null {
    return this.documentElement.descendants().find((e) => e.getAttribute("id") === id) ?? null;
  }

  querySelectorAll(): never {
    throw new Error("the fake DOM has no selector engine; use getElementById or a kept reference");
  }

  write(_html: string): void {
    sink("document.write");
  }

  writeln(_html: string): void {
    sink("document.writeln");
  }

  createRange(): { createContextualFragment(html: string): never } {
    return { createContextualFragment: () => sink("createContextualFragment") };
  }
}

/** The document every test shares. */
export const fakeDocument = new FakeDocument();

/** The `matchMedia` answers tests set. */
export const mediaAnswers = new Map<string, boolean>();

let installed = false;

/**
 * Installs the fake DOM as the global `document`, `window`, `Node`,
 * `Element`, `HTMLElement`, `Text` and `matchMedia`. Idempotent.
 */
export function installFakeDom(): void {
  if (installed) {
    return;
  }
  installed = true;
  const g = globalThis as unknown as Record<string, unknown>;
  g["document"] = fakeDocument;
  g["window"] = globalThis;
  g["Node"] = FakeNode;
  g["Element"] = FakeElement;
  g["HTMLElement"] = FakeElement;
  g["HTMLInputElement"] = FakeElement;
  g["Text"] = FakeText;
  g["DocumentFragment"] = FakeFragment;
  g["matchMedia"] = (query: string) => ({
    matches: mediaAnswers.get(query) ?? false,
    media: query,
    addEventListener: () => undefined,
    removeEventListener: () => undefined,
  });
}

/** Empties the page and the counters before a test. */
export function freshDom(): void {
  installFakeDom();
  fakeDocument.head.textContent = "";
  fakeDocument.body.textContent = "";
  fakeDocument.activeElement = fakeDocument.body;
  sinkUses.length = 0;
  createdElements = 0;
  mediaAnswers.clear();
}

/** How many elements `createElement` made since `freshDom`. */
export function elementsCreated(): number {
  return createdElements;
}

/** Narrows a node that production code returned to the fake type. */
export function asFake(n: unknown): FakeElement {
  if (!(n instanceof FakeElement)) {
    throw new Error("expected an element of the fake DOM");
  }
  return n;
}
