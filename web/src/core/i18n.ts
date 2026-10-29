// Catalogues per locale and message placeholders (R-NF-04; M4 design
// section 3.9, ADR-014 "Accessibility and localisation").
//
// Interface strings are `Label`, which tenant terminology may override.
// Approved wording, such as notices and terms, is `ApprovedText` and is
// never overridable (I-72 seam). The two never share an id, so no
// override can reach approved wording. Arguments are inserted as text and
// never parsed.

declare const LABEL: unique symbol;
declare const APPROVED: unique symbol;

/**
 * An interface string from a catalogue. Terminology overrides may change
 * it (I-72). The mark exists for the compiler only, so a page cannot pass
 * a bare string where a catalogue label belongs.
 */
export type Label = string & { readonly [LABEL]: true };

/**
 * Approved wording from a catalogue. Never overridable (I-72). The mark
 * exists for the compiler only.
 */
export type ApprovedText = string & { readonly [APPROVED]: true };

/** One part of a parsed message. Text parts are never empty or adjacent. */
export type MessagePart =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "placeholder"; readonly name: string };

/** The outcome of parsing a message, with the offset of a refusal. */
export type MessageResult =
  | { readonly ok: true; readonly parts: readonly MessagePart[] }
  | { readonly ok: false; readonly offset: number };

/** One locale's catalogue. Label ids and approved ids never overlap. */
export interface CatalogueInput {
  readonly locale: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly approved: Readonly<Record<string, string>>;
}

/** What `createI18n` takes. `overrides` maps label ids to terminology. */
export interface I18nOptions {
  readonly catalogues: readonly CatalogueInput[];
  readonly locale: string;
  readonly overrides?: Readonly<Record<string, string>>;
}

/**
 * A catalogue for one locale. A missing or extra argument, or an unknown
 * id, throws `I18nError`, so a page never shows a raw key.
 */
export interface I18n {
  readonly locale: string;
  label(id: string, args?: Readonly<Record<string, string>>): Label;
  approved(id: string, args?: Readonly<Record<string, string>>): ApprovedText;
}

/** The error for a catalogue, override or lookup outside the rules. */
export class I18nError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "I18nError";
  }
}

/** A placeholder name: a lower-case letter, then up to 63 of `[a-z0-9_]`. */
const NAME = /^[a-z][a-z0-9_]{0,63}$/;
const OPEN = 0x7b;
const CLOSE = 0x7d;

/**
 * Parses a catalogue message, left to right. `{{` is a literal `{`, `}}`
 * a literal `}`, and `{name}` a placeholder. Any other `{` or `}` is
 * refused at its offset. It never throws.
 *
 * Interim grammar, pending Daniel and `fstp_html::parse_message_format`
 * (lane W1d).
 */
export function parseMessage(text: string): MessageResult {
  if (typeof text !== "string") {
    return Object.freeze({ ok: false, offset: 0 });
  }
  const parts: MessagePart[] = [];
  let buf = "";
  const flush = (): void => {
    if (buf !== "") {
      parts.push(Object.freeze({ kind: "text", text: buf }));
      buf = "";
    }
  };
  let i = 0;
  while (i < text.length) {
    const c = text.charCodeAt(i);
    if (c === OPEN) {
      if (text.charCodeAt(i + 1) === OPEN) {
        buf += "{";
        i += 2;
        continue;
      }
      const close = text.indexOf("}", i + 1);
      const name = close < 0 ? "" : text.slice(i + 1, close);
      if (!NAME.test(name)) {
        return Object.freeze({ ok: false, offset: i });
      }
      flush();
      parts.push(Object.freeze({ kind: "placeholder", name }));
      i = close + 1;
    } else if (c === CLOSE) {
      if (text.charCodeAt(i + 1) !== CLOSE) {
        return Object.freeze({ ok: false, offset: i });
      }
      buf += "}";
      i += 2;
    } else {
      let j = i + 1;
      while (j < text.length && text.charCodeAt(j) !== OPEN && text.charCodeAt(j) !== CLOSE) {
        j += 1;
      }
      buf += text.slice(i, j);
      i = j;
    }
  }
  flush();
  return Object.freeze({ ok: true, parts: Object.freeze(parts) });
}

/** A parsed message and its placeholder names. */
interface Message {
  readonly parts: readonly MessagePart[];
  readonly names: ReadonlySet<string>;
}

function compileMessage(text: unknown, what: string): Message {
  if (typeof text !== "string") {
    throw new I18nError(`${what} is not a string`);
  }
  const parsed = parseMessage(text);
  if (!parsed.ok) {
    throw new I18nError(`${what} does not parse at offset ${parsed.offset}`);
  }
  const names = new Set<string>();
  for (const p of parsed.parts) {
    if (p.kind === "placeholder") {
      names.add(p.name);
    }
  }
  return { parts: parsed.parts, names };
}

function record(v: unknown, what: string): [string, unknown][] {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new I18nError(`${what} is not an object`);
  }
  return Object.keys(v).map((k) => [k, (v as Record<string, unknown>)[k]]);
}

interface Catalogue {
  readonly labels: Map<string, Message>;
  readonly approved: Map<string, Message>;
}

function compileCatalogue(c: CatalogueInput): Catalogue {
  const labels = new Map<string, Message>();
  const approved = new Map<string, Message>();
  for (const [id, text] of record(c.labels, `labels of ${c.locale}`)) {
    labels.set(id, compileMessage(text, `label ${id} of ${c.locale}`));
  }
  for (const [id, text] of record(c.approved, `approved text of ${c.locale}`)) {
    if (labels.has(id)) {
      throw new I18nError(`id ${id} of ${c.locale} is both a label and approved text (I-72)`);
    }
    approved.set(id, compileMessage(text, `approved text ${id} of ${c.locale}`));
  }
  return { labels, approved };
}

function sameNames(a: ReadonlySet<string>, b: ReadonlySet<string>): boolean {
  return a.size === b.size && [...a].every((n) => b.has(n));
}

function format(m: Message, id: string, args: unknown): string {
  const given = args === undefined ? [] : record(args, `arguments of ${id}`);
  const values = new Map<string, string>();
  for (const [k, v] of given) {
    if (!m.names.has(k)) {
      throw new I18nError(`argument ${k} is not a placeholder of ${id}`);
    }
    if (typeof v !== "string") {
      throw new I18nError(`argument ${k} of ${id} is not a string`);
    }
    values.set(k, v);
  }
  let out = "";
  for (const p of m.parts) {
    if (p.kind === "text") {
      out += p.text;
    } else {
      const v = values.get(p.name);
      if (v === undefined) {
        throw new I18nError(`argument ${p.name} of ${id} is missing`);
      }
      out += v;
    }
  }
  return out;
}

/**
 * The catalogue of `opts.locale`. It throws `I18nError` for an unknown
 * locale, a locale given twice, a message that does not parse, an id that
 * is both a label and approved text, an override of an approved id
 * (I-72), and an override of an unknown label or one that does not parse.
 *
 * Interim strict reading, pending Daniel: an override must keep the
 * placeholders of the label it replaces, so a page's arguments still fit.
 * Every catalogue given is checked, not only the chosen one, and no id
 * may be a label in one catalogue and approved text in another.
 */
export function createI18n(opts: I18nOptions): I18n {
  if (typeof opts !== "object" || opts === null || !Array.isArray(opts.catalogues)) {
    throw new I18nError("createI18n takes catalogues and a locale");
  }
  const byLocale = new Map<string, Catalogue>();
  for (const c of opts.catalogues as readonly CatalogueInput[]) {
    if (typeof c !== "object" || c === null || typeof c.locale !== "string" || c.locale === "") {
      throw new I18nError("a catalogue needs a locale");
    }
    if (byLocale.has(c.locale)) {
      throw new I18nError(`locale ${c.locale} is given twice`);
    }
    byLocale.set(c.locale, compileCatalogue(c));
  }
  const labelIds = new Set<string>();
  for (const c of byLocale.values()) {
    for (const id of c.labels.keys()) {
      labelIds.add(id);
    }
  }
  for (const [loc, c] of byLocale) {
    for (const id of c.approved.keys()) {
      if (labelIds.has(id)) {
        throw new I18nError(`approved id ${id} of ${loc} is a label in another catalogue (I-72)`);
      }
    }
  }
  const locale = opts.locale;
  const chosen = typeof locale === "string" ? byLocale.get(locale) : undefined;
  if (chosen === undefined) {
    throw new I18nError(`no catalogue for locale ${String(locale)}`);
  }
  const labels = new Map(chosen.labels);
  if (opts.overrides !== undefined) {
    for (const [id, text] of record(opts.overrides, "overrides")) {
      if (chosen.approved.has(id)) {
        throw new I18nError(`approved text ${id} cannot be overridden (I-72)`);
      }
      const original = chosen.labels.get(id);
      if (original === undefined) {
        throw new I18nError(`override of unknown label ${id}`);
      }
      const m = compileMessage(text, `override of ${id}`);
      if (!sameNames(m.names, original.names)) {
        throw new I18nError(`override of ${id} changes its placeholders`);
      }
      labels.set(id, m);
    }
  }
  const approved = chosen.approved;
  return Object.freeze({
    locale,
    label(id: string, args?: Readonly<Record<string, string>>): Label {
      const m = labels.get(id);
      if (m === undefined) {
        throw new I18nError(`unknown label ${String(id)}`);
      }
      return format(m, id, args) as Label;
    },
    approved(id: string, args?: Readonly<Record<string, string>>): ApprovedText {
      const m = approved.get(id);
      if (m === undefined) {
        throw new I18nError(`unknown approved text ${String(id)}`);
      }
      return format(m, id, args) as ApprovedText;
    },
  });
}
