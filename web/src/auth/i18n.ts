// A minimal message catalogue lookup for the M3 auth and vault pages
// (R-NF-04, M3 design section 11.2).
//
// It follows the rules of `web/src/core/i18n.ts`, which lane m4w1c builds
// in parallel: every user-visible string comes from a catalogue keyed by
// id, an unknown id or a missing or extra argument throws, and arguments
// are inserted as text and never parsed as markup. The merge can switch
// these pages to core's `label` without changing a catalogue.
//
// A message is plain text with `{name}` placeholders. `{{` and `}}` are a
// literal brace.

/** One locale's messages, keyed by id. */
export interface Catalogue<Id extends string> {
  readonly locale: string;
  readonly messages: Readonly<Record<Id, string>>;
}

/** The error for an unknown id or wrong arguments. It names no text. */
export class I18nError extends Error {
  constructor(code: string) {
    super(code);
    this.name = 'I18nError';
  }
}

/** A placeholder name, as core's grammar has it. */
const NAME = /^[a-z][a-z0-9_]{0,63}$/;

/** The message `text` with each `{name}` replaced by `args[name]`. */
function fill(text: string, args: Readonly<Record<string, string>>): string {
  const used = new Set<string>();
  let out = '';
  let i = 0;
  while (i < text.length) {
    const c = text.charAt(i);
    const d = text.charAt(i + 1);
    if ((c === '{' && d === '{') || (c === '}' && d === '}')) {
      out += c;
      i += 2;
    } else if (c === '{') {
      const end = text.indexOf('}', i + 1);
      const name = end < 0 ? '' : text.slice(i + 1, end);
      const value = args[name];
      if (!NAME.test(name) || value === undefined) {
        throw new I18nError('i18n.argument');
      }
      used.add(name);
      out += value;
      i = end + 1;
    } else if (c === '}') {
      throw new I18nError('i18n.brace');
    } else {
      out += c;
      i += 1;
    }
  }
  for (const name of Object.keys(args)) {
    if (!used.has(name)) {
      throw new I18nError('i18n.argument');
    }
  }
  return out;
}

/** The lookups of one catalogue. */
export interface I18n<Id extends string> {
  readonly locale: string;
  /** The message `id`, with its placeholders filled from `args`. */
  label(id: Id, args?: Readonly<Record<string, string>>): string;
}

/** Lookups over `catalogue`. */
export function createI18n<Id extends string>(catalogue: Catalogue<Id>): I18n<Id> {
  return {
    locale: catalogue.locale,
    label(id: Id, args: Readonly<Record<string, string>> = {}): string {
      if (!Object.prototype.hasOwnProperty.call(catalogue.messages, id)) {
        throw new I18nError('i18n.id');
      }
      return fill(catalogue.messages[id], args);
    },
  };
}
