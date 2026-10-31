/**
 * A source scan for user-visible literals in the TypeScript of the
 * creator, onboarding and people pages (R-NF-04), and a reader of the
 * label ids they look up.
 *
 * The lexer is the one of `e2e/r-nf-03-auth-and-vault-pages.spec.ts`
 * (M3 lane W3c), copied because a spec file cannot be imported without
 * registering its tests twice. The lead may move both to `e2e/support/`.
 */

import { existsSync, readFileSync, readdirSync } from 'node:fs';
import { join } from 'node:path';

/** Every `.ts` file below `dir`, skipping build output. */
export function filesUnder(dir: string, ext: string): string[] {
  if (!existsSync(dir)) return [];
  const out: string[] = [];
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = join(dir, e.name);
    if (e.isDirectory()) {
      if (e.name !== 'node_modules' && e.name !== 'dist' && e.name !== 'target') {
        out.push(...filesUnder(p, ext));
      }
    } else if (e.isFile() && e.name.endsWith(ext)) {
      out.push(p);
    }
  }
  return out;
}

/** A message catalogue file: `messages[.<locale>].ts` or under `messages/`. */
export function isTsCatalogue(path: string): boolean {
  const parts = path.split(/[\\/]/);
  const base = parts[parts.length - 1] ?? '';
  return (
    /^(messages|catalogue)(\.[a-z]{2,3}(-[A-Z]{2})?)?\.ts$/.test(base) ||
    parts.slice(0, -1).some((d) => d === 'messages' || d === 'catalogue')
  );
}

/** Tokens a page may spell that are not interface text. */
const TECHNICAL = new Set([
  'Enter',
  'Escape',
  'Tab',
  'Home',
  'End',
  'Space',
  'ArrowUp',
  'ArrowDown',
  'ArrowLeft',
  'ArrowRight',
  'Error',
  'TypeError',
  'AbortError',
  'NotAllowedError',
  'InvalidStateError',
  'NotSupportedError',
  'SecurityError',
]);

/** Whether a literal reads as interface text in some language. */
export function looksLikeUserText(s: string): boolean {
  const t = s.trim();
  if (!/\p{L}/u.test(t) || TECHNICAL.has(t)) return false;
  if (/\p{L}[.!?,]?\s+\p{L}/u.test(t)) return true;
  return /^\p{Lu}\p{Ll}+[.!?:]?$/u.test(t);
}

export interface Literal {
  readonly text: string;
  readonly line: number;
  readonly pos: number;
}

/**
 * The string literals of TypeScript source `src`, with the static parts
 * of template literals, and without module specifiers. Comments and
 * regular expression literals are skipped.
 */
export function tsLiterals(src: string): Literal[] {
  const out: Literal[] = [];
  const keywordsBeforeRegex = new Set([
    'return',
    'typeof',
    'case',
    'do',
    'else',
    'in',
    'of',
    'new',
    'delete',
    'void',
    'throw',
    'yield',
    'await',
  ]);
  let i = 0;
  let prev = '';
  let prev2 = '';
  const lineAt = (p: number): number => src.slice(0, p).split('\n').length;
  const push = (text: string, pos: number, specifier: boolean): void => {
    if (!specifier) out.push({ text, line: lineAt(pos), pos });
  };
  const sig = (t: string): void => {
    prev2 = prev;
    prev = t;
  };
  const readString = (q: string): string => {
    let s = '';
    i++;
    while (i < src.length && src[i] !== q) {
      if (src[i] === '\\') {
        s += src[i + 1] ?? '';
        i += 2;
      } else {
        s += src[i];
        i++;
      }
    }
    i++;
    return s;
  };
  // Lexes from `i` until the `}` that closes a template expression when
  // `inTemplate`, or until the end.
  const lex = (inTemplate: boolean): void => {
    let depth = 0;
    while (i < src.length) {
      const c = src[i] ?? '';
      const d = src[i + 1] ?? '';
      if (/\s/.test(c)) {
        i++;
      } else if (c === '/' && d === '/') {
        while (i < src.length && src[i] !== '\n') i++;
      } else if (c === '/' && d === '*') {
        const end = src.indexOf('*/', i + 2);
        i = end < 0 ? src.length : end + 2;
      } else if (c === "'" || c === '"') {
        const start = i;
        const s = readString(c);
        const specifier = prev === 'from' || prev === 'import' || (prev === '(' && prev2 === 'import');
        push(s, start, specifier);
        sig('"');
      } else if (c === '`') {
        i++;
        let chunk = '';
        let start = i;
        while (i < src.length && src[i] !== '`') {
          if (src[i] === '\\') {
            chunk += src[i + 1] ?? '';
            i += 2;
          } else if (src[i] === '$' && src[i + 1] === '{') {
            push(chunk, start, false);
            chunk = '';
            i += 2;
            lex(true);
            start = i;
          } else {
            chunk += src[i];
            i++;
          }
        }
        push(chunk, start, false);
        i++;
        sig('`');
      } else if (c === '/') {
        const regex = prev === '' || /^[(,=:[!&|?{};+\-*%<>~^]$/.test(prev) || keywordsBeforeRegex.has(prev);
        if (regex) {
          i++;
          let cls = false;
          while (i < src.length) {
            const r = src[i];
            if (r === '\\') {
              i += 2;
              continue;
            }
            if (r === '[') cls = true;
            else if (r === ']') cls = false;
            else if (r === '/' && !cls) break;
            i++;
          }
          i++;
          while (/[a-z]/.test(src[i] ?? '')) i++;
          sig('regex');
        } else {
          i++;
          sig('/');
        }
      } else if (/[A-Za-z_$0-9]/.test(c)) {
        let w = '';
        while (/[A-Za-z_$0-9]/.test(src[i] ?? '')) {
          w += src[i];
          i++;
        }
        sig(w);
      } else {
        if (inTemplate && c === '{') depth++;
        if (inTemplate && c === '}') {
          if (depth === 0) {
            i++;
            return;
          }
          depth--;
        }
        i++;
        sig(c);
      }
    }
  };
  lex(false);
  return out;
}


/** A catalogue lookup in source: `label("<id>")` or `approved("<id>")` with a literal id. */
export interface Lookup {
  readonly kind: 'label' | 'approved';
  readonly id: string;
  readonly line: number;
}

/**
 * Every catalogue lookup with a literal id in TypeScript source `src`. A
 * lookup with a computed id is not listed: the catalogue test cannot see
 * it, so a page should spell its ids literally.
 */
export function lookups(src: string): Lookup[] {
  const out: Lookup[] = [];
  const re = /\b(label|approved)\(\s*(['"`])([A-Za-z0-9_.-]+)\2/g;
  for (let m = re.exec(src); m !== null; m = re.exec(src)) {
    const kind = m[1] === 'approved' ? 'approved' : 'label';
    out.push({ kind, id: m[3] ?? '', line: src.slice(0, m.index).split('\n').length });
  }
  return out;
}

/**
 * User-visible literals in the TypeScript of `web/src/<dir>` outside its
 * catalogues (R-NF-04). A folder with no sources is a problem too.
 */
export function literalProblems(webSrc: string, dir: string): string[] {
  const root = join(webSrc, dir);
  const files = filesUnder(root, '.ts');
  if (files.length === 0) return [`web/src/${dir}: no TypeScript sources to scan (lane W4a page agent)`];
  const problems: string[] = [];
  for (const f of files) {
    if (isTsCatalogue(f)) continue;
    for (const l of tsLiterals(readFileSync(f, 'utf8'))) {
      if (looksLikeUserText(l.text)) {
        problems.push(`web/src/${dir}/${f.slice(root.length + 1)}:${l.line}: literal "${l.text.trim().slice(0, 60)}"`);
      }
    }
  }
  return problems;
}

/**
 * Lookups in `web/src/<dir>` whose literal id is not in `labels` or
 * `approved` of that kind (R-NF-04, and the I-72 split of labels from
 * approved text).
 */
export function lookupProblems(
  webSrc: string,
  dir: string,
  labels: ReadonlySet<string>,
  approved: ReadonlySet<string>,
): string[] {
  const root = join(webSrc, dir);
  const problems: string[] = [];
  for (const f of filesUnder(root, '.ts')) {
    if (isTsCatalogue(f)) continue;
    for (const k of lookups(readFileSync(f, 'utf8'))) {
      const known = k.kind === 'label' ? labels : approved;
      if (!known.has(k.id)) {
        problems.push(`web/src/${dir}/${f.slice(root.length + 1)}:${k.line}: ${k.kind} id ${k.id} is not in the catalogue`);
      }
    }
  }
  return problems;
}
