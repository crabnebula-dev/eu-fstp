/**
 * Source scans of the Judging page folders (ADR-014 feature folders
 * `web/src/{coordinator,reviewer,committee,irc}`). They need no stack.
 *
 * - I-17: Judging roles cannot read identity attributes of an applicant
 *   before negotiation. Design section 3.6 adds that no Judging read
 *   model carries an identity field. So no Judging page names one, and a
 *   page cannot show an identity field even if a response carried it.
 * - R-IR-03: IRC members see the nominated proposal and its outcome, not
 *   committee deliberation. So the IRC pages name no score, ballot, vote,
 *   rationale or tie-break.
 *
 * Comments are left out of the scan, so a doc comment may cite the rule.
 * Identifiers are split at case changes, so `displayName` reads as
 * `display_name`. Interim, pending Daniel: the word lists are the test
 * author's reading of identity attributes (`overview.md` vault contents)
 * and of deliberation (P-16, P-17, NOTE 6).
 */

import { expect, test } from '@playwright/test';
import { readFileSync } from 'node:fs';
import { relative } from 'node:path';
import { JUDGING_FOLDERS } from '../contract';
import { NotImplemented, sourcesOf, webDir } from './harness';

/** The text of a TypeScript file without its comments. */
function withoutComments(src: string): string {
  let out = '';
  let i = 0;
  while (i < src.length) {
    const c = src[i];
    const d = src[i + 1];
    if (c === '/' && d === '/') {
      while (i < src.length && src[i] !== '\n') i += 1;
    } else if (c === '/' && d === '*') {
      i += 2;
      while (i < src.length && !(src[i] === '*' && src[i + 1] === '/')) {
        // Keeps line numbers of later hits true.
        if (src[i] === '\n') out += '\n';
        i += 1;
      }
      i += 2;
      out += ' ';
    } else if (c === '"' || c === "'" || c === '`') {
      const q = c;
      out += c;
      i += 1;
      while (i < src.length && src[i] !== q) {
        if (src[i] === '\\') {
          out += src.slice(i, i + 2);
          i += 2;
        } else {
          out += src[i];
          i += 1;
        }
      }
      out += q;
      i += 1;
    } else {
      out += c;
      i += 1;
    }
  }
  return out;
}

/** Splits identifiers at case changes and lower-cases the text. */
function words(code: string): string {
  return code.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase();
}

/** Identity attribute names (I-17). */
const IDENTITY =
  /(^|[^a-z])(e_?mail|display_name|legal_name|given_name|family_name|first_name|last_name|full_name|surname|date_of_birth|birth_?date|birth|nationality|country|countries|address|phone|iban|passport|national_id)([^a-z]|$)/;

/** Committee deliberation names (R-IR-03). */
const DELIBERATION =
  /(^|[^a-z])(scores?|scoring|ballots?|votes?|voting|rationale|tie_?break|tie_breaks|deliberation)([^a-z]|$)/;

/** Every line of `files` that matches `rule`, as `path:line: text`. */
function hits(files: readonly string[], rule: RegExp): string[] {
  const web = webDir();
  const found: string[] = [];
  for (const f of files) {
    const lines = words(withoutComments(readFileSync(f, 'utf8'))).split('\n');
    lines.forEach((line, n) => {
      if (rule.test(line)) found.push(`${relative(web, f)}:${n + 1}: ${line.trim()}`);
    });
  }
  return found;
}

function sourcesOrRed(folder: string): string[] {
  const files = sourcesOf(folder);
  if (files.length === 0) {
    throw new NotImplemented(`web/src/${folder} holds no page source yet (lane W4c page agent)`);
  }
  return files;
}

test.describe('I-17 and R-IR-03 source scans', () => {
  test('i17_judging_page_sources_name_no_identity_attribute', async () => {
    const files = JUDGING_FOLDERS.flatMap((f) => sourcesOrRed(f));
    expect(hits(files, IDENTITY)).toEqual([]);
  });

  test('r_ir_03_irc_page_sources_name_no_deliberation', async () => {
    expect(hits(sourcesOrRed('irc'), DELIBERATION)).toEqual([]);
  });

  test('i17_the_scan_finds_an_identity_field_and_skips_comments', async () => {
    // Teeth: the scan itself, on fixed text, so an empty word list or a
    // broken comment filter cannot pass the two scans above.
    const code = [
      '// A comment may say email (I-17).',
      '/* displayName in a block comment */',
      'const row = { title: view.title };',
      'const who = view.applicantDisplayName;',
      "h('td', {}, [view['legal_name']]);",
    ].join('\n');
    const lines = words(withoutComments(code)).split('\n');
    expect(lines.map((l) => IDENTITY.test(l))).toEqual([false, false, false, true, true]);
    expect(DELIBERATION.test(words('const s = view.scoreSheet;'))).toBe(true);
    expect(DELIBERATION.test(words('const o = view.outcome;'))).toBe(false);
  });
});
