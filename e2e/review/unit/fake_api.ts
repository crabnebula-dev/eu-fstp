/**
 * A fake of `/api/v1` for the page specs in this folder. It serves the
 * tsc build of `web/src` in Chromium, so the specs need no e2e stack.
 *
 * The generated operation table in this worktree is the W0 stub, which
 * holds no operation. The fake serves its own `gen/api.js` with the
 * operations each spec needs, named as M4 design section 2.2 names them.
 *
 * Build first: web/node_modules/.bin/tsc -p web
 */

import { expect, type Page, type Route } from '@playwright/test';
import { existsSync, readFileSync } from 'node:fs';
import { join, normalize } from 'node:path';
import { webDir } from './harness';

export const ORIGIN = 'http://judging.test';

/** One entry of the fake operation table. */
export interface FakeOp {
  readonly name: string;
  readonly method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  readonly path: string;
}

/** A fake answer: the data of a completed call for `METHOD /api/v1/...`. */
export type Answers = Readonly<Record<string, unknown>>;

/** One request the page made below `/api/v1`. */
export interface SeenRequest {
  readonly key: string;
  readonly body: string;
}

const SHELL =
  '<!doctype html><html lang="en"><head><meta charset="utf-8"><title>t</title></head>' +
  '<body><div id="app"></div><script type="module" src="/entry.js"></script></body></html>';

const ENTRY =
  'import { mountJudging } from "/dist/reviewer/judging.js";\n' +
  'import { browserEnv } from "/dist/reviewer/kit.js";\n' +
  'const root = document.getElementById("app");\n' +
  'await mountJudging(browserEnv(root), location.pathname);\n' +
  'document.body.setAttribute("data-mounted", "1");\n';

/**
 * Serves the built pages, the fake operation table and the fake answers.
 * Every request below `/api/v1` is pushed to the returned list, reads
 * included. A completed call answers with its read model itself, as
 * `web/src/core/api.ts` reads `Done` (M4 design section 3.7).
 */
export async function serve(page: Page, ops: readonly FakeOp[], answers: Answers): Promise<SeenRequest[]> {
  const dist = join(webDir(), 'dist');
  if (!existsSync(join(dist, 'reviewer', 'judging.js'))) {
    throw new Error('web/dist is missing: build with web/node_modules/.bin/tsc -p web');
  }
  const seen: SeenRequest[] = [];
  await page.route(`${ORIGIN}/**`, async (route: Route) => {
    const url = new URL(route.request().url());
    const method = route.request().method();
    const p = url.pathname;
    if (p === '/entry.js') {
      await route.fulfill({ contentType: 'text/javascript', body: ENTRY });
      return;
    }
    if (p === '/dist/gen/api.js') {
      await route.fulfill({
        contentType: 'text/javascript',
        body: `export const OPERATIONS = ${JSON.stringify(ops.map((o) => ({ ...o, base: 'api' })))};\n`,
      });
      return;
    }
    if (p.startsWith('/dist/')) {
      const file = normalize(join(dist, p.slice('/dist/'.length)));
      if (!file.startsWith(dist) || !existsSync(file)) {
        await route.fulfill({ status: 404, body: '' });
        return;
      }
      await route.fulfill({ contentType: 'text/javascript', body: readFileSync(file, 'utf8') });
      return;
    }
    if (p.startsWith('/api/v1/')) {
      const key = `${method} ${p}`;
      seen.push({ key, body: route.request().postData() ?? '' });
      if (!Object.hasOwn(answers, key)) {
        await route.fulfill({ status: 404, contentType: 'application/json', body: '{"code":"not_found","rule":null}' });
        return;
      }
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify(answers[key]),
      });
      return;
    }
    await route.fulfill({ contentType: 'text/html', body: SHELL });
  });
  return seen;
}

/** Opens `path` and waits until the page has mounted and loaded its data. */
export async function open(page: Page, path: string): Promise<void> {
  await page.goto(`${ORIGIN}${path}`);
  await expect(page.locator('body[data-mounted="1"]')).toHaveCount(1);
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
}

/** The writes among `seen`, as `METHOD path` and the parsed body. */
export function writesOf(seen: readonly SeenRequest[]): { readonly key: string; readonly body: unknown }[] {
  return seen
    .filter((r) => !r.key.startsWith('GET '))
    .map((r) => ({ key: r.key, body: r.body === '' ? null : (JSON.parse(r.body) as unknown) }));
}
