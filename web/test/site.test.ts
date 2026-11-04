// The token sheet and the copy rules of the site (lane m4/site scope
// item 3; I-70, I-72, R-NF-03, R-NF-04; `docs/design/08-design-tokens.md`).
//
// - i70_web_token_sheet_copies_the_design_tokens: `web/src` holds a copy
//   of `design/tokens.css` as the tenant-overridable token sheet. Every
//   custom property of its light `:root` set and of its dark set under
//   `prefers-color-scheme: dark` has the design's value, so the measured
//   AA ratios of `08-design-tokens.md` hold. The build never reads
//   `design/`, so the copy lives in `web/`. Red until the copy exists.
// - r_nf_04_site_catalogues_follow_the_copy_rules: no string of a
//   message catalogue holds an em dash, and every sentence is under 40
//   words (`.claude/CLAUDE.md` writing style, R-NF-04).
//
// These tests read source text only. Every value is synthetic.

import { existsSync, readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { NotImplemented, assert, eq, test } from "./support/harness.js";
import { REPO_DIR, WEB_DIR } from "./support/paths.js";

/** Every file below `dir` whose name passes `keep`, depth first, in name order. */
function filesBelow(dir: string, keep: (name: string) => boolean): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir).sort()) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      out.push(...filesBelow(p, keep));
    } else if (keep(name)) {
      out.push(p);
    }
  }
  return out;
}

/** The text of the first `{ ... }` block after `start` in `css`, or null. */
function blockAfter(css: string, start: number): string | null {
  const open = css.indexOf("{", start);
  if (open < 0) {
    return null;
  }
  let depth = 0;
  for (let i = open; i < css.length; i += 1) {
    const c = css[i];
    if (c === "{") {
      depth += 1;
    } else if (c === "}") {
      depth -= 1;
      if (depth === 0) {
        return css.slice(open + 1, i);
      }
    }
  }
  return null;
}

/** The custom properties declared directly in a block, with comments removed. */
function customProperties(block: string): Map<string, string> {
  const out = new Map<string, string>();
  const text = block.replace(/\/\*[\s\S]*?\*\//g, "");
  for (const m of text.matchAll(/(--[a-z0-9-]+)\s*:\s*([^;{}]+);/g)) {
    const name = m[1];
    const value = m[2];
    if (name !== undefined && value !== undefined) {
      out.set(name, value.trim().toLowerCase().replace(/\s+/g, " "));
    }
  }
  return out;
}

/** The light set (the first `:root` block) and the dark set of a token sheet. */
function tokenSets(css: string): { readonly light: Map<string, string>; readonly dark: Map<string, string> } {
  const clean = css.replace(/\/\*[\s\S]*?\*\//g, "");
  const rootAt = clean.search(/(^|[\s}]):root\s*\{/);
  const light = rootAt < 0 ? null : blockAfter(clean, rootAt);
  const mediaAt = clean.search(/@media\s*\(\s*prefers-color-scheme\s*:\s*dark\s*\)/);
  const media = mediaAt < 0 ? null : blockAfter(clean, mediaAt);
  const darkAt = media === null ? -1 : media.search(/:root/);
  const dark = media === null || darkAt < 0 ? null : blockAfter(media, darkAt);
  return { light: customProperties(light ?? ""), dark: customProperties(dark ?? "") };
}

test("i70_web_token_sheet_copies_the_design_tokens", () => {
  const design = tokenSets(readFileSync(join(REPO_DIR, "design", "tokens.css"), "utf8"));
  assert(design.light.size > 40 && design.dark.size > 20, "design/tokens.css has its light and dark sets");
  const sheets = filesBelow(join(WEB_DIR, "src"), (n) => n.endsWith(".css")).filter((f) =>
    /--color-surface-0\s*:/.test(readFileSync(f, "utf8")),
  );
  if (sheets.length === 0) {
    throw new NotImplemented("no token sheet under web/src declares --color-surface-0 (copy of design/tokens.css)");
  }
  // Every sheet that declares the tokens agrees with the design, so the
  // auth pages and the app never drift apart.
  for (const sheet of sheets) {
    const web = tokenSets(readFileSync(sheet, "utf8"));
    for (const [set, want, got] of [
      ["light", design.light, web.light],
      ["dark", design.dark, web.dark],
    ] as const) {
      for (const [name, value] of want) {
        eq(got.get(name), value, `I-70: ${sheet} ${set} ${name}`);
      }
    }
  }
});

/** The string literals of a TypeScript catalogue, as written (no escapes decoded beyond quotes). */
function literals(source: string): string[] {
  const out: string[] = [];
  for (const m of source.matchAll(/"((?:[^"\\\n]|\\.)*)"|'((?:[^'\\\n]|\\.)*)'/g)) {
    const v = m[1] ?? m[2];
    if (v !== undefined) {
      out.push(v);
    }
  }
  return out;
}

test("r_nf_04_site_catalogues_follow_the_copy_rules", () => {
  const catalogues = filesBelow(join(WEB_DIR, "src"), (n) => /\.en\.ts$/.test(n));
  assert(catalogues.length >= 8, `the message catalogues are found (${catalogues.length})`);
  const problems: string[] = [];
  for (const f of catalogues) {
    const text = readFileSync(f, "utf8");
    if (text.includes("—") || /\\u2014/i.test(text)) {
      problems.push(`${f}: an em dash`);
    }
    for (const s of literals(text)) {
      for (const sentence of s.split(/(?<=[.!?])\s+/)) {
        const words = sentence.split(/\s+/).filter((w) => w !== "").length;
        if (words >= 40) {
          problems.push(`${f}: a sentence of ${words} words: ${sentence.slice(0, 60)}...`);
        }
      }
    }
  }
  eq(problems, [], "R-NF-04: catalogue copy rules");
  assert(existsSync(join(WEB_DIR, "src", "home", "messages.en.ts")), "the home catalogue exists");
});
