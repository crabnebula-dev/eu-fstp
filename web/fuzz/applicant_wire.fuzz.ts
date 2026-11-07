// Fuzz target `applicant_wire` for the decoders of web/src/applicant/wire.ts
// (M4 design section 9, ADR-014, TH-26, H-05). The decoders read every
// server body of the applicant and call pages, and `parseGuideHtml` reads
// the stored Guide page of `calls.guide` (R-GA-01, I-53).
//
// Checks, for any string:
// - no decoder throws on the value `JSON.parse` gives, if any;
// - `parseGuideHtml` never throws, and a page it accepts gives only
//   elements of `GUIDE_TAGS`, no deeper than `GUIDE_MAX_DEPTH`, with an
//   `href` on `a` only;
// - an accepted page written back in the writer's subset parses to the
//   same nodes (round trip), so text never turns into an element;
// - `decodeGuide` agrees with `parseGuideHtml` on the `html` member.

import { assert, show } from "../test/support/harness.js";
import * as wire from "../src/applicant/wire.js";
import type { Checker, FuzzTarget } from "./harness.js";
import { readExpectations } from "./harness.js";

type Node = wire.GuideNode;

const TAGS: ReadonlySet<string> = new Set(wire.GUIDE_TAGS);
const VOID: ReadonlySet<string> = new Set(["br", "hr"]);

function esc(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

/** The nodes written back as the `fstp-html` writer would write them. */
function write(nodes: readonly Node[]): string {
  return nodes
    .map((n) => {
      if (typeof n === "string") return esc(n);
      const attr = n.href === null ? "" : ` href="${esc(n.href)}"`;
      return VOID.has(n.tag) ? `<${n.tag}${attr}>` : `<${n.tag}${attr}>${write(n.children)}</${n.tag}>`;
    })
    .join("");
}

/** Text nodes next to each other merge when written back, so compare them merged. */
function norm(nodes: readonly Node[]): unknown[] {
  const out: unknown[] = [];
  for (const n of nodes) {
    if (typeof n === "string") {
      if (n === "") continue;
      const last = out[out.length - 1];
      if (typeof last === "string") out[out.length - 1] = last + n;
      else out.push(n);
    } else {
      out.push({ tag: n.tag, href: n.href, children: VOID.has(n.tag) ? [] : norm(n.children) });
    }
  }
  return out;
}

function shapeOk(nodes: readonly Node[], depth: number): string | null {
  for (const n of nodes) {
    if (typeof n === "string") continue;
    if (!TAGS.has(n.tag)) return `tag ${n.tag} outside the subset`;
    if (n.href !== null && n.tag !== "a") return `href on ${n.tag}`;
    if (depth > wire.GUIDE_MAX_DEPTH) return "too deep";
    const inner = shapeOk(n.children, depth + 1);
    if (inner !== null) return inner;
  }
  return null;
}

const DECODERS: readonly ((v: unknown) => unknown)[] = [
  wire.decodeOpenCalls,
  wire.decodeCall,
  wire.decodeGuide,
  wire.decodeOwnProposals,
  wire.decodeProposal,
  wire.decodeCreated,
  wire.decodeWorkspace,
  wire.decodeAccepted,
  wire.decodePlanSaved,
  wire.decodeRedirect,
  wire.decodeStage2,
  wire.decodeNotices,
  wire.decodeNegotiation,
  wire.instantOfMicros,
  wire.dayOf,
];

const DIGEST = "0".repeat(64);

/** The checker over the production `wire.ts`. */
export function checkerFor(w: typeof wire): Checker {
  return (input: string) => {
    let value: unknown = undefined;
    let parsed = false;
    try {
      value = JSON.parse(input);
      parsed = true;
    } catch {
      parsed = false;
    }
    const values: unknown[] = [input];
    if (parsed) values.push(value);
    for (const v of values) {
      for (const d of DECODERS) {
        try {
          d(v);
        } catch (e) {
          throw new Error(`a wire decoder threw on ${show(input)}: ${String(e)}`);
        }
      }
    }
    let nodes: readonly Node[] | null;
    try {
      nodes = w.parseGuideHtml(input);
    } catch (e) {
      throw new Error(`parseGuideHtml threw on ${show(input)}: ${String(e)}`);
    }
    const g = w.decodeGuide({ call: "1", version: 1, digest: DIGEST, html: input });
    assert((g === null) === (nodes === null), `decodeGuide and parseGuideHtml disagree on ${show(input)}`);
    if (nodes === null) return;
    const bad = shapeOk(nodes, 1);
    assert(bad === null, `parseGuideHtml gave ${String(bad)} on ${show(input)}`);
    const again = w.parseGuideHtml(`<main>${write(nodes)}</main>`);
    assert(again !== null, `the written-back page of ${show(input)} is refused`);
    assert(
      JSON.stringify(norm(again)) === JSON.stringify(norm(nodes)),
      `the written-back page of ${show(input)} parses to other nodes`,
    );
  };
}

export const target: FuzzTarget = {
  name: "applicant_wire",
  seeds: () => readExpectations("applicant_wire").map((e) => e.input),
  dictionary: [
    "<main>",
    "</main>",
    "<h2>",
    "</h2>",
    "<p>",
    "</p>",
    "<ul><li>",
    "</li></ul>",
    "<table><tr><td>",
    '<a href="https://platform.fstp.test/">',
    "</a>",
    "<script>",
    "</script>",
    "<!--",
    "-->",
    "&amp;",
    "&lt;",
    "&#39;",
    "&#x1F600;",
    '"',
    "'",
    "=",
    "/>",
    '{"call":"1","version":1,"digest":"',
    '","html":"',
    '"}',
  ],
  prepare: async () => checkerFor(wire),
};
