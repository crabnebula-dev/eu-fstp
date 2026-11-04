// The TypeScript fuzz targets of M4 design section 9 (Q33 interim, TH-26,
// H-05). Each target exists, holds on a short seeded run against the
// production module, and has teeth: it passes over the reference-backed
// module and catches a mutant of it.

import { type Checker, type FuzzTarget, readExpectations, runTarget } from "../fuzz/harness.js";
import * as message from "../fuzz/message_format.fuzz.js";
import * as money from "../fuzz/money_parse.fuzz.js";
import * as returnPath from "../fuzz/return_path.fuzz.js";
import * as router from "../fuzz/router_match.fuzz.js";
import { TARGETS } from "../fuzz/targets.js";
import * as safe from "../fuzz/safe_url.fuzz.js";
import * as validators from "../fuzz/validators.fuzz.js";
import type { GenApiModule, MoneyModule, RouterModule } from "./support/contract.js";
import { assert, eq, show, test } from "./support/harness.js";
import { refMatch } from "./reference/route_ref.js";
import {
  SAMPLE_SCHEMAS,
  refGenApi,
  refMessageModule,
  refMoneyModule,
  refRouterModule,
  refSafeUrlModule,
} from "./reference/models.js";

const SMOKE_SEED = 20261030;
const SMOKE_RUNS = 400;
const TEETH_RUNS = 3000;

async function holds(t: FuzzTarget): Promise<void> {
  const out = await runTarget(t, SMOKE_SEED, SMOKE_RUNS);
  if (!out.ok) {
    throw new Error(`${t.name} failed at iteration ${out.iteration} on ${show(out.input)}: ${out.message}`);
  }
}

function over(t: FuzzTarget, checker: () => Checker, extraSeeds: readonly string[] = []): FuzzTarget {
  return {
    name: `${t.name}-teeth`,
    seeds: () => [...t.seeds(), ...extraSeeds],
    dictionary: t.dictionary,
    prepare: async () => checker(),
  };
}

async function passes(t: FuzzTarget): Promise<void> {
  const out = await runTarget(t, SMOKE_SEED, TEETH_RUNS);
  assert(out.ok, `the reference-backed module fails ${t.name}: ${out.ok ? "" : `${out.message} on ${show(out.input)}`}`);
}

async function caught(t: FuzzTarget): Promise<void> {
  const out = await runTarget(t, SMOKE_SEED, TEETH_RUNS);
  assert(!out.ok, `${t.name} did not catch the mutant`);
}

/** TH-26, H-05: every TypeScript parser of design section 9 has its fuzz target and a non-empty corpus. */
test("th26_every_typescript_parser_has_a_fuzz_target", () => {
  eq(
    TARGETS.map((t) => t.name).sort(),
    ["message_format", "money_parse", "return_path", "router_match", "safe_url", "validators"],
    "target names",
  );
  for (const t of TARGETS) {
    assert(t.seeds().length > 0, `${t.name} has seeds`);
    assert(readExpectations(t.name).length > 0, `${t.name} has an expect.tsv corpus`);
  }
});

/** TH-26, ADR-006: `money_parse` holds on a seeded run over web/src/core/money.ts. */
test("th26_money_parse_target_holds", async () => {
  await holds(money.target);
});

/** TH-26, ADR-014: `safe_url` holds on a seeded run over web/src/core/dom.ts. */
test("th26_safe_url_target_holds", async () => {
  await holds(safe.target);
});

/** TH-26, ADR-014: `router_match` holds on a seeded run over web/src/core/router.ts. */
test("th26_router_match_target_holds", async () => {
  await holds(router.target);
});

/** TH-26, ADR-014: `validators` holds on a seeded run over the generated web/src/gen/api.ts. */
test("th26_validators_target_holds", async () => {
  await holds(validators.target);
});

/** TH-26, R-NF-04: `message_format` holds on a seeded run over web/src/core/i18n.ts. */
test("th26_message_format_target_holds", async () => {
  await holds(message.target);
});

/** TH-26, ADR-006 teeth: `money_parse` passes the reference and catches a parser that normalises. */
test("th26_money_parse_teeth_normalising_parser_is_caught", async () => {
  await passes(over(money.target, () => money.checkerFor(refMoneyModule)));
  const mutant: MoneyModule = {
    parseAmount(input, currency) {
      if (typeof input === "string" && /^[0-9]+\.[0-9]$/.test(input)) {
        return { ok: true, amount: { currency, text: `${input}0` } };
      }
      return refMoneyModule.parseAmount(input, currency);
    },
    amountText: (a) => a.text,
  };
  await caught(over(money.target, () => money.checkerFor(mutant)));
});

/** TH-26, ADR-006 teeth: `money_parse` catches a parser that accepts a sign or a leading zero. */
test("th26_money_parse_teeth_lenient_parser_is_caught", async () => {
  const mutant: MoneyModule = {
    parseAmount(input, currency) {
      if (typeof input === "string" && /^[+-]?0*[0-9]+\.[0-9]{2}$/.test(input)) {
        return { ok: true, amount: { currency, text: input } };
      }
      return refMoneyModule.parseAmount(input, currency);
    },
    amountText: (a) => a.text,
  };
  await caught(over(money.target, () => money.checkerFor(mutant)));
});

/** TH-26, ADR-014 teeth: `safe_url` passes the reference and catches a case-sensitive script-scheme filter. */
test("th26_safe_url_teeth_denylist_filter_is_caught", async () => {
  await passes(over(safe.target, () => safe.checkerFor(refSafeUrlModule)));
  const mutant = {
    safeUrl: (input: unknown): string | null =>
      typeof input === "string" && !input.startsWith("javascript:") && !input.startsWith("data:") ? input : null,
  };
  await caught(over(safe.target, () => safe.checkerFor(mutant)));
});

/** TH-26, ADR-014 teeth: `safe_url` catches a filter that lets protocol-relative URLs through. */
test("th26_safe_url_teeth_protocol_relative_is_caught", async () => {
  const mutant = {
    safeUrl: (input: unknown): string | null =>
      typeof input === "string" && input.startsWith("//") ? input : refSafeUrlModule.safeUrl(input),
  };
  await caught(over(safe.target, () => safe.checkerFor(mutant)));
});

/** TH-26, ADR-014 teeth: `router_match` passes the reference and catches a router that skips segment checks. */
test("th26_router_match_teeth_unchecked_segment_is_caught", async () => {
  await passes(over(router.target, () => router.checkerFor(refRouterModule)));
  const mutant: RouterModule = {
    createRouter(defs) {
      const unchecked = defs.map((d) => ({
        ...d,
        segments: Object.fromEntries(Object.keys(d.segments).map((k) => [k, () => true])),
      }));
      return { match: (p) => refMatch(unchecked, p) };
    },
    RouterError: refRouterModule.RouterError,
  };
  await caught(over(router.target, () => router.checkerFor(mutant)));
});

/** TH-26, ADR-014 teeth: `router_match` catches a router that does not refuse encoded slashes. */
test("th26_router_match_teeth_encoded_slash_is_caught", async () => {
  const mutant: RouterModule = {
    createRouter(defs) {
      const inner = refRouterModule.createRouter(defs);
      return { match: (p) => inner.match(p.replace(/%2F/gi, "x")) };
    },
    RouterError: refRouterModule.RouterError,
  };
  await caught(over(router.target, () => router.checkerFor(mutant)));
});

/** TH-26, R-NF-04 teeth: `message_format` passes the reference and catches a parser that allows capitals. */
test("th26_message_format_teeth_lenient_name_is_caught", async () => {
  await passes(over(message.target, () => message.checkerFor(refMessageModule)));
  const mutant = {
    parseMessage: (text: string) => refMessageModule.parseMessage(text.replace(/\{([A-Z])/g, (_m, c: string) => `{${c.toLowerCase()}`)),
  };
  await caught(over(message.target, () => message.checkerFor(mutant)));
});

/**
 * TH-26, ADR-006 teeth: `validators` passes reference validators and
 * catches a validator that takes a JSON number for an amount, or one that
 * ignores unknown members.
 */
test("th26_validators_teeth_number_amount_and_open_object_are_caught", async () => {
  const seeds = ['{"id":"p1","title":"t","cap":"1.00","state":"DRAFT"}', '{"id":"p1","title":"t","cap":1.5,"state":"DRAFT"}'];
  await passes(over(validators.target, () => validators.checkerFor(refGenApi), seeds));
  const numberAmount: GenApiModule = {
    SCHEMAS: SAMPLE_SCHEMAS,
    VALIDATORS: {
      ...refGenApi.VALIDATORS,
      draft_summary: (v) => {
        if (typeof v === "object" && v !== null && typeof (v as Record<string, unknown>)["cap"] === "number") {
          return refGenApi.VALIDATORS["draft_summary"]?.({ ...(v as Record<string, unknown>), cap: "1.00" }) === true;
        }
        return refGenApi.VALIDATORS["draft_summary"]?.(v) === true;
      },
    },
  };
  await caught(over(validators.target, () => validators.checkerFor(numberAmount), seeds));
  const openObject: GenApiModule = {
    SCHEMAS: SAMPLE_SCHEMAS,
    VALIDATORS: {
      ...refGenApi.VALIDATORS,
      draft_summary: (v) => {
        if (typeof v !== "object" || v === null || Array.isArray(v)) {
          return false;
        }
        const r = v as Record<string, unknown>;
        const known = Object.fromEntries(Object.entries(r).filter(([k]) => ["id", "title", "cap", "state", "note"].includes(k)));
        return refGenApi.VALIDATORS["draft_summary"]?.(known) === true;
      },
    },
  };
  await caught(over(validators.target, () => validators.checkerFor(openObject), [...seeds, '{"id":"p1","title":"t","cap":"1.00","state":"DRAFT","extra":1}']));
});

/** TH-26, ADR-014 (review finding F2): `return_path` holds on a seeded run over web/src/auth/next.ts. */
test("th26_return_path_target_holds", async () => {
  await holds(returnPath.target);
});

/** TH-26, ADR-014: the module and its reference give every `return_path` corpus line its verdict. */
test("th26_return_path_corpus_verdicts", () => {
  for (const e of readExpectations("return_path")) {
    const want = e.verdict === "accept";
    assert(e.verdict === "accept" || e.verdict === "refuse", `line ${e.line}: verdict ${e.verdict}`);
    eq(returnPath.PRODUCTION.isReturnPath(e.input), want, `line ${e.line}: next.ts on ${show(e.input)}`);
    eq(returnPath.refIsReturnPath(e.input), want, `line ${e.line}: the reference on ${show(e.input)}`);
  }
});

/** TH-26, ADR-014 teeth: `return_path` passes the reference and catches a guard that lets `//` through. */
test("th26_return_path_teeth_double_slash_is_caught", async () => {
  await passes(
    over(returnPath.target, () =>
      returnPath.checkerFor({
        isReturnPath: returnPath.refIsReturnPath,
        landingAfterSignIn: (s) => {
          const n = new URLSearchParams(s).get("next");
          return returnPath.refIsReturnPath(n) && n !== null ? n : "/app/";
        },
      }),
    ),
  );
  const lenient = (p: unknown): boolean =>
    typeof p === "string" && p.startsWith("/app/") && p.includes("//") ? true : returnPath.refIsReturnPath(p);
  await caught(
    over(returnPath.target, () =>
      returnPath.checkerFor({
        isReturnPath: lenient,
        landingAfterSignIn: (s) => {
          const n = new URLSearchParams(s).get("next");
          return lenient(n) && n !== null ? n : "/app/";
        },
      }),
    ),
  );
});

/** TH-26, ADR-014 teeth: `return_path` catches a guard that misses an encoded dot segment. */
test("th26_return_path_teeth_encoded_dot_is_caught", async () => {
  const lenient = (p: unknown): boolean =>
    typeof p === "string" && /^\/app\/%2e%2e\//i.test(p) ? true : returnPath.refIsReturnPath(p);
  await caught(
    over(returnPath.target, () =>
      returnPath.checkerFor({
        isReturnPath: lenient,
        landingAfterSignIn: (s) => {
          const n = new URLSearchParams(s).get("next");
          return lenient(n) && n !== null ? n : "/app/";
        },
      }),
    ),
  );
});
