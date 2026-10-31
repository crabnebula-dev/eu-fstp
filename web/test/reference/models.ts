// Reference-backed modules of the contract, for teeth tests only.
//
// A teeth test runs a fuzz target or a property over one of these, and
// over a mutant of it, to show that the check passes on correct code and
// catches the fault. They are test code: production never imports them,
// and the web scan keeps web/src from importing outside web/src.

import type {
  GenApiModule,
  I18nModule,
  MoneyModule,
  RouteDef,
  RouterModule,
  Schema,
} from "../support/contract.js";
import { refMoney } from "./money_ref.js";
import { refParseMessage } from "./message_ref.js";
import { refMatch, tableFault } from "./route_ref.js";
import { refSafeUrl } from "./safe_url_ref.js";
import { fits } from "./schema_ref.js";

/** money.ts by the reference. */
export const refMoneyModule: MoneyModule = {
  parseAmount(input, currency) {
    if (currency !== "EUR") {
      return { ok: false, kind: "UnknownCurrency" };
    }
    const v = refMoney(input);
    return v.ok && typeof input === "string"
      ? { ok: true, amount: { currency: "EUR", text: input } }
      : { ok: false, kind: v.ok ? "NotAString" : v.kind };
  },
  amountText: (a) => a.text,
};

/** `safeUrl` by the reference. */
export const refSafeUrlModule = {
  safeUrl: (input: unknown): string | null => (refSafeUrl(input) && typeof input === "string" ? input : null),
};

/** `parseMessage` by the reference. */
export const refMessageModule: Pick<I18nModule, "parseMessage"> = {
  parseMessage: (text) => refParseMessage(text),
};

/** The reference router error. */
export class RefRouterError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "RouterError";
  }
}

/** router.ts by the reference. */
export const refRouterModule: RouterModule = {
  createRouter(defs: readonly RouteDef[]) {
    const fault = tableFault(defs);
    if (fault !== null) {
      throw new RefRouterError(fault);
    }
    return { match: (path: string) => refMatch(defs, path) };
  },
  RouterError: RefRouterError,
};

/** A small generated table, as tools/gen-ts might emit it. */
export const SAMPLE_SCHEMAS: Readonly<Record<string, Schema>> = {
  draft_summary: {
    kind: "object",
    fields: {
      id: { schema: { kind: "id" }, optional: false },
      title: { schema: { kind: "string" }, optional: false },
      cap: { schema: { kind: "amount" }, optional: false },
      state: { schema: { kind: "enum", values: ["DRAFT", "ACTIVE"] }, optional: false },
      note: { schema: { kind: "nullable", inner: { kind: "string" } }, optional: true },
    },
  },
  amounts: { kind: "array", items: { kind: "amount" } },
};

/** Generated validators by the reference. */
export const refGenApi: GenApiModule = {
  SCHEMAS: SAMPLE_SCHEMAS,
  VALIDATORS: Object.fromEntries(
    Object.entries(SAMPLE_SCHEMAS).map(([k, s]) => [k, (v: unknown): boolean => fits(s, v)]),
  ),
};
