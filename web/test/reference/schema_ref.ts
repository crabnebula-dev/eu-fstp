// Independent reference for the generated structural validators: whether a
// value from `JSON.parse` fits a schema of support/contract.ts. Amounts
// use the ADR-006 reference, so a JSON number never fits an amount.

import type { Schema } from "../support/contract.js";
import type { Rng } from "../support/rng.js";
import { refMoney } from "./money_ref.js";

function plainObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v) && Object.getPrototypeOf(v) === Object.prototype;
}

/** Whether `v` fits `s`. Objects are closed. */
export function fits(s: Schema, v: unknown): boolean {
  switch (s.kind) {
    case "string":
      return typeof v === "string";
    case "id":
      return typeof v === "string" && v !== "";
    case "amount":
      return refMoney(v).ok;
    case "bool":
      return typeof v === "boolean";
    case "int":
      return typeof v === "number" && Number.isSafeInteger(v);
    case "null":
      return v === null;
    case "enum":
      return typeof v === "string" && s.values.includes(v);
    case "array":
      return Array.isArray(v) && v.every((x) => fits(s.items, x));
    case "nullable":
      return v === null || fits(s.inner, v);
    case "object": {
      if (!plainObject(v)) {
        return false;
      }
      for (const k of Object.keys(v)) {
        if (!Object.prototype.hasOwnProperty.call(s.fields, k)) {
          return false;
        }
      }
      return Object.entries(s.fields).every(([k, f]) =>
        Object.prototype.hasOwnProperty.call(v, k) ? fits(f.schema, v[k]) : f.optional,
      );
    }
  }
}

const NASTY_STRINGS: readonly string[] = [
  "",
  "x",
  "1234.50",
  "1234.5",
  "0.00",
  "-1.00",
  "__proto__",
  "constructor",
  "\u0000",
  "<script>",
];

/** A value that fits `s`, built from `r`. */
export function sampleFitting(s: Schema, r: Rng, depth = 0): unknown {
  switch (s.kind) {
    case "string":
      return r.pick(NASTY_STRINGS);
    case "id":
      return r.pick(["a", "p1", "0", "x-y"]);
    case "amount":
      return r.pick(["0.00", "1234.50", "9999999999999999.99"]);
    case "bool":
      return r.bool();
    case "int":
      return r.pick([0, 1, -1, 42, Number.MAX_SAFE_INTEGER]);
    case "null":
      return null;
    case "enum":
      return r.pick(s.values);
    case "array": {
      const n = depth > 3 ? 0 : r.below(3);
      return Array.from({ length: n }, () => sampleFitting(s.items, r, depth + 1));
    }
    case "nullable":
      return r.bool() ? null : sampleFitting(s.inner, r, depth + 1);
    case "object": {
      const out: Record<string, unknown> = {};
      for (const [k, f] of Object.entries(s.fields)) {
        if (!f.optional || r.bool()) {
          out[k] = sampleFitting(f.schema, r, depth + 1);
        }
      }
      return out;
    }
  }
}

/** Any JSON value, often near the shape of `s`. */
export function sampleAny(s: Schema, r: Rng, depth = 0): unknown {
  if (r.oneIn(3)) {
    return r.pick<unknown>([null, true, false, 0, 1.5, -1, 1e21, "", "1234.50", 1234.5, [], {}, "x"]);
  }
  const v = sampleFitting(s, r, depth);
  if (typeof v === "object" && v !== null && !Array.isArray(v) && r.bool()) {
    const o = { ...(v as Record<string, unknown>) };
    const keys = Object.keys(o);
    if (keys.length > 0 && r.bool()) {
      const k = r.pick(keys);
      o[k] = sampleAny(s.kind === "object" ? (s.fields[k]?.schema ?? s) : s, r, depth + 1);
    } else if (keys.length > 0 && r.bool()) {
      delete o[r.pick(keys)];
    } else {
      o[r.pick(["extra", "__proto__x", "constructor"])] = 1;
    }
    return o;
  }
  return v;
}
