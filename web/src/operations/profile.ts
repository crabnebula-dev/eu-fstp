// The funder profile panel of the funder reports page (M9 finish;
// R-RP-01, I-44, I-69; M9 design section 2.2 `programme.funder_profile.view`).
//
// The panel names the funder profile the programme pins through P-53, its
// version and file hash, the outputs it defines and its funder visibility
// elements. A P-53 that names no shipped profile is said in words. A read
// the cell refuses leaves the panel with one line and the page unchanged.

import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import { readOp, type PageEnv } from "../reviewer/kit.js";

/** The output kinds a profile may define (`fstp_report_core::ReportKind`). */
const KINDS = ["call_publication_record", "open_call_package", "periodic_reporting_data", "audit_file", "deliverable_draft"] as const;

/** A pinned funder profile. */
export interface FunderProfile {
  readonly id: string;
  readonly version: string;
  readonly digest: string;
  readonly outputs: readonly string[];
  readonly visibility: readonly string[];
}

/** One reporting period of P-57: instants in UTC microseconds, as decimals. */
export interface ReportingPeriod {
  readonly period: string;
  readonly start: string;
  readonly end: string;
  readonly deadline: string;
}

/** The reply of `programme.funder_profile.view`. */
export interface FunderProfileView {
  readonly programme: string;
  readonly profile: FunderProfile | null;
  /** The reporting periods of P-57 (Daniel, 2026-11-15 late). */
  readonly periods: readonly ReportingPeriod[];
}

const DECIMAL = /^(0|[1-9][0-9]{0,18})$/;

function period(v: unknown): ReportingPeriod | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const o = v as Readonly<Record<string, unknown>>;
  const { period: p, start, end, deadline } = o;
  if (
    Object.keys(o).length === 4 &&
    typeof p === "string" &&
    typeof start === "string" &&
    typeof end === "string" &&
    typeof deadline === "string" &&
    [p, start, end, deadline].every((x) => DECIMAL.test(x))
  ) {
    return { period: p, start, end, deadline };
  }
  return null;
}

/** The UTC date `YYYY-MM-DD` of the last day before the instant `micros`: the end date of a period or a deadline. */
export function lastDay(micros: string): string {
  const ms = Number(BigInt(micros) / 1000n) - 86_400_000;
  return new Date(ms).toISOString().slice(0, 10);
}

function strings(v: unknown): string[] | null {
  return Array.isArray(v) && (v as unknown[]).every((x) => typeof x === "string") ? (v as string[]) : null;
}

/** Reads the reply, or null for any other shape. */
export function decodeFunderProfile(v: unknown): FunderProfileView | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    return null;
  }
  const o = v as Readonly<Record<string, unknown>>;
  const programme = o["programme"];
  if (typeof programme !== "string" || !/^(0|[1-9][0-9]{0,38})$/.test(programme)) {
    return null;
  }
  const raw = o["reporting_periods"];
  if (!Array.isArray(raw)) {
    return null;
  }
  const read = (raw as unknown[]).map(period);
  const periods: ReportingPeriod[] = [];
  for (const r of read) {
    if (r === null) {
      return null;
    }
    periods.push(r);
  }
  const p = o["profile"];
  if (p === null) {
    return { programme, profile: null, periods };
  }
  if (typeof p !== "object" || p === undefined || Array.isArray(p)) {
    return null;
  }
  const r = p as Readonly<Record<string, unknown>>;
  const outputs = strings(r["outputs"]);
  const visibility = strings(r["visibility_elements"]);
  const { id, version, digest } = r;
  if (
    typeof id !== "string" ||
    typeof version !== "string" ||
    typeof digest !== "string" ||
    !/^[0-9a-f]{64}$/.test(digest) ||
    outputs === null ||
    !outputs.every((k) => (KINDS as readonly string[]).includes(k)) ||
    visibility === null
  ) {
    return null;
  }
  return { programme, profile: { id, version, digest, outputs, visibility }, periods };
}

/** The P-57 reporting periods of `v`, or a line saying P-57 names none. */
function periodsBody(t: I18n, v: FunderProfileView): HTMLElement {
  if (v.periods.length === 0) {
    return h("p", { id: "ops-profile-periods-none" }, [t.label("ops.profile.periods_none")]);
  }
  return h("table", { id: "ops-profile-periods" }, [
    h("caption", {}, [t.label("ops.profile.periods")]),
    h("thead", {}, [
      h("tr", {}, [
        h("th", { scope: "col" }, [t.label("ops.profile.period")]),
        h("th", { scope: "col" }, [t.label("ops.profile.period_end")]),
        h("th", { scope: "col" }, [t.label("ops.profile.period_deadline")]),
      ]),
    ]),
    h(
      "tbody",
      {},
      v.periods.map((r) => h("tr", { "data-period": r.period }, [h("th", { scope: "row" }, [r.period]), h("td", {}, [lastDay(r.end)]), h("td", {}, [lastDay(r.deadline)])])),
    ),
  ]);
}

/** The panel's content for `v`. */
export function profileBody(t: I18n, v: FunderProfileView): Child[] {
  const p = v.profile;
  if (p === null) {
    return [h("p", { id: "ops-profile-none" }, [t.label("ops.profile.none")]), periodsBody(t, v)];
  }
  const out: Child[] = [
    h("p", { id: "ops-profile-pinned", "data-profile": p.id, "data-version": p.version }, [
      t.label("ops.profile.pinned", { id: p.id, version: p.version }),
    ]),
    h("dl", {}, [
      h("dt", {}, [t.label("ops.profile.digest")]),
      h("dd", {}, [h("code", {}, [p.digest])]),
      h("dt", {}, [t.label("ops.profile.outputs")]),
      h("dd", {}, [
        h(
          "ul",
          { id: "ops-profile-outputs" },
          p.outputs.map((k) => h("li", { "data-kind": k }, [t.label(`ops.reports.kind.${k}`)])),
        ),
      ]),
    ]),
  ];
  if (p.visibility.length > 0) {
    out.push(h("p", { id: "ops-profile-visibility" }, [t.label("ops.profile.visibility", { keys: p.visibility.join(", ") })]));
  }
  out.push(periodsBody(t, v));
  return out;
}

/** The panel of `programme`: a section that fills once the read answers. */
export async function profilePanel(env: PageEnv, t: I18n, programme: string): Promise<HTMLElement> {
  const r = await readOp(env, "programme.funder_profile.view", { programme }, (x): x is FunderProfileView => decodeFunderProfile(x) !== null);
  const v = r.ok ? decodeFunderProfile(r.data) : null;
  const body: Child[] = v === null ? [h("p", { id: "ops-profile-unread" }, [t.label("ops.profile.unread")])] : profileBody(t, v);
  return h("section", { id: "ops-profile", "aria-labelledby": "ops-profile-heading", class: "card" }, [
    h("h2", { id: "ops-profile-heading" }, [t.label("ops.profile.heading")]),
    ...body,
  ]);
}
