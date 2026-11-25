// The audit log findings on the tenant admins' System page (ADR-012
// record of lane m10/declared-restore, I-24). A window a declared restore
// lost, or a possible deletion, shows with a red light and an Acknowledge
// button. An acknowledgement sends `tenant.acknowledge_finding` and never
// removes the finding: it stays listed with a green light. Every value
// here is synthetic.

import { SYSTEM_LABELS } from "../src/admin/system/messages.en.js";
import { acknowledgeBody, decodeSystem, openFindings, type SystemReply } from "../src/admin/system/model.js";
import { SYSTEM_PAGES } from "../src/admin/system/page.js";
import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { OPERATIONS, VALIDATORS } from "../src/gen/api.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { FakeElement, fakeDocument, freshDom } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const NOW = "1795000000000000";

function lost(id: string, acknowledged: string | null): Record<string, unknown> {
  return { id, kind: "lost_in_restore", chain: "app", from: "4", to: "9", acknowledged_at: acknowledged };
}

function wire(findings: readonly Record<string, unknown>[]): Record<string, unknown> {
  return {
    now: NOW,
    vault: "answers",
    mail: "works",
    last_cell_erasure: null,
    findings,
    host_file: "not_configured",
    host: null,
  };
}

function decoded(findings: readonly Record<string, unknown>[]): SystemReply {
  const r = decodeSystem(wire(findings));
  if (r === null) throw new Error("does not decode");
  return r;
}

/** I-24, ADR-012: findings decode strictly, as the generated validator does, and every label they name exists. */
test("adr012_declared_restore_findings_decode_strictly", () => {
  const validate = VALIDATORS["tenant.system"];
  assert(validate !== undefined, "a generated validator");
  const good = wire([
    lost("17", null),
    { id: "18", kind: "possible_deletion", chain: "app", from: "3", to: "3", acknowledged_at: "1794000000000000" },
    { id: "19", kind: "lost_in_restore", chain: "vault", from: "1", to: "2", acknowledged_at: null },
  ]);
  assert(decodeSystem(good) !== null, "decodes");
  assert(validate?.(good) === true, "the validator accepts it");
  for (const bad of [
    wire([{ ...lost("17", null), kind: "deleted" }]),
    wire([{ ...lost("17", null), chain: "edge" }]),
    wire([{ ...lost("17", null), from: "9", to: "4" }]),
    wire([{ ...lost("017", null) }]),
    wire([{ ...lost("17", null), note: "synthetic" }]),
  ]) {
    eq(decodeSystem(bad), null, JSON.stringify(bad));
  }
  const without: Record<string, unknown> = { ...wire([]) };
  delete without["findings"];
  eq(decodeSystem(without), null, "the findings member is required");
  for (const r of [decoded([]), decodeSystem(good)]) {
    for (const f of r?.findings ?? []) {
      assert(typeof SYSTEM_LABELS[`system.findings.${f.kind}.${f.chain}`] === "string", `${f.kind}.${f.chain}`);
    }
  }
  eq(acknowledgeBody("17"), { finding: "17" }, "the acknowledgement body");
  const op = OPERATIONS.find((o) => o.name === "tenant.acknowledge_finding");
  eq(op?.method, "POST", "the acknowledgement");
  eq(op?.highRisk, false, "no step-up");
});

const g = globalThis as unknown as Record<string, unknown>;

/** The first Acknowledge button on the page, or null. */
function ackButton(): FakeElement | null {
  return (fakeDocument.body as unknown as FakeElement).descendants().find((e) => e.classList.contains("system-acknowledge")) ?? null;
}

/** I-24, ADR-012: an open finding makes the page red and offers Acknowledge; the click sends the finding's id, and the acknowledged finding stays listed. */
test("adr012_declared_restore_finding_is_acknowledged_and_stays_listed", async () => {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  let acknowledged: string | null = null;
  const sent: unknown[] = [];
  const api: ApiClient = {
    async call(op: OperationRef, _params, body, validate): Promise<ApiOutcome> {
      const key = `${op.method} ${op.path}`;
      if (key === "POST /admin/system/acknowledgements") {
        sent.push(body);
        acknowledged = "1795000000000001";
        return validate({}) ? { kind: "done", body: {} } : { kind: "failed", reason: "invalid_response" };
      }
      if (key === "GET /admin/system") {
        const r = wire([lost("17", acknowledged)]);
        return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
      }
      return { kind: "refused", code: "refused", rule: "R-AC-01" };
    },
  };
  const env: PageEnv = { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
  await SYSTEM_PAGES[0]?.mount(env, {});
  const overall = fakeDocument.getElementById("system-overall") as FakeElement | null;
  eq(overall?.getAttribute("data-light"), "red", "an open finding makes the page red");
  const text = fakeDocument.body.textContent ?? "";
  assert(text.includes("Entries 4 to 9"), "the lost window");
  const button = ackButton();
  assert(button !== null, "an Acknowledge button");
  eq(button?.getAttribute("data-finding"), "17", "it names the finding");
  button?.click();
  for (let i = 0; i < 20 && sent.length === 0; i += 1) await Promise.resolve();
  for (let i = 0; i < 50; i += 1) await Promise.resolve();
  eq(sent.length, 1, "one acknowledgement");
  const after = fakeDocument.body.textContent ?? "";
  assert(after.includes(SYSTEM_LABELS["system.findings.acknowledged"] ?? "?"), "it stays listed as acknowledged");
  assert(after.includes("Entries 4 to 9"), "the finding is still shown");
  eq(ackButton(), null, "no button once acknowledged");
  eq(openFindings(decoded([lost("17", "1")])).length, 0, "an acknowledged finding is not open");
});
