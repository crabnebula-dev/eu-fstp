// The tenant admin override of I-67 on the approval inbox (ADR-022,
// Daniel 2026-11-15). A tenant admin who built the programme sees an
// "Approve as override" form with a reason field, in plain words. A
// blank reason is never sent. Every value here is synthetic.

import { OPERATIONS, SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { readApprovals, type ApprovalRow } from "../src/creator/model.js";
import { offerOverride, overrideForm, type OverrideSend } from "../src/creator/pages/approvals.js";
import { approverOverrideSlot } from "../src/setup/view.js";
import type { Outcome } from "../src/creator/ops.js";
import { FakeElement, asFake, fakeDocument, freshDom } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const g = globalThis as unknown as Record<string, unknown>;

function prepare(): void {
  freshDom();
  for (const n of ["HTMLButtonElement", "HTMLTextAreaElement"]) {
    g[n] = FakeElement;
  }
}

/** The elements under `root` whose tag is `tag`. */
function all(root: FakeElement, tag: string): FakeElement[] {
  const out: FakeElement[] = [];
  const walk = (n: FakeElement): void => {
    for (const c of n.childNodes) {
      if (c instanceof FakeElement) {
        if (c.tagName.toLowerCase() === tag) out.push(c);
        walk(c);
      }
    }
  };
  walk(root);
  return out;
}

const ROW: ApprovalRow = {
  kind: "activation",
  programme: "41",
  revision: "6.18",
  approvable: false,
  overridable: true,
  name: "Synthetic programme",
  approval: null,
  role: null,
  grantee: null,
};

/** ADR-022: the inbox reply carries `overridable`, which the generated validator and the reader accept. */
test("i67_adr022_approval_rows_read_overridable", () => {
  const body = {
    approvals: [
      { kind: "activation", programme: "41", revision: "6.18", approvable: false, overridable: true },
      { kind: "activation", programme: "42", revision: "2.9", approvable: true, overridable: false },
      { kind: "activation", programme: "43", revision: "2.9", approvable: true },
    ],
    unlisted: ["self_grant"],
  };
  const check = VALIDATORS["admin.approvals"];
  assert(check !== undefined && SCHEMAS["admin.approvals"] !== undefined, "gen/api.ts holds admin.approvals");
  assert(check(body), "the sample fits its generated validator");
  const rows = readApprovals(body);
  eq(
    rows?.map((r) => [r.programme, r.approvable, r.overridable]),
    [
      ["41", false, true],
      ["42", true, false],
      ["43", true, false],
    ],
    "overridable reads, and an absent member is false",
  );
  eq(readApprovals({ approvals: [{ ...body.approvals[0], overridable: "yes" }] }), null, "a non-boolean is refused");
  const op = OPERATIONS.find((o) => o.name === "creator.override_activation");
  assert(op !== undefined, "gen/api.ts holds creator.override_activation");
  eq(`${op?.method} ${op?.path}`, "POST /programmes/{programme}/activation-override", "the route of the override");
});

/**
 * ADR-022, I-67: a builder admin's row offers "Approve as override" with a
 * labelled reason field and the plain words. A blank reason is not sent.
 * A written one is sent with the revision, and the row says it is done.
 */
test("i67_adr022_override_form_needs_a_reason_and_sends_it", async () => {
  prepare();
  const sent: { name: string; params: readonly string[]; body: unknown }[] = [];
  const send: OverrideSend = async (name, params, body): Promise<Outcome> => {
    sent.push({ name, params, body });
    return { kind: "done", body: {} };
  };
  const alert = asFake(fakeDocument.createElement("p"));
  let finished = 0;
  const form = asFake(
    overrideForm(ROW, async () => "6.18", alert as unknown as HTMLElement, send, () => {
      finished += 1;
    }),
  );
  fakeDocument.body.appendChild(form);
  const text = form.textContent ?? "";
  assert(
    text.includes("You built this programme. As a tenant admin you can approve it anyway. Your reason is recorded."),
    `the plain words are shown: ${text}`,
  );
  const [area] = all(form, "textarea");
  const [button] = all(form, "button");
  const [label] = all(form, "label");
  assert(area !== undefined && button !== undefined && label !== undefined, "a reason field, its label and a button");
  eq(label?.getAttribute("for"), area?.getAttribute("id"), "the label names the reason field");
  eq(button?.textContent, "Approve as override", "the button says what it does");

  for (const blank of ["", "   \n"]) {
    if (area !== undefined) area.value = blank;
    button?.click();
    await new Promise((r) => setTimeout(r, 5));
    eq(sent.length, 0, `a blank reason ${JSON.stringify(blank)} is not sent`);
    assert((alert.textContent ?? "") !== "", "the page asks for a reason");
  }

  if (area !== undefined) area.value = "SYNTHETIC: the second admin is on leave.";
  button?.click();
  await new Promise((r) => setTimeout(r, 5));
  eq(sent.length, 1, "the override is sent once");
  eq(sent[0]?.name, "creator.override_activation", "the override operation");
  eq(sent[0]?.params, ["41"], "the programme of the row");
  eq(sent[0]?.body, { revision: "6.18", reason: "SYNTHETIC: the second admin is on leave." }, "revision and reason");
  eq(form.getAttribute("data-status"), "approved", "the row says it is approved");
  eq(finished, 1, "the page hears that the override completed");
});

/** Gives `offerOverride` a fake cell: `me.roles` with `admin`, and the inbox with `rows`. */
function cell(admin: boolean, rows: unknown[]): string[] {
  const asked: string[] = [];
  g["location"] = { pathname: "/app/programmes/41/setup/progress", hash: "", search: "", origin: "https://cell-a.e2e.invalid", href: "https://cell-a.e2e.invalid/app/programmes/41/setup/progress" };
  g["fetch"] = async (input: unknown): Promise<Response> => {
    const path = new URL(String(input), "https://cell-a.e2e.invalid").pathname;
    asked.push(path);
    const json = (v: unknown, status = 200): Response =>
      new Response(JSON.stringify(v), { status, headers: { "Content-Type": "application/json" } });
    if (path.endsWith("/me/roles")) {
      return json({ tenant_admin: admin, roles: [], calls: [], rounds: [], drafts: [], signatories: [] });
    }
    if (path.endsWith("/admin/approvals")) {
      return admin ? json({ approvals: rows }) : json({ code: "refused", rule: "actor" }, 403);
    }
    return json({ code: "not_found", rule: "Input" }, 404);
  };
  return asked;
}

/**
 * ADR-022: the set-up wizard's `i67-override` slot holds the override form
 * for a tenant admin who built the programme. For anyone else it stays
 * empty and hidden, and a reader who is no tenant admin never asks for
 * the approval inbox.
 */
test("i67_adr022_setup_slot_offers_the_override_to_a_builder_admin_only", async () => {
  prepare();
  const alert = asFake(fakeDocument.createElement("p")) as unknown as HTMLElement;
  const row = { kind: "activation", programme: "41", revision: "6.18", approvable: false, overridable: true };

  cell(true, [row]);
  const filled = asFake(approverOverrideSlot());
  await offerOverride(filled as unknown as HTMLElement, "41", alert, () => undefined);
  eq(filled.getAttribute("hidden"), null, "the slot shows for the builder admin");
  assert((filled.textContent ?? "").includes("Approve as override"), "the override form is in the slot");
  eq(all(filled, "textarea").length, 1, "with its reason field");

  cell(true, [{ ...row, approvable: true, overridable: false }]);
  const second = asFake(approverOverrideSlot());
  await offerOverride(second as unknown as HTMLElement, "41", alert, () => undefined);
  assert(second.getAttribute("hidden") !== null, "a second person sees no override");
  eq(second.childNodes.length, 0, "and no form");

  const asked = cell(false, [row]);
  const manager = asFake(approverOverrideSlot());
  await offerOverride(manager as unknown as HTMLElement, "41", alert, () => undefined);
  assert(manager.getAttribute("hidden") !== null, "a programme manager sees no override");
  assert(!asked.some((p) => p.endsWith("/admin/approvals")), "a non-admin never asks for the inbox");
});
