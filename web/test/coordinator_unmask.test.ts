// The coordinator unmask pages over the fake DOM (ADR-023, I-17 as
// amended 2026-11-15, I-78). The parties page lists each person with an
// Unmask control, the form asks for a purpose, says it is recorded, and
// sends the body `fstp-api-core` decodes. The released identity opens on
// the vault origin only.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { COORDINATOR_PAGES } from "../src/coordinator/pages.js";
import { isParties, purposeOk, unmaskBody } from "../src/coordinator/unmask.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, fakeDocument, freshDom } from "./support/fakedom.js";

const g = globalThis as unknown as Record<string, unknown>;

interface Sent {
  readonly path: string;
  readonly body: unknown;
}

function env(replies: Readonly<Record<string, unknown>>, sent: Sent[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      sent.push({ path: `${op.method} ${path}`, body });
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "actor" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

const assigned: string[] = [];

function prepare(): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  assigned.length = 0;
  g["location"] = {
    protocol: "http:",
    hostname: "a.fstp.localhost",
    port: "8990",
    pathname: "/app/proposals/1001/parties",
    assign: (to: string) => assigned.push(to),
  };
}

function text(): string {
  return fakeDocument.body.textContent ?? "";
}

function byId(id: string): FakeElement {
  const el = fakeDocument.getElementById(id) as FakeElement | null;
  if (el === null) {
    throw new Error(`no #${id} in: ${text().slice(0, 400)}`);
  }
  return el;
}

const PARTIES = {
  programme: "1",
  proposal: "1001",
  parties: [
    { party: "applicant", subject_type: "binding", subject: "11", role: "applicant", label: "" },
    { party: "reviewer", subject_type: "assignment", subject: "21", role: "committee_member", label: "Reviewer R1" },
    { party: "staff", subject_type: "binding", subject: "31", role: "programme_manager", label: "" },
  ],
};

function page(name: string): (env: PageEnv, params: Readonly<Record<string, string>>) => Promise<void> {
  const p = COORDINATOR_PAGES.find((x) => x.route.name === name);
  if (p === undefined) {
    throw new Error(`no page ${name}`);
  }
  return (e, params) => p.mount(e, params);
}

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

/** ADR-023 reading 4: the purpose is not blank and at most 500 characters, and the body names the subject by id only. */
test("adr023_unmask_body_names_the_subject_and_the_purpose", () => {
  assert(purposeOk("Synthetic purpose"), "a purpose");
  assert(!purposeOk(""), "empty");
  assert(!purposeOk("  \n\t"), "blank");
  assert(purposeOk("a".repeat(500)), "500 characters");
  assert(!purposeOk("a".repeat(501)), "501 characters");
  eq(unmaskBody("binding", "11", ""), null, "no purpose, no body");
  eq(
    JSON.stringify(unmaskBody("binding", "11", "Why")),
    '{"purpose":"Why","subject":{"binding":"11","type":"Binding"}}',
    "binding",
  );
  eq(
    JSON.stringify(unmaskBody("assignment", "21", "Why")),
    '{"purpose":"Why","subject":{"assignment":"21","type":"Assignment"}}',
    "assignment",
  );
  assert(isParties(PARTIES), "the parties guard admits the cell's reply");
  assert(!isParties({ ...PARTIES, parties: [{ ...PARTIES.parties[0], name: "Synthetic Name" }] }), "a closed row");
});

/** I-17 (ADR-023): the parties page lists each person by kind and handle, each with an Unmask control, and says the purpose is recorded. */
test("i17_parties_page_offers_an_unmask_control_per_party", async () => {
  prepare();
  const sent: Sent[] = [];
  await page("coordinator.parties")(env({ "GET /proposals/1001/parties": PARTIES }, sent), { proposal: "1001" });
  await tick();
  const shown = text();
  for (const s of ["Applicant (lead)", "Reviewer Reviewer R1", "Staff: programme manager", "Your purpose is recorded"]) {
    assert(shown.includes(s), `${s} is not shown: ${shown.slice(0, 600)}`);
  }
  for (const id of ["unmask-binding-11", "unmask-assignment-21", "unmask-binding-31"]) {
    byId(id);
  }
});

/**
 * I-17, I-78 (ADR-023): the control opens a form with the plain notice,
 * refuses an empty purpose without a request, then sends the unmask with
 * the purpose and opens the vault origin's page. An address that is not
 * this cell's vault origin is not opened.
 */
test("i17_unmask_form_sends_the_purpose_and_opens_the_vault_origin", async () => {
  prepare();
  const sent: Sent[] = [];
  const vault = "http://id.a.fstp.localhost:8990/r#synthetic-ticket-0";
  const e = env({ "GET /proposals/1001/parties": PARTIES, "POST /programmes/1/unmask": { redirect: vault } }, sent);
  await page("coordinator.parties")(e, { proposal: "1001" });
  await tick();
  byId("unmask-binding-11").click();
  assert(text().includes("As FSTP coordinator you can see who this is. Your purpose is recorded."), "the notice");
  byId("unmask-binding-11-form").dispatchEvent(new Event("submit", { cancelable: true }));
  await tick();
  assert(!sent.some((s) => s.path.startsWith("POST")), "an empty purpose sent a request");
  assert(text().includes("Enter your purpose"), "the purpose error");
  (byId("unmask-binding-11-purpose") as unknown as { value: string }).value = "Synthetic purpose: check an affiliation.";
  byId("unmask-binding-11-form").dispatchEvent(new Event("submit", { cancelable: true }));
  await tick();
  const post = sent.find((s) => s.path === "POST /programmes/1/unmask");
  assert(post !== undefined, `no unmask was sent: ${JSON.stringify(sent)}`);
  eq(
    post === undefined ? "" : JSON.stringify(post.body),
    '{"purpose":"Synthetic purpose: check an affiliation.","subject":{"binding":"11","type":"Binding"}}',
    "the canonical body",
  );
  eq(assigned.join(","), vault, "the vault origin opened");
});

/** I-17 (ADR-023 reading 7): a redirect off the vault origin is never opened. */
test("i17_unmask_refuses_a_redirect_off_the_vault_origin", async () => {
  prepare();
  const sent: Sent[] = [];
  const e = env(
    { "GET /proposals/1001/parties": PARTIES, "POST /programmes/1/unmask": { redirect: "http://evil.localhost/r#x" } },
    sent,
  );
  await page("coordinator.parties")(e, { proposal: "1001" });
  await tick();
  byId("unmask-assignment-21").click();
  (byId("unmask-assignment-21-purpose") as unknown as { value: string }).value = "Synthetic purpose";
  byId("unmask-assignment-21-form").dispatchEvent(new Event("submit", { cancelable: true }));
  await tick();
  eq(assigned.length, 0, "an address off the vault origin was opened");
  assert(text().includes("not this cell's vault"), text().slice(0, 400));
});

/** I-17: a principal the cell refuses sees no Unmask control. */
test("i17_parties_page_shows_no_control_when_refused", async () => {
  prepare();
  const sent: Sent[] = [];
  await page("coordinator.parties")(env({}, sent), { proposal: "1001" });
  await tick();
  assert(!text().includes("Unmask"), text().slice(0, 300));
});
