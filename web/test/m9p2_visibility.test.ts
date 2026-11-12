// The grantee visibility screen (M9 lane P2; R-PB-02, R-PB-03, I-41,
// I-42, I-43). The lead reaches it from the grant page by clicking, sees
// each phase's maximum, current choice and effective level, and saves or
// withdraws a choice. The texts travel as text, never as references.

import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { mountPostGrant } from "../src/grant/routes.js";
import { decodePublicity, setBody, shownFields, withdrawBody } from "../src/grant/visibility/model.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { VALIDATORS } from "../src/gen/api.js";
import { assert, test } from "./support/harness.js";
import { fakeDocument, freshDom, FakeElement } from "./support/fakedom.js";

const g = globalThis as unknown as Record<string, unknown>;

interface Sent {
  readonly line: string;
  readonly body: string | undefined;
}

function env(replies: Readonly<Record<string, unknown>>, sent: Sent[]): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      const line = `${op.method} ${path}`;
      sent.push({ line, body: typeof body === "string" ? body : body === undefined ? undefined : JSON.stringify(body) });
      const r = replies[line];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "test" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function text(): string {
  return fakeDocument.body.textContent ?? "";
}

function prepare(path: string): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
  g["location"] = { protocol: "http:", hostname: "cell.localhost", port: "8650", pathname: path };
}

const settle = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

const VIEW = {
  proposal: "3",
  state: "IN_EXECUTION",
  minor: false,
  max_funded: "project_and_grantee",
  max_finished: "full",
  funded: {
    open: true,
    choice: {
      level: "full",
      effective: "project_and_grantee",
      title: "Synthetic Harbour Sensors",
      summary: "Synthetic public summary.",
      grantee: "Synthetic Grantee Org",
      deliverables: [],
    },
  },
  finished: { open: false, choice: null },
  deliverables: [{ id: "7", licence: "Apache-2.0", snapshot: "ab".repeat(32) }],
};

/** R-PB-02, I-43: the generated validator accepts the cell's view, and the decoder keeps the effective level. */
test("r_pb_02_publicity_view_validates_and_decodes", () => {
  const check = (VALIDATORS as Readonly<Record<string, (x: unknown) => boolean>>)["grant.publicity.view"];
  assert(check?.(VIEW) === true, "the generated validator accepts the view");
  const v = decodePublicity(VIEW);
  assert(v !== null && v.funded.choice?.effective === "project_and_grantee", JSON.stringify(v));
  assert(v?.finished.choice === null && v.finished.open === false, "finished is closed with no choice");
  assert(decodePublicity({ ...VIEW, max_funded: "everything" }) === null, "an unknown level is refused");
  assert(decodePublicity({ ...VIEW, funded: { open: true, choice: { ...VIEW.funded.choice, deliverables: [7] } } }) === null, "a number id is refused");
});

/** R-PB-03, I-41: the set body carries the texts as text, refuses empty texts a level shows, and never puts deliverables on the funded phase. */
test("r_pb_03_set_body_carries_texts_as_text", () => {
  const b = setBody("finished", { level: "full", title: " T ", summary: "S", grantee: "G", deliverables: ["10", "7", "7"] });
  assert(b !== null && b["title"] === "T" && b["level"] === "Full" && b["phase"] === "Finished", JSON.stringify(b));
  assert(JSON.stringify(b?.["deliverables"]) === '["7","10"]', "deliverables ascend, once each");
  assert(setBody("funded", { level: "project", title: "", summary: "S", grantee: "", deliverables: [] }) === null, "a title is needed");
  assert(setBody("funded", { level: "project_and_grantee", title: "T", summary: "S", grantee: " ", deliverables: [] }) === null, "a grantee name is needed");
  assert(setBody("funded", { level: "project", title: "T", summary: "S", grantee: "", deliverables: ["7"] }) === null, "no deliverable on funded");
  assert(setBody("funded", { level: "hidden", title: "", summary: "", grantee: "", deliverables: [] }) !== null, "hidden needs no text");
  assert(JSON.stringify(withdrawBody("funded")) === '{"phase":"Funded"}', "withdraw body");
  assert(shownFields("project").length === 4 && shownFields("full").includes("amount"), "levels table");
});

/** R-NF-03, R-PB-02: from the grant page, the lead clicks through to the visibility screen. */
test("r_nf_03_grant_page_links_to_the_visibility_screen", async () => {
  prepare("/app/grants/3");
  const sent: Sent[] = [];
  const overview = { proposal: "3", state: "IN_EXECUTION", determination: "4", amount: "1000.00", paid: "0.00", contract: "5", requests: 0, plan: "6", milestones: [] };
  await mountPostGrant(env({ "GET /grants/3": overview }, sent), "/app/grants/3");
  await settle();
  const a = fakeDocument.body.descendants().find((e) => e.getAttribute("href") === "/app/grants/3/visibility");
  assert(a !== undefined, `a link to the visibility screen: ${text().slice(0, 600)}`);
});

/** R-PB-02, I-42, I-43: the screen shows each phase's maximum, choice and effective level, and saves a choice with its texts as text. */
test("r_pb_02_visibility_screen_shows_and_saves_a_choice", async () => {
  prepare("/app/grants/3/visibility");
  const sent: Sent[] = [];
  await mountPostGrant(env({ "GET /grants/3/publicity": VIEW, "POST /grants/3/publicity": { accepted: true } }, sent), "/app/grants/3/visibility");
  await settle();
  const t = text();
  assert(t.includes("Your choice governs this platform only."), "NOTE 3 is shown");
  assert(t.includes("The programme allows at most: Project and grantee"), t.slice(0, 800));
  assert(t.includes("The public pages show: Project and grantee"), "the effective level");
  assert(t.includes("You can choose this once the project is finished."), "the finished phase is closed (I-41)");
  const title = fakeDocument.getElementById("grant-visibility-funded-title") as unknown as { value: string } | null;
  assert(title?.value === "Synthetic Harbour Sensors", "the current title is filled in");
  const form = fakeDocument.getElementById("grant-visibility-funded-form");
  assert(form !== null, "the funded form");
  form?.dispatchEvent(new Event("submit", { cancelable: true }));
  await settle();
  const post = sent.find((s) => s.line === "POST /grants/3/publicity");
  assert(post !== undefined, sent.map((s) => s.line).join(", "));
  assert(post?.body?.includes('"title":"Synthetic Harbour Sensors"') === true, post?.body ?? "no body");
  assert(post?.body?.includes('"level":"Full"') === true, "the chosen level");
  assert(post?.body?.includes('"digest"') === false, "R-PB-03: no text reference is sent");
});

/** I-42, D4: a minor-flagged grant offers Hidden only. */
test("i42_visibility_screen_disables_levels_for_a_minor", async () => {
  prepare("/app/grants/3/visibility");
  const sent: Sent[] = [];
  await mountPostGrant(env({ "GET /grants/3/publicity": { ...VIEW, minor: true } }, sent), "/app/grants/3/visibility");
  await settle();
  assert(text().includes("never shown on the public pages"), "the minor notice");
  const full = fakeDocument.getElementById("grant-visibility-funded-level-full") as unknown as { disabled: boolean } | null;
  const hidden = fakeDocument.getElementById("grant-visibility-funded-level-hidden") as unknown as { disabled: boolean } | null;
  assert(full?.disabled === true && hidden?.disabled === false, "only Hidden is enabled");
});
