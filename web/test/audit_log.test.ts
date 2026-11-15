// The audit log page over the fake DOM (R-AU-01, I-24, ADR-007,
// ADR-022, ADR-023). The auditor sees the programme's entries newest
// first with an event type filter, the unmask records and the vault
// answers. Texts appear by id only. SA-08 (Daniel, 2026-11-15): the
// tenant admins and the programme's FSTP coordinator read the entries
// too. The homes of all three link to the page.

import { AUDIT_PAGES } from "../src/audit/pages.js";
import { filterRows, isAuditLog, isOutcomes, isUnmasks, kindsOf, shortHash, utcMinute } from "../src/audit/model.js";
import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { VALIDATORS } from "../src/gen/api.js";
import { readMyRoles, workOf } from "../src/home/model.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { assert, eq, test } from "./support/harness.js";
import { FakeElement, fakeDocument, freshDom } from "./support/fakedom.js";

const g = globalThis as unknown as Record<string, unknown>;

function env(replies: Readonly<Record<string, unknown>>): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, params, _body, validate): Promise<ApiOutcome> {
      let path = op.path;
      for (const [k, v] of Object.entries(params)) {
        path = path.replace(`{${k}}`, v);
      }
      const r = replies[`${op.method} ${path}`];
      if (r === undefined) {
        return { kind: "refused", code: "refused", rule: "R-AC-01" };
      }
      return validate(r) ? { kind: "done", body: r } : { kind: "failed", reason: "invalid_response" };
    },
  };
  return { api, root: fakeDocument.body as unknown as HTMLElement, navigate: () => undefined };
}

function prepare(): void {
  freshDom();
  for (const n of ["HTMLSelectElement", "HTMLFormElement", "HTMLButtonElement", "HTMLTextAreaElement", "HTMLInputElement"]) {
    g[n] = FakeElement;
  }
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

const tick = (): Promise<void> => new Promise((r) => setTimeout(r, 20));

const HASH = "9f2c41e0".padEnd(64, "a");

const LOG = {
  programme: "1",
  entries: [
    {
      seq: "40",
      at: "1793520720000000",
      side: "core",
      kind: "PartyUnmasked",
      actor: "201",
      actor_role: "fstp_coordinator",
      object_type: "programme",
      object: "1",
      texts: ["77"],
      hash: HASH,
    },
    {
      seq: "31",
      at: "1793434320000000",
      side: "creator",
      kind: "ActivationOverridden",
      actor: "1",
      actor_role: "tenant_admin",
      object_type: "decision",
      object: "5",
      texts: ["66"],
      hash: HASH,
    },
    {
      seq: "12",
      at: "1793347920000000",
      side: "core",
      kind: "BindingGranted",
      actor: "2",
      actor_role: "tenant_admin",
      object_type: "binding",
      object: "193",
      texts: [],
      hash: HASH,
    },
    {
      seq: "11",
      at: "1793347860000000",
      side: "creator",
      kind: "ProbeRecorded",
      actor: null,
      actor_role: "system",
      object_type: "programme",
      object: "1",
      texts: [],
      hash: HASH,
    },
  ],
};

const UNMASKS = {
  unmasks: [
    {
      party: "applicant",
      subject_type: "binding",
      subject: "11",
      by: "201",
      purpose: "SYNTHETIC PURPOSE: check the declared affiliation.",
      conflict: false,
      at: "1793520720000000",
    },
    {
      party: "reviewer",
      subject_type: "assignment",
      subject: "12",
      by: "203",
      purpose: "SYNTHETIC PURPOSE: confirm the reviewer behind a handle.",
      conflict: true,
      at: "1793520780000000",
    },
  ],
};

const OUTCOMES = {
  programme: "1",
  outcomes: [{ seq: "30", at: "1793434320000000", query: "SameIdentityAsAny", digest: "ef".repeat(32), holds: false, epoch: "3" }],
};

async function mount(replies: Readonly<Record<string, unknown>>): Promise<void> {
  const p = AUDIT_PAGES.find((x) => x.route.name === "audit.log");
  assert(p !== undefined, "the audit page");
  await p.mount(env(replies), { programme: "1" });
  await tick();
}

const ALL = {
  "GET /programmes/1/audit": LOG,
  "GET /programmes/1/audit/unmasks": UNMASKS,
  "GET /programmes/1/audit/vault-outcomes": OUTCOMES,
};

/** TH-26: the page's guards and the generated validators take the same replies and refuse an extra member. */
test("th26_audit_guards_agree_with_the_generated_shapes", () => {
  const pairs: [string, unknown, (v: unknown) => boolean][] = [
    ["audit.entries", LOG, isAuditLog],
    ["audit.unmasks", UNMASKS, isUnmasks],
    ["audit.vault_outcomes", OUTCOMES, isOutcomes],
  ];
  for (const [name, v, guard] of pairs) {
    const check = VALIDATORS[name];
    assert(check !== undefined, `gen/api.ts holds ${name}`);
    assert(check(v), `the generated ${name} validator accepts the fixture`);
    assert(guard(v), `the page guard accepts ${name}`);
  }
  const extra = { ...LOG, entries: [{ ...LOG.entries[0], text: "SYNTHETIC REASON" }] };
  eq(isAuditLog(extra), false, "ADR-007: a row with a text member is refused");
  eq(VALIDATORS["audit.entries"]?.(extra), false, "the generated validator refuses it too");
});

/** R-AU-01: the helpers format UTC minutes, short hashes and the kind filter. */
test("r_au_01_audit_helpers", () => {
  const log: unknown = LOG;
  assert(isAuditLog(log), "the fixture is an audit log");
  eq(utcMinute("1793520720000000"), "2026-11-01 08:12 UTC", "UTC minute");
  eq(utcMinute("x"), null, "not a decimal");
  eq(shortHash(HASH), "9f2c41e0…", "the prototype's short hash");
  eq([...kindsOf(log.entries)], ["ActivationOverridden", "BindingGranted", "PartyUnmasked", "ProbeRecorded"], "kinds");
  eq(filterRows(log.entries, "BindingGranted").length, 1, "one grant");
  eq(filterRows(log.entries, "").length, 4, "all");
});

/**
 * R-AU-01, ADR-022, ADR-023, ADR-007: the auditor's page lists every
 * entry newest first with its event type in words, the actor's role and
 * the object, the override and the unmask included. A text shows by id
 * only, and the unmask records and the vault answers follow.
 */
test("r_au_01_auditor_page_lists_entries_overrides_and_unmasks", async () => {
  prepare();
  await mount(ALL);
  const shown = text();
  for (const s of [
    "Audit log of programme 1",
    "4 entries, newest first",
    "Party unmasked",
    "Activation override by a building admin (I-67)",
    "Role granted",
    "FSTP coordinator, account 201",
    "Tenant admin, account 1",
    "System",
    "ProbeRecorded",
    "binding 193",
    "text 77",
    "text 66",
    "9f2c41e0…",
    "Unmasks",
    "Vault answers",
    "SameIdentityAsAny",
  ]) {
    assert(shown.includes(s), `${s} is not shown: ${shown.slice(0, 900)}`);
  }
  const rows = byId("audit-table").getElementsByTagName("tr").filter((r) => r.getAttribute("data-seq") !== null);
  eq(
    rows.map((r) => r.getAttribute("data-seq")),
    ["40", "31", "12", "11"],
    "newest first",
  );
  assert(!shown.includes("SYNTHETIC REASON"), "ADR-007: no override reason text");
});

/** R-AU-01: the event type filter keeps the rows of one kind and says how many of all it shows. */
test("r_au_01_event_type_filter_narrows_the_table", async () => {
  prepare();
  await mount(ALL);
  const select = byId("audit-kind");
  select.value = "ActivationOverridden";
  select.dispatchEvent(new Event("change"));
  const rows = byId("audit-table").getElementsByTagName("tr").filter((r) => r.getAttribute("data-seq") !== null);
  eq(
    rows.map((r) => r.getAttribute("data-kind")),
    ["ActivationOverridden"],
    "one kind",
  );
  assert(text().includes("1 of 4 entries, newest first"), "the caption counts the filter");
});

/** R-AU-01, SA-08 (Daniel, 2026-11-15): a tenant admin reads the entries, the unmask records and the vault answers, with no refusal note. */
test("r_au_01_sa08_tenant_admin_reads_the_entries_and_the_unmasks", async () => {
  prepare();
  await mount(ALL);
  const shown = text();
  assert(shown.includes("4 entries, newest first"), "the entries table");
  assert(shown.includes("SYNTHETIC PURPOSE"), "the unmask purpose, as ADR-023 shows it to admins");
  assert(shown.includes("SameIdentityAsAny"), "the vault answers");
  eq(fakeDocument.getElementById("audit-not-auditor"), null, "no refusal note");
});

/** R-AU-01, SA-08: the FSTP coordinator of the programme reads the entries and the vault answers; the unmask records stay the auditor's and the admins'. */
test("r_au_01_sa08_coordinator_reads_the_entries", async () => {
  prepare();
  await mount({ "GET /programmes/1/audit": LOG, "GET /programmes/1/audit/vault-outcomes": OUTCOMES });
  const shown = text();
  assert(shown.includes("4 entries, newest first"), "the entries table");
  assert(shown.includes("SameIdentityAsAny"), "the vault answers");
  assert(!shown.includes("SYNTHETIC PURPOSE"), "no unmask records");
  eq(fakeDocument.getElementById("audit-not-auditor"), null, "no refusal note");
});

/** R-AU-01, ADR-023 reading 11: a reader refused the entries sees why, and the unmask records the cell still sends. */
test("r_au_01_refused_entries_show_a_note", async () => {
  prepare();
  await mount({ "GET /programmes/1/audit/unmasks": UNMASKS });
  const shown = text();
  byId("audit-not-auditor");
  assert(shown.includes("SYNTHETIC PURPOSE"), "the unmask records");
  assert(!shown.includes("entries, newest first"), "no entries table");
});

/** R-AU-01, demo click-through: an auditor's home links to the audit log of each programme it audits. */
test("r_au_01_auditor_home_links_to_the_audit_log", () => {
  const r = readMyRoles({
    tenant_admin: false,
    roles: [{ role: "auditor", programme: "1", calls: [] }],
    calls: [],
    rounds: [],
    drafts: [],
    signatories: [],
  });
  assert(r !== null, "me.roles");
  const w = workOf(r, null, (c) => `Call ${c}`, (p) => `Proposal ${p}`);
  const item = w.items.find((i) => i.kind === "audit");
  eq(item?.href, "/app/programmes/1/audit", "the audit log link");
});

function rolesOf(tenantAdmin: boolean, roles: readonly unknown[]): NonNullable<ReturnType<typeof readMyRoles>> {
  const r = readMyRoles({ tenant_admin: tenantAdmin, roles, calls: [], rounds: [], drafts: [], signatories: [] });
  assert(r !== null, "me.roles");
  return r;
}

function auditLinks(w: ReturnType<typeof workOf>): string[] {
  return w.items.filter((i) => i.kind === "audit").map((i) => i.href);
}

/** R-AU-01, SA-08: a tenant admin's home links to the audit log of each programme of the tenant. */
test("r_au_01_sa08_tenant_admin_home_links_to_each_audit_log", () => {
  const w = workOf(rolesOf(true, []), null, (c) => `Call ${c}`, (p) => `Proposal ${p}`, ["2", "1"]);
  eq(auditLinks(w), ["/app/programmes/1/audit", "/app/programmes/2/audit"], "one link per programme");
  assert(
    w.items.filter((i) => i.kind === "audit").every((i) => i.group === "tenant_admin"),
    "under the tenant admin work",
  );
});

/** R-AU-01, SA-08: a coordinator's home links to the audit log of its own programmes only. */
test("r_au_01_sa08_coordinator_home_links_to_its_programmes_audit_log", () => {
  const w = workOf(
    rolesOf(false, [{ role: "fstp_coordinator", programme: "3", calls: ["9"] }]),
    null,
    (c) => `Call ${c}`,
    (p) => `Proposal ${p}`,
    ["1", "2", "3"],
  );
  eq(auditLinks(w), ["/app/programmes/3/audit"], "its programme alone, never the tenant list");
});

/** R-AU-01, SA-08: a committee member, an applicant and a programme manager get no audit link. */
test("r_au_01_sa08_other_roles_get_no_audit_link", () => {
  for (const roles of [
    [{ role: "committee_member", programme: "1", calls: ["1"] }],
    [{ role: "programme_manager", programme: "1", calls: ["1"] }],
    [{ role: "applicant", programme: "1", calls: ["1"], proposal: "5" }],
  ]) {
    const w = workOf(rolesOf(false, roles), null, (c) => `Call ${c}`, (p) => `Proposal ${p}`, ["1"]);
    eq(auditLinks(w), [], `no audit link for ${JSON.stringify(roles)}`);
  }
});

/**
 * R-AU-01, ADR-023 decision 2 (Daniel, 2026-11-15): the unmask table
 * shows whether the coordinator held a conflict on the proposal, per row.
 */
test("r_au_01_adr023_unmask_table_shows_the_conflict_flag", async () => {
  prepare();
  await mount({ "GET /programmes/1/audit/unmasks": UNMASKS });
  const rows = byId("audit-unmasks")
    .getElementsByTagName("tr")
    .filter((r) => r.getAttribute("data-conflict") !== null);
  eq(
    rows.map((r) => r.getAttribute("data-conflict")),
    ["false", "true"],
    "one flag per row, oldest first",
  );
  const shown = text();
  assert(shown.includes("Conflict on the proposal"), "the column heading");
  assert(shown.includes("Yes, a conflict was recorded"), "the flagged row");
});
