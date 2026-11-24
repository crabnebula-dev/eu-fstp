// The tenant admins' System page (ADR-028 record of lane L20; Daniel,
// 2026-11-21: anything the non-technical operator needs is on a web
// page). The page reads `tenant.system` and `tenant.list_admins`, shows
// one light per part with a plain sentence, and names who acts when a
// light is not green. Every value here is synthetic.

import { SYSTEM_LABELS } from "../src/admin/system/messages.en.js";
import {
  BACKUP_LATE,
  BACKUP_MISSING,
  HOST_NEXT,
  HOUR,
  ROW_IDS,
  SNAPSHOT_LATE,
  ageOf,
  decodeSystem,
  hostNext,
  overall,
  rows,
  type Row,
  type SystemReply,
} from "../src/admin/system/model.js";
import { SYSTEM_PAGES } from "../src/admin/system/page.js";
import type { ApiClient, ApiOutcome, OperationRef } from "../src/core/api.js";
import { OPERATIONS, PAGES, VALIDATORS } from "../src/gen/api.js";
import { WORK_PATHS } from "../src/home/model.js";
import { HOME_LABELS } from "../src/home/messages.en.js";
import type { PageEnv } from "../src/reviewer/kit.js";
import { appPatterns } from "../src/shell/routes.js";
import { FakeElement, fakeDocument, freshDom } from "./support/fakedom.js";
import { assert, eq, test } from "./support/harness.js";

const NOW = 1_795_000_000_000_000n;
const MIN = 60_000_000n;

/** A healthy reply in wire form, written `minutesAgo` before NOW. */
function wire(over: Record<string, unknown> = {}, hostOver: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    now: NOW.toString(),
    vault: "answers",
    mail: "works",
    last_cell_erasure: null,
    host_file: "present",
    host: {
      written_at: (NOW - 5n * MIN).toString(),
      setup_done: true,
      parts: { cell: "running", vault: "running", witness: "running", edge: "running", databases: "running", keys: "running" },
      backups_configured: true,
      last_backup: (NOW - 3n * HOUR).toString(),
      last_key_copy: "1794000000000000",
      last_vault_erasure: null,
      last_app_snapshot: (NOW - 2n * HOUR).toString(),
      app_snapshot_failed: false,
      last_vault_snapshot: (NOW - 4n * HOUR).toString(),
      vault_snapshot_failed: false,
      certificate_days: 5,
      self_signed: false,
      route: "current",
      next: "nothing",
      custodian: "linked",
      guard_owed: false,
      guard_copy_owed: false,
      wal_archive: "ok",
      last_wal_archived: (NOW - 2n * MIN).toString(),
      ...hostOver,
    },
    ...over,
  };
}

function decoded(over: Record<string, unknown> = {}, hostOver: Record<string, unknown> = {}): SystemReply {
  const r = decodeSystem(wire(over, hostOver));
  if (r === null) throw new Error(`does not decode: ${JSON.stringify(wire(over, hostOver))}`);
  return r;
}

function rowOf(r: SystemReply, id: string): Row {
  const x = rows(r).find((y) => y.id === id);
  if (x === undefined) throw new Error(`no row ${id}`);
  return x;
}

/** ADR-028 record of lane L20, R-NF-02: the reply decodes strictly, and the generated validator agrees. */
test("adr028_l20_system_reply_decodes_strictly", () => {
  const validate = VALIDATORS["tenant.system"];
  assert(validate !== undefined, "a generated validator");
  for (const good of [
    wire(),
    wire({ host_file: "not_configured", host: null, vault: "silent", mail: "not_configured" }),
    wire({}, { last_backup: null, last_key_copy: null, certificate_days: null }),
  ]) {
    assert(decodeSystem(good) !== null, JSON.stringify(good));
    assert(validate?.(good) === true, `the validator accepts ${JSON.stringify(good)}`);
  }
  for (const bad of [
    null,
    {},
    wire({ vault: "maybe" }),
    wire({ email: "a@example.eu" }),
    wire({ host_file: "missing" }),
    wire({ host_file: "present", host: null }),
    wire({}, { next: "reboot" }),
    wire({}, { certificate_days: -1 }),
    wire({}, { written_at: "07" }),
    wire({}, { parts: { cell: "running" } }),
    wire({}, { domain: "grants.example.eu" }),
  ]) {
    eq(decodeSystem(bad), null, JSON.stringify(bad));
  }
});

/** ADR-028 record of lane L20: a healthy host shows every row green and says so at the top. */
test("adr028_l20_healthy_host_is_all_green", () => {
  const r = decoded();
  const rs = rows(r);
  eq(
    rs.map((x) => x.id),
    [...ROW_IDS],
    "every row, in order",
  );
  for (const x of rs) {
    eq(x.light, "green", x.id);
    eq(x.actor, null, `${x.id} needs nobody`);
  }
  eq(overall(rs), "green", "everything runs");
  eq(hostNext(r), null, "nothing next");
  eq(rowOf(r, "certificates").params["due"], "3", "five days left: renewal is due in three");
});

/** ADR-028 record of lane L20: each problem names its light, the host admin and what to tell them. */
test("adr028_l20_problems_name_who_acts_and_what_to_tell", () => {
  const cases: [SystemReply, string, string, string | null][] = [
    [decoded({ vault: "silent" }), "vault", "red", "system.tell.start"],
    [decoded({ mail: "fails" }), "mail", "red", "system.tell.mail"],
    [decoded({ mail: "not_configured" }), "mail", "red", "system.tell.mail_setup"],
    [decoded({}, { parts: { cell: "running", vault: "running", witness: "stopped", edge: "running", databases: "running", keys: "running" } }), "services", "red", "system.tell.start"],
    [decoded({}, { parts: { cell: "running", vault: "running", witness: "running", edge: "unhealthy", databases: "running", keys: "running" } }), "edge", "red", "system.tell.start"],
    [decoded({}, { route: "mismatch" }), "edge", "amber", "system.tell.renew"],
    [decoded({}, { backups_configured: false }), "backups", "amber", "system.tell.configure_backups"],
    [decoded({}, { last_backup: null }), "backups", "red", "system.tell.backup"],
    [decoded({}, { last_key_copy: null }), "keys", "amber", "system.tell.copy_keys"],
    [decoded({}, { vault_snapshot_failed: true }), "snapshots", "red", "system.tell.keystore_snapshot"],
    [decoded({}, { last_app_snapshot: null }), "snapshots", "amber", "system.tell.keystore_snapshot"],
    [decoded({}, { certificate_days: 1 }), "certificates", "amber", "system.tell.renew"],
    [decoded({}, { certificate_days: 0 }), "certificates", "red", "system.tell.renew"],
    [decoded({}, { self_signed: true }), "certificates", "amber", "system.tell.public_certificate"],
  ];
  for (const [r, id, light, tell] of cases) {
    const x = rowOf(r, id);
    eq(x.light, light, `${id} light`);
    eq(x.actor, "host", `${id} names the host admin`);
    eq(x.tell, tell, `${id} says what to tell`);
    eq(overall(rows(r)), light, `${id} sets the top line`);
  }
});

/** ADR-028 record of lane L20: backups are late after 36 hours and a problem after 72, as `fstp-admin status` reads them. */
test("adr028_l20_backup_age_thresholds", () => {
  const at = (age: bigint): string => rowOf(decoded({}, { last_backup: (NOW - age).toString() }), "backups").light;
  eq(at(BACKUP_LATE), "green", "36 hours is still on time");
  eq(at(BACKUP_LATE + MIN), "amber", "just over 36 hours is late");
  eq(at(BACKUP_MISSING + MIN), "red", "over 72 hours is a problem");
  eq(ageOf(90n * MIN), { label: "system.age.minutes", n: "90" }, "minutes under two hours");
  eq(ageOf(30n * HOUR), { label: "system.age.hours", n: "30" }, "hours under two days");
  eq(ageOf(100n * HOUR), { label: "system.age.days", n: "4" }, "days after that");
});

/** ADR-028 record of lane L20: an old, missing or unreadable host report is a problem of its own, and host rows without a report are unknown. */
test("adr028_l20_old_or_missing_report_is_shown", () => {
  const old = decoded({}, { written_at: (NOW - 2n * HOUR).toString() });
  eq(rowOf(old, "report").light, "amber", "an old report");
  eq(rowOf(old, "report").tell, "system.tell.report_timer", "the timer stopped");
  eq(rowOf(old, "backups").light, "green", "the old facts still show");
  for (const file of ["not_configured", "missing", "unreadable"]) {
    const r = decoded({ host_file: file, host: null });
    const report = rowOf(r, "report");
    eq(report.light, "amber", file);
    eq(report.actor, "host", file);
    for (const id of ["services", "edge", "backups", "archive", "keys", "snapshots", "certificates"]) {
      eq(rowOf(r, id).light, "unknown", `${id} without a report`);
    }
    eq(rowOf(r, "mail").light, "green", "the cell's own facts stay");
  }
});

/** ADR-028 record of lane L20, R-NF-04: every label a row, an actor or a next thing names exists. */
test("adr028_l20_every_label_exists", () => {
  const replies: SystemReply[] = [
    decoded(),
    decoded({ vault: "silent", mail: "fails" }),
    decoded({ mail: "not_configured" }),
    decoded({}, { route: "mismatch", last_key_copy: null, certificate_days: 0, backups_configured: false }),
    decoded({}, { route: "unknown", last_backup: null, certificate_days: null, self_signed: true }),
    decoded({}, { written_at: "1" }),
    decoded({ last_cell_erasure: "1794500000000000" }),
    decoded({}, { app_snapshot_failed: true, last_vault_snapshot: null }),
    decoded({}, { last_app_snapshot: "1" }),
    decoded({}, { backups_configured: false }),
    decoded({}, { custodian: "unreachable" }),
    decoded({}, { custodian: "unpaired" }),
    decoded({}, { guard_owed: true }),
    decoded({}, { guard_copy_owed: true }),
    ...(["ok", "late", "failing", "unknown"] as const).map((w) => decoded({}, { wal_archive: w })),
    decoded({}, { last_wal_archived: null }),
    ...["not_configured", "missing", "unreadable"].map((f) => decoded({ host_file: f, host: null })),
    ...HOST_NEXT.map((n) => decoded({}, { next: n })),
  ];
  const has = (k: string): boolean => typeof SYSTEM_LABELS[k] === "string";
  for (const r of replies) {
    for (const x of rows(r)) {
      assert(has(x.text), x.text);
      assert(has(`system.name.${x.id}`), x.id);
      assert(has(`system.light.${x.light}`), x.light);
      if (x.actor !== null) assert(has(`system.actor.${x.actor}`), x.actor);
      if (x.tell !== null) assert(has(x.tell), x.tell);
      if (x.params["unit"] !== undefined) assert(has(x.params["unit"]), x.params["unit"]);
    }
    assert(has(`system.overall.${overall(rows(r))}`), "the top line");
    const n = hostNext(r);
    if (n !== null) assert(has(n.text), n.text);
  }
  eq(hostNext(decoded({}, { next: "web_admins" }))?.actor, "you", "the web admins act on web_admins");
  eq(hostNext(decoded({}, { next: "verify_admins" }))?.actor, "host", "the host admin verifies");
});

/** SA-09, ADR-028 record of lane L20: the page, its gate row, its read and the home link. */
test("adr028_l20_system_page_is_gated_and_linked_from_home", () => {
  eq(SYSTEM_PAGES.map((p) => p.route.pattern), ["/app/admin/system"], "one page");
  assert(appPatterns().includes("/app/admin/system"), "the shell mounts it");
  const row = PAGES.find((p) => p.pattern === "/app/admin/system");
  assert(row !== undefined, "the page gate lists the page");
  const read = OPERATIONS.find((o) => o.name === "tenant.system");
  eq(read?.method, "GET", "the read");
  eq(read?.highRisk, false, "no step-up");
  eq(WORK_PATHS.system, "/app/admin/system", "home links to it");
  assert(typeof HOME_LABELS["home.work.system"] === "string", "the home link has a label");
});

// ---------------------------------------------------------------------------
// The page over a fake API
// ---------------------------------------------------------------------------

const g = globalThis as unknown as Record<string, unknown>;

function env(replies: Readonly<Record<string, unknown>>): PageEnv {
  const api: ApiClient = {
    async call(op: OperationRef, _params, _body, validate): Promise<ApiOutcome> {
      const r = replies[`${op.method} ${op.path}`];
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

function byId(id: string): FakeElement {
  const el = fakeDocument.getElementById(id) as FakeElement | null;
  if (el === null) throw new Error(`no #${id} in: ${(fakeDocument.body.textContent ?? "").slice(0, 400)}`);
  return el;
}

const ADMINS = {
  admins: [
    { account: "41", handle: "synthetic-a1", verified: true },
    { account: "42", handle: "synthetic-a2", verified: false },
  ],
};

/** ADR-028 record of lane L20, R-NF-03: the page shows each light as a word, says who acts, lists the admins by handle and links to the checklist. */
test("adr028_l20_r_nf_03_page_renders_lights_actors_and_admins", async () => {
  prepare();
  const page = SYSTEM_PAGES[0];
  assert(page !== undefined, "the page");
  await page?.mount(
    env({ "GET /admin/system": wire({ mail: "fails" }, { next: "verify_admins" }), "GET /admin/admins": ADMINS }),
    {},
  );
  const text = fakeDocument.body.textContent ?? "";
  eq(byId("system-overall").getAttribute("data-light"), "red", "the top line is red");
  assert(text.includes(SYSTEM_LABELS["system.row.mail.fails"] ?? "?"), "the mail sentence");
  assert(text.includes(SYSTEM_LABELS["system.light.red"] ?? "?"), "the light is a word, not only a colour");
  assert(text.includes(SYSTEM_LABELS["system.actor.host"] ?? "?"), "who acts");
  assert(text.includes(SYSTEM_LABELS["system.next.verify_admins"] ?? "?"), "the host's next thing");
  assert(text.includes("synthetic-a1: identity checked."), "a checked admin");
  assert(text.includes("synthetic-a2: identity not checked yet."), "an admin not checked yet");
  assert(!text.includes("41") && !text.includes("42"), "no account number, handles only");
  assert(text.includes(SYSTEM_LABELS["system.admins.checklist"] ?? "?"), "the checklist link");
  assert(text.includes("5 minutes"), "the report's age in words");
});

/** ADR-028 record of lane L20: without the admins read the page still shows the system, and says the list is unavailable. */
test("adr028_l20_page_survives_an_unavailable_admin_list", async () => {
  prepare();
  await SYSTEM_PAGES[0]?.mount(env({ "GET /admin/system": wire() }), {});
  eq(byId("system-overall").getAttribute("data-light"), "green", "all green");
  byId("system-admins-unavailable");
});

/** ADR-028 record of lane L20: a key copy older than the last erasure of the cell or the vault turns amber, and asks the host admin for a new copy. */
test("adr028_l20_key_copy_older_than_an_erasure_is_amber", () => {
  const copy = 1_794_000_000_000_000n;
  eq(rowOf(decoded({ last_cell_erasure: (copy - 1n).toString() }), "keys").light, "green", "an erasure before the copy");
  for (const [over, hostOver] of [
    [{ last_cell_erasure: (copy + 1n).toString() }, {}],
    [{}, { last_vault_erasure: (copy + 1n).toString() }],
  ] as const) {
    const r = decoded(over, hostOver);
    const keys = rowOf(r, "keys");
    eq(keys.light, "amber", JSON.stringify([over, hostOver]));
    eq(keys.text, "system.row.keys.before_erasure", "the sentence");
    eq(keys.tell, "system.tell.copy_keys_again", "what to tell");
    eq(keys.actor, "host", "the host admin acts");
  }
  eq(decodeSystem(wire({ last_cell_erasure: 5 })), null, "an erasure instant is a decimal string");
  eq(decodeSystem(wire({}, { last_vault_erasure: "x" })), null, "so is the vault's");
});

/** ADR-028 records of lanes L27 and L26: the keystore snapshot row is late after 36 hours, a problem when a last try failed, and off without backups; the reply refuses a snapshot fact out of its grammar. */
test("adr028_l26_keystore_snapshot_row", () => {
  const at = (age: bigint): string =>
    rowOf(decoded({}, { last_vault_snapshot: (NOW - age).toString() }), "snapshots").light;
  eq(at(SNAPSHOT_LATE), "green", "36 hours is still on time");
  eq(at(SNAPSHOT_LATE + MIN), "amber", "just over 36 hours is late");
  eq(rowOf(decoded(), "snapshots").params["age"], "4", "the older of the two");
  eq(rowOf(decoded({}, { app_snapshot_failed: true }), "snapshots").light, "red", "a failed cell snapshot");
  eq(rowOf(decoded({}, { backups_configured: false, last_app_snapshot: null }), "snapshots").light, "green", "off without backups");
  eq(rowOf(decoded({}, { next: "keystore_snapshot" }), "report").light, "green", "the next word decodes");
  eq(hostNext(decoded({}, { next: "keystore_snapshot" }))?.actor, "host", "the host admin acts");
  for (const bad of [
    wire({}, { app_snapshot_failed: "no" }),
    wire({}, { last_vault_snapshot: "07" }),
    wire({}, { vault_snapshot_failed: undefined }),
  ]) {
    eq(decodeSystem(JSON.parse(JSON.stringify(bad))), null, JSON.stringify(bad));
  }
});

/** ADR-028 record of lane `m10/guard-key`, I-81, F-018: the key copy row shows the second custodian. It is red while the custodian does not answer or a guard is still to be replaced, since erasures then wait, and amber while none is paired. The reply refuses a custodian fact out of its grammar. */
test("adr028_guard_key_copy_row_shows_the_custodian", () => {
  for (const [hostOver, light, text, tell] of [
    [{ custodian: "unreachable" }, "red", "system.row.keys.custodian_down", "system.tell.custodian"],
    [{ guard_owed: true }, "red", "system.row.keys.custodian_down", "system.tell.custodian"],
    [{ custodian: "unpaired" }, "amber", "system.row.keys.custodian_unpaired", "system.tell.pair_custodian"],
  ] as const) {
    const keys = rowOf(decoded({}, hostOver), "keys");
    eq(keys.light, light, JSON.stringify(hostOver));
    eq(keys.text, text, "the sentence");
    eq(keys.tell, tell, "what to tell");
    eq(keys.actor, "host", "the host admin acts");
  }
  eq(rowOf(decoded({}, { custodian: "not_used" }), "keys").light, "green", "direct mode uses none");
  eq(hostNext(decoded({}, { next: "custodian" }))?.actor, "host", "the host admin acts");
  for (const bad of [wire({}, { custodian: "down" }), wire({}, { guard_owed: "no" }), wire({}, { guard_owed: undefined })]) {
    eq(decodeSystem(JSON.parse(JSON.stringify(bad))), null, JSON.stringify(bad));
  }
});

/** ADR-028 record of lane `m10/guard-key`, part 2 (Q-F018-4), F-018, I-81: an owed fresh copy for the custodian shows the key copy row amber with the host admin to act, below an unreachable custodian, and the reply refuses the fact out of its grammar. */
test("adr028_guard_key_copy_row_shows_an_owed_copy", () => {
  const keys = rowOf(decoded({}, { guard_copy_owed: true }), "keys");
  eq(keys.light, "amber", "an owed copy");
  eq(keys.text, "system.row.keys.custodian_copy_owed", "the sentence");
  eq(keys.tell, "system.tell.custodian_copy", "what to tell");
  eq(keys.actor, "host", "the host admin acts");
  eq(rowOf(decoded({}, { guard_copy_owed: true, custodian: "unreachable" }), "keys").light, "red", "unreachable wins");
  eq(hostNext(decoded({}, { next: "custodian_copy" }))?.actor, "host", "the host admin acts");
  for (const bad of [wire({}, { guard_copy_owed: "yes" }), wire({}, { guard_copy_owed: undefined })]) {
    eq(decodeSystem(JSON.parse(JSON.stringify(bad))), null, JSON.stringify(bad));
  }
});

/** ADR-012 and ADR-028 records of lane `m10/backup-health` (Daniel, 2026-11-24: backup is mission critical): the backup of recent changes is red while the WAL archive fails, amber while it is late, not known when the host cannot read it, and green with the age of the last saved change; the host admin acts, and the reply refuses the facts out of their grammar. */
test("adr028_bh_archive_and_drill_rows", () => {
  const healthy = rowOf(decoded(), "archive");
  eq(healthy.light, "green", "an archive that keeps up");
  eq(healthy.text, "system.row.archive.fresh", "the sentence");
  eq(healthy.params["age"], "2", "two minutes ago");
  const failing = rowOf(decoded({}, { wal_archive: "failing" }), "archive");
  eq(failing.light, "red", "a failing archive");
  eq(failing.actor, "host", "the host admin acts");
  eq(failing.tell, "system.tell.wal_archive", "what to tell");
  eq(rowOf(decoded({}, { wal_archive: "late" }), "archive").light, "amber", "a late archive");
  eq(rowOf(decoded({}, { wal_archive: "unknown" }), "archive").light, "unknown", "not known");
  eq(rowOf(decoded({}, { last_wal_archived: null }), "archive").text, "system.row.archive.none_yet", "nothing saved yet");
  eq(rowOf(decoded({}, { backups_configured: false, wal_archive: "unknown" }), "archive").text, "system.row.archive.off", "starts with backups");
  eq(hostNext(decoded({}, { next: "wal_archive" }))?.actor, "host", "the host admin acts");
  for (const bad of [
    wire({}, { wal_archive: "stuck" }),
    wire({}, { wal_archive: undefined }),
    wire({}, { last_wal_archived: 5 }),
  ]) {
    eq(decodeSystem(JSON.parse(JSON.stringify(bad))), null, JSON.stringify(bad));
  }
});
