// The platform mailbox (lane m6/mailbox, `docs/handoff/mailbox-design.md`
// section 7, T7): the closed reader of `me.mailbox`, the routes of its
// kinds and the catalogue.

import { readFileSync, readdirSync, statSync } from "node:fs";
import { join } from "node:path";

import { SCHEMAS, VALIDATORS } from "../src/gen/api.js";
import { HOME_LABELS } from "../src/home/messages.en.js";
import { WORK_PATHS } from "../src/home/model.js";
import { MAILBOX_LABELS } from "../src/mailbox/messages.en.js";
import { M5_ROUTES, MAILBOX_PATHS, MAILBOX_ROUTES, MAIL_KINDS, type MailKind, fills, labelArgs, labelKey, readMailbox, split } from "../src/mailbox/model.js";
import { mailboxLabel, readPendingList } from "../src/mailbox/pages.js";
import { MAILBOX_PAGE_ROUTES } from "../src/mailbox/routes.js";
import { assert, eq, show, test } from "./support/harness.js";
import { REPO_DIR, WEB_DIR } from "./support/paths.js";

/** A message of `kind` with every id its route names. */
function msg(kind: MailKind, action = true): Record<string, unknown> {
  const ids: Record<string, string> = { proposal: "11", call: "12", assignment: "13", round: "14", pending: "17", request: "16", programme: "18", contract: "15" };
  const href = MAILBOX_ROUTES[kind].replace(/\{([a-z_]+)\}/g, (_, n: string) => ids[n] ?? "");
  // MB-Q1, ADR-020: a notice carries its read mark, a work message none.
  return { id: `${kind}:1`, kind, action, href, ...ids, ...(action ? {} : { read: false }) };
}

function reply(messages: Record<string, unknown>[]): Record<string, unknown> {
  return { open: messages.filter((m) => m["action"] === true).length, messages };
}

/** I-27, I-86: a well formed reply reads, and work and notices split. */
test("i27_i86_mailbox_reader_accepts_the_reply_shape", () => {
  const v = reply([msg("contract.sign"), msg("notice.outcome", false), msg("payment.release")]);
  assert(VALIDATORS["me.mailbox"]?.(v) === true, "the generated validator accepts it");
  const b = readMailbox(v);
  assert(b !== null, show(v));
  eq(b.open, 2, "open counts the work");
  const s = split(b);
  eq(s.work.map((m) => m.kind), ["contract.sign", "payment.release"], "work");
  eq(s.notices.map((m) => m.kind), ["notice.outcome"], "notices");
  eq(readMailbox(reply([])), { open: 0, messages: [] }, "an empty mailbox");
});

/**
 * I-27, I-86: the reader refuses a member outside the shape, a text
 * member, an id that is not decimal, a page that is not the route of its
 * kind filled with its own ids, an unknown kind and a wrong count.
 */
test("i27_i86_mailbox_reader_refuses_anything_outside_the_shape", () => {
  const bad: unknown[] = [
    { ...reply([msg("contract.sign")]), extra: 1 },
    reply([{ ...msg("contract.sign"), title: "Synthetic title" }]),
    reply([{ ...msg("contract.sign"), email: "x@example.invalid" }]),
    reply([{ ...msg("contract.sign"), proposal: "1e3" }]),
    reply([{ ...msg("contract.sign"), href: "https://evil.example/app/grants/11/contract" }]),
    reply([{ ...msg("contract.sign"), href: "/app/grants/99/contract" }]),
    reply([{ ...msg("contract.sign"), href: "/app/proposals/11" }]),
    reply([{ ...msg("contract.sign"), kind: "contract.forge" }]),
    { open: 5, messages: [msg("contract.sign")] },
    { open: -1, messages: [] },
    reply([{ ...msg("contract.sign"), since: "yesterday" }]),
    [],
    null,
  ];
  for (const v of bad) {
    eq(readMailbox(v), null, `refused: ${show(v)}`);
  }
});

/** Design section 2: the kinds are those of the generated reply shape, each with a route and a label. */
test("r_nf_04_mailbox_kinds_match_the_generated_shape_and_have_routes_and_labels", () => {
  const schema = JSON.stringify(SCHEMAS["me.mailbox"]);
  for (const k of MAIL_KINDS) {
    assert(schema.includes(`"${k}"`), `${k} is in the generated shape`);
    assert(MAILBOX_ROUTES[k].startsWith("/app/"), `${k} has an /app/ route`);
    assert(typeof MAILBOX_LABELS[labelKey(k)] === "string", `${k} has a label`);
  }
  eq(Object.keys(MAILBOX_ROUTES).length, MAIL_KINDS.length, "one route per kind");
});

/** Design section 4: the web routes of the kinds equal the server's `MAILBOX_ROUTES`. */
test("i27_mailbox_web_routes_equal_the_server_routes", () => {
  const rust = readFileSync(join(REPO_DIR, "crates", "fstp-api-core", "src", "mailbox.rs"), "utf8");
  const table = rust.slice(rust.indexOf("pub const MAILBOX_ROUTES"), rust.indexOf("];", rust.indexOf("pub const MAILBOX_ROUTES")));
  const server = new Set(Array.from(table.matchAll(/"(\/app\/[^"]*)"/g), (m) => m[1]));
  const web = new Set(Object.values(MAILBOX_ROUTES));
  eq([...web].sort(), [...server].sort(), "the same routes");
});

function sources(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) {
      if (name !== "gen" && name !== "mailbox") {
        out.push(...sources(p));
      }
    } else if (name.endsWith(".ts")) {
      out.push(p);
    }
  }
  return out;
}

/** A route with each parameter name dropped, so `{assignment}` matches `{irc_assignment}`. */
function shape(pattern: string): string {
  return pattern.replace(/\{[a-z_]+\}/g, "{}");
}

/**
 * Design section 4: every page a message links to is a route the
 * `/app/` shell mounts, by the route tables of `web/src`, or one of the
 * M5 pages that lane `m5/ui` builds (MB-D7). The mailbox pages are
 * mounted by this lane's own table.
 */
test("i27_mailbox_every_message_page_is_mounted_or_an_m5_page", () => {
  const text = sources(join(WEB_DIR, "src"))
    .map((p) => readFileSync(p, "utf8"))
    .join("\n");
  const mounted = new Set(Array.from(text.matchAll(/"(\/app\/[^"]*)"/g), (m) => shape(m[1] ?? "")));
  for (const r of MAILBOX_PAGE_ROUTES) {
    mounted.add(shape(r.pattern));
  }
  for (const r of new Set(Object.values(MAILBOX_ROUTES))) {
    if (M5_ROUTES.includes(r)) {
      continue;
    }
    assert(mounted.has(shape(r)), `${r} is mounted by the shell`);
  }
  for (const r of M5_ROUTES) {
    assert(Object.values(MAILBOX_ROUTES).includes(r), `${r} is a mailbox route`);
  }
});

/** Design section 4: `fills` checks the page against the route and the message's own ids. */
test("i27_mailbox_fills_matches_route_and_own_ids_only", () => {
  assert(fills("/app/cut-off-rounds/4", "/app/cut-off-rounds/{round}", { round: "4" }), "filled");
  assert(!fills("/app/cut-off-rounds/5", "/app/cut-off-rounds/{round}", { round: "4" }), "another id");
  assert(!fills("/app/cut-off-rounds/4/x", "/app/cut-off-rounds/{round}", { round: "4" }), "longer");
  assert(!fills("/app/cut-off-rounds/4", "/app/cut-off-rounds/{round}", {}), "no id");
});

/** The shell links: the top bar and the home page reach the mailbox page. */
test("r_nf_03_mailbox_shell_links_reach_the_mailbox_page", () => {
  eq(WORK_PATHS.mailbox, MAILBOX_PATHS.mailbox, "the same page");
  eq(MAILBOX_PAGE_ROUTES.map((r) => r.pattern), ["/app/mailbox", "/app/pending/{pending}"], "mailbox routes");
  for (const k of ["nav.mailbox", "nav.mailbox_count", "home.mailbox", "home.mailbox_none"]) {
    assert(typeof HOME_LABELS[k] === "string" && HOME_LABELS[k] !== "", `${k} is in the home catalogue`);
  }
});

/** I-85, TW-9: the pending list reader keeps the request as text and refuses a bad digest. */
test("i85_pending_list_reader", () => {
  const ok = [{ id: "7", agent: "9", op: "call.draft", request: "{\"x\":\"<b>\"}", digest: "a".repeat(64), created: "1", expires: "2", status: "open", confirm_path: "/api/v1/pending-actions/7/confirmation" }];
  const r = readPendingList(ok);
  assert(r !== null, "read");
  eq(r[0]?.request, "{\"x\":\"<b>\"}", "the request text as given");
  eq(readPendingList([{ ...ok[0], digest: "zz" }]), null, "a bad digest");
  eq(readPendingList([{ ...ok[0], status: "gone" }]), null, "a bad status");
});

/**
 * R-NF-04: every kind's label formats from a message that names every
 * id, so the page never throws on an id its label does not use, and the
 * label names each id it shows.
 */
test("r_nf_04_mailbox_every_label_formats_with_every_id", () => {
  for (const k of MAIL_KINDS) {
    const b = readMailbox(reply([msg(k, !k.startsWith("notice."))]));
    assert(b !== null, k);
    const m = b.messages[0];
    assert(m !== undefined, k);
    const key = labelKey(k);
    const text = String(mailboxLabel(key, labelArgs(m, MAILBOX_LABELS[key] ?? "")));
    assert(!text.includes("{"), `${k}: ${text}`);
  }
});

/** I-27: a label shows a proposal or call number, never a 19-digit assignment, request, round or pending id. */
test("i27_mailbox_labels_show_no_internal_ids", () => {
  for (const k of MAIL_KINDS) {
    const label = MAILBOX_LABELS[labelKey(k)] ?? "";
    for (const bad of ["{assignment}", "{request}", "{round}", "{pending}", "{contract}"]) {
      assert(!label.includes(bad), `${k} shows ${bad}`);
    }
  }
});

/** MB-Q1, ADR-020, I-27: a notice carries a boolean read mark, a work message none, and the reader refuses either the other way round. */
test("adr020_i27_mailbox_reader_reads_the_read_mark_of_notices_only", () => {
  const read = { ...msg("notice.outcome", false), read: true };
  const ok = readMailbox(reply([msg("contract.sign"), read]));
  assert(ok !== null, "a read notice reads");
  eq(ok.messages.map((m) => m.read), [null, true], "work has no mark, the notice its own");
  const { read: _drop, ...bare } = msg("notice.outcome", false);
  for (const bad of [
    reply([bare]),
    reply([{ ...msg("notice.outcome", false), read: "yes" }]),
    reply([{ ...msg("contract.sign"), read: false }]),
  ]) {
    eq(readMailbox(bad), null, show(bad));
  }
});
