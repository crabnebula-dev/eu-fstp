// SA-09: the client router and the server's page gate list the same
// `/app/` pages, so a new page cannot skip the gate; and the shell reads
// the gate's answers as the server gives them.

import { passkeyAsked } from "../src/auth/pages/login.js";
import { CREATOR_STEPS } from "../src/creator/model.js";
import { PAGES } from "../src/gen/api.js";
import { ONBOARDING_STEPS, SETTINGS } from "../src/onboarding/model.js";
import { STAGES } from "../src/setup/model.js";
import { createGate, gateOf, pagePathOf } from "../src/shell/gate.js";
import { appPatterns, appRoutes } from "../src/shell/routes.js";
import { assert, eq, test } from "./support/harness.js";

/** R-AC-01, SA-09: the client routes are exactly the server's page table, each once. */
test("r_ac_01_sa09_client_routes_are_the_server_page_table", () => {
  const client = [...appPatterns()].sort();
  const server = PAGES.map((p) => p.pattern).sort();
  eq(new Set(client).size, client.length, "a client pattern repeats");
  eq(client, server, "the client routes and the server page table");
});

/** R-AC-01, SA-09: each closed parameter lists the values the client route accepts, exactly. */
test("r_ac_01_sa09_closed_page_parameters_match_the_client", () => {
  const lists: Readonly<Record<string, readonly string[]>> = {
    "/app/programmes/{programme}/creator/{step}": CREATOR_STEPS.map((s) => s.id),
    "/app/programmes/{programme}/setup/{stage}": STAGES.map((s) => s.id).filter((s) => s !== "start"),
    "/app/admin/onboarding/{step}": [...ONBOARDING_STEPS],
    "/app/admin/settings/{param}": [...SETTINGS],
  };
  const routes = appRoutes();
  for (const row of PAGES) {
    const closed = Object.entries(row.values);
    if (closed.length === 0) {
      continue;
    }
    const want = lists[row.pattern];
    assert(want !== undefined, `${row.pattern} has closed values the test does not know`);
    const route = routes.find((r) => r.pattern === row.pattern);
    assert(route !== undefined, `${row.pattern} has no client route`);
    for (const [name, values] of closed) {
      eq([...values], [...want], `${row.pattern} {${name}}`);
      const check = route.segments[name];
      assert(check !== undefined, `${row.pattern} checks no {${name}}`);
      for (const v of values) {
        assert(check(v), `${row.pattern} refuses ${v}`);
      }
      assert(!check("no-such-value"), `${row.pattern} accepts an unlisted value`);
    }
  }
});

/** R-AC-01, SA-09: every id parameter of the table is one the client accepts as a decimal id. */
test("r_ac_01_sa09_page_ids_are_decimal_for_the_client", () => {
  for (const r of appRoutes()) {
    const row = PAGES.find((p) => p.pattern === r.pattern);
    assert(row !== undefined, r.pattern);
    for (const [name, check] of Object.entries(r.segments)) {
      if (row.values[name] === undefined) {
        assert(check("12"), `${r.pattern} refuses the id 12 for {${name}}`);
      }
    }
  }
});

/**
 * R-AC-01, SA-09 and its amendment (Daniel, 2026-11-15): the gate reads
 * 200 as open and a redirect as closed. The server answers sign-in and a
 * closed or unknown page alike with a 303, which the gate never follows.
 */
test("r_ac_01_sa09_gate_reads_the_server_answer", async () => {
  eq(gateOf({ type: "basic", status: 200 }), "open", "200");
  eq(gateOf({ type: "opaqueredirect", status: 0 }), "closed", "a redirect not followed");
  eq(gateOf({ type: "basic", status: 303 }), "closed", "303");
  eq(gateOf({ type: "basic", status: 404 }), "closed", "404");
  eq(gateOf({ type: "basic", status: 503 }), "unknown", "503");
  const asked: { path: string; method: string | undefined; redirect: string | undefined }[] = [];
  const gate = createGate((path, init) => {
    asked.push({ path, method: init.method, redirect: init.redirect });
    return Promise.resolve(path === "/app/grants" ? { type: "opaqueredirect", status: 0 } : { type: "basic", status: 200 });
  });
  eq(await gate.check("/app/"), "open", "home");
  eq(await gate.check("/app/"), "open", "home asked again");
  eq(asked.length, 1, "an open page is asked once per page load");
  eq(asked[0], { path: "/app/", method: "HEAD", redirect: "manual" }, "a HEAD with no redirect followed");
  eq(await gate.check("/app/grants"), "closed", "the grants hub");
  eq(await gate.check("/app/grants"), "closed", "asked again");
  // R-CF-02: a page opens as the person acts, such as the knock-out check
  // once the coordinator declared no conflict, so a closed answer is
  // never kept.
  eq(asked.length, 3, "a closed page is asked each time");
  await gate.fresh("/app/");
  eq(asked.length, 4, "fresh asks again");
  const failing = createGate(() => Promise.reject(new Error("network")));
  eq(await failing.check("/app/"), "unknown", "a network failure");
});

/** R-AC-01, SA-09: only an in-app page path of this origin is gated. */
test("r_ac_01_sa09_only_app_page_links_are_gated", () => {
  const base = "https://cell.example/app/";
  eq(pagePathOf("/app/grants", base), "/app/grants", "a page");
  eq(pagePathOf("https://cell.example/app/proposals/1?x=1#y", base), "/app/proposals/1", "a page with query");
  eq(pagePathOf("/auth/login", base), null, "the login page");
  eq(pagePathOf("/app/assets/a.js", base), null, "an asset");
  eq(pagePathOf("https://other.example/app/", base), null, "another origin");
  eq(pagePathOf("/p/1/", base), null, "a public page");
});

/** I-77, SA-09 rule 4: the login page reads the gate's passkey request. */
test("i77_sa09_login_page_reads_the_passkey_request", () => {
  assert(passkeyAsked("?method=passkey&next=%2Fapp%2Fgrants"), "method=passkey");
  assert(!passkeyAsked("?next=%2Fapp%2Fgrants"), "no method");
  assert(!passkeyAsked(""), "no query");
});
