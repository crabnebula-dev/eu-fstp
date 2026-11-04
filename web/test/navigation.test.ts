// The in-app navigation of `web/src/core/router.ts` (lane m4/site scope
// item 1, ADR-014): which links render in place in the one `/app/`
// document, and which are a normal navigation. The browser's URL parser
// resolves each link; this checks the rule on top of it. Every value is
// synthetic, under the reserved `.example` and `.invalid` domains.

import * as router from "../src/core/router.js";
import { appPathOf } from "../src/core/router.js";
import { pathish } from "./support/gen.js";
import { assert, eq, forAll, test } from "./support/harness.js";

const BASE = "https://cell.example/app/proposals/7";

/** ADR-014: an `/app/` path of this origin renders in place, with its query and fragment. */
test("adr014_app_links_of_this_origin_render_in_place", () => {
  eq(appPathOf("/app/", BASE), "/app/", "the home page");
  eq(appPathOf("/app", BASE), "/app", "the shell root");
  eq(appPathOf("/app/me", BASE), "/app/me", "the profile page");
  eq(appPathOf("plan", BASE), "/app/proposals/plan", "a relative link resolves against the page");
  eq(appPathOf("/app/calls?x=1#top", BASE), "/app/calls?x=1#top", "query and fragment are kept");
  eq(appPathOf("https://cell.example/app/me", BASE), "/app/me", "an absolute link of this origin");
});

/** ADR-014: anything outside `/app/` of this origin, and the assets, is a normal navigation. */
test("adr014_other_links_are_normal_navigations", () => {
  for (const href of [
    "/auth/login",
    "/auth/account",
    "/app/assets/0000.js",
    "/app/assets",
    "/application",
    "/p/calls",
    "https://other.example/app/",
    "//other.example/app/me",
    "http://cell.example/app/",
    "https://id.cell.example/w#ticket",
    "mailto:demo@e2e.invalid",
  ]) {
    eq(appPathOf(href, BASE), null, href);
  }
  eq(appPathOf("/app/", "not a url"), null, "a base that does not parse");
});

/** ADR-014: whatever a link holds, an in-place path stays below `/app` of this origin and outside the assets. */
test("adr014_in_place_paths_never_leave_the_app", () => {
  forAll(
    (r) => pathish(r, ["app", "assets", "auth", "..", ".", "%2e%2e", "me", "//", "\\"]),
    (href) => {
      const p = appPathOf(href, BASE);
      if (p === null) {
        return;
      }
      const u = new URL(p, BASE);
      assert(u.origin === "https://cell.example", `${href} stays on the origin`);
      assert(u.pathname === "/app" || u.pathname.startsWith("/app/"), `${href} stays below /app`);
      assert(u.pathname !== "/app/assets" && !u.pathname.startsWith("/app/assets/"), `${href} is not an asset`);
    },
  );
});

/**
 * Runs `body` with minimal browser globals for the in-app navigation:
 * a URL that `history` moves, and a document with no page. The router
 * reads them at call time, so they are put back afterwards.
 */
async function withBrowser(
  body: (b: { path(): string; rendered: string[] }) => Promise<void>,
): Promise<void> {
  const g = globalThis as unknown as Record<string, unknown>;
  const names = ["location", "history", "window", "document", "HTMLElement"];
  const saved = new Map(names.map((n) => [n, Object.getOwnPropertyDescriptor(g, n)]));
  let path = "/app/proposals/7/workspace";
  const set = (n: string, v: unknown): void => {
    Object.defineProperty(g, n, { value: v, configurable: true, writable: true });
  };
  set("location", {
    get pathname(): string {
      return path;
    },
    search: "",
    hash: "",
    get href(): string {
      return `https://cell.example${path}`;
    },
    assign(): void {
      throw new Error("an in-app path never loads a document");
    },
  });
  set("history", {
    pushState(_s: unknown, _t: string, p: string): void {
      path = p;
    },
    replaceState(_s: unknown, _t: string, p: string): void {
      path = p;
    },
  });
  set("window", { addEventListener: () => undefined, scrollTo: () => undefined });
  set("document", {
    addEventListener: () => undefined,
    querySelector: () => null,
    querySelectorAll: () => [],
    activeElement: null,
    body: {},
    title: "",
  });
  if (typeof g["HTMLElement"] !== "function") {
    set("HTMLElement", class {});
  }
  try {
    await body({ path: () => path, rendered: [] });
  } finally {
    for (const [n, d] of saved) {
      if (d === undefined) {
        delete g[n];
      } else {
        Object.defineProperty(g, n, d);
      }
    }
  }
}

/** Lets the router's pending promises run. */
function settle(): Promise<void> {
  return new Promise((r) => setTimeout(r, 0));
}

/**
 * I-21, ADR-014: a page that holds its leave keeps the person on it
 * while its check says no, such as a workspace whose save failed, and
 * lets them go once the check says yes. The check ends with the page.
 */
test("i21_leave_hold_keeps_the_page_until_its_check_lets_it_go", async () => {
  await withBrowser(async (b) => {
    await router.startNavigation({
      render: (p) => {
        b.rendered.push(p);
      },
      announce: () => undefined,
    });
    eq(b.rendered.length, 1, "the first page renders");
    let answer = false;
    let asked = 0;
    router.holdLeave(async () => {
      asked += 1;
      return answer;
    });
    router.navigate("/app/proposals");
    await settle();
    eq(b.path(), "/app/proposals/7/workspace", "a held navigation keeps the URL");
    eq(b.rendered.length, 1, "a held navigation renders nothing");
    eq(asked, 1, "the check ran once");
    answer = true;
    router.navigate("/app/proposals");
    await settle();
    eq(b.path(), "/app/proposals", "a navigation the check lets go moves the URL");
    eq(b.rendered[b.rendered.length - 1], "/app/proposals", "and renders the new page");
    router.navigate("/app/me");
    await settle();
    eq(asked, 2, "the check of a page that was left never runs again");
    eq(b.path(), "/app/me", "the next page goes freely");
    router.holdLeave(() => {
      throw new Error("a broken check");
    });
    router.navigate("/app/");
    await settle();
    eq(b.path(), "/app/", "a check that throws lets the page go");
  });
});

/**
 * I-70, R-NF-03 (WCAG 2.2 SC 4.1.3): a navigation speaks the heading, and
 * the document title beside it when that names more, so each step of a
 * set-up whose steps share one heading is told apart.
 */
test("i70_navigation_speaks_the_step_the_title_names", () => {
  eq(router.spokenTitle("Your work", "Your work | FSTP"), "Your work", "a title that holds the heading adds nothing");
  eq(
    router.spokenTitle("Programme set-up", "Step 2: Budget"),
    "Programme set-up, Step 2: Budget",
    "a step title is spoken beside the shared heading",
  );
  eq(router.spokenTitle("  Proposals ", ""), "Proposals", "no title: the heading alone");
  eq(router.spokenTitle("", "Step 2: Budget"), "", "no heading yet: nothing is spoken");
});
