// The home page `/app/`, "Your work" (R-NF-03, R-NF-04, I-86; M4 design
// sections 2.2 J0 to J8 and 3.9; `docs/design/01-navigation-home.md`
// "Your work home per role", approved by Daniel on 2026-11-01).
//
// Every sign-in lands here. The page reads the caller's own roles
// (`me.roles`) and own proposals (`proposal.list_own`), and lists one
// link per piece of work (`model.ts` `workOf`). It has one `h1`, "Your
// work", then one card per role group, each with its `h2`:
//
// - a primary card, "Start here", with the caller's first piece of work
//   as its one primary action;
// - a card per role group the caller holds (applications, guardian
//   consent, tenant administration, programme management, coordination,
//   committee review, independent review) with the rest of its links;
// - the open calls, which anyone may read, last.
//
// Interim, pending the lead: the count summaries and the recent activity
// of the design need reads this release does not have (counts by state,
// and the activity log filtered by the visibility function, I-93). They
// are left out rather than shown empty.
//
// The page contract of the e2e specs (`e2e/navigation/support.ts`):
//
// - `main` holds `#home`, and `#home` holds `#home-work`: one `li` per
//   piece of work, each with one link `a[data-work="<kind>"]` whose text
//   names the work, such as the call or the proposal title.
// - A person with no role sees `#home-no-role`, which says so. The list
//   then holds the open calls only.
// - `#home-other` names each role this release has no page for.
//
// Every element is built with `h`, and every text goes in as a text node.

import { h } from "../core/dom.js";
import { call } from "../applicant/client.js";
import { frame } from "../applicant/ui.js";
import { decodeOwnProposals } from "../applicant/wire.js";
import { type OwnProposal, type Work, type WorkGroup, type WorkItem, workOf } from "./model.js";
import { homeLabel } from "./nav.js";
import { myRoles } from "./session.js";

/** One link of the home page, as its list item. */
function workLink(i: WorkItem, primary: boolean): HTMLElement {
  const attrs: Record<string, string> = { href: i.href, "data-work": i.kind };
  if (primary) {
    attrs["class"] = "btn btn--primary";
  }
  return h("li", { "data-work-item": i.kind }, [h("a", attrs, [homeLabel(i.text.id, i.text.args)])]);
}

/** A card with heading `title` and the links `items`. */
function card(id: string, title: string, items: readonly WorkItem[], kicker: string | null): HTMLElement {
  const heading = `${id}-heading`;
  const primary = kicker !== null;
  return h("section", { id, class: primary ? "card card--primary" : "card", "aria-labelledby": heading }, [
    ...(kicker === null ? [] : [h("p", { class: "card-kicker" }, [kicker])]),
    h("h2", { id: heading }, [title]),
    h(
      "ul",
      { class: primary ? "fstp-list btn-row" : "fstp-list" },
      items.map((i) => workLink(i, primary)),
    ),
  ]);
}

/**
 * The cards of the home page: the primary card with the first piece of
 * work that is not the open calls, then one card per role group in the
 * order `workOf` lists them.
 */
function workCards(w: Work): HTMLElement {
  const first = w.items.find((i) => i.group !== "everyone");
  const rest = w.items.filter((i) => i !== first);
  const groups: WorkGroup[] = [];
  for (const i of rest) {
    if (!groups.includes(i.group)) {
      groups.push(i.group);
    }
  }
  const cards: HTMLElement[] = [];
  if (first !== undefined) {
    cards.push(card("home-primary", homeLabel("home.primary.title"), [first], homeLabel("home.primary.kicker")));
  }
  for (const g of groups) {
    cards.push(
      card(
        `home-group-${g.replace(/_/g, "-")}`,
        homeLabel(`home.group.${g}`),
        rest.filter((i) => i.group === g),
        null,
      ),
    );
  }
  return h("div", { id: "home-work" }, cards);
}

/** The roles this release has no page for, named without a link. */
function otherRoles(w: Work): HTMLElement[] {
  if (w.other.length === 0) {
    return [];
  }
  return [
    h("section", { id: "home-other", class: "card", "aria-labelledby": "home-other-heading" }, [
      h("h2", { id: "home-other-heading" }, [homeLabel("home.other.title")]),
      h(
        "ul",
        { class: "fstp-list" },
        w.other.map((o) =>
          h("li", {}, [
            homeLabel("home.other.item", { role: homeLabel(`role.${o.role}`), programme: o.programme }),
          ]),
        ),
      ),
    ]),
  ];
}

/** Mounts the home page. */
export function mountHome(): void {
  const f = frame(homeLabel("home.title"));
  const loading = h("p", { "aria-busy": "true" }, [homeLabel("home.loading")]);
  const home = h("section", { id: "home", "aria-label": homeLabel("home.title") }, [loading]);
  f.main.append(home);
  const failed = (): void => {
    f.alert.textContent = homeLabel("home.failed");
    f.alert.hidden = false;
    home.replaceChildren();
  };
  (async () => {
    const a = await myRoles();
    if (a.kind === "signed_out") {
      // The shell opens the login page (`session.ts`).
      home.replaceChildren(h("p", { role: "status" }, [homeLabel("home.signed_out")]));
      return;
    }
    if (a.kind !== "roles") {
      failed();
      return;
    }
    const listed = await call("proposal.list_own", {}, undefined, decodeOwnProposals);
    const own: readonly OwnProposal[] | null = listed.ok
      ? listed.value.map((p) => ({ proposal: p.proposal, role: p.role, title: p.title }))
      : null;
    const w = workOf(
      a.roles,
      own,
      (c) => homeLabel("home.call", { id: c }),
      (p) => homeLabel("home.proposal", { id: p }),
    );
    const parts: HTMLElement[] = [];
    if (w.noRole) {
      parts.push(h("p", { id: "home-no-role" }, [homeLabel("home.no_role")]));
    } else {
      parts.push(h("p", { class: "muted" }, [homeLabel("home.intro")]));
    }
    parts.push(workCards(w), ...otherRoles(w));
    home.replaceChildren(...parts);
  })().catch(failed);
}
