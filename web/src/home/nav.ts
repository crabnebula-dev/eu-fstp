// The page shell of every `/app/` page: the skip link, the top bar and
// the sidebar with the site navigation (R-NF-03, R-NF-04; M4 design
// section 3.9 "Shell"; `docs/design/01-navigation-home.md` "Sidebar
// layout" and "Layout and routing contract", approved by Daniel on
// 2026-11-01).
//
// Source order: skip link, top bar (`header`), then `div.page-body` with
// `aside.sidebar` and the page's `main`. The frames of the feature pages
// pass their `main` to `appShell` and put the footer after it. A page
// renders only its main content and never builds the shell itself.
//
// - Top bar: the tenant mark, which links to the home page, a spacer and
//   Notifications. Help has no page in this release, so it is left out.
// - Sidebar, top to bottom: the role chip ("Signed in as ..."), the
//   "Navigation" label, then `nav` with every page the caller may open
//   without an id (`model.ts` `navOf`), and Account pinned at the
//   bottom. Pages that need an id are listed on the home page.
// - The masquerade banner of the design is a synthetic role preview that
//   a later lane builds (`SPEC/12-journey-ui.md` section 8.6), so this
//   shell has no slot for it yet.
// - Sign out has no route of its own: the account page ends the current
//   session. So the sidebar foot holds Account only.
// - Account stays in the sidebar at every width, and the top bar has no
//   avatar. So `nav a[data-nav="account"]` is visible on every page
//   (the e2e contract of `e2e/navigation/support.ts`).
//
// Each link has `data-nav` naming it, and the current page's link has
// `aria-current="page"`. The shell builds the navigation at once with
// Home, the pages anyone signed in may open, and Account. The role links
// and the role chip need `me.roles`, which only the shell reads
// (`session.ts`). When that read answers, `showRoles` fills every shell
// on the page and every one built later. So a feature entry or a page
// test that never loads the shell makes no extra request, and this
// module imports nothing from `gen/api.ts`.

import { h } from "../core/dom.js";
import { type I18n, type Label, createI18n } from "../core/i18n.js";
import { HOME_LABELS } from "./messages.en.js";
import { type MyRoles, type NavLink, WORK_PATHS, chipRoles, navOf } from "./model.js";

let catalogue: I18n | null = null;

/**
 * The home catalogue. Interim, pending the lead: the shell passes no
 * locale or terminology overrides yet, so the pages use English.
 */
function i18n(): I18n {
  catalogue ??= createI18n({ catalogues: [{ locale: "en", labels: HOME_LABELS, approved: {} }], locale: "en" });
  return catalogue;
}

/** The home interface string `id`. */
export function homeLabel(id: string, args?: Readonly<Record<string, string>>): Label {
  return i18n().label(id, args);
}

/** The locale of the home catalogue. */
export function homeLocale(): string {
  return i18n().locale;
}

/** The caller's roles, once the shell read them. */
let known: MyRoles | null = null;

/** The attribute that marks the link list of a site navigation. */
const LIST = "data-site-nav";

/** The attribute that marks the role chip of a sidebar. */
const CHIP = "data-role-chip";

/** The path of the current page, or `""` outside a browser. */
function here(): string {
  return typeof location === "object" && location !== null ? location.pathname : "";
}

/** One link of the navigation, marked current on its own page. */
function item(l: NavLink, current: string): HTMLElement {
  const attrs: Record<string, string> = { href: l.href, "data-nav": l.kind };
  if (l.href === current || (l.kind === "home" && current === "/app")) {
    attrs["aria-current"] = "page";
  }
  return h("li", l.kind === "account" ? { class: "sidebar-account" } : {}, [h("a", attrs, [homeLabel(l.label)])]);
}

/** The links of the navigation for `roles`, Account apart. */
function links(roles: MyRoles | null): { readonly main: HTMLElement[]; readonly foot: HTMLElement[] } {
  const current = here();
  const all = navOf(roles);
  return {
    main: all.filter((l) => l.kind !== "account").map((l) => item(l, current)),
    foot: all.filter((l) => l.kind === "account").map((l) => item(l, current)),
  };
}

/** The text of the role chip for `roles`. */
function chipText(roles: MyRoles | null): Label {
  const named = roles === null ? [] : chipRoles(roles);
  if (named.length === 0) {
    return homeLabel("nav.role_chip_none");
  }
  return homeLabel("nav.role_chip", {
    roles: named.map((r) => homeLabel(`role.${r}`)).join(homeLabel("nav.role_join")),
  });
}

/** The site navigation: a labelled `nav` landmark with its link list and Account. */
export function siteNav(): HTMLElement {
  const l = links(known);
  return h("nav", { class: "main-nav", "aria-label": homeLabel("nav.label"), "data-slot": "nav" }, [
    h("ul", { class: "fstp-nav", [LIST]: "main" }, l.main),
    h("ul", { class: "sidebar-foot", [LIST]: "foot", "data-slot": "account" }, l.foot),
  ]);
}

/** The sidebar: the role chip, the navigation label and the site navigation. */
function sidebar(): HTMLElement {
  return h("aside", { class: "sidebar", "aria-label": homeLabel("nav.label") }, [
    h("p", { class: "role-chip", "data-slot": "role", [CHIP]: true }, [chipText(known)]),
    h("p", { class: "sidebar-label", "aria-hidden": "true" }, [homeLabel("nav.section_label")]),
    siteNav(),
  ]);
}

/** The top bar: the tenant mark that links home, and Notifications. */
function topBar(): HTMLElement {
  return h("header", { class: "site-header site-header--app" }, [
    h("div", { class: "topbar" }, [
      h("a", { class: "brand", href: WORK_PATHS.home, "data-brand": "home" }, [
        h("span", { class: "brand-mark", "aria-hidden": "true" }, ["F"]),
        h("span", {}, [homeLabel("nav.brand"), h("span", { class: "sr-only" }, [homeLabel("nav.brand_home")])]),
      ]),
      h("span", { class: "topbar-spacer" }),
      h("ul", { class: "topbar-tools" }, [
        h("li", {}, [
          h("a", { class: "tool-link", href: WORK_PATHS.notices, "data-tool": "notices" }, [
            homeLabel("nav.notifications"),
          ]),
        ]),
      ]),
    ]),
  ]);
}

/**
 * The shell around `main`, in source order: the skip link, the top bar
 * and the page body with the sidebar and `main`. The skip link moves
 * focus to `main`, which takes focus from script only.
 */
export function appShell(main: HTMLElement): HTMLElement[] {
  if (main.id === "") {
    main.id = "main";
  }
  main.setAttribute("tabindex", "-1");
  const skip = h("a", { class: "skip-link", href: `#${main.id}` }, [homeLabel("nav.skip_to_main")]);
  return [skip, topBar(), h("div", { class: "page-body" }, [sidebar(), main])];
}

/**
 * Adds the role links and the role chip of `roles` to every shell on
 * the page, and to every one a frame builds later.
 */
export function showRoles(roles: MyRoles): void {
  known = roles;
  for (const list of Array.from(document.querySelectorAll(`ul[${LIST}]`))) {
    const l = links(roles);
    list.replaceChildren(...(list.getAttribute(LIST) === "foot" ? l.foot : l.main));
  }
  for (const chip of Array.from(document.querySelectorAll(`[${CHIP}]`))) {
    chip.replaceChildren(chipText(roles));
  }
}
