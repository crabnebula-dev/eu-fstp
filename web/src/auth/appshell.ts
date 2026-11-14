// The app shell of the account page `/auth/account` (Daniel,
// 2026-11-14: the account page must match the rest of the design).
//
// The `/app/` pages share one shell (`web/src/home/nav.ts` `appShell`,
// `docs/design/01-navigation-home.md` "Sidebar layout"): a skip link,
// the top bar with the tenant mark, Mailbox, Notifications and the
// "Account tools" `nav` with Passkeys and sessions, then `div.page-body`
// with `aside.sidebar` and `main`, and the footer. The auth pages are
// delivered on their own (`main.ts` "Delivery"), so this module restates
// that markup with the classes of `tokens.css`, which the auth bundle
// shares with the site. It builds the same element tree, `data-nav`
// names and labels, so the account page looks and navigates like every
// other signed-in page.
//
// The links come from `sitenav.ts`, which `r_nf_03_account_nav_matches_the_app_nav`
// keeps equal to the app's `navOf`. As in the app shell, `navOf`'s
// Account link (`/auth/account`) sits in the top bar as Passkeys and
// sessions, and the sidebar foot holds Account, the profile page
// `/app/me`. The role chip and the role links follow once `me.roles`
// answers, and the Mailbox link shows its open count once `me.mailbox`
// answers. A failed read leaves the links every signed-in person has.

import { get, ok, record } from './api.js';
import { h } from './dom.js';
import { PATHS, t } from './layout.js';
import { AUTH_EN, type AuthMessageId } from './messages.en.js';
import { type NavRoles, type SiteLink, navRolesOf, siteLinks } from './sitenav.js';

/** The caller's own roles (`me.roles`, I-86). */
const ME_ROLES = '/api/v1/me/roles';

/** The caller's mailbox (`me.mailbox`, lane m6/mailbox). */
const ME_MAILBOX = '/api/v1/me/mailbox';

/** The paths of the top bar and the sidebar foot, as `home/model.ts` names them. */
const APP = { home: '/app/', mailbox: '/app/mailbox', notices: '/app/notices', profile: '/app/me' } as const;

/** The order in which the role chip names roles, as `home/model.ts` `CHIP_ORDER`. */
const CHIP_ORDER: readonly string[] = [
  'programme_manager',
  'call_drafter',
  'fstp_coordinator',
  'committee_chair',
  'committee_member',
  'irc_member',
  'finance_approver',
  'payment_releaser',
  'contract_signatory',
  'financial_signatory',
  'legal_signatory',
  'auditor',
  'tenant_admin',
  'applicant',
  'applicant_team_member',
  'guardian',
];

/** Whether `id` names a role label of the catalogue. */
function roleLabel(role: string): string | null {
  const id = `role.${role}`;
  return Object.hasOwn(AUTH_EN.messages, id) ? t(id as AuthMessageId) : null;
}

/** The roles the chip names, in chip order: every role binding, signatory role and tenant admin. */
export function chipRolesOf(v: unknown): readonly string[] {
  const o = record(v);
  if (o === null) return [];
  const held = new Set<string>();
  const roles = o['roles'];
  if (Array.isArray(roles)) {
    for (const r of roles as readonly unknown[]) {
      const role = record(r)?.['role'];
      if (typeof role === 'string') held.add(role);
    }
  }
  const sig = o['signatories'];
  if (Array.isArray(sig)) {
    for (const s of sig as readonly unknown[]) if (typeof s === 'string') held.add(s);
  }
  if (o['tenant_admin'] === true) held.add('tenant_admin');
  return CHIP_ORDER.filter((r) => held.has(r));
}

/** The text of the role chip for `roles`. */
function chipText(roles: readonly string[]): string {
  const named = roles.map(roleLabel).filter((x): x is string => x !== null);
  if (named.length === 0) return t('shell.chip_none');
  return t('shell.chip', { roles: named.join(t('shell.role_join')) });
}

/** One link of the sidebar navigation, marked current on its own page. */
function item(l: SiteLink): HTMLElement {
  const attrs: Record<string, string> = { href: l.href, 'data-nav': l.kind };
  if (l.href === location.pathname) attrs['aria-current'] = 'page';
  return h('li', {}, [h('a', attrs, [t(`account.nav.${l.kind}`)])]);
}

/** The sidebar list for `roles`: every link but Account, which the top bar holds. */
function fillNav(list: HTMLElement, roles: NavRoles | null): void {
  list.replaceChildren(...siteLinks(roles).filter((l) => l.kind !== 'account').map(item));
}

/** The top bar: the tenant mark, Mailbox, Notifications and Passkeys and sessions. */
function topBar(mailbox: HTMLElement): HTMLElement {
  const security: Record<string, string> = { class: 'tool-link', href: PATHS.account, 'data-nav': 'account' };
  if (location.pathname === PATHS.account) security['aria-current'] = 'page';
  return h('header', { class: 'site-header site-header--app' }, [
    h('div', { class: 'topbar' }, [
      h('a', { class: 'brand', href: APP.home, 'data-brand': 'home' }, [
        h('span', { class: 'brand-mark', 'aria-hidden': 'true' }, ['F']),
        h('span', {}, [t('top.brand'), h('span', { class: 'sr-only' }, [t('shell.brand_home')])]),
      ]),
      h('span', { class: 'topbar-spacer' }),
      h('ul', { class: 'topbar-tools' }, [
        h('li', {}, [mailbox]),
        h('li', {}, [
          h('a', { class: 'tool-link', href: APP.notices, 'data-tool': 'notices' }, [t('shell.notifications')]),
        ]),
      ]),
      h('nav', { class: 'topbar-nav', 'aria-label': t('shell.tools') }, [
        h('ul', { class: 'topbar-tools' }, [h('li', {}, [h('a', security, [t('shell.security')])])]),
      ]),
    ]),
  ]);
}

/** The footer, as the PublicLayout and the app pages show it. */
function footer(): HTMLElement {
  return h('footer', { class: 'site-footer' }, [
    h('div', { class: 'inner' }, [
      h('p', {}, [t('footer.privacy')]),
      h('p', {}, [t('footer.accessibility')]),
      h('p', {}, [t('footer.attribution')]),
    ]),
  ]);
}

/**
 * Puts the app shell around `main`, once per document: the top bar
 * before it, `div.page-body` with the sidebar and
 * `main`, and the footer after. Then reads `me.roles` and `me.mailbox`
 * to fill the role chip, the role links and the open count.
 */
export function appShell(main: HTMLElement): void {
  if (document.querySelector('header.site-header') !== null) return;
  if (main.id === '') main.id = 'main';
  main.setAttribute('tabindex', '-1');
  const mailbox = h('a', { class: 'tool-link', href: APP.mailbox, 'data-tool': 'mailbox' }, [t('shell.mailbox')]);
  const chip = h('p', { class: 'role-chip', 'data-slot': 'role', 'data-role-chip': 'true' }, [t('shell.chip_none')]);
  const list = h('ul', { class: 'fstp-nav', 'data-site-nav': 'main' });
  fillNav(list, null);
  const profile: Record<string, string> = { href: APP.profile, 'data-nav': 'account' };
  const aside = h('aside', { class: 'sidebar', 'aria-label': t('account.nav') }, [
    chip,
    h('p', { class: 'sidebar-label', 'aria-hidden': 'true' }, [t('shell.section')]),
    h('nav', { id: 'site-nav', class: 'main-nav', 'aria-label': t('account.nav'), 'data-slot': 'nav' }, [list]),
    h('ul', { class: 'sidebar-foot', 'data-slot': 'account' }, [
      h('li', { class: 'sidebar-account' }, [h('a', profile, [t('account.nav.account')])]),
    ]),
  ]);
  const body = h('div', { class: 'page-body' });
  main.replaceWith(body);
  body.append(aside, main);
  // No skip link, as on the other auth pages (`layout.ts` `chrome`): a
  // fragment link would mount the page again, and the landmarks lead to
  // `main` (WCAG 2.2 SC 2.4.1).
  body.before(topBar(mailbox));
  body.after(footer());
  void get(ME_ROLES).then(
    (r) => {
      if (!ok(r)) return;
      const roles = navRolesOf(r.body);
      if (roles !== null) fillNav(list, roles);
      chip.replaceChildren(chipText(chipRolesOf(r.body)));
    },
    () => undefined,
  );
  void get(ME_MAILBOX).then(
    (r) => {
      const open = ok(r) ? record(r.body)?.['open'] : undefined;
      if (typeof open === 'number' && Number.isSafeInteger(open) && open >= 0) {
        mailbox.setAttribute('data-open', String(open));
        mailbox.replaceChildren(t('shell.mailbox_count', { count: String(open) }));
      }
    },
    () => undefined,
  );
}
