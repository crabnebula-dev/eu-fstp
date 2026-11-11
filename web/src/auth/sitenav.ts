// The links of the account page's navigation (Daniel, 2026-10-31:
// "please add all links to routes in the top row";
// `docs/design/01-navigation-home.md` "Top row").
//
// The auth pages are delivered on their own: the cell serves only the
// tsc output of `web/dist/auth` below `/assets/auth/` (`main.ts`
// "Delivery"). So this module restates the navigation table of
// `web/src/home/model.ts` `navOf` instead of importing it. The web test
// `r_nf_03_account_nav_matches_the_app_nav` checks that both give the
// same links for any roles. This module is pure: it reads a value that
// `JSON.parse` produced and builds plain data.

/** The roles whose work is in the operations queues, as `home/model.ts` names them. */
const OPERATIONS_ROLES: readonly string[] = ['programme_manager', 'finance_approver', 'payment_releaser', 'contract_signatory', 'auditor'];

/** One link of the navigation: its `data-nav` kind and its path. Its label is `account.nav.<kind>`. */
export interface SiteLink {
  readonly kind: NavKind;
  readonly href: string;
}

/** The kinds of link, as `a[data-nav]` names them. */
export type NavKind =
  | 'home'
  | 'assignments'
  | 'irc-cases'
  | 'onboarding'
  | 'creator'
  | 'approvals'
  | 'operations'
  | 'proposals'
  | 'grants'
  | 'calls'
  | 'account';

/** What the navigation needs of the `me.roles` reply. */
export interface NavRoles {
  readonly tenantAdmin: boolean;
  /** The roles of the caller's programme bindings, without a proposal. */
  readonly staff: ReadonlySet<string>;
  /** The tenant-wide signatory roles of the caller. */
  readonly signatories: readonly string[];
}

/** The parts of a `me.roles` reply the navigation reads, or null when it does not fit. */
export function navRolesOf(v: unknown): NavRoles | null {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) return null;
  const o = v as Readonly<Record<string, unknown>>;
  const roles = o['roles'];
  if (typeof o['tenant_admin'] !== 'boolean' || !Array.isArray(roles)) return null;
  const staff = new Set<string>();
  for (const r of roles as readonly unknown[]) {
    if (typeof r !== 'object' || r === null || Array.isArray(r)) return null;
    const b = r as Readonly<Record<string, unknown>>;
    if (typeof b['role'] !== 'string') return null;
    if (!Object.hasOwn(b, 'proposal')) staff.add(b['role']);
  }
  const sig = o['signatories'];
  const signatories = Array.isArray(sig) ? (sig as readonly unknown[]).filter((x): x is string => typeof x === 'string') : [];
  return { tenantAdmin: o['tenant_admin'], staff, signatories };
}

/**
 * The navigation, in order: Home, the pages the caller's roles may open
 * without an id, the caller's applications, the open calls and Account.
 * `roles` is null until `me.roles` answers.
 */
export function siteLinks(roles: NavRoles | null): readonly SiteLink[] {
  const out: SiteLink[] = [{ kind: 'home', href: '/app/' }];
  if (roles !== null) {
    if (roles.staff.has('committee_member')) {
      out.push({ kind: 'assignments', href: '/app/me/assignments' });
    }
    if (roles.staff.has('irc_member')) {
      out.push({ kind: 'irc-cases', href: '/app/me/irc-cases' });
    }
    if (OPERATIONS_ROLES.some((r) => roles.staff.has(r)) || roles.signatories.length > 0) {
      out.push({ kind: 'operations', href: '/app/operations' });
    }
    if (roles.tenantAdmin) {
      out.push({ kind: 'onboarding', href: '/app/admin/onboarding/summary' });
      out.push({ kind: 'creator', href: '/app/creator/new' });
      out.push({ kind: 'approvals', href: '/app/admin/approvals' });
    }
  }
  out.push(
    { kind: 'proposals', href: '/app/proposals' },
    { kind: 'grants', href: '/app/grants' },
    { kind: 'calls', href: '/app/calls' },
    { kind: 'account', href: '/auth/account' },
  );
  return out;
}
