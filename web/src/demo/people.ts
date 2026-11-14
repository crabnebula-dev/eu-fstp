// The reader of the demo switcher's replies (lane m4/demo-switch). Test
// only: `fstp-e2e-cell` serves the demo modules on a cell started with
// `--demo-signin`, and no shipped cell serves them (layering rule A9).
//
// `GET /auth/demo-signin/people` answers the scene and its people. The
// browser's `JSON.parse` reads the body; this module only checks its
// shape, and refuses the whole reply when one member is off. It never
// throws. `POST /auth/demo-signin/switch` answers one fresh token.

/** One person the switcher lists. */
export interface DemoPerson {
  /** The account id in decimal. */
  readonly account: string;
  /** The persona label, or the email when the person has none. */
  readonly name: string;
  readonly email: string;
  /** The roles in words, such as `FSTP coordinator`. */
  readonly roles: string;
  /** One line on what the person can do in the scene. */
  readonly does: string;
  /** Whether this is the person signed in now. */
  readonly current: boolean;
}

/** The scene and its people. */
export interface DemoScene {
  readonly scene: string;
  readonly people: readonly DemoPerson[];
}

/** The most people one reply may list. */
export const MAX_PEOPLE = 200;

/** The longest text member, in UTF-16 code units. */
export const MAX_TEXT = 1024;

/** An account id: a decimal number with no sign and no leading zero. */
const ACCOUNT = /^(?:0|[1-9][0-9]{0,38})$/;

/** A token as the cell issues it: 32 lowercase hex digits. */
const TOKEN = /^[0-9a-f]{32}$/;

/** `v` as a plain object, or null. */
function object(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === 'object' && v !== null && !Array.isArray(v) ? (v as Record<string, unknown>) : null;
}

/** `v` when it is a string of at most [`MAX_TEXT`] code units, else null. */
function text(v: unknown, empty: boolean): string | null {
  if (typeof v !== 'string' || v.length > MAX_TEXT || (!empty && v.trim() === '')) {
    return null;
  }
  return v;
}

/** One person, or null when a member is missing or off. */
function person(v: unknown): DemoPerson | null {
  const o = object(v);
  if (o === null) {
    return null;
  }
  const account = o['account'];
  const name = text(o['name'], false);
  const email = text(o['email'], true);
  const roles = text(o['roles'], false);
  const does = text(o['does'], false);
  const current = o['current'];
  if (
    typeof account !== 'string' ||
    !ACCOUNT.test(account) ||
    name === null ||
    email === null ||
    roles === null ||
    does === null ||
    typeof current !== 'boolean'
  ) {
    return null;
  }
  return { account, name, email, roles, does, current };
}

/**
 * The scene of a people reply, or null. It is null unless every person
 * is well formed, no account repeats, and at most one person is current.
 */
export function readScene(body: unknown): DemoScene | null {
  const o = object(body);
  if (o === null) {
    return null;
  }
  const scene = text(o['scene'], true);
  const list = o['people'];
  if (scene === null || !Array.isArray(list) || list.length > MAX_PEOPLE) {
    return null;
  }
  const people: DemoPerson[] = [];
  const seen = new Set<string>();
  let current = 0;
  for (const item of list as readonly unknown[]) {
    const p = person(item);
    if (p === null || seen.has(p.account)) {
      return null;
    }
    seen.add(p.account);
    if (p.current) {
      current += 1;
    }
    people.push(p);
  }
  if (current > 1) {
    return null;
  }
  return { scene, people };
}

/** The person signed in now, if the scene lists them. */
export function currentPerson(scene: DemoScene): DemoPerson | null {
  return scene.people.find((p) => p.current) ?? null;
}

/** The token of a switch reply, or null. */
export function readToken(body: unknown): string | null {
  const o = object(body);
  const t = o === null ? undefined : o['token'];
  return typeof t === 'string' && TOKEN.test(t) ? t : null;
}
