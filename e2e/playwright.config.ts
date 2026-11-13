/**
 * Playwright configuration and the shared stack contract of the M3 specs
 * (M3 design sections 8, 11.2 and 14.7, ADR-003, ADR-008, ADR-009).
 *
 * Each spec of design section 14.7 runs in Chromium only, with Chromium's
 * virtual authenticator driven through CDP. Retries are off, since these
 * are invariant journeys. The specs never sleep: they wait on elements,
 * responses and the stack's test clock.
 *
 * The lane's file scope allows this file and the named spec files only.
 * So the helpers the specs share live here, below the configuration. The
 * lead may move them to `e2e/support/` later without changing a test.
 *
 * # Stack contract (lane W3b, `fstp-devstack`)
 *
 * The specs reach a running stack through a manifest. The environment
 * variable `FSTP_E2E_STACK` names a JSON file that `fstp-devstack` writes
 * once its cells listen:
 *
 * ```json
 * {
 *   "version": 1,
 *   "cells": {
 *     "a": { "origin": "https://a.fstp.test:8443",
 *            "vault_origin": "https://id.a.fstp.test:8443",
 *            "control": "http://127.0.0.1:9101" },
 *     "b": { "origin": "https://b.fstp.test:8443",
 *            "vault_origin": "https://id.b.fstp.test:8443",
 *            "control": "http://127.0.0.1:9102" }
 *   },
 *   "resolver_rules": "MAP *.fstp.test 127.0.0.1",
 *   "spki_pins": ["<base64 SHA-256 of each served leaf SPKI>"]
 * }
 * ```
 *
 * - The two cell hosts are siblings under one parent domain, so a parent
 *   domain RP id would be accepted by the browser (I-20).
 * - Each vault origin host is `id.` followed by its cell host (design
 *   section 1.5).
 * - TLS is real. Chromium trusts the served leaves through
 *   `--ignore-certificate-errors-spki-list`, which keeps a secure context,
 *   the `__Host-` cookie and WebAuthn working. Certificate errors are
 *   never ignored wholesale, since Chromium then disables WebAuthn.
 * - The control base is loopback HTTP of the test-only devstack. It is
 *   never part of a cell origin. Its routes are in [`Control`].
 * - The M4 e2e cell (`fstp-e2e-cell`, M4 design section 1.2) serves plain
 *   HTTP on loopback under `.localhost` instead. Chromium resolves those
 *   names to loopback and treats them as secure contexts (RFC 6761), so
 *   WebAuthn and the `__Host-` cookie still work. A manifest may then name
 *   `http:` cell and vault origins and no SPKI pin, but only when every
 *   cell and vault host ends in `.localhost`. Interim, pending Daniel.
 *
 * Without a manifest every stack spec fails at its first step, with a
 * message that names the missing piece. No spec is skipped.
 */

import {
  test as base,
  defineConfig,
  expect,
  type BrowserContext,
  type APIRequestContext,
  type APIResponse,
  type CDPSession,
  type Page,
} from '@playwright/test';
import { readFileSync } from 'node:fs';

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

/** The endpoints of one cell in the stack manifest. */
export interface CellEndpoints {
  /** The cell origin, `https://<cell host>[:port]`. */
  readonly origin: string;
  /** The vault origin, `https://id.<cell host>[:port]`. */
  readonly vault_origin: string;
  /** The loopback base of the devstack control routes of this cell. */
  readonly control: string;
}

/** The stack manifest that `fstp-devstack` writes. */
export interface StackManifest {
  readonly version: 1;
  readonly cells: { readonly a: CellEndpoints; readonly b: CellEndpoints };
  readonly resolver_rules: string;
  readonly spki_pins: readonly string[];
}

/** Why the stack is not usable. Specs fail with this, never skip. */
export class StackMissing extends Error {
  override readonly name = 'StackMissing';
}

const MANIFEST_ENV = 'FSTP_E2E_STACK';

function str(v: unknown, what: string): string {
  if (typeof v !== 'string' || v.length === 0) {
    throw new StackMissing(`stack manifest: ${what} must be a non-empty string`);
  }
  return v;
}

/** Whether `host` is a loopback name under `.localhost` (RFC 6761). */
function isLocalhostName(host: string): boolean {
  return host.endsWith('.localhost');
}

/**
 * `v` as a bare origin of `scheme`. `cell` takes `https:`, or `http:` for
 * a host under `.localhost` (the e2e cell).
 */
function bareOrigin(v: unknown, what: string, scheme: 'https:' | 'http:' | 'cell'): string {
  const s = str(v, what);
  const u = new URL(s);
  const schemeOk =
    scheme === 'cell'
      ? u.protocol === 'https:' || (u.protocol === 'http:' && isLocalhostName(u.hostname))
      : u.protocol === scheme;
  if (!schemeOk || u.origin !== s) {
    throw new StackMissing(`stack manifest: ${what} must be a bare ${scheme}// origin`);
  }
  return s;
}

function cellOf(v: unknown, name: string): CellEndpoints {
  if (typeof v !== 'object' || v === null) {
    throw new StackMissing(`stack manifest: cells.${name} is missing`);
  }
  const o = v as Record<string, unknown>;
  const origin = bareOrigin(o['origin'], `cells.${name}.origin`, 'cell');
  const vault = bareOrigin(o['vault_origin'], `cells.${name}.vault_origin`, 'cell');
  if (new URL(origin).protocol !== new URL(vault).protocol) {
    throw new StackMissing(`stack manifest: cells.${name} mixes http: and https: origins`);
  }
  const control = bareOrigin(o['control'], `cells.${name}.control`, 'http:');
  const cu = new URL(origin);
  const vu = new URL(vault);
  if (vu.hostname !== `id.${cu.hostname}` || vu.port !== cu.port) {
    throw new StackMissing(
      `stack manifest: cells.${name}.vault_origin must be id.<cell host> on the cell's port`,
    );
  }
  const ch = new URL(control).hostname;
  if (ch !== '127.0.0.1' && ch !== '[::1]') {
    throw new StackMissing(`stack manifest: cells.${name}.control must be loopback`);
  }
  return { origin, vault_origin: vault, control };
}

function readManifest(path: string): StackManifest {
  const raw: unknown = JSON.parse(readFileSync(path, 'utf8'));
  if (typeof raw !== 'object' || raw === null) {
    throw new StackMissing('stack manifest: not a JSON object');
  }
  const m = raw as Record<string, unknown>;
  if (m['version'] !== 1) {
    throw new StackMissing('stack manifest: version must be 1');
  }
  const cells = m['cells'];
  if (typeof cells !== 'object' || cells === null) {
    throw new StackMissing('stack manifest: cells is missing');
  }
  const c = cells as Record<string, unknown>;
  const a = cellOf(c['a'], 'a');
  const b = cellOf(c['b'], 'b');
  const plain = [a, b].every((x) => new URL(x.origin).protocol === 'http:');
  const mixed = !plain && [a, b].some((x) => new URL(x.origin).protocol === 'http:');
  if (mixed) {
    throw new StackMissing('stack manifest: the cells mix http: and https: origins');
  }
  const pins = m['spki_pins'];
  if (!Array.isArray(pins) || (pins.length === 0 && !plain)) {
    throw new StackMissing('stack manifest: spki_pins must list the served leaf SPKIs');
  }
  if (plain && pins.length !== 0) {
    throw new StackMissing('stack manifest: a plain loopback stack names no SPKI pin');
  }
  return {
    version: 1,
    cells: { a, b },
    resolver_rules: str(m['resolver_rules'], 'resolver_rules'),
    spki_pins: pins.map((p, i) => str(p, `spki_pins[${i}]`)),
  };
}

function manifestOrError(): StackManifest | StackMissing {
  const path = process.env[MANIFEST_ENV];
  if (path === undefined || path.length === 0) {
    return new StackMissing(
      `${MANIFEST_ENV} is not set. Run the M3 specs with ` +
        '`tools/devstack/run.sh e2e`, which starts `fstp-devstack e2e --manifest-out <file>` ' +
        `and sets ${MANIFEST_ENV}=<file>, and the other specs with \`tools/demo/run.sh e2e\`.`,
    );
  }
  try {
    return readManifest(path);
  } catch (e) {
    return e instanceof StackMissing
      ? e
      : new StackMissing(`stack manifest ${path} is unreadable: ${String(e)}`);
  }
}

const MANIFEST = manifestOrError();

/** The stack manifest. Throws [`StackMissing`] when there is none. */
export function stack(): StackManifest {
  if (MANIFEST instanceof StackMissing) {
    throw MANIFEST;
  }
  return MANIFEST;
}

function launchArgs(): string[] {
  if (MANIFEST instanceof StackMissing) {
    return [];
  }
  const args = [`--host-resolver-rules=${MANIFEST.resolver_rules}`];
  if (MANIFEST.spki_pins.length > 0) {
    args.push(`--ignore-certificate-errors-spki-list=${MANIFEST.spki_pins.join(',')}`);
  }
  return args;
}

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/**
 * The M3 browser specs of design section 14.7, at the root of `e2e/`.
 * They run against `fstp-devstack e2e` only (project `devstack`).
 */
const DEVSTACK_SPECS =
  /(^|[\\/])(i17-vault-origin-release|i20-passkey-not-offered-across-tenants|i77-management-login|r_lg_03_committee_grant_and_add_passkey_need_stepup|r-lg-04-sessions|r-nf-03-auth-and-vault-pages)\.spec\.ts$/;

/** The Playwright project of the M3 browser specs, which run against `fstp-devstack e2e`. */
export const DEVSTACK_PROJECT = 'devstack';

export default defineConfig({
  testDir: '.',
  testMatch: /.*\.spec\.ts$/,
  // The specs reset shared cells, so they run one at a time.
  fullyParallel: false,
  workers: 1,
  // Invariant journeys: a flaky pass is not a pass (M4 design section 8.7).
  retries: 0,
  forbidOnly: true,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [['list']],
  outputDir: 'test-results',
  use: {
    browserName: 'chromium',
    headless: true,
    launchOptions: { args: launchArgs() },
    trace: 'off',
    video: 'off',
    screenshot: 'off',
    serviceWorkers: 'block',
  },
  // Two stacks, one project each. `devstack` holds the M3 browser specs
  // of design section 14.7, which need the real cell of `fstp-devstack
  // e2e` (`tools/devstack/run.sh e2e`). `demo` holds every other spec,
  // which runs against `fstp-e2e-cell` (`tools/demo/run.sh e2e`).
  projects: [
    { name: DEVSTACK_PROJECT, testMatch: DEVSTACK_SPECS, use: { browserName: 'chromium' } },
    { name: 'demo', testIgnore: DEVSTACK_SPECS, use: { browserName: 'chromium' } },
  ],
});

// ---------------------------------------------------------------------------
// Constants of the specification
// ---------------------------------------------------------------------------

/** P-71, the step-up freshness, in microseconds: 5 minutes (proposed). */
export const P71_MICROS = 300_000_000;

/** The session cookie name (design section 8.2, ADR-008 Sessions). */
export const SESSION_COOKIE = '__Host-fstp';

/**
 * The pages on the cell origin (design section 11.2, `web/src/auth`).
 * Design section 8.7 lists the API routes only, plus the magic-link
 * confirm page. `GET /auth/sessions` is the JSON route of R-LG-04, so the
 * sessions and devices page is `/auth/account`.
 *
 * - Every sign-in and enrolment ends on the home page `/app/` (interim,
 *   pending Daniel: design section 15.0 row of 2026-10-31, after Daniel
 *   reported that the account page led nowhere). A login page opened
 *   with a safe `?next=/app/...` ends on that page instead. The home
 *   page links to the account page through `nav a[data-nav="account"]`.
 * - The account page sends a browser without a session to the login page.
 * - Tokens in links travel in the fragment, never in the query.
 * - Each high-risk action on a page opens the modal `dialog#stepup`. Its
 *   confirm button runs the step-up, and Escape closes it.
 * - A refusal shows an element with `role="alert"`.
 */
export const PAGES = {
  login: '/auth/login',
  signup: '/auth/signup',
  invite: '/auth/invite',
  magic: '/auth/magic',
  recovery: '/auth/recovery',
  account: '/auth/account',
} as const;

/** The vault origin pages (design section 6.5, ADR-009, `web/src/vault`). */
export const VAULT_PAGES = { write: '/w', release: '/r' } as const;

/**
 * Element ids of the page contract with the page agent of lane W3c. Each
 * control also has an accessible name from the message catalogue, which
 * `r-nf-03-auth-and-vault-pages.spec.ts` checks.
 */
export const UI = {
  login: {
    passkey: '#passkey-login',
    email: '#magic-email',
    magic: '#magic-request',
    status: '#magic-status',
    error: '#login-error',
  },
  magic: { confirm: '#magic-confirm' },
  invite: { register: '#invite-register' },
  signup: {
    email: '#signup-email',
    submit: '#signup-submit',
    status: '#signup-status',
    register: '#signup-register',
  },
  recovery: { email: '#recovery-email', submit: '#recovery-submit' },
  account: {
    sessions: '#sessions-list',
    devices: '#devices-list',
    addPasskey: '#passkey-add',
  },
  stepup: { dialog: '#stepup', confirm: '#stepup-confirm' },
} as const;

// ---------------------------------------------------------------------------
// Small values
// ---------------------------------------------------------------------------

/** `n` random bytes in lowercase hex. */
export function randomHex(n: number): string {
  const b = new Uint8Array(n);
  globalThis.crypto.getRandomValues(b);
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** A synthetic login email under the reserved `.invalid` domain. */
export function syntheticEmail(tag: string): string {
  return `synthetic-${tag}-${randomHex(6)}@e2e.invalid`;
}

/** The host of an origin. */
export function hostOf(origin: string): string {
  return new URL(origin).hostname;
}

/** The parent domain of a host: the host without its first label. */
export function parentOf(host: string): string {
  const i = host.indexOf('.');
  return i < 0 ? '' : host.slice(i + 1);
}

/** Base64url of standard base64, without padding. */
export function b64url(s: string): string {
  return s.replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

// ---------------------------------------------------------------------------
// Devstack control (test only, loopback)
// ---------------------------------------------------------------------------

/** What `POST /test/reset` returns: the cell at first start. */
export interface FreshCell {
  /** The first tenant admin's invitation, `<origin>/auth/invite#<token>`. */
  readonly first_admin: { readonly url: string; readonly email: string };
}

/** One message the devstack captured from the cell's outbox. */
export interface Mail {
  readonly kind: 'magic' | 'signup' | 'recovery';
  readonly link: string;
}

/** What `POST /test/scenario/negotiation` seeds and returns. */
export interface NegotiationScenario {
  readonly programme: string;
  /** A proposal in NEGOTIATION, with the vault's negotiation fact pushed. */
  readonly proposal: string;
  /** Its lead applicant, whose verification and country the vault holds. */
  readonly subject: string;
  /** A proposal of the same programme in RANKED, before negotiation. */
  readonly ranked_proposal: string;
  readonly ranked_subject: string;
  /** An invitation for an Operations role holder of the programme. */
  readonly operations: { readonly invite_url: string };
  /** An invitation for a Judging role holder of the programme. */
  readonly judging: { readonly invite_url: string };
  /**
   * Canary strings that the vault shows in the subject's release and that
   * appear nowhere else in the stack.
   */
  readonly released: readonly string[];
}

/** A command the devstack built, with the ids it creates. */
export interface BuiltCommand {
  readonly command: unknown;
  readonly ids: Readonly<Record<string, string>>;
}

async function json(r: APIResponse, what: string): Promise<unknown> {
  if (!r.ok()) {
    throw new StackMissing(`devstack control ${what} answered ${r.status()}`);
  }
  return r.json();
}

/**
 * The devstack control routes of one cell. Test only: they exist in
 * `fstp-devstack` (`fstp-celltest`, layering rule 9) and never in the
 * shipped `fstp-cell`.
 */
export class Control {
  constructor(
    private readonly request: APIRequestContext,
    readonly cell: CellEndpoints,
  ) {}

  private url(path: string): string {
    return `${this.cell.control}${path}`;
  }

  /** `POST /test/reset`: fresh databases, keys and first-admin token. */
  async reset(): Promise<FreshCell> {
    const v = (await json(await this.request.post(this.url('/test/reset')), 'reset')) as FreshCell;
    expect(new URL(v.first_admin.url).origin).toBe(this.cell.origin);
    return v;
  }

  /** `GET /test/mailbox?to=`: every outbox message to `to`, oldest first. */
  async mailbox(to: string): Promise<Mail[]> {
    const r = await this.request.get(this.url('/test/mailbox'), { params: { to } });
    return ((await json(r, 'mailbox')) as { messages: Mail[] }).messages;
  }

  /** The newest message of `kind` to `to`. Fails when there is none. */
  async newest(to: string, kind: Mail['kind']): Promise<Mail> {
    const all = (await this.mailbox(to)).filter((m) => m.kind === kind);
    const last = all[all.length - 1];
    if (last === undefined) {
      throw new Error(`no ${kind} message to ${to}`);
    }
    return last;
  }

  /**
   * `POST /test/clock/advance`: moves the cell's test clock forward. The
   * test clock moves only through this route, so an action admitted and
   * committed between two calls sees one instant.
   */
  async advanceClock(micros: number): Promise<void> {
    await json(
      await this.request.post(this.url('/test/clock/advance'), {
        data: { micros: String(micros) },
      }),
      'clock',
    );
  }

  /**
   * `POST /test/commands/{kind}`: a valid command JSON with fresh ids,
   * built by the devstack so the specs never spell a policy. The command
   * is only built here. The spec sends it through the real routes. `ids`
   * names the ids the command creates, such as `programme`.
   *
   * Kinds the specs use: `CreateProgramme {}`, `GrantRole {programme,
   * account, role}` with an M2 role name, and `SetLoginPolicy
   * {magic_links}` (P-70, a strict addition of design section 8.4).
   */
  async command(kind: string, params: Record<string, string> = {}): Promise<BuiltCommand> {
    const r = await this.request.post(this.url(`/test/commands/${kind}`), { data: params });
    const v = (await json(r, `command ${kind}`)) as Partial<BuiltCommand>;
    if (v.command === undefined || typeof v.ids !== 'object' || v.ids === null) {
      throw new StackMissing(`devstack control command ${kind}: expected {command, ids}`);
    }
    return { command: v.command, ids: v.ids };
  }

  /** `GET /test/account?email=`: the account id with that login email. */
  async account(email: string): Promise<string> {
    const r = await this.request.get(this.url('/test/account'), { params: { email } });
    return ((await json(r, 'account')) as { account: string }).account;
  }

  /** `POST /test/scenario/negotiation` (design section 6.9 seeding). */
  async negotiation(): Promise<NegotiationScenario> {
    const r = await this.request.post(this.url('/test/scenario/negotiation'));
    return (await json(r, 'scenario negotiation')) as NegotiationScenario;
  }

  /**
   * `POST /test/vault-tickets/write`: a write ticket of `kind` for a test
   * account, as `<vault origin>/w#<ticket>`. Used only to reach the write
   * page for its accessibility checks.
   */
  async writeTicketUrl(kind: string): Promise<string> {
    const r = await this.request.post(this.url('/test/vault-tickets/write'), { data: { kind } });
    return ((await json(r, 'write ticket')) as { url: string }).url;
  }
}

// ---------------------------------------------------------------------------
// Chromium virtual authenticator over CDP
// ---------------------------------------------------------------------------

/** A credential of the virtual authenticator, as CDP reports it. */
export interface VirtualCredential {
  readonly credentialId: string;
  readonly isResidentCredential: boolean;
  readonly rpId?: string;
  readonly privateKey: string;
  readonly userHandle?: string;
  readonly signCount: number;
}

/** Options of a virtual authenticator. */
export interface AuthenticatorOptions {
  /** Whether the authenticator can verify the user at all. */
  readonly hasUserVerification?: boolean;
  /** Whether verification succeeds. */
  readonly isUserVerified?: boolean;
  /**
   * `internal` for the platform authenticator, `usb` for a security key.
   * Chromium allows one internal authenticator per page, so a second
   * device on the same page is a security key.
   */
  readonly transport?: 'internal' | 'usb';
}

const WEBAUTHN_SESSIONS = new WeakMap<Page, Promise<CDPSession>>();

/**
 * The one CDP session of a page, with the WebAuthn domain enabled. Specs
 * that need other CDP domains use this session too: a second session
 * that detaches can take the virtual authenticators with it.
 */
export function pageCdp(page: Page): Promise<CDPSession> {
  let s = WEBAUTHN_SESSIONS.get(page);
  if (s === undefined) {
    s = page
      .context()
      .newCDPSession(page)
      .then(async (cdp) => {
        await cdp.send('WebAuthn.enable', { enableUI: false });
        return cdp;
      });
    WEBAUTHN_SESSIONS.set(page, s);
  }
  return s;
}

/** One CTAP2 authenticator with resident keys, attached to a page. */
export class VirtualAuthenticator {
  private constructor(
    readonly cdp: CDPSession,
    readonly id: string,
  ) {}

  static async attach(page: Page, o: AuthenticatorOptions = {}): Promise<VirtualAuthenticator> {
    const cdp = await pageCdp(page);
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        transport: o.transport ?? 'internal',
        hasResidentKey: true,
        hasUserVerification: o.hasUserVerification ?? true,
        isUserVerified: o.isUserVerified ?? true,
        automaticPresenceSimulation: true,
      },
    });
    return new VirtualAuthenticator(cdp, authenticatorId);
  }

  async credentials(): Promise<VirtualCredential[]> {
    const r = await this.cdp.send('WebAuthn.getCredentials', { authenticatorId: this.id });
    return r.credentials as VirtualCredential[];
  }

  async setUserVerified(v: boolean): Promise<void> {
    await this.cdp.send('WebAuthn.setUserVerified', {
      authenticatorId: this.id,
      isUserVerified: v,
    });
  }

  /**
   * Makes the authenticator clear the UV flag in every response, even
   * when the request requires UV: a modified client or authenticator.
   */
  async setBadUserVerification(bad: boolean): Promise<void> {
    await this.cdp.send('WebAuthn.setResponseOverrideBits', {
      authenticatorId: this.id,
      isBadUV: bad,
    });
  }

  /** Copies a credential in, as a passkey synced to another device. */
  async add(c: VirtualCredential): Promise<void> {
    const credential: {
      credentialId: string;
      isResidentCredential: boolean;
      privateKey: string;
      signCount: number;
      rpId?: string;
      userHandle?: string;
    } = {
      credentialId: c.credentialId,
      isResidentCredential: c.isResidentCredential,
      privateKey: c.privateKey,
      signCount: c.signCount,
    };
    if (c.rpId !== undefined) credential.rpId = c.rpId;
    if (c.userHandle !== undefined) credential.userHandle = c.userHandle;
    await this.cdp.send('WebAuthn.addCredential', { authenticatorId: this.id, credential });
  }
}

// ---------------------------------------------------------------------------
// Cell API calls from inside a page (same origin, session cookie, Origin)
// ---------------------------------------------------------------------------

/** The status and body of one call. */
export interface Answer {
  readonly status: number;
  readonly body: string;
}

/**
 * The RFC 8785 canonical text of `v`, as `web/src/auth/encoding.ts`
 * writes it. The cell refuses any body that is not byte-equal to its
 * canonical text (`fstp-cell` `http::body::object`). Members are sorted
 * by UTF-16 code units at every depth, with no white space. Only strings,
 * booleans, null, safe integers, arrays and objects are written, so no
 * float is ever sent. A member whose value is undefined is left out.
 */
export function canonicalJson(v: unknown): string {
  if (v === null || typeof v === 'boolean' || typeof v === 'string') {
    return JSON.stringify(v);
  }
  if (typeof v === 'number') {
    if (!Number.isSafeInteger(v)) {
      throw new Error('canonical JSON: only safe integers are sent');
    }
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) {
    return `[${v.map(canonicalJson).join(',')}]`;
  }
  if (typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const parts: string[] = [];
    for (const k of Object.keys(o).sort()) {
      if (o[k] !== undefined) {
        parts.push(`${JSON.stringify(k)}:${canonicalJson(o[k])}`);
      }
    }
    return `{${parts.join(',')}}`;
  }
  throw new Error(`canonical JSON: a ${typeof v} is not sent`);
}

/**
 * One same-origin call from `page`, which must show a page of `origin`.
 * The browser adds the session cookie and the `Origin` header, as for the
 * pages' own calls. State-changing calls send canonical JSON (design
 * section 8.2), the one body form the cell takes.
 */
export async function call(
  page: Page,
  origin: string,
  method: 'GET' | 'POST' | 'DELETE',
  path: string,
  body?: unknown,
): Promise<Answer> {
  expect(new URL(page.url()).origin, 'the call must start on the cell origin').toBe(origin);
  return page.evaluate(
    async ([m, p, b]) => {
      const init: RequestInit = { method: m, credentials: 'same-origin' };
      if (b !== undefined) {
        init.headers = { 'content-type': 'application/json', 'x-fstp-request': '1' };
        init.body = b;
      } else if (m !== 'GET') {
        init.headers = { 'x-fstp-request': '1' };
      }
      const r = await fetch(p, init);
      return { status: r.status, body: await r.text() };
    },
    [method, path, body === undefined ? undefined : canonicalJson(body)] as const,
  );
}

/** Whether the page's session cookie is admitted: `GET /auth/sessions`. */
export async function sessionStatus(page: Page, origin: string): Promise<number> {
  return (await call(page, origin, 'GET', '/auth/sessions')).status;
}

/** The parsed JSON body of a 2xx answer. */
export function okJson(a: Answer, what: string): Record<string, unknown> {
  expect(a.status, `${what}: ${a.body}`).toBeGreaterThanOrEqual(200);
  expect(a.status, `${what}: ${a.body}`).toBeLessThan(300);
  return JSON.parse(a.body) as Record<string, unknown>;
}

/** Lowercase hex of the unpadded base64url string `s`. */
export function base64urlHex(s: unknown, what: string): string {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error(`${what} must be base64url`);
  }
  return Buffer.from(s, 'base64url').toString('hex');
}

/** `v` as a plain object, or a failure that names `what`. */
function objectOf(v: unknown, what: string): Record<string, unknown> {
  if (typeof v !== 'object' || v === null || Array.isArray(v)) {
    throw new Error(`${what} must be a JSON object`);
  }
  return v as Record<string, unknown>;
}

/** A challenge id and its WebAuthn options, from a cell options reply. */
export interface CellOptions {
  readonly challenge_id: string;
  readonly public_key: Record<string, unknown>;
}

/**
 * Reads `{challenge_id, public_key}`, the options reply of the cell's
 * ceremony and step-up routes (`fstp-cell` `routes::auth`). The
 * `public_key` member is in the WebAuthn JSON form.
 */
export function cellOptions(o: Record<string, unknown>, what: string): CellOptions {
  const challenge_id = o['challenge_id'];
  if (typeof challenge_id !== 'string' || !/^[0-9a-f]{32}$/.test(challenge_id)) {
    throw new Error(`${what}: \`challenge_id\` must be 16 bytes of lowercase hex`);
  }
  return { challenge_id, public_key: objectOf(o['public_key'], `${what}: public_key`) };
}

/**
 * The hex members of an assertion, as the cell's assertion bodies name
 * them (`fstp-cell` `routes::auth` `ASSERTION_MEMBERS`).
 */
export interface AssertionMembers {
  readonly authenticator_data: string;
  readonly client_data_json: string;
  readonly credential_id: string;
  readonly signature: string;
}

/** A passkey assertion inside the page for request options in JSON. */
export async function assertIn(page: Page, publicKey: unknown): Promise<AssertionMembers> {
  const j = objectOf(
    await page.evaluate(async (pk) => {
      const options = PublicKeyCredential.parseRequestOptionsFromJSON(
        pk as PublicKeyCredentialRequestOptionsJSON,
      );
      const c = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential;
      return c.toJSON() as unknown;
    }, publicKey),
    'assertion',
  );
  const r = objectOf(j['response'], 'assertion response');
  return {
    authenticator_data: base64urlHex(r['authenticatorData'], 'authenticatorData'),
    client_data_json: base64urlHex(r['clientDataJSON'], 'clientDataJSON'),
    credential_id: base64urlHex(j['rawId'], 'rawId'),
    signature: base64urlHex(r['signature'], 'signature'),
  };
}

/**
 * The hex members of a new credential, as the account page sends them
 * (`web/src/auth/webauthn.ts` `RegistrationBody`).
 */
export interface RegistrationMembers {
  readonly attestation_object: string;
  readonly client_data_json: string;
  readonly credential_id: string;
}

/** A new passkey inside the page for creation options in JSON. */
export async function createIn(page: Page, publicKey: unknown): Promise<RegistrationMembers> {
  const j = objectOf(
    await page.evaluate(async (pk) => {
      const options = PublicKeyCredential.parseCreationOptionsFromJSON(
        pk as PublicKeyCredentialCreationOptionsJSON,
      );
      const c = (await navigator.credentials.create({ publicKey: options })) as PublicKeyCredential;
      return c.toJSON() as unknown;
    }, publicKey),
    'registration',
  );
  const r = objectOf(j['response'], 'registration response');
  return {
    attestation_object: base64urlHex(r['attestationObject'], 'attestationObject'),
    client_data_json: base64urlHex(r['clientDataJSON'], 'clientDataJSON'),
    credential_id: base64urlHex(j['rawId'], 'rawId'),
  };
}

/** A granted step-up: its id, for the one action it authorises. */
export interface StepUp {
  readonly stepup: string;
  readonly command_id: string;
}

/**
 * A step-up for `command` with the given `command_id` (design section
 * 8.4), on the wire of `fstp-cell` `routes::auth` and as the pages'
 * `web/src/auth/stepup.ts` runs it:
 *
 * 1. `POST /auth/stepup/options {command, command_id}` answers
 *    `{challenge_id, public_key}`.
 * 2. A passkey assertion with UV in the page over that challenge.
 * 3. `POST /auth/stepup` with the assertion's hex members
 *    `authenticator_data`, `client_data_json`, `credential_id` and
 *    `signature`, plus `challenge_id`.
 *
 * The step-up id is the challenge id, as the cell keys it. A grant reply
 * that names its own `stepup` id is used instead, as the pages do.
 */
export async function stepUp(
  page: Page,
  origin: string,
  command: unknown,
  command_id: string = randomHex(16),
): Promise<StepUp> {
  const o = cellOptions(
    okJson(
      await call(page, origin, 'POST', '/auth/stepup/options', { command, command_id }),
      'step-up options',
    ),
    'step-up options',
  );
  const assertion = await assertIn(page, o.public_key);
  const g = okJson(
    await call(page, origin, 'POST', '/auth/stepup', {
      ...assertion,
      challenge_id: o.challenge_id,
    }),
    'step-up',
  );
  const named = g['stepup'];
  const stepup =
    typeof named === 'string' && /^[0-9a-f]{32}$/.test(named) ? named : o.challenge_id;
  return { stepup, command_id };
}

/**
 * The action a step-up names for a high-risk route that takes no domain
 * command (design section 8.7): adding a passkey, or removing a device.
 * Assumed shapes, pending lanes w3ar and w3ae.
 */
export const ROUTE_ACTIONS = {
  addPasskey: { type: 'AddPasskey' },
  removeDevice: (device: string) => ({ type: 'ChangeLoginMethods', device }),
} as const;

/**
 * `POST /api/v1/commands {command, command_id, stepup?}`. Without a
 * `stepup` the member is left out, since the cell takes `stepup` as an
 * optional hex member and refuses `null`.
 */
export async function sendCommand(
  page: Page,
  origin: string,
  command: unknown,
  s: { readonly command_id: string; readonly stepup?: string },
): Promise<Answer> {
  return call(page, origin, 'POST', '/api/v1/commands', {
    command,
    command_id: s.command_id,
    ...(s.stepup === undefined ? {} : { stepup: s.stepup }),
  });
}

/**
 * The body of a release ticket request, `POST /api/v1/vault-tickets
 * {command_id, kind, proposal}` (`fstp-cell` `routes::api`). The cell
 * takes the subject from the proposal, so the body never names one.
 */
export function releaseTicketBody(proposal: string): Record<string, string> {
  return { command_id: randomHex(16), kind: 'release', proposal };
}

/** A command sent with a fresh step-up of its own. Must be accepted. */
export async function runHighRisk(page: Page, origin: string, command: unknown): Promise<void> {
  const s = await stepUp(page, origin, command);
  okJson(await sendCommand(page, origin, command, s), 'high-risk command');
}

// ---------------------------------------------------------------------------
// Page flows (the page contract above)
// ---------------------------------------------------------------------------

/**
 * Opens a link as a click in a mail client does: a full load, even when
 * the page already shows the same path with another fragment.
 */
export async function openLink(page: Page, url: string): Promise<void> {
  await page.goto('about:blank');
  await page.goto(url);
}

/**
 * Attaches a security key to `page` just before the page asks for passkey
 * creation options, so the new passkey has a device that does not hold
 * the enrolled one. Chromium allows one platform authenticator per page,
 * and an empty second authenticator breaks the step-up assertion that
 * comes first. `key` resolves once the key is attached.
 */
export async function keyForNextPasskey(
  page: Page,
): Promise<{ readonly key: Promise<VirtualAuthenticator> }> {
  let attached: (a: VirtualAuthenticator) => void = () => undefined;
  const key = new Promise<VirtualAuthenticator>((resolve) => {
    attached = resolve;
  });
  await page.route(
    '**/auth/passkeys/options',
    async (route) => {
      attached(await VirtualAuthenticator.attach(page, { transport: 'usb' }));
      await route.continue();
    },
    { times: 1 },
  );
  return { key };
}

/** Whether `u` is the account page of `origin`. */
export function isAccountPage(u: URL, origin: string): boolean {
  return u.origin === origin && u.pathname === PAGES.account;
}

/** The home page on the cell origin, where every sign-in lands on the demo cell (interim, design section 15.0). */
export const HOME_PAGE = '/app/';

/** Whether `u` is the home page of `origin`. */
export function isHomePage(u: URL, origin: string): boolean {
  return u.origin === origin && u.pathname === HOME_PAGE;
}

/**
 * The page a sign-in lands on in the running project. The M3 cell serves
 * the auth pages only and no `/app/` page, so on it every sign-in lands
 * on the account page (Daniel, 2026-11-13, M3 exit audit section 7, item
 * 9). Its shell names that landing (`web/src/auth/next.ts`). The demo
 * cell lands on the home page.
 */
export function landingPage(): string {
  return base.info().project.name === DEVSTACK_PROJECT ? PAGES.account : HOME_PAGE;
}

/** Whether `u` is the landing page of `origin` in the running project ([`landingPage`]). */
export function isLandingPage(u: URL, origin: string): boolean {
  return u.origin === origin && u.pathname === landingPage();
}

/** The most Tab presses `expectSignedIn` makes to reach the Account link. */
const MAX_TABS_TO_ACCOUNT = 40;

/**
 * Waits until the page shows the landing of `origin` after a sign-in
 * ([`landingPage`]) and ends on the account page, signed in. So a caller
 * goes on from the account page in either project.
 *
 * On the M3 stack the landing is the account page itself (Daniel,
 * 2026-11-13, M3 exit audit section 7, item 9).
 *
 * On the demo cell the landing is the home page (interim, design section
 * 15.0 of 2026-10-31). R-NF-03 (review finding F1): the Account link is
 * then reached by Tab and opened with Enter, never with a pointer. So the
 * keyboard flow of `r_nf_03_flows_complete_by_keyboard_alone` stays
 * keyboard only: home, then Account, by keyboard. It also checks that a
 * keyboard user can reach the account page from the home landing.
 */
export async function expectSignedIn(page: Page, origin: string): Promise<void> {
  await expect(page).toHaveURL((u) => isLandingPage(u, origin));
  if (landingPage() === HOME_PAGE) {
    await expect(page.locator('main #home')).toBeVisible();
    // The home page has loaded, so the shell has filled the navigation.
    await expect(page.locator('main [aria-busy="true"]')).toHaveCount(0);
    const account = page.locator('nav a[data-nav="account"]').first();
    await expect(account).toBeVisible();
    let focused = false;
    for (let i = 0; i < MAX_TABS_TO_ACCOUNT && !focused; i += 1) {
      await page.keyboard.press('Tab');
      focused = await page.evaluate(() => document.activeElement?.matches('nav a[data-nav="account"]') === true);
    }
    expect(focused, `R-NF-03: the Account link is reachable by Tab within ${MAX_TABS_TO_ACCOUNT} presses`).toBe(true);
    await page.keyboard.press('Enter');
  }
  await expect(page).toHaveURL((u) => isAccountPage(u, origin));
  await expect(page.locator(UI.account.sessions)).toBeVisible();
  expect(await sessionStatus(page, origin)).toBe(200);
}

/**
 * Waits for the outcome of a sign-in step: the landing page (true) or a
 * visible alert (false). Neither within the timeout fails the test.
 */
export async function signInOutcome(page: Page, origin: string): Promise<boolean> {
  const ok = page.waitForURL((u) => isLandingPage(u, origin)).then(
    () => true,
    () => null,
  );
  const refused = page
    .getByRole('alert')
    .first()
    .waitFor({ state: 'visible' })
    .then(
      () => false,
      () => null,
    );
  const r = await Promise.race([ok, refused]);
  if (r === null) {
    throw new Error('the page showed neither the landing page nor an alert');
  }
  if (r) {
    await expectSignedIn(page, origin);
  }
  return r;
}

/** Enrols a passkey through an invitation link (design section 8.3). */
export async function enrolByInvite(page: Page, origin: string, url: string): Promise<void> {
  const u = new URL(url);
  expect(u.origin).toBe(origin);
  expect(u.pathname).toBe(PAGES.invite);
  expect(u.search, 'no token in the query string').toBe('');
  expect(u.hash.length, 'the invitation token travels in the fragment').toBeGreaterThan(1);
  await openLink(page, url);
  await page.locator(UI.invite.register).click();
  await expectSignedInAfterInvite(page, origin);
}

/**
 * Waits until an invitation enrolment on `origin` has signed the person
 * in, then goes on as [`expectSignedIn`].
 *
 * On the M3 stack the invitation enrols the passkey and opens no session
 * (`fstp_cell::routes::auth::invitation_register`). So the page lands on
 * the account page, which sends the browser to the login page, and the
 * person signs in there with the new passkey (`tools/devstack/run.sh`,
 * "Logging in through a browser"; Daniel, 2026-11-13, M3 exit audit
 * section 7, item 9). The sign-in button is reached by Tab and pressed
 * with Enter, so a keyboard-only flow stays keyboard only (R-NF-03).
 */
export async function expectSignedInAfterInvite(page: Page, origin: string): Promise<void> {
  if (landingPage() === PAGES.account) {
    await expect(page).toHaveURL((u) => u.origin === origin && u.pathname === PAGES.login);
    const button = page.locator(UI.login.passkey);
    await expect(button).toBeVisible();
    let focused = false;
    for (let i = 0; i < MAX_TABS_TO_ACCOUNT && !focused; i += 1) {
      await page.keyboard.press('Tab');
      focused = await page.evaluate((s) => document.activeElement?.matches(s) === true, UI.login.passkey);
    }
    expect(focused, `R-NF-03: the passkey sign-in is reachable by Tab within ${MAX_TABS_TO_ACCOUNT} presses`).toBe(true);
    await page.keyboard.press('Enter');
  }
  await expectSignedIn(page, origin);
}

/** A passkey login on the login page. Returns whether it signed in. */
export async function passkeyLogin(page: Page, origin: string): Promise<boolean> {
  await page.goto(`${origin}${PAGES.login}`);
  await page.locator(UI.login.passkey).click();
  return signInOutcome(page, origin);
}

/** Requests a magic link on the login page. Returns the status text. */
export async function requestMagic(page: Page, origin: string, email: string): Promise<string> {
  await page.goto(`${origin}${PAGES.login}`);
  await page.locator(UI.login.email).fill(email);
  await page.locator(UI.login.magic).click();
  const status = page.locator(UI.login.status);
  await expect(status).toBeVisible();
  await expect(status).not.toHaveText('');
  return (await status.innerText()).trim();
}

/** Opens a magic link and confirms it. Returns whether it signed in. */
export async function consumeMagic(page: Page, origin: string, link: string): Promise<boolean> {
  const u = new URL(link);
  expect(u.origin).toBe(origin);
  expect(u.pathname).toBe(PAGES.magic);
  await openLink(page, link);
  await page.locator(UI.magic.confirm).click();
  return signInOutcome(page, origin);
}

/**
 * Self-registration of a Receiving account (design section 8.3, item 2):
 * email proof, then a passkey in the same ceremony.
 */
export async function signUp(
  page: Page,
  control: Control,
  origin: string,
  email: string,
): Promise<void> {
  await page.goto(`${origin}${PAGES.signup}`);
  await page.locator(UI.signup.email).fill(email);
  await page.locator(UI.signup.submit).click();
  await expect(page.locator(UI.signup.status)).toBeVisible();
  const proof = await control.newest(email, 'signup');
  expect(new URL(proof.link).origin).toBe(origin);
  await openLink(page, proof.link);
  await page.locator(UI.signup.register).click();
  await expectSignedIn(page, origin);
}

/** Completes the step-up dialog the page opened for a high-risk action. */
export async function confirmStepUp(page: Page): Promise<void> {
  const dialog = page.locator(UI.stepup.dialog);
  await expect(dialog).toBeVisible();
  await page.locator(UI.stepup.confirm).click();
  await expect(dialog).toBeHidden();
}

// ---------------------------------------------------------------------------
// Tenant set-up through the real routes
// ---------------------------------------------------------------------------

/**
 * Enables magic links for the tenant (P-70) through `SetLoginPolicy`, a
 * high-risk action with its own step-up, in the admin's `page`.
 */
export async function enableMagicLinks(page: Page, control: Control): Promise<void> {
  const c = await control.command('SetLoginPolicy', { magic_links: 'enabled' });
  await runHighRisk(page, control.cell.origin, c.command);
}

/** Creates a programme (high risk, design section 8.4). Returns its id. */
export async function createProgramme(page: Page, control: Control): Promise<string> {
  const c = await control.command('CreateProgramme');
  const programme = c.ids['programme'];
  if (programme === undefined) {
    throw new StackMissing('devstack control command CreateProgramme: no programme id');
  }
  await runHighRisk(page, control.cell.origin, c.command);
  return programme;
}

/** Copies every credential of `from` into a new authenticator on `page`. */
export async function syncedAuthenticator(
  page: Page,
  from: VirtualAuthenticator,
  o: AuthenticatorOptions = {},
): Promise<VirtualAuthenticator> {
  const to = await VirtualAuthenticator.attach(page, o);
  for (const c of await from.credentials()) {
    await to.add(c);
  }
  return to;
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/**
 * The specs' `test`. `person()` opens a page in a new browser context: a
 * separate person or device with its own cookies. Every context closes
 * when the test ends.
 */
export const test = base.extend<{ person: () => Promise<Page> }>({
  person: async ({ browser }, use) => {
    const contexts: BrowserContext[] = [];
    await use(async () => {
      const c = await browser.newContext();
      contexts.push(c);
      return c.newPage();
    });
    for (const c of contexts) {
      await c.close();
    }
  },
});
