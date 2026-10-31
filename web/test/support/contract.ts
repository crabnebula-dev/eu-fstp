// The API the W1c tests expect from web/src/core/*.ts and web/src/gen/api.ts.
//
// W0 left no stub below web/src/core, so the test author states the API
// here, from M4 design section 3.9 and ADR-014. Where the design names a
// function (`h`, `safeUrl`), the name is the design's. Every other name and
// shape is the test author's reading. Interim, pending Daniel. The
// implementer may widen parameter types; the module interfaces use method
// syntax, so a narrower parameter type in the implementation still
// conforms. web/test/conformance checks the implementation against these
// types with tsc.
//
// The tests load each module through support/load.ts, so they compile and
// run red while a module is missing.

// ---------------------------------------------------------------- money.ts

/** The currencies ADR-006 fixes a scale for. EUR has two minor digits. */
export type Currency = "EUR";

/**
 * Why a text is not an ADR-006 amount. The first five mirror
 * `fstp_money::AmountParseErrorKind`, decided in the same order as
 * `fstp_money::decimal::parse_fixed`:
 * 1. `Empty`: the text is empty.
 * 2. `UnexpectedByte`: the first character is not an ASCII digit.
 * 3. `LeadingZero`: a `0` followed by another integer digit.
 * 4. `WrongScale`: nothing after the integer digits; or more than the
 *    scale of fraction digits; or fewer, at the end of the text.
 * 5. `UnexpectedByte`: something other than `.` after the integer digits;
 *    or fewer fraction digits than the scale, followed by more text; or
 *    text after the fraction digits.
 * 6. `OutOfRange`: canonical, but above 999999999999999999 minor units.
 * `NotAString` covers a JSON number or any other non-string value, and
 * `UnknownCurrency` a currency other than EUR.
 */
export type MoneyErrorKind =
  | "NotAString"
  | "UnknownCurrency"
  | "Empty"
  | "UnexpectedByte"
  | "LeadingZero"
  | "WrongScale"
  | "OutOfRange";

/** An ADR-006 amount. It holds the canonical string and no number. */
export interface Amount {
  readonly currency: Currency;
  readonly text: string;
}

/** The outcome of reading an amount. Never thrown. */
export type MoneyResult =
  | { readonly ok: true; readonly amount: Amount }
  | { readonly ok: false; readonly kind: MoneyErrorKind };

/**
 * money.ts: ADR-006 strings only. The browser never computes money, so the
 * module has no arithmetic.
 */
export interface MoneyModule {
  /** Reads any value. Any other spelling is refused, never normalised. Never throws. */
  parseAmount(input: unknown, currency: Currency): MoneyResult;
  /** The canonical text, byte for byte what was parsed. */
  amountText(amount: Amount): string;
}

// ------------------------------------------------------------------ dom.ts

/** An attribute value. `true` sets an empty attribute; `false` omits it. */
export type AttrValue = string | boolean;

/** A child of `h`: a node, or a string that becomes a text node. */
export type Child = Node | string;

/** Why `h` refused. */
export type DomRefusalCode = "tag" | "attribute" | "url" | "child";

/** The error `h` throws. */
export interface DomRefusalLike extends Error {
  readonly code: DomRefusalCode;
}

/**
 * dom.ts. `h` builds elements through `document.createElement`,
 * `setAttribute` and text nodes only. Strings never reach an HTML parser.
 * Tags and attributes outside the allowlists are refused. Every `on*`
 * attribute and `style` are refused, in any case. `href`, `src` and
 * `action` values pass through `safeUrl`, and an unsafe one is refused.
 */
export interface DomModule {
  h(tag: string, attrs?: Readonly<Record<string, AttrValue>>, children?: readonly Child[]): HTMLElement;
  /**
   * The input itself when it is a same-origin path or an `https:` URL,
   * else null. Never normalises and never throws. Interim grammar, pending
   * Daniel and the `fstp-oauth` URL subset (W1e):
   * - printable ASCII only (0x21 to 0x7E), and no backslash;
   * - each `%` followed by two hex digits;
   * - a path starts with `/` and its second character is not `/`;
   * - an `https:` URL starts with exactly `https://`, then a host of
   *   lower-case LDH labels separated by dots, an optional `:` and 1 to 5
   *   digits, then nothing or `/`, `?` or `#` and the rest. No userinfo.
   *   A host whose last label is all digits, or `0x` and hex digits, is
   *   IPv4 to the URL parser and is refused;
   * - a fragment-only link is `#`, an ASCII letter, then letters, digits,
   *   `.`, `-` or `_` (skip links, WCAG 2.2 SC 2.4.1). Any other text
   *   starting with `#` is refused.
   */
  safeUrl(input: unknown): string | null;
  /**
   * Creates the one Trusted Types policy, named `fstp-dom`, whose
   * `createHTML`, `createScript` and `createScriptURL` refuse every input.
   * Idempotent. A no-op without `trustedTypes`.
   */
  installTrustedTypesPolicy(): void;
  readonly TRUSTED_TYPES_POLICY: "fstp-dom";
  readonly DomRefusal: new (...args: never[]) => DomRefusalLike;
}

// --------------------------------------------------------------- router.ts

/** The generated check for one path segment, applied to its decoded text. */
export type SegmentCheck = (segment: string) => boolean;

/**
 * One route. `pattern` is `/` or `/seg/seg...`, where a segment is a
 * literal or a whole-segment `{name}` with `name` matching
 * `[a-z][a-z0-9_]*`. A literal is non-empty, holds no brace and is not
 * `.` or `..`. `segments` holds exactly one check per `{name}`.
 */
export interface RouteDef {
  readonly name: string;
  readonly pattern: string;
  readonly segments: Readonly<Record<string, SegmentCheck>>;
}

/** A matched route with its decoded and checked parameters. */
export interface RouteMatch {
  readonly name: string;
  readonly params: Readonly<Record<string, string>>;
}

/**
 * `match` takes a pathname and never throws. It returns null when the path:
 * - does not start with `/`, or holds `?` or `#`;
 * - has an empty segment, except the root `/`;
 * - holds a `%` not followed by two hex digits, or escapes that are not UTF-8;
 * - has a segment that decodes to `.` or `..`;
 * - has a segment whose decoded text holds `/`, `\` or a control
 *   character (U+0000 to U+001F, U+007F to U+009F);
 * - has a segment whose decoded text still holds `%` followed by two hex
 *   digits, so a double-encoded value never reaches a page.
 * Literals are compared with the decoded segment. A parameter is bound
 * only after its check passes.
 */
export interface Router {
  match(path: string): RouteMatch | null;
}

/**
 * router.ts. `createRouter` throws `RouterError` for a malformed table:
 * - a duplicate route name;
 * - a pattern not starting with `/`, or with a malformed segment;
 * - a malformed or partial-segment brace, or a parameter named twice;
 * - a parameter without a check, or a check without a parameter;
 * - two ambiguous routes.
 * Two routes are ambiguous when they have the same number of segments.
 * At every position, the literals must also be equal, or both must be
 * parameters, or the literal must pass the other route's check.
 */
export interface RouterModule {
  createRouter(defs: readonly RouteDef[]): Router;
  readonly RouterError: new (...args: never[]) => Error;
}

// ---------------------------------------------------------------- store.ts

/** A store of application state. */
export interface Store<S> {
  /** The current state, deeply frozen. */
  get(): S;
  /**
   * Replaces the state with `f(current)`. When `f` returns the same
   * reference, nothing is notified. An update made inside a listener runs
   * after the current notification round, so each listener sees every
   * state in order.
   */
  update(f: (s: S) => S): void;
  /** Adds a listener. The returned function removes it. */
  subscribe(listener: (s: S) => void): () => void;
}

/**
 * store.ts. It never writes to browser storage. State is plain data: a
 * primitive, an array, or an object whose prototype is `Object.prototype`
 * or null, with data properties only. Anything else, such as a function,
 * a Map, a Set, a Date or a typed array, is refused with `StoreError`.
 */
export interface StoreModule {
  createStore<S>(initial: S): Store<S>;
  readonly StoreError: new (...args: never[]) => TypeError;
}

// ----------------------------------------------------------------- i18n.ts

/** An interface string. Terminology overrides may change it (I-72). */
export type Label = string;
/** Approved wording. Never overridable (I-72). */
export type ApprovedText = string;

/** One part of a parsed message. Text parts are never empty or adjacent. */
export type MessagePart =
  | { readonly kind: "text"; readonly text: string }
  | { readonly kind: "placeholder"; readonly name: string };

/**
 * The outcome of parsing a message. Interim grammar, pending Daniel and
 * `fstp_html::parse_message_format` (W1d): `{{` is a literal `{`, `}}` a
 * literal `}`, and `{name}` a placeholder with `name` matching
 * `[a-z][a-z0-9_]{0,63}`. Any other `{` or `}` is refused. Read left to
 * right.
 */
export type MessageResult =
  | { readonly ok: true; readonly parts: readonly MessagePart[] }
  | { readonly ok: false; readonly offset: number };

/** One locale's catalogue. Label ids and approved ids never overlap. */
export interface CatalogueInput {
  readonly locale: string;
  readonly labels: Readonly<Record<string, string>>;
  readonly approved: Readonly<Record<string, string>>;
}

/** What `createI18n` takes. `overrides` maps label ids to terminology. */
export interface I18nOptions {
  readonly catalogues: readonly CatalogueInput[];
  readonly locale: string;
  readonly overrides?: Readonly<Record<string, string>>;
}

/**
 * A catalogue for one locale. A missing or extra argument, or an unknown
 * id, throws `I18nError`. Arguments are inserted as text and never parsed.
 */
export interface I18n {
  readonly locale: string;
  label(id: string, args?: Readonly<Record<string, string>>): Label;
  approved(id: string, args?: Readonly<Record<string, string>>): ApprovedText;
}

/**
 * i18n.ts. `createI18n` throws `I18nError` for:
 * - an unknown locale, or a message that does not parse;
 * - an id that is both a label and approved text;
 * - an override of an approved id (I-72);
 * - an override of an unknown label, or one that does not parse.
 */
export interface I18nModule {
  parseMessage(text: string): MessageResult;
  createI18n(opts: I18nOptions): I18n;
  readonly I18nError: new (...args: never[]) => Error;
}

// ----------------------------------------------------------------- a11y.ts

/** a11y.ts (R-NF-03). */
export interface A11yModule {
  /**
   * Puts `message` as text into the page's one live region of that
   * politeness, an element with `aria-live` set to it, created on first use.
   */
  announce(message: string, politeness: "polite" | "assertive"): void;
  /**
   * Creates both live regions, empty, unless they are already in the page.
   * The shell calls it at start-up. Idempotent.
   */
  installLiveRegions(): void;
  /**
   * Marks `control` invalid and adds the id of `error` to its
   * `aria-describedby`, keeping the ids already there. Throws when
   * `error` has no id.
   */
  linkError(control: HTMLElement, error: HTMLElement): void;
  /** Undoes `linkError`, keeping the other described-by ids. */
  clearError(control: HTMLElement, error: HTMLElement): void;
  /** Whether the user asked for reduced motion. */
  prefersReducedMotion(): boolean;
}

// ---------------------------------------------------------------- forms.ts

/** The options of one form field. */
export interface FieldOptions {
  readonly id: string;
  readonly label: Label;
  readonly kind: "text" | "amount";
  readonly required: boolean;
}

/** What a field read gives. An amount is its ADR-006 text. */
export type FieldRead =
  | { readonly ok: true; readonly value: string }
  | { readonly ok: false; readonly reason: "required" | "amount" };

/** One built field: a root holding a bound `<label>` and the control. */
export interface FormField {
  readonly root: HTMLElement;
  readonly control: HTMLInputElement;
  /**
   * Reads the control. It never rewrites what the user typed. An empty
   * required field gives `required`, and an empty optional one reads as
   * `""`. An amount field gives its ADR-006 text, or `amount`.
   */
  read(): FieldRead;
}

/** forms.ts. */
export interface FormsModule {
  field(opts: FieldOptions): FormField;
}

// ------------------------------------------------------------------ api.ts

/** The fetch the API client calls. Tests pass a recording fake. */
export type FetchLike = (input: string, init: RequestInit) => Promise<Response>;

/** An operation of the generated table. */
export interface OperationRef {
  readonly method: "GET" | "POST" | "PUT" | "DELETE";
  readonly path: string;
}

/** What one API call gives. */
export type ApiOutcome =
  | { readonly kind: "done"; readonly body: unknown }
  | { readonly kind: "pending"; readonly confirmPath: string; readonly expires: string }
  | { readonly kind: "step_up_required"; readonly challenge: unknown }
  | { readonly kind: "strong_method_required" }
  | { readonly kind: "refused"; readonly code: string; readonly rule: string | null }
  | { readonly kind: "failed"; readonly reason: "network" | "invalid_response" | "request" };

/** The API client. */
export interface ApiClient {
  /**
   * Fills the `{name}` segments of `op.path` from `params`, each encoded
   * as one segment, and calls `fetch` with a same-origin path. A missing
   * or empty parameter makes no request and gives `failed` with reason
   * `request`. A parameter never yields a `.` or `..` segment, a `/`, a
   * query or a fragment. Every request carries `X-FSTP-Request: 1` and
   * never sends credentials cross-origin. A thrown `fetch` gives `failed`
   * with reason `network`. A 2xx body that is not JSON, or that
   * `validate` refuses, gives `failed` with reason `invalid_response`,
   * never `done`. The mapping of other statuses waits for the wire format
   * of lanes W3b and W4e.
   */
  call(
    op: OperationRef,
    params: Readonly<Record<string, string>>,
    body: unknown,
    validate: (v: unknown) => boolean,
  ): Promise<ApiOutcome>;
}

/** api.ts. */
export interface ApiModule {
  createApi(opts: { readonly fetch: FetchLike }): ApiClient;
}

// --------------------------------------------------------------- stepup.ts

/** What `withStepUp` needs from the page and from the M3 ceremony. */
export interface StepUpDeps {
  /** Runs the M3 WebAuthn step-up for the challenge. True when it completed. */
  ceremony(challenge: unknown): Promise<boolean>;
  /** Sends the user to add a passkey first. */
  addPasskey(): void;
}

/**
 * stepup.ts. On `step_up_required`, runs the ceremony for the challenge
 * and retries once. On `strong_method_required`, calls `addPasskey` and
 * does not retry. Any other outcome is returned as it is.
 */
export interface StepUpModule {
  withStepUp(attempt: () => Promise<ApiOutcome>, deps: StepUpDeps): Promise<ApiOutcome>;
}

// --------------------------------------------------------------- gen/api.ts

/**
 * The schema description the generated validators are checked against.
 * Interim, pending W3a (`tools/gen-ts`): objects are closed, `amount` is an
 * ADR-006 EUR string, `int` a safe integer, and `id` a string the
 * generator's id rule accepts, checked here as a non-empty string.
 */
export type Schema =
  | { readonly kind: "string" }
  | { readonly kind: "id" }
  | { readonly kind: "amount" }
  | { readonly kind: "bool" }
  | { readonly kind: "int" }
  | { readonly kind: "null" }
  | { readonly kind: "enum"; readonly values: readonly string[] }
  | { readonly kind: "array"; readonly items: Schema }
  | { readonly kind: "nullable"; readonly inner: Schema }
  | {
      readonly kind: "object";
      readonly fields: Readonly<Record<string, { readonly schema: Schema; readonly optional: boolean }>>;
    };

/** What the validators fuzz target needs from web/src/gen/api.ts. */
export interface GenApiModule {
  readonly VALIDATORS: Readonly<Record<string, (v: unknown) => boolean>>;
  readonly SCHEMAS: Readonly<Record<string, Schema>>;
}

// ---------------------------------------------------------------- registry

/** Every core module by file name. */
export interface CoreModules {
  readonly money: MoneyModule;
  readonly dom: DomModule;
  readonly router: RouterModule;
  readonly store: StoreModule;
  readonly i18n: I18nModule;
  readonly a11y: A11yModule;
  readonly forms: FormsModule;
  readonly api: ApiModule;
  readonly stepup: StepUpModule;
}

/** The exports each module must have. */
export const REQUIRED_EXPORTS: { readonly [K in keyof CoreModules]: readonly (keyof CoreModules[K])[] } = {
  money: ["parseAmount", "amountText"],
  dom: ["h", "safeUrl", "installTrustedTypesPolicy", "TRUSTED_TYPES_POLICY", "DomRefusal"],
  router: ["createRouter", "RouterError"],
  store: ["createStore", "StoreError"],
  i18n: ["parseMessage", "createI18n", "I18nError"],
  a11y: ["announce", "installLiveRegions", "linkError", "clearError", "prefersReducedMotion"],
  forms: ["field"],
  api: ["createApi"],
  stepup: ["withStepUp"],
};
