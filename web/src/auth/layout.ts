// The frame every auth page shares (R-NF-03, R-NF-04, M3 design section
// 11.2): the document language and title from the catalogue, the one
// `main` landmark with its `h1`, one alert region per page for refusals,
// a status region, and field errors tied to their field.

import { clear, h } from './dom.js';
import { createI18n } from './i18n.js';
import { AUTH_EN, type AuthMessageId } from './messages.en.js';
import { Failure, type FailureCode } from './webauthn.js';

/** The catalogue of the auth pages. */
export const i18n = createI18n<AuthMessageId>(AUTH_EN);

/** A message of the auth catalogue. */
export function t(id: AuthMessageId, args?: Readonly<Record<string, string>>): string {
  return i18n.label(id, args);
}

/** The page paths of the cell origin (design section 8.7 reading). */
export const PATHS = {
  login: '/auth/login',
  signup: '/auth/signup',
  invite: '/auth/invite',
  magic: '/auth/magic',
  recovery: '/auth/recovery',
  account: '/auth/account',
} as const;

/** The live regions of a page. */
export interface Frame {
  /** The `main` landmark, after its heading. */
  readonly main: HTMLElement;
  /** The page's one `role="alert"` region. */
  readonly alert: HTMLElement;
}

/**
 * Sets the document language and title, and fills the shell's `main`
 * with the page heading and its alert region. A second call starts the
 * page again.
 */
export function frame(title: AuthMessageId, alertId: string): Frame {
  document.documentElement.lang = i18n.locale;
  document.title = t(title);
  let main = document.querySelector('main');
  if (main === null) {
    main = h('main', { id: 'main' });
    document.body.append(main);
  }
  clear(main);
  const alert = h('p', { id: alertId, role: 'alert', class: 'alert' });
  main.append(h('h1', {}, [t(title)]), alert);
  return { main, alert };
}

const FAILURE_MESSAGES: Readonly<Record<FailureCode, AuthMessageId>> = {
  cancelled: 'error.cancelled',
  unsupported: 'error.unsupported',
  refused: 'error.refused',
  session: 'error.session',
  unavailable: 'error.unavailable',
  malformed: 'error.malformed',
  link: 'error.link',
};

/** Shows the message of `e` in `alert`. An unknown error is malformed. */
export function showFailure(alert: HTMLElement, e: unknown): void {
  const code: FailureCode = e instanceof Failure ? e.code : 'malformed';
  alert.textContent = t(FAILURE_MESSAGES[code]);
}

/** Empties `region`. */
export function hush(region: HTMLElement): void {
  region.textContent = '';
}

/** A `role="status"` region, empty until a message is set. */
export function statusRegion(id: string): HTMLElement {
  return h('p', { id, role: 'status', class: 'status' });
}

/** A labelled email field with its error text, inside a field group. */
export interface EmailField {
  readonly group: HTMLElement;
  readonly input: HTMLInputElement;
  /** Checks the field and ties an error to it. Returns the value if valid. */
  check(): string | null;
}

/** An email field with id `id`, and its error element `<id>-error`. */
export function emailField(id: string): EmailField {
  const errorId = `${id}-error`;
  const input = h('input', {
    id,
    name: 'email',
    type: 'email',
    autocomplete: 'email',
    spellcheck: 'false',
    required: true,
  }) as HTMLInputElement;
  const error = h('p', { id: errorId, class: 'field-error' });
  const group = h('div', { class: 'field' }, [h('label', { for: id }, [t('field.email')]), input, error]);
  const check = (): string | null => {
    const v = input.validity;
    const problem: AuthMessageId | null = v.valueMissing
      ? 'field.email.missing'
      : v.valid
        ? null
        : 'field.email.invalid';
    if (problem === null) {
      input.removeAttribute('aria-invalid');
      input.removeAttribute('aria-describedby');
      error.textContent = '';
      return input.value.trim();
    }
    input.setAttribute('aria-invalid', 'true');
    input.setAttribute('aria-describedby', errorId);
    error.textContent = t(problem);
    input.focus();
    return null;
  };
  return { group, input, check };
}

/** The buttons whose action is pending. */
const PENDING = new WeakSet<HTMLButtonElement>();

/**
 * A button that ignores presses while `run` is pending.
 *
 * The button is marked `aria-disabled` and `aria-busy`, never
 * `disabled`. Disabling the focused button moves focus to the body, so a
 * keyboard or screen reader user would start again from the top of the
 * page after every refusal (R-NF-03, WCAG 2.4.3). The pending guard is
 * kept per button, so a wrapper made anew for each form submission
 * guards as well.
 */
export function busy(button: HTMLButtonElement, run: () => Promise<void>): () => void {
  return () => {
    if (PENDING.has(button)) {
      return;
    }
    PENDING.add(button);
    button.setAttribute('aria-disabled', 'true');
    button.setAttribute('aria-busy', 'true');
    run().finally(() => {
      PENDING.delete(button);
      button.removeAttribute('aria-disabled');
      button.removeAttribute('aria-busy');
    });
  };
}

/** Opens `path` of this origin, replacing the current history entry. */
export function go(path: string): void {
  location.replace(path);
}

/**
 * The URL fragment, without `#`, and removes it from the address bar and
 * the history entry. Tokens travel in the fragment, so they never reach a
 * server log, and they leave the page's URL once read.
 */
export function takeFragment(): string {
  const f = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  if (f !== '') {
    history.replaceState(null, '', location.pathname);
  }
  return f;
}
