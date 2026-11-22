// The anonymous draft page, `/auth/draft` (ADR-032, Daniel 2026-11-22).
//
// A person may start writing for an open call without an account.
//
// - `/auth/draft?call=<id>` offers to start a draft for that call. Start
//   asks `POST /auth/drafts {call}` for a new draft and its token.
// - `/auth/draft#<token>` is the resume link. The page reads the token
//   from the fragment, keeps it in local storage and removes it from the
//   address bar, so it never reaches a server log (R-NF-02).
// - With neither, the page opens the draft this browser keeps.
//
// The editor saves by itself through `POST /auth/drafts/save` a moment
// after each change. Beside it the page shows the resume link with a
// copy button, the deletion date, and the way to submit: register, or
// sign in to an existing account. Both lead to the claim page of the
// signed-in app (`/app/calls/<id>/claim`), which moves the draft into the
// account. No AI pre-check runs before that (ADR-032, interim).

import { ok, post, record } from '../api.js';
import {
  type Kept,
  callOfQuery,
  claimPath,
  forget,
  isToken,
  keep,
  kept,
  resumeLink,
} from '../anondraft.js';
import { h } from '../dom.js';
import { PATHS, busy, frame, hush, showFailure, statusRegion, t } from '../layout.js';
import { Failure } from '../webauthn.js';

/** How long the editor waits after a change before it saves, in ms. */
const SAVE_DELAY_MS = 1200;

/** The workspace limits, in bytes (`fstp_api_core::anon`). */
const LIMITS = { title: 300, summary: 1200, narrative: 65536 } as const;

/** The draft as the open route answers it. */
interface Opened {
  readonly call: string;
  readonly title: string;
  readonly summary: string;
  readonly narrative: string;
  readonly expires: number;
}

function openedOf(body: unknown): Opened | null {
  const o = record(body);
  if (o === null) return null;
  const s = (k: string): string | null => (typeof o[k] === 'string' ? (o[k] as string) : null);
  const call = s('call');
  const title = s('title');
  const summary = s('summary');
  const narrative = s('narrative');
  const expires = Number(s('expires'));
  if (call === null || title === null || summary === null || narrative === null || !Number.isFinite(expires)) {
    return null;
  }
  return { call, title, summary, narrative, expires };
}

/** The date of `micros` in the reader's own words. */
function dateOf(micros: number): string {
  return new Date(Math.floor(micros / 1000)).toLocaleDateString(undefined, {
    year: 'numeric',
    month: 'long',
    day: 'numeric',
  });
}

function utf8Length(s: string): number {
  return new TextEncoder().encode(s).length;
}

/** The page that says the link no longer works. */
function gone(): void {
  forget();
  const { main } = frame('draft.gone.title', 'draft-error');
  main.append(
    h('p', {}, [t('draft.gone.intro')]),
    h('p', {}, [h('a', { href: PATHS.login }, [t('top.signin')])]),
  );
}

/** The page with nothing to open and no call to start. */
function none(): void {
  const { main } = frame('draft.none.title', 'draft-error');
  main.append(h('p', {}, [t('draft.none.intro')]), h('p', {}, [h('a', { href: '/app/calls' }, [t('top.calls')])]));
}

/** The start screen for `call`. */
function mountStart(call: string): void {
  const { main, alert } = frame('draft.start.title', 'draft-error');
  const button = h('button', { id: 'draft-start', type: 'button', class: 'primary' }, [
    t('draft.start.button'),
  ]) as HTMLButtonElement;
  button.addEventListener(
    'click',
    busy(button, async () => {
      hush(alert);
      const r = await post('/auth/drafts', { call });
      const o = record(r.body);
      const token = o === null ? null : o['token'];
      if (ok(r) && isToken(token)) {
        keep({ token, call });
        await mountEditor({ token, call });
        return;
      }
      if (r.status === 409) {
        alert.textContent = t('draft.closed');
      } else if (r.status === 429) {
        alert.textContent = t('draft.busy');
      } else {
        showFailure(alert, new Failure(r.status === 0 ? 'unavailable' : 'refused'));
      }
    }),
  );
  main.append(h('p', {}, [t('draft.start.intro')]), button, h('p', {}, [t('draft.ai')]));
}

/** A labelled text field of the editor. */
function textField(
  id: string,
  label: 'draft.field.title' | 'draft.field.summary' | 'draft.field.narrative',
  value: string,
  multi: boolean,
  hint: 'draft.field.summary.hint' | null,
): { group: HTMLElement; control: HTMLInputElement | HTMLTextAreaElement } {
  const attrs: Record<string, string | boolean> = { id, name: id, spellcheck: 'true' };
  if (hint !== null) attrs['aria-describedby'] = `${id}-hint`;
  const control = multi
    ? (h('textarea', { ...attrs, rows: id === 'draft-narrative' ? '16' : '4' }) as HTMLTextAreaElement)
    : (h('input', { ...attrs, type: 'text', autocomplete: 'off' }) as HTMLInputElement);
  control.value = value;
  const children: HTMLElement[] = [h('label', { for: id }, [t(label)])];
  if (hint !== null) children.push(h('p', { id: `${id}-hint`, class: 'hint' }, [t(hint)]));
  children.push(control);
  return { group: h('div', { class: 'field' }, children), control };
}

/** The editor of the kept draft `k`. */
async function mountEditor(k: Kept): Promise<void> {
  const r = await post('/auth/drafts/open', { token: k.token });
  if (r.status === 404) {
    gone();
    return;
  }
  const d = ok(r) ? openedOf(r.body) : null;
  const { main, alert } = frame('draft.title', 'draft-error');
  if (d === null) {
    showFailure(alert, new Failure(r.status === 0 ? 'unavailable' : 'malformed'));
    return;
  }
  if (d.call !== k.call) keep({ token: k.token, call: d.call });
  const title = textField('draft-title', 'draft.field.title', d.title, false, null);
  const summary = textField('draft-summary', 'draft.field.summary', d.summary, true, 'draft.field.summary.hint');
  const narrative = textField('draft-narrative', 'draft.field.narrative', d.narrative, true, null);
  const status = statusRegion('draft-status');
  let timer: ReturnType<typeof setTimeout> | null = null;
  let saving = false;
  let again = false;
  const save = async (): Promise<void> => {
    if (saving) {
      again = true;
      return;
    }
    const body = {
      narrative: narrative.control.value,
      summary: summary.control.value,
      title: title.control.value,
      token: k.token,
    };
    if (
      utf8Length(body.title) > LIMITS.title ||
      utf8Length(body.summary) > LIMITS.summary ||
      utf8Length(body.narrative) > LIMITS.narrative
    ) {
      status.textContent = t('draft.toolong');
      return;
    }
    saving = true;
    status.textContent = t('draft.saving');
    const s = await post('/auth/drafts/save', body);
    saving = false;
    if (s.status === 404) {
      gone();
      return;
    }
    status.textContent = ok(s) ? t('draft.saved') : s.status === 400 ? t('draft.toolong') : t('draft.unsaved');
    if (again) {
      again = false;
      await save();
    }
  };
  const later = (): void => {
    if (timer !== null) clearTimeout(timer);
    timer = setTimeout(() => {
      timer = null;
      void save();
    }, SAVE_DELAY_MS);
  };
  for (const f of [title, summary, narrative]) {
    f.control.addEventListener('input', later);
    f.control.addEventListener('blur', () => {
      if (timer !== null) {
        clearTimeout(timer);
        timer = null;
        void save();
      }
    });
  }
  const link = resumeLink(location.origin, k.token);
  const linkInput = h('input', {
    id: 'draft-link',
    type: 'text',
    readonly: true,
    value: link,
    spellcheck: 'false',
    autocomplete: 'off',
  }) as HTMLInputElement;
  const copied = statusRegion('draft-link-status');
  const copy = h('button', { id: 'draft-copy', type: 'button' }, [t('draft.link.copy')]) as HTMLButtonElement;
  copy.addEventListener('click', () => {
    linkInput.select();
    const done = (): void => {
      copied.textContent = t('draft.link.copied');
    };
    try {
      navigator.clipboard.writeText(link).then(done, () => undefined);
    } catch {
      // No clipboard here: the link stays selected for a manual copy.
    }
  });
  const del = h('button', { id: 'draft-delete', type: 'button', class: 'danger' }, [
    t('draft.delete'),
  ]) as HTMLButtonElement;
  let armed = false;
  del.addEventListener(
    'click',
    busy(del, async () => {
      if (!armed) {
        armed = true;
        del.textContent = t('draft.delete.confirm');
        return;
      }
      const x = await post('/auth/drafts/discard', { token: k.token });
      if (ok(x) || x.status === 404) {
        forget();
        const f = frame('draft.title', 'draft-error');
        f.main.append(h('p', { role: 'status' }, [t('draft.deleted')]));
        return;
      }
      showFailure(alert, new Failure('unavailable'));
    }),
  );
  main.append(
    h('form', { id: 'draft-form', novalidate: true }, [title.group, summary.group, narrative.group]),
    status,
    h('section', { class: 'card', 'aria-labelledby': 'draft-link-heading' }, [
      h('h2', { id: 'draft-link-heading' }, [t('draft.link.heading')]),
      h('p', {}, [t('draft.link.intro')]),
      h('div', { class: 'field' }, [h('label', { for: 'draft-link' }, [t('draft.link.label')]), linkInput]),
      copy,
      copied,
      h('p', {}, [t('draft.expires', { date: dateOf(d.expires) })]),
    ]),
    h('section', { class: 'card', 'aria-labelledby': 'draft-next-heading' }, [
      h('h2', { id: 'draft-next-heading' }, [t('draft.next.heading')]),
      h('p', {}, [t('draft.next.intro')]),
      h('p', {}, [
        h('a', { href: PATHS.signup, class: 'button primary', id: 'draft-register' }, [t('draft.next.register')]),
      ]),
      h('p', {}, [h('a', { href: claimPath(d.call), id: 'draft-signin' }, [t('draft.next.signin')])]),
      h('p', {}, [t('draft.ai')]),
    ]),
    h('p', {}, [del]),
  );
}

/** Mounts the draft page (module documentation). */
export function mount(): void {
  const fragment = location.hash.startsWith('#') ? location.hash.slice(1) : '';
  const call = callOfQuery(location.search);
  if (fragment !== '') {
    // The token leaves the address bar and the history entry once read.
    history.replaceState(null, '', location.pathname);
    if (!isToken(fragment)) {
      gone();
      return;
    }
    const held = kept();
    // The call is learnt from the open route.
    void mountEditor({ token: fragment, call: held?.token === fragment ? held.call : '0' });
    return;
  }
  const held = kept();
  if (held !== null && (call === null || call === held.call)) {
    void mountEditor(held);
    return;
  }
  if (call !== null) {
    mountStart(call);
    return;
  }
  none();
}
