// The write page, `GET /w#<ticket>` on the vault origin (M3 design
// section 6.5, ADR-009 "Vault origin" and "Write kinds").
//
// The page reads the ticket from the fragment and shows the form of its
// kind. It posts `{"body":<fact body>,"ticket":"<hex>"}` in canonical
// JSON to `POST /w` on its own origin (`fstp-vault` `codec`). The cell
// never sees the entry, and receives only the resulting epoch change.
//
// Kinds with a form here, with the fact bodies of `fstp-vault-core`:
//
// - `write:guardian_consent`: `{guardian, proposal}`, both from the
//   ticket. The guardian ticks one consent statement.
// - `write:adult_attestation`: `{account, adult_from}`. `adult_from` is
//   the instant, in UTC microseconds, of the 18th birthday at 00:00 UTC.
//   A birthday on 29 February falls on 1 March in a year that has none.
//   That reading is interim. TODO(legal): L-02.
//
// Kinds without a form yet, each reported as an open point:
//
// - `write:country_stated`: the fact takes a numeric country code, and no
//   source fixes the code list yet.
// - `write:affiliation_declared`, `write:partner_staff_declared`,
//   `write:proximity_list_declared` and `write:reviewer_declaration`: they
//   name organisation and person ids, which no M3 directory offers.
// - `write:document_upload`: no fact body exists for it yet.
// - `write:verification_recorded`: never decoded from a browser body
//   (design section 6.4, Q17).
//
// For these the page says so, and posts nothing.
//
// The M5 bank and hardship kinds (I-33, I-86, R-PR-04, `./bank.ts`):
//
// - `write:bank_details`: holder and IBAN, by the lead, for the grant
//   the ticket names. Every write starts the hold.
// - `write:bank_verification`: method and checks of the latest version,
//   or the resolution of an open dispute.
// - `write:bank_dispute`: the lead freezes payments.
// - `write:hardship_evidence`: a statement. The reply names the evidence
//   reference, which the page shows once.
// - `write:hardship_verification`: the reference and a confirmation.

import { h } from '../auth/dom.js';
import { canonical, type Json } from '../auth/encoding.js';
import {
  BANK_CHECKS,
  BANK_METHODS,
  bankDetailsBody,
  bankDisputeBody,
  bankVerifiedBody,
  evidenceOf,
  hardshipBody,
  hardshipVerifiedBody,
  holderOk,
  ibanOk,
  normaliseIban,
  statementOk,
} from './bank.js';
import { claimsView, frame, isId, t, takeTicket, type ClaimsView, type Frame } from './page.js';
import type { VaultMessageId } from './messages.en.js';

/** One form of a write kind: its fields and the fact body they give. */
interface KindForm {
  readonly fields: HTMLElement;
  /** The fact body, or null after it tied an error to its field. */
  body(): Json | null;
}

/** Ties `message` to `input`, or clears its error when null. */
function fieldError(input: HTMLInputElement, error: HTMLElement, message: VaultMessageId | null): boolean {
  if (message === null) {
    input.removeAttribute('aria-invalid');
    input.removeAttribute('aria-describedby');
    error.textContent = '';
    return true;
  }
  input.setAttribute('aria-invalid', 'true');
  input.setAttribute('aria-describedby', error.id);
  error.textContent = t(message);
  return false;
}

function checkbox(id: string, label: VaultMessageId): {
  readonly row: HTMLElement;
  readonly input: HTMLInputElement;
  readonly error: HTMLElement;
} {
  const input = h('input', { id, type: 'checkbox', required: true }) as HTMLInputElement;
  const error = h('p', { id: `${id}-error`, class: 'field-error' });
  const row = h('div', { class: 'field' }, [input, h('label', { for: id, class: 'check' }, [t(label)]), error]);
  return { row, input, error };
}

function guardianForm(c: ClaimsView): KindForm | null {
  const proposal = c.proposal;
  if (proposal === null) return null;
  const consent = checkbox('guardian-consent', 'guardian.consent');
  return {
    fields: h('fieldset', {}, [h('legend', {}, [t('guardian.legend')]), consent.row]),
    body(): Json | null {
      if (!fieldError(consent.input, consent.error, consent.input.checked ? null : 'guardian.missing')) {
        consent.input.focus();
        return null;
      }
      return { guardian: c.account, proposal };
    },
  };
}

/** Today as `YYYY-MM-DD` in UTC, the latest date of birth the field takes. */
function today(): string {
  return new Date().toISOString().slice(0, 10);
}

function adultForm(c: ClaimsView): KindForm {
  const birth = h('input', {
    id: 'adult-birth',
    type: 'date',
    required: true,
    autocomplete: 'bday',
    min: '1900-01-01',
    max: today(),
  }) as HTMLInputElement;
  const birthError = h('p', { id: 'adult-birth-error', class: 'field-error' });
  const confirm = checkbox('adult-confirm', 'adult.confirm');
  return {
    fields: h('fieldset', {}, [
      h('legend', {}, [t('adult.legend')]),
      h('div', { class: 'field' }, [h('label', { for: 'adult-birth' }, [t('adult.birth')]), birth, birthError]),
      confirm.row,
    ]),
    body(): Json | null {
      // The browser parses the date field. A complete, in-range value has
      // a date; anything else is missing.
      const d = birth.validity.valid ? birth.valueAsDate : null;
      const birthOk = fieldError(birth, birthError, d === null ? 'adult.birth.missing' : null);
      const confirmOk = fieldError(
        confirm.input,
        confirm.error,
        confirm.input.checked ? null : 'adult.confirm.missing',
      );
      if (d === null) {
        birth.focus();
        return null;
      }
      if (!birthOk || !confirmOk) {
        confirm.input.focus();
        return null;
      }
      const ms = Date.UTC(d.getUTCFullYear() + 18, d.getUTCMonth(), d.getUTCDate());
      const adultFrom = ms * 1000;
      if (!Number.isSafeInteger(adultFrom)) {
        fieldError(birth, birthError, 'adult.birth.missing');
        birth.focus();
        return null;
      }
      return { account: c.account, adult_from: adultFrom };
    },
  };
}

/** A labelled text field with its error line. */
function textField(
  id: string,
  label: VaultMessageId,
  attrs: Readonly<Record<string, string | boolean>>,
  multiline = false,
): { readonly row: HTMLElement; readonly input: HTMLInputElement; readonly error: HTMLElement } {
  const input = h(multiline ? 'textarea' : 'input', { id, required: true, ...attrs }) as HTMLInputElement;
  const error = h('p', { id: `${id}-error`, class: 'field-error' });
  const row = h('div', { class: 'field' }, [h('label', { for: id }, [t(label)]), input, error]);
  return { row, input, error };
}

function bankForm(c: ClaimsView, grant: string): KindForm {
  const holder = textField('bank-holder', 'bank.holder', { type: 'text', autocomplete: 'name', maxlength: '140' });
  const iban = textField('bank-iban', 'bank.iban', { type: 'text', autocomplete: 'off', spellcheck: false });
  return {
    fields: h('fieldset', {}, [
      h('legend', {}, [t('bank.legend')]),
      h('p', {}, [t('bank.hold')]),
      holder.row,
      iban.row,
    ]),
    body(): Json | null {
      const name = holder.input.value.trim();
      const number = normaliseIban(iban.input.value);
      const nameOk = fieldError(holder.input, holder.error, holderOk(name) ? null : 'bank.holder.missing');
      const numberOk = fieldError(iban.input, iban.error, ibanOk(number) ? null : 'bank.iban.invalid');
      if (!nameOk) {
        holder.input.focus();
        return null;
      }
      if (!numberOk) {
        iban.input.focus();
        return null;
      }
      return bankDetailsBody(c.account, grant, name, number);
    },
  };
}

function bankVerifyForm(c: ClaimsView, grant: string): KindForm {
  const method = h(
    'select',
    { id: 'bank-method', required: true },
    BANK_METHODS.map((m) => h('option', { value: m }, [t(`bank.method.${m}`)])),
  ) as HTMLSelectElement;
  const checks = BANK_CHECKS.map((k) => ({ key: k, box: checkbox(`bank-check-${k}`, `bank.check.${k}`) }));
  for (const k of checks) k.box.input.required = false;
  const resolve = checkbox('bank-resolve', 'bank.verify.resolve');
  resolve.input.required = false;
  const first = checks[0];
  return {
    fields: h('fieldset', {}, [
      h('legend', {}, [t('bank.verify.legend')]),
      h('div', { class: 'field' }, [h('label', { for: 'bank-method' }, [t('bank.verify.method')]), method]),
      ...checks.map((k) => k.box.row),
      resolve.row,
    ]),
    body(): Json | null {
      if (resolve.input.checked) return bankDisputeBody(c.account, grant, false);
      const picked = checks.filter((k) => k.box.input.checked).map((k) => k.key);
      if (first !== undefined && !fieldError(first.box.input, first.box.error, picked.length > 0 ? null : 'bank.verify.missing')) {
        first.box.input.focus();
        return null;
      }
      const m = BANK_METHODS.find((x) => x === method.value) ?? 'bank_statement';
      return bankVerifiedBody(c.account, grant, m, picked);
    },
  };
}

function bankDisputeForm(c: ClaimsView, grant: string): KindForm {
  const confirm = checkbox('bank-dispute', 'bank.dispute.confirm');
  return {
    fields: h('fieldset', {}, [h('legend', {}, [t('bank.dispute.legend')]), confirm.row]),
    body(): Json | null {
      if (!fieldError(confirm.input, confirm.error, confirm.input.checked ? null : 'bank.dispute.missing')) {
        confirm.input.focus();
        return null;
      }
      return bankDisputeBody(c.account, grant, true);
    },
  };
}

function hardshipForm(c: ClaimsView, grant: string): KindForm {
  const statement = textField('hardship-statement', 'hardship.statement', { maxlength: '4000', rows: '8' }, true);
  return {
    fields: h('fieldset', {}, [h('legend', {}, [t('hardship.legend')]), statement.row]),
    body(): Json | null {
      const text = statement.input.value.replace(/\r\n?/g, '\n');
      if (!fieldError(statement.input, statement.error, statementOk(text) ? null : 'hardship.statement.missing')) {
        statement.input.focus();
        return null;
      }
      return hardshipBody(c.account, grant, text);
    },
  };
}

function hardshipVerifyForm(c: ClaimsView, grant: string): KindForm {
  const evidence = textField('hardship-evidence', 'hardship.verify.evidence', { type: 'text', inputmode: 'numeric', autocomplete: 'off' });
  const confirm = checkbox('hardship-confirm', 'hardship.verify.confirm');
  return {
    fields: h('fieldset', {}, [h('legend', {}, [t('hardship.verify.legend')]), evidence.row, confirm.row]),
    body(): Json | null {
      const ref = evidence.input.value.trim();
      const refOk = fieldError(evidence.input, evidence.error, isId(ref) ? null : 'hardship.verify.evidence.missing');
      const confirmOk = fieldError(
        confirm.input,
        confirm.error,
        confirm.input.checked ? null : 'hardship.verify.confirm.missing',
      );
      if (!refOk) {
        evidence.input.focus();
        return null;
      }
      if (!confirmOk) {
        confirm.input.focus();
        return null;
      }
      return hardshipVerifiedBody(c.account, grant, ref);
    },
  };
}

function formOf(c: ClaimsView): KindForm | null {
  if (!isId(c.account)) return null;
  const grant = c.proposal;
  switch (c.kind) {
    case 'write:guardian_consent':
      return guardianForm(c);
    case 'write:adult_attestation':
      return adultForm(c);
    case 'write:bank_details':
      return grant === null ? null : bankForm(c, grant);
    case 'write:bank_verification':
      return grant === null ? null : bankVerifyForm(c, grant);
    case 'write:bank_dispute':
      return grant === null ? null : bankDisputeForm(c, grant);
    case 'write:hardship_evidence':
      return grant === null ? null : hardshipForm(c, grant);
    case 'write:hardship_verification':
      return grant === null ? null : hardshipVerifyForm(c, grant);
    default:
      return null;
  }
}


/** The status and text of a write reply. Status 0 is a network failure. */
interface Sent {
  readonly status: number;
  readonly text: string;
}

async function send(ticket: string, body: Json): Promise<Sent> {
  try {
    const r = await fetch('/w', {
      method: 'POST',
      credentials: 'omit',
      cache: 'no-store',
      redirect: 'error',
      headers: { 'content-type': 'application/json' },
      body: canonical({ body, ticket }),
    });
    return { status: r.status, text: r.status === 200 ? await r.text() : '' };
  } catch {
    return { status: 0, text: '' };
  }
}

function mountForm(f: Frame, ticket: string, k: KindForm): void {
  const submit = h('button', { id: 'write-submit', type: 'submit', class: 'primary' }, [
    t('write.submit'),
  ]) as HTMLButtonElement;
  const form = h('form', { id: 'write-form', novalidate: true }, [k.fields, submit]) as HTMLFormElement;
  // The pending submit is marked `aria-disabled`, never `disabled`, so
  // the focused button keeps focus after a refusal (R-NF-03, WCAG 2.4.3).
  let pending = false;
  form.addEventListener('submit', (ev) => {
    ev.preventDefault();
    if (pending) return;
    f.alert.textContent = '';
    f.status.textContent = '';
    const body = k.body();
    if (body === null) return;
    pending = true;
    submit.setAttribute('aria-disabled', 'true');
    submit.setAttribute('aria-busy', 'true');
    send(ticket, body).then(({ status, text }) => {
      pending = false;
      submit.removeAttribute('aria-disabled');
      submit.removeAttribute('aria-busy');
      if (status >= 200 && status < 300) {
        form.remove();
        const ref = evidenceOf(text);
        f.status.textContent = ref === null ? t('write.saved') : t('hardship.saved', { ref });
        // The form and its focused button are gone: focus the outcome.
        f.status.tabIndex = -1;
        f.status.focus();
        return;
      }
      f.alert.textContent = t(status >= 400 && status < 500 ? 'error.refused' : 'error.unavailable');
    });
  });
  f.main.append(h('p', {}, [t('write.intro')]), form);
}

/** Mounts the write page for the ticket in the fragment. */
export function mount(): void {
  const ticket = takeTicket();
  const f = frame('write.title');
  if (ticket === null) {
    f.alert.textContent = t('error.link');
    return;
  }
  const c = claimsView(ticket);
  if (c === null) {
    f.alert.textContent = t('error.link');
    return;
  }
  const k = formOf(c);
  if (k === null) {
    f.alert.textContent = t('error.kind');
    return;
  }
  mountForm(f, ticket, k);
}
