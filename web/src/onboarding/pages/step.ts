// An onboarding step page, `/app/admin/onboarding/{step}` (R-TN-01,
// SoD-07, R-LG-03; M4 design sections 2.2 J0 and 3.5).
//
// - `#onboarding-steps` shows every step with its status. Each step
//   validates before the next opens, so a step after one that is not
//   validated holds no link, and opened directly it shows
//   `#onboarding-locked` and no form.
// - `#onboarding-form` holds the step's values in the `fstp-tenant` codec
//   form. Every set goes out strictly ascending, as the codec
//   requires. The Agreements step sends only the versions the control
//   plane recorded, and nothing while it has recorded none.
//   `#onboarding-save` saves and validates them against the current
//   tenant revision (`tenant.save_step`). The tenant can save and return
//   at any point: the saved values show again on the next visit.
// - `#onboarding-outcome` names the outcome as `fstp-tenant` spells it,
//   such as `validated` or `too_few_admins`. `#onboarding-next` exists
//   once the step is validated.
// - The Payments step changes P-20, a tenant setting and so a high-risk
//   action with its own step-up (`tenant.set_payment_mode`). The
//   Administrators step invites a tenant admin, also high-risk
//   (`tenant.invite_admin`). It also shows and grants the holders of
//   Financial signatory and Legal signatory, which it needs (SoD-14,
//   SoD-15), each grant and end with its own step-up (`./signatories.ts`).

import { h } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { busy, frame, hush, warn } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { labelOr, t } from "../i18n.js";
import {
  CHANNELS_VALUES,
  ONBOARDING_STEPS,
  PAYMENT_MODES,
  accountSet,
  isOutcome,
  nameSet,
  nextOnboardingStep,
  openableSteps,
  readAdmins,
  readSaved,
  record,
  type AdminRow,
  type OnboardingStep,
  type StepView,
} from "../model.js";
import { PATHS, link, loadSteps, statusesOf, stepName, stepNav } from "./common.js";
import { loadSignatories, signatorySection } from "./signatories.js";

/** The text of a save outcome code. */
export function outcomeText(code: string): Label {
  return labelOr(`onboarding.outcome.${code}`, () => t.label("onboarding.outcome.unnamed", { code }));
}

/** A labelled text control. */
function textControl(name: string, label: Label, value: unknown, attrs: Readonly<Record<string, string | boolean>> = {}): HTMLElement {
  const id = `ob.${name}`;
  const input = h("input", { id, name, type: "text", ...attrs });
  if (input instanceof HTMLInputElement && typeof value === "string") input.value = value;
  return h("div", { class: "fstp-control" }, [h("label", { for: id }, [label]), input]);
}

/** A fieldset of radios or checkboxes named `name`, one per option. */
function choices(
  kind: "radio" | "checkbox",
  name: string,
  legend: Label,
  options: readonly (readonly [string, Label])[],
  chosen: ReadonlySet<string>,
): HTMLElement {
  const items = options.map(([value, text]) => {
    const id = `ob.${name}.${value}`;
    return h("div", { class: "fstp-check" }, [
      h("input", { id, type: kind, name, value, checked: chosen.has(value) }),
      h("label", { for: id }, [text]),
    ]);
  });
  return h("fieldset", { class: "fstp-group" }, [h("legend", {}, [legend]), ...items]);
}

/** The values of the controls named `name` in `form` that are checked. */
function checked(form: HTMLElement, name: string): string[] {
  const out: string[] = [];
  for (const el of Array.from(form.querySelectorAll("input"))) {
    if (el instanceof HTMLInputElement && el.name === name && el.checked) out.push(el.value);
  }
  return out;
}

/** The value of the control named `name` in `form`, or "". */
function valueOf(form: HTMLElement, name: string): string {
  for (const el of Array.from(form.querySelectorAll("input,textarea"))) {
    if ((el instanceof HTMLInputElement || el instanceof HTMLTextAreaElement) && el.name === name) return el.value;
  }
  return "";
}

/** An agreement version as the codec takes it (`take_u32`): a canonical decimal string, or null. */
function agreementVersion(x: unknown): string | null {
  const s = typeof x === "number" && Number.isSafeInteger(x) && x >= 0 ? String(x) : x;
  return typeof s === "string" && /^(0|[1-9][0-9]{0,9})$/.test(s) && BigInt(s) <= 4_294_967_295n ? s : null;
}

function strings(v: unknown): Set<string> {
  return new Set(Array.isArray(v) ? (v as unknown[]).filter((x): x is string => typeof x === "string") : []);
}

/** The controls of `step`, showing `values`. */
function controls(step: OnboardingStep, view: StepView, admins: readonly AdminRow[]): HTMLElement[] {
  const v = view.values ?? {};
  switch (step) {
    case "organisation":
      return [
        textControl("data_protection_contact", t.label("onboarding.organisation.contact"), v["data_protection_contact"]),
        admins.length === 0
          ? h("p", {}, [t.label("onboarding.organisation.no_admins")])
          : choices(
              "checkbox",
              "signatories",
              t.label("onboarding.organisation.signatories"),
              admins.map((a) => [a.account, t.label("onboarding.admin.item", { handle: a.handle })] as const),
              strings(v["signatories"]),
            ),
      ];
    case "agreements": {
      // The versions the control plane recorded, which are the versions a save sends.
      const shown = view.accepted ?? {};
      const version = (k: string): string => agreementVersion(shown[k]) ?? t.label("onboarding.agreements.none");
      return [
        h("dl", {}, [
          h("dt", {}, [t.label("onboarding.agreements.saas_terms")]),
          h("dd", {}, [version("saas_terms")]),
          h("dt", {}, [t.label("onboarding.agreements.dpa")]),
          h("dd", {}, [version("dpa")]),
          h("dt", {}, [t.label("onboarding.agreements.sub_processors")]),
          h("dd", {}, [version("sub_processors")]),
        ]),
      ];
    }
    case "branding":
      return [
        choices(
          "radio",
          "package",
          t.label("onboarding.branding.package"),
          [
            ["default", t.label("onboarding.branding.default")],
            ["white_label", t.label("onboarding.branding.white_label")],
          ],
          new Set(typeof v["package"] === "string" ? [v["package"]] : []),
        ),
      ];
    case "domains_and_email":
      return [
        textControl("sending_domain", t.label("onboarding.domains.sending_domain"), v["sending_domain"], {
          autocomplete: "off",
          spellcheck: "false",
        }),
        h("p", { class: "fstp-hint" }, [t.label("onboarding.domains.hint")]),
      ];
    case "identity":
      return [
        choices(
          "checkbox",
          "p18",
          t.label("onboarding.identity.p18"),
          [
            ["eudi_wallet", t.label("onboarding.identity.eudi_wallet")],
            ["document_upload", t.label("onboarding.identity.document_upload")],
          ],
          strings(v["p18"]),
        ),
        choices(
          "radio",
          "p45",
          t.label("onboarding.identity.p45"),
          [
            ["tenant_registration", t.label("onboarding.identity.tenant_registration")],
            ["crabnebula_intermediary", t.label("onboarding.identity.crabnebula_intermediary")],
          ],
          new Set(typeof v["p45"] === "string" ? [v["p45"]] : []),
        ),
      ];
    case "inference": {
      const fallbacks = h("textarea", { id: "ob.fallbacks", name: "fallbacks", rows: "3", spellcheck: "false" });
      if (fallbacks instanceof HTMLTextAreaElement) fallbacks.value = [...strings(v["fallbacks"])].join("\n");
      return [
        textControl("provider", t.label("onboarding.inference.provider"), v["provider"], { spellcheck: "false" }),
        textControl("primary", t.label("onboarding.inference.primary"), v["primary"], { spellcheck: "false" }),
        h("div", { class: "fstp-control" }, [
          h("label", { for: "ob.fallbacks" }, [t.label("onboarding.inference.fallbacks")]),
          fallbacks,
        ]),
      ];
    }
    case "payments":
      return [
        choices(
          "radio",
          "bank_interface",
          t.label("onboarding.payments.bank_interface"),
          [
            ["not_connected", t.label("onboarding.payments.not_connected")],
            ["connect", t.label("onboarding.payments.connect")],
          ],
          new Set(typeof v["bank_interface"] === "string" ? [v["bank_interface"]] : []),
        ),
      ];
    case "channels": {
      // P-32: email is the one channel of this release. Matrix (B-05) and
      // WhatsApp (B-03) show disabled and marked as coming later, and the
      // save sends no value for them (design section 15.0, 2026-11-06).
      const note = "ob-channels-later-note";
      const later = { disabled: true, "aria-describedby": note } as const;
      return [
        h("p", { id: "ob-channels-email" }, [t.label("onboarding.channels.email")]),
        h("fieldset", { id: "ob-channels-later", class: "fstp-group", disabled: true }, [
          h("legend", {}, [t.label("onboarding.channels.later_title")]),
          textControl("matrix_homeserver", t.label("onboarding.channels.matrix"), "", { ...later, autocomplete: "off" }),
          h("div", { class: "fstp-check" }, [
            h("input", { id: "ob.whatsapp", type: "checkbox", name: "whatsapp", ...later }),
            h("label", { for: "ob.whatsapp" }, [t.label("onboarding.channels.whatsapp")]),
          ]),
          h("p", { id: note, class: "fstp-hint" }, [t.label("onboarding.channels.coming_later")]),
        ]),
      ];
    }
    case "administrators":
      return [h("p", {}, [t.label("onboarding.administrators.review")])];
  }
}

/** The values a step sends, or the reason the page sends nothing. */
type Values = { readonly ok: Record<string, unknown> } | { readonly problem: Label };

/**
 * The values of `step` as the form holds them, in the `fstp-tenant` codec
 * form. Every set goes out strictly ascending, as the codec requires
 * (`take_name_set`, `take_accounts`). Agreements sends only the versions
 * the control plane recorded as accepted, never a version of its own.
 */
function values(step: OnboardingStep, form: HTMLElement, view: StepView, admins: readonly AdminRow[]): Values {
  const invalid: Values = { problem: t.label("onboarding.values_invalid") };
  switch (step) {
    case "organisation": {
      const signatories = accountSet(checked(form, "signatories"));
      if (signatories === null) return invalid;
      return { ok: { data_protection_contact: valueOf(form, "data_protection_contact"), signatories } };
    }
    case "agreements": {
      const a = view.accepted;
      const dpa = agreementVersion(a?.["dpa"]);
      const saas = agreementVersion(a?.["saas_terms"]);
      const sub = agreementVersion(a?.["sub_processors"]);
      if (dpa === null || saas === null || sub === null) return { problem: t.label("onboarding.agreements.not_recorded") };
      return { ok: { dpa, saas_terms: saas, sub_processors: sub } };
    }
    case "branding":
      return { ok: { package: checked(form, "package")[0] ?? "" } };
    case "domains_and_email":
      return { ok: { sending_domain: valueOf(form, "sending_domain").trim() } };
    case "identity":
      return { ok: { p18: nameSet(checked(form, "p18")), p45: checked(form, "p45")[0] ?? "" } };
    case "inference":
      // The fallbacks are an ordered list, not a set: the order is the person's.
      return {
        ok: {
          fallbacks: valueOf(form, "fallbacks")
            .split("\n")
            .map((x) => x.trim())
            .filter((x) => x !== ""),
          primary: valueOf(form, "primary").trim(),
          provider: valueOf(form, "provider").trim(),
        },
      };
    case "payments":
      return { ok: { bank_interface: checked(form, "bank_interface")[0] ?? "" } };
    case "channels":
      // P-32, B-03, B-05: no Matrix or WhatsApp value goes out, whatever
      // the disabled fields or the server hold.
      return { ok: { ...CHANNELS_VALUES } };
    case "administrators": {
      const set = accountSet(admins.map((a) => a.account));
      return set === null ? invalid : { ok: { admins: set } };
    }
  }
}

/**
 * The P-20 section of the Payments step: a tenant setting with its own
 * step-up. A change of P-20 is a tenant record, so it moves the tenant
 * revision a step save names as its base. `saved` runs once the change
 * is recorded, before the section reports it, and `track` receives each
 * change in flight, so a step save waits for it and sends the fresh base.
 */
function paymentMode(
  alert: HTMLElement,
  current: unknown,
  saved: () => Promise<void>,
  track: (work: Promise<void>) => void,
): HTMLElement {
  const status = h("p", { id: "setting-p20-status", role: "status", class: "fstp-status" });
  const fieldset = choices(
    "radio",
    "p20",
    t.label("onboarding.payments.p20"),
    PAYMENT_MODES.map((m) => [m, m === "record_only" ? t.label("onboarding.p20.record_only") : t.label("onboarding.p20.execution")] as const),
    new Set(typeof current === "string" ? [current] : []),
  );
  const save = h("button", { id: "setting-p20-save", type: "button" }, [t.label("onboarding.payments.p20_save")]);
  save.addEventListener(
    "click",
    busy(save, () => {
      const work = (async (): Promise<void> => {
        hush(alert);
        const chosen = checked(fieldset, "p20")[0];
        if (chosen === undefined) {
          warn(alert, t.label("onboarding.payments.p20_none"));
          return;
        }
        const o = await call("tenant.set_payment_mode", [], { value: chosen }, anyObject);
        if (report(alert, o)) return;
        await saved();
        status.textContent = t.label("onboarding.payments.p20_saved");
      })();
      track(work);
      return work;
    }),
  );
  return h("section", { id: "setting-p20", "aria-labelledby": "setting-p20-title" }, [
    h("h2", { id: "setting-p20-title" }, [t.label("onboarding.payments.p20_title")]),
    h("p", {}, [t.label("onboarding.payments.p20_intro")]),
    fieldset,
    save,
    status,
  ]);
}

/** The admin list and the invitation of another tenant admin. */
function adminSection(alert: HTMLElement, admins: readonly AdminRow[], reload: () => Promise<void>): HTMLElement {
  const list = h(
    "ul",
    { id: "admins", "aria-labelledby": "admins-title" },
    admins.map((a) =>
      h("li", { "data-account": a.account, "data-verified": a.verified ? "true" : "false" }, [
        t.label("onboarding.admin.item", { handle: a.handle }),
        " ",
        a.verified ? t.label("onboarding.admin.verified") : t.label("onboarding.admin.unverified"),
      ]),
    ),
  );
  const email = h("input", { id: "admin-invite-email", type: "email", autocomplete: "off", spellcheck: "false" });
  const submit = h("button", { id: "admin-invite-submit", type: "button" }, [t.label("onboarding.admin.invite")]);
  const status = h("p", { id: "admin-invite-status", role: "status", class: "fstp-status" });
  submit.addEventListener(
    "click",
    busy(submit, async () => {
      hush(alert);
      const address = email instanceof HTMLInputElement ? email.value.trim() : "";
      if (!/^[^\s@]+@[^\s@]+$/.test(address)) {
        warn(alert, t.label("onboarding.admin.email_invalid"));
        email.focus();
        return;
      }
      const o = await call("tenant.invite_admin", [], { email: address }, anyObject);
      if (report(alert, o)) return;
      if (email instanceof HTMLInputElement) email.value = "";
      status.textContent = t.label("onboarding.admin.invited", { email: address });
      await reload();
    }),
  );
  return h("section", { id: "administrators", "aria-labelledby": "admins-title" }, [
    h("h2", { id: "admins-title" }, [t.label("onboarding.admin.title")]),
    list,
    h("h3", {}, [t.label("onboarding.admin.invite_title")]),
    h("p", {}, [t.label("onboarding.admin.invite_intro")]),
    h("div", { class: "fstp-control" }, [h("label", { for: "admin-invite-email" }, [t.label("onboarding.admin.email")]), email]),
    submit,
    status,
  ]);
}

/** Reads the tenant admins, or shows why not in `alert`. */
async function loadAdmins(alert: HTMLElement): Promise<AdminRow[] | null> {
  const o = await call("tenant.list_admins", [], undefined, (v) => readAdmins(v) !== null);
  if (report(alert, o) || o.kind !== "done") return null;
  return readAdmins(o.body);
}

/** Mounts the page of onboarding step `step`. */
export function mount(step: OnboardingStep): void {
  let nav = stepNav(step, null);
  // The `onboarding` prototype: "Set up your organisation" heads every
  // step, and the step names itself in its `h2` and the document title.
  const heading = t.label("onboarding.step.heading", {
    n: String(ONBOARDING_STEPS.indexOf(step) + 1),
    name: stepName(step),
  });
  const { main, alert } = frame({
    title: t.label("onboarding.step.title"),
    alertId: "onboarding-error",
    nav,
  });
  document.title = heading;
  main.append(h("h2", { id: "onboarding-step-heading" }, [heading]));
  const body = h("div", { id: "onboarding-body" });
  main.append(h("p", {}, [labelOr(`onboarding.intro.${step}`, () => t.label("onboarding.intro"))]), body);

  const draw = async (): Promise<void> => {
    const steps = await loadSteps(alert);
    if (steps === null) return;
    const statuses = statusesOf(steps);
    const fresh = stepNav(step, statuses);
    nav.replaceWith(fresh);
    nav = fresh;
    const view = steps.get(step);
    if (view === undefined) return;
    if (!openableSteps(statuses).includes(step)) {
      body.replaceChildren(
        h("p", { id: "onboarding-locked" }, [t.label("onboarding.locked")]),
        h("p", {}, [link(PATHS.step(openableSteps(statuses).slice(-1)[0] ?? "organisation"), t.label("onboarding.locked_go"))]),
      );
      main.setAttribute("data-ready", "true");
      return;
    }
    const needsAdmins = step === "organisation" || step === "administrators";
    const admins = needsAdmins ? await loadAdmins(alert) : [];
    if (admins === null) return;
    const outcome = h("p", { id: "onboarding-outcome", role: "status", class: "fstp-status" });
    const next = nextOnboardingStep(step);
    const nextBox = h("p", {});
    const showNext = (): void => {
      nextBox.replaceChildren(
        link(next === null ? PATHS.summary : PATHS.step(next), next === null ? t.label("onboarding.next_summary") : t.label("onboarding.next", { name: stepName(next) }), {
          id: "onboarding-next",
        }),
      );
    };
    if (view.status === "validated" || view.status === "skipped") showNext();
    if (view.status === "skipped") {
      outcome.setAttribute("data-outcome", "skipped");
      outcome.textContent = t.label("onboarding.skipped");
      body.replaceChildren(outcome, nextBox);
      main.setAttribute("data-ready", "true");
      return;
    }
    if (view.outcome !== null && isOutcome(view.outcome)) {
      outcome.textContent = t.label("onboarding.outcome.last", { outcome: outcomeText(view.outcome) });
    }
    let base = view.revision;
    // A tenant setting changed on this page (P-20) moves the revision. A
    // save waits for such a change in flight and then sends the fresh base.
    let settling: Promise<void> = Promise.resolve();
    const refreshBase = async (): Promise<void> => {
      const again = await loadSteps(alert);
      if (again === null) return;
      const n = stepNav(step, statusesOf(again));
      nav.replaceWith(n);
      nav = n;
      const v = again.get(step);
      if (v !== undefined) base = v.revision;
    };
    const track = (work: Promise<void>): void => {
      settling = work.catch(() => undefined);
    };
    const save = h("button", { id: "onboarding-save", type: "submit", class: "fstp-primary" }, [t.label("onboarding.save")]);
    const form = h("form", { id: "onboarding-form", novalidate: true }, [...controls(step, view, admins), save]);
    form.addEventListener(
      "submit",
      (e) => {
        e.preventDefault();
        run();
      },
    );
    const run = busy(save, async () => {
      await settling;
      hush(alert);
      outcome.removeAttribute("data-outcome");
      const sent = values(step, form, view, admins);
      if ("problem" in sent) {
        warn(alert, sent.problem);
        outcome.textContent = "";
        return;
      }
      outcome.textContent = t.label("onboarding.saving");
      const o = await call(
        "tenant.save_step",
        [step],
        { base, values: sent.ok },
        (v) => readSaved(v) !== null,
      );
      if (report(alert, o) || o.kind !== "done") {
        outcome.textContent = "";
        return;
      }
      const saved = readSaved(o.body);
      if (saved === null) return;
      const code = isOutcome(saved.outcome) ? saved.outcome : "invalid_values";
      // Fresh statuses and revision, kept beside the form so the person's values stay.
      const again = await loadSteps(alert);
      if (again !== null) {
        const n = stepNav(step, statusesOf(again));
        nav.replaceWith(n);
        nav = n;
        const v = again.get(step);
        if (v !== undefined) base = v.revision;
      }
      outcome.textContent = outcomeText(code);
      outcome.setAttribute("data-outcome", code);
      if (code === "validated") {
        showNext();
      } else {
        nextBox.replaceChildren();
      }
    });
    const parts: HTMLElement[] = [];
    if (step === "payments") {
      const settings = await call("tenant.settings", [], undefined, (x) => record(x) !== null);
      parts.push(paymentMode(alert, settings.kind === "done" ? record(settings.body)?.["p20"] : null, refreshBase, track));
    }
    parts.push(form, outcome, nextBox);
    if (step === "administrators") {
      // SoD-14, SoD-15: the step validates only with a holder of each
      // signatory role, so the holders show and can be granted here.
      const holders = await loadSignatories(alert);
      if (holders === null) return;
      parts.push(
        signatorySection(alert, admins, holders, async () => {
          await draw();
        }),
        adminSection(alert, admins, async () => {
          await draw();
        }),
      );
    }
    body.replaceChildren(...parts);
    main.setAttribute("data-ready", "true");
  };
  void draw();
}
