// A tenant setting page, `/app/admin/settings/{param}` (R-LG-03; M4
// design sections 2.2 J0 and 3.5).
//
// One page per parameter the cell may set in M4: P-20, P-69, P-70, P-71,
// P-72 and P-74. Every change is high-risk (design section 3.5, interim
// strict reading), so the server asks for a step-up, and a cancelled
// step-up changes nothing. `#setting-current` shows the value in force,
// `#setting-value` holds the new value, and `#setting-save` sends it in
// the `fstp-tenant` codec form. P-71 and P-72 are entered in whole
// seconds and sent in microseconds, with integer arithmetic only.
//
// Every set goes out strictly ascending, as the codec requires
// (`take_name_set`). P-74 names roles as `Role::spec_name` spells them,
// with one checkbox per `fstp_domain` role. "Every role" (`roles: null`)
// is its own radio button, so an empty choice never widens the server.
// A stored role the page has no checkbox for keeps one of its own.

import { h } from "../../core/dom.js";
import type { Label } from "../../core/i18n.js";
import { busy, frame, hush, warn } from "../../creator/frame.js";
import { anyObject, call, report } from "../../creator/ops.js";
import { labelOr, t } from "../i18n.js";
import {
  LOGIN_METHODS,
  MCP_ROLES,
  PAYMENT_MODES,
  mcpValue,
  microsToSeconds,
  nameSet,
  readSettings,
  record,
  roleOfSpecName,
  roleSpecName,
  secondsToMicros,
  type SettingParam,
} from "../model.js";

/** The operation that changes each setting (design section 2.2, J0). */
const OPS: Readonly<Record<SettingParam, string>> = {
  p20: "tenant.set_payment_mode",
  p69: "tenant.set_template_licence",
  p70: "tenant.set_login_methods",
  p71: "tenant.set_step_up_freshness",
  p72: "tenant.set_session_lifetimes",
  p74: "tenant.set_mcp",
};

function strings(v: unknown): string[] {
  return Array.isArray(v) ? (v as unknown[]).filter((x): x is string => typeof x === "string") : [];
}

function methodLabel(m: string): Label {
  return labelOr(`onboarding.p70.${m}`, () => t.label("onboarding.value.unnamed", { value: m }));
}

/** The label of a P-74 role, given in the codec spelling of `Role::spec_name`. */
function mcpRoleLabel(name: string): Label {
  const key = roleOfSpecName(name);
  const unnamed = (): Label => t.label("onboarding.value.unnamed", { value: name });
  return key === null ? unnamed() : labelOr(`onboarding.p74.role.${key}`, unnamed);
}

/** The text of the value in force. */
function currentText(param: SettingParam, v: unknown): string {
  if (v === null || v === undefined) return t.label("onboarding.setting.unset");
  switch (param) {
    case "p20":
      return v === "record_only" ? t.label("onboarding.p20.record_only") : v === "execution" ? t.label("onboarding.p20.execution") : String(v);
    case "p69":
      return typeof v === "string" ? v : t.label("onboarding.setting.unset");
    case "p70":
      return strings(v).map(methodLabel).join(", ");
    case "p71": {
      const s = microsToSeconds(v);
      return s === null ? t.label("onboarding.setting.micros", { value: String(v) }) : t.label("onboarding.setting.seconds", { n: s });
    }
    case "p72": {
      const o = record(v);
      const idle = microsToSeconds(o?.["idle_us"]);
      const absolute = microsToSeconds(o?.["absolute_us"]);
      return idle === null || absolute === null
        ? t.label("onboarding.setting.unreadable")
        : t.label("onboarding.p72.current", { idle, absolute });
    }
    case "p74": {
      const o = record(v);
      if (o === null) return t.label("onboarding.setting.unreadable");
      const roles = o["roles"];
      return t.label("onboarding.p74.current", {
        enabled: o["enabled"] === true ? t.label("onboarding.yes") : t.label("onboarding.no"),
        public_tools: o["public_tools"] === true ? t.label("onboarding.yes") : t.label("onboarding.no"),
        roles:
          roles === null
            ? t.label("onboarding.p74.every_role")
            : !Array.isArray(roles)
              ? t.label("onboarding.setting.unreadable")
              : strings(roles).length === 0
                ? t.label("onboarding.p74.no_role")
                : strings(roles).map(mcpRoleLabel).join(", "),
      });
    }
  }
}

/** One labelled checkbox. */
function box(id: string, value: string, label: Label, on: boolean, disabled = false): HTMLElement {
  return h("div", { class: "fstp-check" }, [
    h("input", { id, type: "checkbox", value, checked: on, disabled }),
    h("label", { for: id }, [label]),
  ]);
}

/** One labelled radio button of group `name`. */
function radio(id: string, name: string, value: string, label: Label, on: boolean): HTMLElement {
  return h("div", { class: "fstp-check" }, [
    h("input", { id, type: "radio", name, value, checked: on }),
    h("label", { for: id }, [label]),
  ]);
}

function inputs(el: HTMLElement): HTMLInputElement[] {
  return Array.from(el.querySelectorAll("input")).filter((x): x is HTMLInputElement => x instanceof HTMLInputElement);
}

/** The control of `param`, and the reader of its value. Null from the reader means a problem. */
function editor(param: SettingParam, v: unknown): { readonly el: HTMLElement; read(): unknown } {
  switch (param) {
    case "p20": {
      const select = h(
        "select",
        { id: "setting-value" },
        PAYMENT_MODES.map((m) =>
          h("option", { value: m, selected: v === m }, [m === "record_only" ? t.label("onboarding.p20.record_only") : t.label("onboarding.p20.execution")]),
        ),
      );
      return {
        el: h("div", { class: "fstp-control" }, [h("label", { for: "setting-value" }, [t.label("onboarding.setting.new")]), select]),
        read: () => (select instanceof HTMLSelectElement ? select.value : null),
      };
    }
    case "p69":
    case "p71": {
      const input = h("input", { id: "setting-value", type: "text", spellcheck: "false", autocomplete: "off" });
      const label = param === "p69" ? t.label("onboarding.p69.new") : t.label("onboarding.p71.new");
      return {
        el: h("div", { class: "fstp-control" }, [h("label", { for: "setting-value" }, [label]), input]),
        read: () => {
          const text = input instanceof HTMLInputElement ? input.value.trim() : "";
          if (param === "p69") return text === "" ? null : text;
          return secondsToMicros(text);
        },
      };
    }
    case "p70": {
      const on = new Set(strings(v));
      const set = h("fieldset", { id: "setting-value", class: "fstp-group" }, [
        h("legend", {}, [t.label("onboarding.setting.new")]),
        ...LOGIN_METHODS.map((m) => box(`setting-value.${m}`, m, methodLabel(m), m === "passkey" || on.has(m), m === "passkey")),
      ]);
      return { el: set, read: () => nameSet(inputs(set).filter((x) => x.checked).map((x) => x.value)) };
    }
    case "p72": {
      const idle = h("input", { id: "setting-value.idle", type: "text", inputmode: "numeric", autocomplete: "off" });
      const absolute = h("input", { id: "setting-value.absolute", type: "text", inputmode: "numeric", autocomplete: "off" });
      const set = h("fieldset", { id: "setting-value", class: "fstp-group" }, [
        h("legend", {}, [t.label("onboarding.setting.new")]),
        h("div", { class: "fstp-control" }, [h("label", { for: "setting-value.idle" }, [t.label("onboarding.p72.idle")]), idle]),
        h("div", { class: "fstp-control" }, [h("label", { for: "setting-value.absolute" }, [t.label("onboarding.p72.absolute")]), absolute]),
      ]);
      return {
        el: set,
        read: () => {
          const i = idle instanceof HTMLInputElement ? secondsToMicros(idle.value) : null;
          const a = absolute instanceof HTMLInputElement ? secondsToMicros(absolute.value) : null;
          return i === null || a === null ? null : { absolute_us: a, idle_us: i };
        },
      };
    }
    case "p74": {
      const o = record(v);
      const stored = o === null ? undefined : o["roles"];
      // An unset or unreadable P-74 picks neither scope, so saving needs an explicit choice.
      const every = stored === null && o !== null;
      const listed = Array.isArray(stored);
      const chosen = new Set(strings(stored));
      // A stored name with no checkbox keeps a checkbox of its own, so a save never drops it.
      const unknown = [...chosen].filter((n) => roleOfSpecName(n) === null);
      const roleBoxes: HTMLElement[] = [
        ...MCP_ROLES.map((r) => box(`setting-value.role.${r}`, roleSpecName(r), mcpRoleLabel(roleSpecName(r)), chosen.has(roleSpecName(r)))),
        ...unknown.map((n, i) => box(`setting-value.role.stored-${i}`, n, mcpRoleLabel(n), true)),
      ];
      const roleBox = h("fieldset", { class: "fstp-group" }, [h("legend", {}, [t.label("onboarding.p74.roles")]), ...roleBoxes]);
      const scope = h("fieldset", { class: "fstp-group" }, [
        h("legend", {}, [t.label("onboarding.p74.scope")]),
        radio("setting-value.scope.every", "setting-value.scope", "every", t.label("onboarding.p74.scope_every"), every),
        radio("setting-value.scope.listed", "setting-value.scope", "listed", t.label("onboarding.p74.scope_listed"), listed),
      ]);
      const set = h("fieldset", { id: "setting-value", class: "fstp-group" }, [
        h("legend", {}, [t.label("onboarding.setting.new")]),
        box("setting-value.enabled", "enabled", t.label("onboarding.p74.enabled"), o?.["enabled"] === true),
        box("setting-value.public_tools", "public_tools", t.label("onboarding.p74.public_tools"), o?.["public_tools"] === true),
        scope,
        roleBox,
      ]);
      const on = (id: string): boolean => inputs(set).some((x) => x.id === id && x.checked);
      return {
        el: set,
        read: () => {
          const everyRole = on("setting-value.scope.every");
          if (!everyRole && !on("setting-value.scope.listed")) return null;
          const picked = inputs(roleBox)
            .filter((x) => x.checked)
            .map((x) => x.value);
          return mcpValue(on("setting-value.enabled"), on("setting-value.public_tools"), everyRole, picked);
        },
      };
    }
  }
}

/** Mounts the page of setting `param`. */
export function mount(param: SettingParam): void {
  const title = labelOr(`onboarding.setting.${param}`, () => t.label("onboarding.setting.unnamed"));
  const { main, alert } = frame({ title, alertId: "setting-error" });
  const current = h("p", { id: "setting-current" });
  const status = h("p", { id: "setting-status", role: "status", class: "fstp-status" });
  const box2 = h("div", { id: "setting-editor" });
  main.append(
    h("p", {}, [labelOr(`onboarding.setting_intro.${param}`, () => t.label("onboarding.setting.intro"))]),
    h("h2", {}, [t.label("onboarding.setting.current")]),
    current,
    box2,
  );

  const load = async (): Promise<void> => {
    const o = await call("tenant.get_settings", [], undefined, (v) => readSettings(v) !== null);
    if (report(alert, o) || o.kind !== "done") return;
    const settings = readSettings(o.body);
    if (settings === null) return;
    current.textContent = currentText(param, settings[param]);
    const ed = editor(param, settings[param]);
    const save = h("button", { id: "setting-save", type: "button", class: "fstp-primary" }, [t.label("onboarding.setting.save")]);
    save.addEventListener(
      "click",
      busy(save, async () => {
        hush(alert);
        const value = ed.read();
        if (value === null) {
          warn(alert, t.label("onboarding.setting.invalid"));
          return;
        }
        const s = await call(OPS[param], [param], { value }, anyObject);
        if (report(alert, s)) return;
        status.textContent = t.label("onboarding.setting.saved");
        const again = await call("tenant.get_settings", [], undefined, (v) => readSettings(v) !== null);
        const fresh = again.kind === "done" ? readSettings(again.body) : null;
        if (fresh !== null) current.textContent = currentText(param, fresh[param]);
      }),
    );
    box2.replaceChildren(ed.el, save, status);
    main.setAttribute("data-ready", "true");
  };
  void load();
}
