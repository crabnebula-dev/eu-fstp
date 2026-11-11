// The contract page (lane L-UI1; M5 design sections 3, 5 and 6;
// `docs/design/10-post-grant-screens.md` "Contracts after negotiation"):
// the versions with their signature state beside each badge (I-96), clause
// changes (R-CT-04), sending, signing through the P-30 cascade, advanced
// signature approval, and declining before a grantee signature (R-NG-04).
//
// The page never creates a signature. It asks the cell to sign through
// the signing service for the route the person chose (I-30), and the
// cell decides who may sign (SoD-03).

import { h, type Child } from "../core/dom.js";
import type { I18n } from "../core/i18n.js";
import { frame, guarded, idRoute, readOp, selectEl, type JudgingPage } from "../reviewer/kit.js";
import {
  GRANT_PATHS,
  act,
  actionButton,
  anyObject,
  badge,
  buttonEl,
  can,
  facts,
  formEl,
  labels,
  link,
  onSubmit,
  rolesOrNull,
  section,
  textField,
  type Frame,
  type PageEnv,
} from "../grant/kit.js";
import {
  ROUTES,
  advancedBody,
  changeBody,
  decideBody,
  decodeContract,
  decodeDrawn,
  parseClause,
  reasonBody,
  signBody,
  type ContractView,
  type Route,
  type Version,
} from "../grant/models.js";

const STATES = ["drafted", "sent", "signed_by_grantee", "effective", "amendment_pending", "superseded", "terminated"];

function stateBadge(t: I18n, s: string): HTMLElement {
  return badge(STATES.includes(s) ? t.label(`contract.state.${s}`) : s, s);
}

function versionSection(t: I18n, v: Version): HTMLElement {
  return section(`contract-version-${String(v.version)}`, t.label("contract.version", { n: String(v.version) }), [
    facts([
      [t.label("contract.version_state"), stateBadge(t, v.state)],
      [t.label("contract.version_revisions"), String(v.revisions)],
      [t.label("contract.version_digest"), v.digest === null ? "-" : h("code", {}, [v.digest])],
    ]),
    h("table", { id: `contract-parties-${String(v.version)}` }, [
      h("caption", {}, [t.label("contract.parties", { n: String(v.version) })]),
      h("thead", {}, [
        h("tr", {}, [
          h("th", { scope: "col" }, [t.label("contract.party_col")]),
          h("th", { scope: "col" }, [t.label("contract.party_role")]),
          h("th", { scope: "col" }, [t.label("contract.party_signed")]),
        ]),
      ]),
      h(
        "tbody",
        {},
        v.parties.map((p) =>
          h("tr", { "data-party": p.field }, [
            h("th", { scope: "row" }, [p.field, p.mine ? ` ${t.label("contract.you")}` : ""]),
            h("td", {}, [t.label(`contract.role.${p.role}`)]),
            h("td", {}, [badge(p.signed ? t.label("contract.signed") : t.label("contract.not_signed"), p.signed ? "signed" : "unsigned")]),
          ]),
        ),
      ),
    ]),
    h("p", { class: "text-sm" }, [t.label("contract.version_immutable")]),
  ]);
}

function changesSection(env: PageEnv, t: I18n, f: Frame, c: ContractView, v: Version, reload: () => Promise<void>): HTMLElement {
  const contract = c.contract ?? "";
  const items = v.open_changes.map((n) => {
    const decide = (accept: boolean): HTMLButtonElement =>
      actionButton(`contract-change-${accept ? "accept" : "reject"}-${String(n)}`, t.label(accept ? "contract.changes.accept" : "contract.changes.reject", { n: String(n) }), f, async () => {
        f.clearAlert();
        const r = await act(env, "contract.decide_change", { contract, clause: String(n) }, decideBody(accept), anyObject);
        if (!r.ok) {
          f.problem(r.problem);
          return;
        }
        await reload();
        f.status(t.label("contract.changes.accepted"));
      });
    return h("li", { "data-change": String(n) }, [t.label("contract.changes.open", { n: String(n) }), " ", decide(true), " ", decide(false)]);
  });
  return section("contract-changes", t.label("contract.changes.heading"), [
    h("p", {}, [t.label("contract.changes.intro")]),
    items.length === 0 ? h("p", {}, [t.label("contract.changes.none")]) : h("ul", { class: "fstp-list" }, items),
  ]);
}

function proposeSection(env: PageEnv, t: I18n, f: Frame, c: ContractView, reload: () => Promise<void>): HTMLElement {
  const clause = textField("contract-propose-clause", t.label("contract.propose.clause"), { inputmode: "numeric" });
  const text = textField("contract-propose-text", t.label("contract.propose.text"));
  const submit = buttonEl("contract-propose-submit", "submit", t.label("contract.propose.submit"));
  const form = formEl("contract-propose-form", [clause.root, text.root, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const n = parseClause(clause.control.value);
    if (n === null || text.control.value.trim() === "") {
      f.alert(t.label("contract.propose.err"));
      return;
    }
    const r = await act(env, "contract.propose_change", { contract: c.contract ?? "" }, changeBody(n, text.control.value), anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("contract.propose.done"));
  });
  return section("contract-propose", t.label("contract.propose.heading"), [form]);
}

function signSection(env: PageEnv, t: I18n, f: Frame, c: ContractView, reload: () => Promise<void>): HTMLElement {
  const route = selectEl(
    { id: "contract-sign-route", name: "route" },
    ROUTES.map((r) => h("option", { value: r }, [t.label(`contract.sign.route.${r}`)])),
  );
  const submit = buttonEl("contract-sign-submit", "submit", t.label("contract.sign.submit"));
  const form = formEl("contract-sign-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "contract-sign-route" }, [t.label("contract.sign.route")]), route]),
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const chosen = ROUTES.find((r) => r === route.value) as Route | undefined;
    if (chosen === undefined) {
      return;
    }
    const r = await act(env, "contract.sign", { contract: c.contract ?? "" }, signBody(chosen), anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("contract.sign.done"));
  });
  return section("contract-sign", t.label("contract.sign.heading"), [h("p", {}, [t.label("contract.sign.intro")]), form]);
}

function advancedSection(env: PageEnv, t: I18n, f: Frame, c: ContractView, v: Version, reload: () => Promise<void>): HTMLElement {
  const party = selectEl(
    { id: "contract-advanced-party", name: "party" },
    v.parties.map((p) => h("option", { value: p.field }, [p.field])),
  );
  const reason = textField("contract-advanced-reason", t.label("contract.advanced.reason"));
  const submit = buttonEl("contract-advanced-submit", "submit", t.label("contract.advanced.submit"));
  const form = formEl("contract-advanced-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "contract-advanced-party" }, [t.label("contract.advanced.party")]), party]),
    reason.root,
    submit,
  ]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body = advancedBody(party.value, reason.control.value);
    if (!body.ok) {
      f.alert(t.label("contract.advanced.err"));
      return;
    }
    const r = await act(env, "contract.approve_advanced", { contract: c.contract ?? "" }, body.value, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("contract.advanced.done"));
  });
  return section("contract-advanced", t.label("contract.advanced.heading"), [h("p", {}, [t.label("contract.advanced.intro")]), form]);
}

function declineSection(env: PageEnv, t: I18n, f: Frame, c: ContractView, proposal: string): HTMLElement {
  const reason = textField("contract-decline-reason", t.label("contract.decline.reason"));
  const submit = buttonEl("contract-decline-submit", "submit", t.label("contract.decline.submit"));
  const form = formEl("contract-decline-form", [reason.root, submit]);
  onSubmit(f, form, submit, async () => {
    f.clearAlert();
    const body = reasonBody(reason.control.value);
    if (body === null) {
      f.alert(t.label("contract.decline.err"));
      return;
    }
    const r = await act(env, "contract.decline", { contract: c.contract ?? "" }, body, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    f.status(t.label("contract.decline.done"));
    env.navigate(GRANT_PATHS.grant(proposal));
  });
  return section("contract-decline", t.label("contract.decline.heading"), [h("p", {}, [t.label("contract.decline.intro")]), form]);
}

async function mountContract(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const f = frame(env, t, t.label("contract.title", { id: proposal }));
  const render = async (): Promise<void> => {
    const r = await readOp(env, "contract.view", { proposal }, (v): v is ContractView => decodeContract(v) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("contract.back"))])]);
      return;
    }
    const c = decodeContract(r.data);
    if (c === null) {
      return;
    }
    const roles = await rolesOrNull();
    const pm = can(roles, "programme_manager");
    const lead = can(roles, "applicant", proposal);
    const body: Child[] = [h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("contract.back"))])];
    if (c.contract === null || c.status === null) {
      body.push(h("p", { id: "contract-none" }, [t.label("contract.none")]));
      if (pm) {
        const b = actionButton("contract-draft-submit", t.label("contract.draft.submit"), f, async () => {
          f.clearAlert();
          const d = await act(env, "contract.draft", { proposal }, {}, (v) => decodeDrawn(v, "contract"));
          if (!d.ok) {
            f.problem(d.problem);
            return;
          }
          await render();
          f.status(t.label("contract.draft.done"));
        });
        b.className = "fstp-primary";
        body.push(section("contract-draft", t.label("contract.draft.heading"), [h("p", {}, [t.label("contract.draft.intro")]), b]));
      }
      f.show(body);
      return;
    }
    body.push(h("p", { id: "contract-status" }, [t.label("contract.status"), ": ", stateBadge(t, c.status)]));
    const latest = c.versions[c.versions.length - 1];
    for (const v of c.versions) {
      body.push(versionSection(t, v));
    }
    if (latest !== undefined) {
      const editable = latest.state === "drafted" || latest.state === "sent";
      const mine = latest.parties.some((p) => p.mine && !p.signed);
      const signing = latest.state === "sent" || latest.state === "signed_by_grantee";
      const anySigned = c.versions.some((v) => v.parties.some((p) => p.signed));
      if (editable && (pm || lead)) {
        body.push(changesSection(env, t, f, c, latest, render));
        body.push(proposeSection(env, t, f, c, render));
      }
      if (latest.state === "drafted" && pm && latest.open_changes.length === 0) {
        const b = actionButton("contract-send-submit", t.label("contract.send.submit"), f, async () => {
          f.clearAlert();
          const s = await act(env, "contract.send", { contract: c.contract ?? "" }, {}, anyObject);
          if (!s.ok) {
            f.problem(s.problem);
            return;
          }
          await render();
          f.status(t.label("contract.send.done"));
        });
        b.className = "fstp-primary";
        body.push(section("contract-send", t.label("contract.send.heading"), [h("p", {}, [t.label("contract.send.intro")]), b]));
      }
      if (signing && mine) {
        body.push(signSection(env, t, f, c, render));
      }
      if (signing && pm) {
        body.push(advancedSection(env, t, f, c, latest, render));
      }
      if (editable && lead && !anySigned) {
        body.push(declineSection(env, t, f, c, proposal));
      }
      if (c.status === "terminated") {
        body.push(h("p", { id: "contract-sealed" }, [t.label("contract.sealed_off")]));
      }
    }
    f.show(body);
  };
  await guarded(f, render);
}

/** The contract pages, each with its route below `/app/`. */
export const CONTRACT_PAGES: readonly JudgingPage[] = [
  { route: idRoute("contract.view", "/app/grants/{proposal}/contract", ["proposal"]), mount: (env, p) => mountContract(env, p) },
];

