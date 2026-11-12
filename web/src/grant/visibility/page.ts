// The grantee visibility screen (M9 lane P2; R-PB-02, R-PB-03, I-41,
// I-42, I-43; `public-transparency.md` Opt-in model).
//
// The grantee lead chooses, for the funded and the finished phase, what
// the public pages show about the grant. Each phase shows the programme
// maximum (P-50, P-51), the current choice and the level the public
// pages apply: the lower of the two. A phase opens once the grant's state
// allows it (I-41). A minor-flagged grant takes only Hidden (I-42).
//
// The title, summary and grantee name are written here by the grantee.
// They go to the cell as text and the cell stores them as public texts,
// so no proposal text reaches the public pages (R-PB-03). The cell
// decides every choice again, and a refusal shows its rule.

import { h, type Child } from "../../core/dom.js";
import type { I18n, Label } from "../../core/i18n.js";
import { checkbox, frame, guarded, idRoute, radio, readOp, textArea, type JudgingPage } from "../../reviewer/kit.js";
import { GRANT_PATHS, act, actionButton, anyObject, buttonEl, formEl, labels, link, onSubmit, section, textField, type Frame, type PageEnv } from "../kit.js";
import {
  LEVELS,
  decodePublicity,
  rank,
  setBody,
  shownFields,
  withdrawBody,
  type Level,
  type Phase,
  type PhaseView,
  type Publicity,
} from "./model.js";

function levelName(t: I18n, l: Level): Label {
  return t.label(`grant.visibility.level.${l}`);
}

function fieldsLine(t: I18n, l: Level): HTMLElement {
  const fields = shownFields(l);
  if (fields.length === 0) {
    return h("p", { class: "text-sm" }, [t.label("grant.visibility.shows_nothing")]);
  }
  const names = fields.map((f) => t.label(`grant.visibility.field.${f}`)).join(", ");
  return h("p", { class: "text-sm" }, [t.label("grant.visibility.shows", { fields: names })]);
}

/** The form and the state of one phase. */
function phaseSection(env: PageEnv, t: I18n, f: Frame, v: Publicity, phase: Phase, reload: () => Promise<void>): HTMLElement {
  const p: PhaseView = phase === "funded" ? v.funded : v.finished;
  const max = phase === "funded" ? v.maxFunded : v.maxFinished;
  const id = `grant-visibility-${phase}`;
  const body: Child[] = [h("p", { "data-max": max }, [t.label("grant.visibility.max", { level: levelName(t, max) })])];
  if (p.choice === null) {
    body.push(h("p", { id: `${id}-none` }, [t.label("grant.visibility.none")]));
  } else {
    body.push(
      h("p", { id: `${id}-current`, "data-level": p.choice.level }, [t.label("grant.visibility.current", { level: levelName(t, p.choice.level) })]),
      h("p", { id: `${id}-effective`, "data-effective": p.choice.effective }, [t.label("grant.visibility.effective", { level: levelName(t, p.choice.effective) })]),
      fieldsLine(t, p.choice.effective),
    );
  }
  if (!p.open) {
    body.push(h("p", { id: `${id}-closed` }, [t.label(`grant.visibility.${phase}.closed`)]));
    return section(id, t.label(`grant.visibility.${phase}.heading`), body);
  }
  // The levels: a minor-flagged grant takes Hidden only (I-42). A level above the
  // programme maximum stays selectable, and the public pages cap it (I-43).
  const current = p.choice?.level ?? "hidden";
  const radios = LEVELS.map((l) => {
    const name = rank(l) > rank(max) && l !== "hidden" ? t.label("grant.visibility.level_above_max", { level: levelName(t, l) }) : levelName(t, l);
    const r = radio(`${id}-level-${l}`, `${id}-level`, l, name);
    r.control.checked = l === current;
    if (v.minor && l !== "hidden") {
      r.control.disabled = true;
    }
    return r;
  });
  const legend = h("legend", {}, [t.label("grant.visibility.level")]);
  const levels = h("fieldset", { id: `${id}-levels` }, [legend, ...radios.map((r) => r.root)]);
  const title = textField(`${id}-title`, t.label("grant.visibility.title_label"), { value: p.choice?.title ?? "" });
  const summary = textArea(`${id}-summary`, t.label("grant.visibility.summary_label"));
  summary.control.value = p.choice?.summary ?? "";
  const grantee = textField(`${id}-grantee`, t.label("grant.visibility.grantee_label"), { value: p.choice?.grantee ?? "" });
  const fields: Child[] = [levels, title.root, summary.root, grantee.root];
  const boxes: { readonly id: string; readonly control: HTMLInputElement }[] = [];
  if (phase === "finished" && v.deliverables.length > 0) {
    const items = v.deliverables.map((d) => {
      const c = checkbox(`${id}-deliverable-${d.id}`, `${id}-deliverables`, t.label("grant.visibility.deliverable", { id: d.id, licence: d.licence }));
      c.control.checked = p.choice?.deliverables.includes(d.id) ?? false;
      boxes.push({ id: d.id, control: c.control });
      return c.root;
    });
    fields.push(h("fieldset", { id: `${id}-deliverables` }, [h("legend", {}, [t.label("grant.visibility.deliverables")]), ...items]));
  }
  const save = buttonEl(`${id}-save`, "submit", t.label("grant.visibility.save"));
  save.className = "fstp-primary";
  const form = formEl(`${id}-form`, [...fields, save]);
  onSubmit(f, form, save, async () => {
    f.clearAlert();
    const chosen = radios.find((r) => r.control.checked)?.control.value;
    const level: Level = LEVELS.find((l) => l === chosen) ?? "hidden";
    const built = setBody(phase, {
      level,
      title: title.control.value,
      summary: summary.control.value,
      grantee: grantee.control.value,
      deliverables: boxes.filter((b) => b.control.checked).map((b) => b.id),
    });
    if (built === null) {
      f.alert(t.label("grant.visibility.err_texts"));
      return;
    }
    const r = await act(env, "grant.publicity.set", { proposal: v.proposal }, built, anyObject);
    if (!r.ok) {
      f.problem(r.problem);
      return;
    }
    await reload();
    f.status(t.label("grant.visibility.saved"));
  });
  body.push(form);
  if (p.choice !== null) {
    body.push(
      actionButton(`${id}-withdraw`, t.label("grant.visibility.withdraw"), f, async () => {
        f.clearAlert();
        const r = await act(env, "grant.publicity.withdraw", { proposal: v.proposal }, withdrawBody(phase), anyObject);
        if (!r.ok) {
          f.problem(r.problem);
          return;
        }
        await reload();
        f.status(t.label("grant.visibility.withdrawn"));
      }),
    );
  }
  return section(id, t.label(`grant.visibility.${phase}.heading`), body);
}

async function mountVisibility(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = labels(env);
  const proposal = params["proposal"] ?? "";
  const f = frame(env, t, t.label("grant.visibility.title", { id: proposal }));
  const render = async (): Promise<void> => {
    const r = await readOp(env, "grant.publicity.view", { proposal }, (x): x is Publicity => decodePublicity(x) !== null);
    if (!r.ok) {
      f.problem(r.problem);
      f.show([h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("grant.visibility.back"))])]);
      return;
    }
    const v = decodePublicity(r.data);
    if (v === null) {
      return;
    }
    const body: Child[] = [
      h("p", {}, [t.label("grant.visibility.intro")]),
      h("p", { class: "text-sm", id: "grant-visibility-note-platform" }, [t.label("grant.visibility.note_platform")]),
      h("p", { class: "text-sm" }, [t.label("grant.visibility.note_reporting")]),
    ];
    if (v.minor) {
      body.push(h("p", { id: "grant-visibility-minor", role: "note" }, [t.label("grant.visibility.minor")]));
    }
    body.push(phaseSection(env, t, f, v, "funded", render), phaseSection(env, t, f, v, "finished", render));
    body.push(h("p", {}, [link(GRANT_PATHS.grant(proposal), t.label("grant.visibility.back"))]));
    f.show(body);
  };
  await guarded(f, render);
}

/** The visibility page, below the grant it belongs to. */
export const VISIBILITY_PAGES: readonly JudgingPage[] = [
  {
    route: idRoute("grant.visibility", "/app/grants/{proposal}/visibility", ["proposal"]),
    mount: (env, p) => mountVisibility(env, p),
  },
];
