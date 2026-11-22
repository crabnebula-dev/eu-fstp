// The pages of the programme set-up wizard and the set-up progress page
// (`docs/design/11-programme-setup-wizard.md`; R-PG-01, I-66, I-67,
// SoD-01 to SoD-09, R-PC-03, ADR-021).
//
// - `/app/setup/new`, stage 1: a tenant admin opens the draft
//   (`creator.open_draft`, with its step-up) and invites the programme
//   manager by exact email (`creator.invite`, with the role dates).
// - `/app/programmes/{p}/setup/{stage}`, stages 2 to 7: the programme
//   manager fills the creator steps of each stage (`creator.save_fields`),
//   builds the team (`creator.invite`), and requests activation
//   (`creator.request_activation`) on Review and confirm.
// - `/app/programmes/{p}/setup/progress`: the nine milestones and the team
//   status, from the draft, the report, the invitation list and
//   `call.list`.
//
// The wizard only drives the creator operations. It forks none of their
// logic: the field editors, the draft and report reads and the review
// parts are the creator's own. ADR-021: before activation the cell
// refuses `creator.open_draft`, `creator.invite` and `roles.grant`, and
// the page says so in words through the creator's outcome text. The
// home page shows the way here only once the organisation is active.

import { h } from "../core/dom.js";
import { clearProblems, fieldEditor, showProblems, type FieldEditor, type Problem } from "../creator/editor.js";
import { fieldsOf, type FieldDef } from "../creator/fields.js";
import { busy, frame, go, hush, ready, statusRegion, warn } from "../creator/frame.js";
import { labelOr, t as ct } from "../creator/i18n.js";
import { canonicalJson, draftValue, readOpened, readProgrammes, readReport, stepOfResult, type Draft, type Report } from "../creator/model.js";
import { anyObject, call, report } from "../creator/ops.js";
import { PATHS, checkText, loadDraft, loadReport, queue } from "../creator/pages/common.js";
import { offerOverride } from "../creator/pages/approvals.js";
import { reviewParts } from "../creator/pages/review.js";
import { STUDIO_PATHS } from "../studio/view.js";
import { readWaitingCalls } from "../studio/model.js";
import { record } from "../creator/model.js";
import { plausibleEmail, readInvitations, type InvitationRow } from "../people/model.js";
import { roleLabel } from "../people/i18n.js";
import { attachHelp, labelWithHelp } from "../help/help.js";
import { t } from "./i18n.js";
import {
  ROLE_GROUPS,
  SETUP_PATHS,
  STAGES,
  datesProblem,
  endMicros,
  managers,
  milestones,
  nextStage,
  previousStage,
  refusedLine,
  sodLines,
  stageStates,
  startMicros,
  todayOf,
  type DraftStageId,
  type StageState,
} from "./model.js";
import {
  approverNotice,
  approverOverrideSlot,
  link,
  milestoneList,
  milestoneStrip,
  numberedName,
  stageBar,
  stageKicker,
  stageName,
  statusTable,
  sodItems,
  summaryBody,
  summaryPanel,
  teamTables,
  wizardLayout,
} from "./view.js";

/** The team of `p`, or null when the read failed. A failure is not shown: a page reads the team for its summary only. */
async function loadTeam(p: string): Promise<InvitationRow[] | null> {
  const o = await call("creator.invitations", [p], undefined, (v) => readInvitations(v) !== null);
  return o.kind === "done" ? readInvitations(o.body) : null;
}

/** The report of `p`, or null, with no alert: a draft whose report is not ready leaves later stages locked. */
async function quietReport(p: string): Promise<Report | null> {
  const o = await call("creator.get_report", [p], undefined, (v) => readReport(v) !== null);
  return o.kind === "done" ? readReport(o.body) : null;
}

/** The stage states of a draft. */
function statesOf(d: Draft | null, r: Report | null): readonly StageState[] {
  return stageStates(r, d !== null, d !== null && (d.activationRequested || d.status === "active"));
}

/** A labelled control in the token sheet's `.field` form, with its help (SA-13). */
function field(id: string, label: string, control: HTMLElement, hint: string | null, help: string): HTMLElement {
  const parts: HTMLElement[] = labelWithHelp(id, label, help);
  if (hint !== null) {
    parts.push(h("span", { class: "hint", id: `${id}-hint` }, [hint]));
    control.setAttribute("aria-describedby", `${id}-hint`);
  }
  return h("div", { class: "field" }, [...parts, control]);
}

/** The role date controls: start, required, and an optional end. */
function dateControls(prefix: string): { readonly root: HTMLElement; readonly start: HTMLInputElement; readonly end: HTMLInputElement } {
  const start = h("input", { id: `${prefix}-start`, type: "date", required: true, value: todayOf(Date.now()) }) as HTMLInputElement;
  const end = h("input", { id: `${prefix}-end`, type: "date" }) as HTMLInputElement;
  const root = h("div", { class: "row-2" }, [
    field(`${prefix}-start`, t.label("setup.dates.start"), start, t.label("setup.dates.start_hint"), "help.wizard.role_start"),
    field(`${prefix}-end`, t.label("setup.dates.end"), end, t.label("setup.dates.end_hint"), "help.wizard.role_end"),
  ]);
  return { root, start, end };
}

/**
 * The `start` and `end` members of a `creator.invite` body from the date
 * controls, or shows why not in `alert` and returns null.
 */
function datesBody(alert: HTMLElement, start: HTMLInputElement, end: HTMLInputElement): { start: string; end: string | null } | null {
  const problem = datesProblem(start.value, end.value);
  if (problem !== null) {
    warn(alert, t.label(problem === "start" ? "setup.dates.start_invalid" : problem === "end" ? "setup.dates.end_invalid" : "setup.dates.order"));
    (problem === "start" ? start : end).focus();
    return null;
  }
  const s = startMicros(start.value);
  if (s === null) return null;
  return { start: s, end: end.value === "" ? null : endMicros(end.value) };
}

// ---------------------------------------------------------------------------
// Stage 1, Start
// ---------------------------------------------------------------------------

/** Mounts `/app/setup/new`: a tenant admin opens the draft and invites its programme manager. */
export function mountStart(): void {
  const { main, alert } = frame({ title: t.label("setup.title.new"), alertId: "setup-error" });
  const states = statesOf(null, null);
  const name = h("input", { id: "setup-name", type: "text", autocomplete: "off", required: true }) as HTMLInputElement;
  const email = h("input", { id: "setup-pm-email", type: "email", autocomplete: "off", spellcheck: "false", required: true }) as HTMLInputElement;
  const dates = dateControls("setup-pm");
  const submit = h("button", { id: "setup-open", type: "button", class: "fstp-primary" }, [t.label("setup.start.submit")]);
  const status = statusRegion("setup-start-status");
  const existing = h("ul", { id: "setup-existing" });

  submit.addEventListener(
    "click",
    busy(submit, async () => {
      hush(alert);
      const programmeName = name.value.trim();
      if (programmeName === "") {
        warn(alert, t.label("setup.start.name_invalid"));
        name.setAttribute("aria-invalid", "true");
        name.focus();
        return;
      }
      name.removeAttribute("aria-invalid");
      const address = email.value.trim();
      if (!plausibleEmail(address)) {
        warn(alert, t.label("setup.email.invalid"));
        email.setAttribute("aria-invalid", "true");
        email.focus();
        return;
      }
      email.removeAttribute("aria-invalid");
      const d = datesBody(alert, dates.start, dates.end);
      if (d === null) return;
      const o = await call("creator.open_draft", [], { name: programmeName }, (v) => readOpened(v) !== null);
      if (report(alert, o) || o.kind !== "done") return;
      const p = readOpened(o.body);
      if (p === null) return;
      status.textContent = t.label("setup.start.opened", { programme: p });
      const invite = await call("creator.invite", [p], { email: address, role: "programme_manager", start: d.start, end: d.end }, anyObject);
      if (report(alert, invite)) {
        warn(alert, t.label("setup.start.invite_failed", { programme: p }));
        return;
      }
      go(SETUP_PATHS.progress(p));
    }),
  );

  const stage = h("section", { id: "setup-stage", "aria-labelledby": "setup-stage-title", "data-stage": "start" }, [
    h("p", { class: "card-kicker" }, [stageKicker("start")]),
    h("h2", { id: "setup-stage-title" }, [stageName("start")]),
    field("setup-name", t.label("setup.start.name"), name, t.label("setup.start.name_hint"), "help.wizard.programme_name"),
    h("div", { class: "field" }, [
      h("p", {}, [h("strong", {}, [t.label("setup.summary.profile")]), " ", t.label("setup.summary.profile_value")]),
      h("p", { class: "hint" }, [t.label("setup.start.profile_hint")]),
    ]),
    h("section", { class: "step-block", "aria-labelledby": "setup-pm-title" }, [
      h("h3", { id: "setup-pm-title" }, [t.label("setup.start.pm.title")]),
      h("p", {}, [t.label("setup.start.pm.intro")]),
      field("setup-pm-email", t.label("setup.email"), email, t.label("setup.email.hint"), "help.wizard.manager_email"),
      h("p", { class: "callout callout--warning" }, [t.label("setup.start.pm.self")]),
      dates.root,
    ]),
    approverNotice(),
    h("h3", {}, [t.label("setup.start.next.title")]),
    h("ol", {}, [1, 2, 3].map((n) => h("li", {}, [t.label(`setup.start.next.${n}`)]))),
    h("p", { class: "stepup-note" }, [t.label("setup.stepup_note")]),
    h("div", { class: "btn-row" }, [submit]),
    status,
    h("p", { class: "text-sm muted" }, [t.label("setup.saved_note")]),
  ]);

  main.append(
    h("p", { id: "setup-active", class: "callout callout--success" }, [t.label("setup.start.active")]),
    h("p", {}, [t.label("setup.start.intro")]),
    stageBar(null, states, "start"),
    wizardLayout(stage, summaryPanel(states, { programme: null, draft: null, team: null }, "start")),
    h("section", { id: "setup-existing-section", "aria-labelledby": "setup-existing-title" }, [
      h("h2", { id: "setup-existing-title" }, [t.label("setup.start.existing.title")]),
      existing,
    ]),
  );

  void (async () => {
    const o = await call("creator.list_programmes", [], undefined, (v) => readProgrammes(v) !== null);
    const rows = o.kind === "done" ? (readProgrammes(o.body) ?? []) : [];
    existing.replaceChildren(
      ...rows.map((r) => h("li", { "data-programme": r.id }, [link(SETUP_PATHS.progress(r.id), t.label("setup.start.existing.link", { name: r.name }))])),
    );
    if (rows.length === 0) existing.append(h("li", {}, [t.label("setup.start.existing.none")]));
    ready(main);
  })();
}

// ---------------------------------------------------------------------------
// Stages 2 to 6
// ---------------------------------------------------------------------------

/** One field editor on a stage page. */
interface Shown {
  readonly key: string;
  readonly editor: FieldEditor;
  pending: boolean;
}

/** The value a pending narrative shows, as the creator step page shows it. */
function pendingValue(f: FieldDef, text: string): unknown {
  if (f.shape.t === "text") return text;
  try {
    return JSON.parse(text) as unknown;
  } catch {
    return null;
  }
}

/** The page frame of a stage of programme `p`: heading, stage bar and the layout. */
function stageFrame(p: string, id: DraftStageId): {
  readonly main: HTMLElement;
  readonly alert: HTMLElement;
  readonly stage: HTMLElement;
  show(d: Draft | null, r: Report | null, team: readonly InvitationRow[] | null): void;
} {
  const { main, alert } = frame({ title: t.label("setup.title"), alertId: "setup-error" });
  document.title = t.label("setup.document_title", { stage: numberedName(id) });
  let bar = stageBar(p, statesOf(null, null), id);
  const stage = h("section", { id: "setup-stage", "aria-labelledby": "setup-stage-title", "data-stage": id }, [
    h("p", { class: "card-kicker" }, [stageKicker(id)]),
    h("h2", { id: "setup-stage-title" }, [stageName(id)]),
    h("p", {}, [t.label(`setup.intro.${id}`)]),
  ]);
  let summary = summaryPanel(statesOf(null, null), { programme: p, draft: null, team: null }, id);
  const layout = wizardLayout(stage, summary);
  main.append(bar, layout);
  return {
    main,
    alert,
    stage,
    show(d, r, team) {
      const states = statesOf(d, r);
      const freshBar = stageBar(p, states, id);
      bar.replaceWith(freshBar);
      bar = freshBar;
      const freshSummary = summaryPanel(states, { programme: p, draft: d, team }, id);
      summary.replaceWith(freshSummary);
      summary = freshSummary;
    },
  };
}

/** Mounts stage `id` of programme `p`, for the stages that hold creator fields. */
export function mountStage(p: string, id: DraftStageId): void {
  if (id === "review") {
    mountReview(p);
    return;
  }
  const s = STAGES.find((x) => x.id === id);
  if (s === undefined) return;
  const f = stageFrame(p, id);
  const { main, alert, stage } = f;
  const write = queue();
  const fieldsBox = h("div", { id: "setup-fields" });
  const checks = h("ul", { id: "setup-checks", "aria-labelledby": "setup-checks-title" });
  const status = statusRegion("setup-stage-status");
  const locked = h("div", {});
  let draft: Draft | null = null;
  let team: InvitationRow[] | null = null;
  let shown: Shown[] = [];

  const render = (d: Draft): void => {
    clearProblems(fieldsBox);
    shown = [];
    const blocks = s.steps.map((step) => {
      const editors = fieldsOf(step).map((def) => {
        const pendingText = Object.hasOwn(d.pendingNarratives, def.key) ? d.pendingNarratives[def.key] : undefined;
        const value = pendingText === undefined ? draftValue(d, def.key) : pendingValue(def, pendingText);
        const editor = fieldEditor(def, value, { mark: true, prefix: `f.${def.key}` });
        const item: Shown = { key: def.key, editor, pending: pendingText !== undefined };
        if (item.pending) addAccept(item);
        shown.push(item);
        return editor.root;
      });
      const title = labelOr(`creator.step.${step}`, () => ct.label("creator.step.unnamed"));
      return h("section", { class: "step-block", "data-step": step, "aria-labelledby": `setup-step-${step}` }, [
        h("h3", { id: `setup-step-${step}` }, [title]),
        ...editors,
      ]);
    });
    fieldsBox.replaceChildren(...blocks);
  };

  /** The template note and the accept button of a pending narrative (TH-49). */
  const addAccept = (item: Shown): void => {
    const note = h("p", { class: "fstp-note" }, [t.label("setup.narrative.pending")]);
    const accept = h("button", { type: "button", "data-action": "accept-narrative" }, [t.label("setup.narrative.accept")]);
    accept.addEventListener("click", () => {
      accept.remove();
      void write(async () => {
        const d = draft;
        if (d === null) return;
        hush(alert);
        const o = await call("creator.accept_narrative", [p, item.key], { base: d.revision }, anyObject);
        if (report(alert, o)) {
          item.editor.notes.append(accept);
          return;
        }
        draft = (await loadDraft(p, alert)) ?? draft;
        item.pending = false;
        note.textContent = t.label("setup.narrative.accepted");
      });
    });
    item.editor.notes.append(note, accept);
  };

  /** The fields a person changed, or the problems of what they entered. */
  const changes = (): { readonly fields: { field: string; value: unknown }[]; readonly problems: Problem[] } => {
    const fields: { field: string; value: unknown }[] = [];
    const problems: Problem[] = [];
    for (const x of shown) {
      if (!x.editor.touched()) continue;
      const r = x.editor.read();
      if (!r.ok) {
        problems.push(...r.problems);
      } else if (canonicalJson(r.value) !== x.editor.initial || x.pending) {
        fields.push({ field: x.key, value: r.value });
      }
    }
    return { fields, problems };
  };

  /** Shows the checks of this stage's steps, and whether it validates. */
  const showChecks = (r: Report | null): boolean => {
    const mine = r === null ? [] : r.results.filter((x) => s.steps.some((st) => st === stepOfResult(x)));
    checks.replaceChildren(
      ...mine.map((x) =>
        h("li", { "data-check": x.check, "data-severity": x.severity }, [
          h("strong", {}, [x.severity === "failure" ? ct.label("creator.severity.failure") : ct.label("creator.severity.warning")]),
          " ",
          checkText(x.check, x.values, x.field),
        ]),
      ),
    );
    if (mine.length === 0) checks.append(h("li", {}, [t.label("setup.checks.none")]));
    const st = statesOf(draft, r).find((x) => x.id === id);
    return r !== null && st !== undefined && st.condition === "done";
  };

  const prev = previousStage(id);
  const next = nextStage(id);
  const save = h("button", { id: "setup-continue", type: "button", class: "fstp-primary" }, [t.label("setup.continue")]);
  save.addEventListener(
    "click",
    busy(save, () =>
      write(async () => {
        const d = draft;
        if (d === null) return;
        hush(alert);
        status.removeAttribute("data-state");
        status.textContent = t.label("setup.saving");
        clearProblems(fieldsBox);
        const { fields, problems } = changes();
        if (problems.length > 0) {
          warn(alert, ct.label("creator.step.problems"));
          status.setAttribute("data-state", "invalid");
          status.textContent = "";
          showProblems(problems);
          return;
        }
        if (fields.length > 0) {
          const o = await call("creator.save_fields", [p], { base: d.revision, fields }, anyObject);
          if (report(alert, o)) {
            status.setAttribute("data-state", "refused");
            status.textContent = "";
            return;
          }
          const fresh = await loadDraft(p, alert);
          if (fresh === null) return;
          draft = fresh;
          render(fresh);
        }
        const r = await loadReport(p, alert);
        f.show(draft, r, team);
        if (showChecks(r) && next !== null && next !== "start") {
          status.setAttribute("data-state", "saved");
          go(SETUP_PATHS.stage(p, next));
          return;
        }
        status.setAttribute("data-state", "failures");
        status.textContent = t.label("setup.stage_failures");
      }),
    ),
  );

  const actions = h("div", { class: "btn-row" }, [
    ...(prev !== null && prev !== "start" ? [link(SETUP_PATHS.stage(p, prev), t.label("setup.back", { stage: stageName(prev) }), { class: "btn btn--ghost" })] : []),
    save,
  ]);
  stage.append(locked);
  if (id === "programme") {
    stage.append(
      h("p", {}, [link(`${PATHS.start(p)}?then=setup`, ct.label("studio.overview.start_link"), { id: "setup-start-link" })]),
      h("p", {}, [link(STUDIO_PATHS.overview(p), t.label("setup.editor_link"), { id: "setup-editor-link" })]),
    );
  }
  stage.append(fieldsBox);
  const teamBox = h("div", {});
  if (id === "team") stage.append(teamBox);
  stage.append(
    h("h3", { id: "setup-checks-title" }, [t.label("setup.checks.title")]),
    checks,
    actions,
    status,
    h("p", { class: "text-sm muted" }, [t.label("setup.saved_note")]),
  );

  void write(async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    draft = d;
    render(d);
    const r = await quietReport(p);
    team = await loadTeam(p);
    f.show(d, r, team);
    showChecks(r);
    const st = statesOf(d, r).find((x) => x.id === id);
    locked.replaceChildren(...(st?.condition === "locked" ? [h("p", { class: "callout", role: "status", "data-note": "locked" }, [t.label("setup.locked")])] : []));
    if (id === "team") {
      teamBox.replaceWith(
        teamSection(p, alert, team ?? [], r, async () => {
          team = await loadTeam(p);
          f.show(draft, await quietReport(p), team);
          return team ?? [];
        }),
      );
    }
    ready(main);
  });
}

// ---------------------------------------------------------------------------
// Stage 5, Team
// ---------------------------------------------------------------------------

/**
 * The Team stage's add form, live checks and team tables
 * (design doc 11 section 6). `reload` reads the team again after an
 * invitation.
 */
function teamSection(
  p: string,
  alert: HTMLElement,
  initial: readonly InvitationRow[],
  r: Report | null,
  reload: () => Promise<readonly InvitationRow[]>,
): HTMLElement {
  let team: readonly InvitationRow[] = initial;
  const email = h("input", { id: "setup-team-email", type: "email", autocomplete: "off", spellcheck: "false", required: true }) as HTMLInputElement;
  const radios: HTMLInputElement[] = [];
  const groups = ROLE_GROUPS.map((g) =>
    h("fieldset", { "data-group": g.group }, [
      h("legend", {}, [t.label(`setup.team.group.${g.group}`)]),
      ...g.roles.map((role) => {
        const radio = h("input", { type: "radio", id: `setup-role-${role}`, name: "setup-role", value: role, "data-group": g.group }) as HTMLInputElement;
        radios.push(radio);
        return h("div", { class: "choice" }, [radio, h("label", { for: `setup-role-${role}` }, [roleLabel(role)])]);
      }),
    ]),
  );
  const first = radios[0];
  if (first !== undefined) first.checked = true;
  const organisation = h("input", { id: "setup-team-organisation", type: "text", inputmode: "numeric", autocomplete: "off" }) as HTMLInputElement;
  const dates = dateControls("setup-team");
  const checkList = h("ul", { class: "check-list", id: "setup-sod" });
  const add = h("button", { id: "setup-team-add", type: "button", class: "btn btn--secondary", "aria-describedby": "setup-team-add-why" }, [t.label("setup.team.add")]);
  const why = h("p", { id: "setup-team-add-why", class: "text-sm muted" }, [t.label("setup.team.add_hint")]);
  const added = statusRegion("setup-team-status");
  const tables = h("div", {});
  const hints = h("div", {});
  const count = h("p", { id: "setup-team-count" });

  const chosen = (): string => radios.find((x) => x.checked)?.value ?? "";

  /** Draws the live checks for the current choice, and disables "Add to team" on a refusal. */
  const live = (): void => {
    const lines = sodLines(chosen(), email.value, team);
    checkList.replaceChildren(...sodItems(lines));
    const refused = refusedLine(lines);
    if (refused === null) {
      add.removeAttribute("disabled");
      why.textContent = t.label("setup.team.add_hint");
    } else {
      add.setAttribute("disabled", "");
      why.textContent = t.label("setup.team.refused_reason", { rule: refused.rule });
    }
  };

  const drawTeam = (): void => {
    const granted = team.filter((x) => x.state === "granted").length;
    count.textContent = t.label("setup.team.count", { people: String(team.length), granted: String(granted) });
    tables.replaceChildren(teamTables(team));
    const notes: HTMLElement[] = [];
    if (r !== null && r.results.some((x) => x.check === "RosterShort")) {
      notes.push(h("p", { class: "callout callout--warning", "data-hint": "roster-short" }, [t.label("setup.team.roster_short")]));
    }
    if (managers(team) < 2) {
      notes.push(h("p", { class: "callout callout--warning", "data-hint": "call-approval" }, [t.label("setup.team.call_approval")]));
    }
    hints.replaceChildren(...notes);
    live();
  };

  for (const x of radios) x.addEventListener("change", live);
  email.addEventListener("input", live);

  add.addEventListener(
    "click",
    busy(add, async () => {
      hush(alert);
      added.textContent = "";
      const address = email.value.trim();
      if (!plausibleEmail(address)) {
        warn(alert, t.label("setup.email.invalid"));
        email.setAttribute("aria-invalid", "true");
        email.focus();
        return;
      }
      email.removeAttribute("aria-invalid");
      const org = organisation.value.trim();
      if (org !== "" && !/^[0-9]{1,39}$/.test(org)) {
        warn(alert, t.label("setup.team.organisation_invalid"));
        organisation.focus();
        return;
      }
      if (refusedLine(sodLines(chosen(), address, team)) !== null) return;
      const d = datesBody(alert, dates.start, dates.end);
      if (d === null) return;
      const body: Record<string, unknown> = { email: address, role: chosen(), start: d.start, end: d.end };
      if (org !== "") body["organisation"] = org;
      const o = await call("creator.invite", [p], body, anyObject);
      if (report(alert, o)) return;
      added.textContent = t.label("setup.team.added", { email: address });
      email.value = "";
      team = await reload();
      drawTeam();
    }),
  );

  drawTeam();
  const roleLegend = h("legend", {}, [t.label("setup.team.role")]);
  const roleSet = h("fieldset", {}, [roleLegend, h("span", { class: "hint" }, [t.label("setup.team.role_hint")]), h("div", { class: "role-groups" }, groups)]);
  attachHelp(roleLegend, "setup-team-role", "help.wizard.role");
  return h("div", { id: "setup-team" }, [
    h("p", { class: "callout callout--info" }, [t.label("setup.team.scope")]),
    h("section", { class: "step-block", "aria-labelledby": "setup-add-title" }, [
      h("h3", { id: "setup-add-title" }, [t.label("setup.team.add.title")]),
      h("fieldset", {}, [h("legend", {}, [t.label("setup.team.person")]), field("setup-team-email", t.label("setup.email"), email, t.label("setup.email.hint"), "help.wizard.team_email")]),
      roleSet,
      field("setup-team-organisation", t.label("setup.team.organisation"), organisation, t.label("setup.team.organisation_hint"), "help.wizard.organisation"),
      dates.root,
      h("section", { class: "checks", "aria-labelledby": "setup-sod-title", "aria-live": "polite" }, [
        h("h4", { id: "setup-sod-title" }, [t.label("setup.sod.title")]),
        h("p", { class: "text-sm" }, [t.label("setup.sod.for")]),
        checkList,
      ]),
      h("div", { class: "btn-row" }, [add]),
      why,
      added,
      h("p", { class: "text-sm" }, [t.label("setup.sod.identity_note")]),
    ]),
    h("section", { id: "setup-team-so-far", "aria-labelledby": "setup-team-title" }, [
      h("h3", { id: "setup-team-title" }, [t.label("setup.team.so_far")]),
      count,
      tables,
      hints,
      approverNotice(),
    ]),
  ]);
}

// ---------------------------------------------------------------------------
// Stage 7, Review and confirm
// ---------------------------------------------------------------------------

/** The previews of `reviewParts`, in its order. */
const PREVIEW_NAMES = ["guide", "public", "contract"] as const;

/** Mounts Review and confirm of programme `p` (design doc 11 section 7). */
function mountReview(p: string): void {
  const f = stageFrame(p, "review");
  const { main, alert, stage } = f;
  const overrideSlot = approverOverrideSlot();
  const write = queue();
  let draft: Draft | null = null;
  let team: InvitationRow[] | null = null;
  const parts = reviewParts(p, alert, write, {
    onRequested: () => go(SETUP_PATHS.progress(p)),
    onReport: (r) => f.show(draft, r, team),
  });
  const cards = h("div", { id: "setup-review-cards" });
  let notice = approverNotice();
  stage.append(
    h("h3", { id: "report-title" }, [t.label("setup.review.report")]),
    parts.summary,
    parts.list,
    h("h3", {}, [t.label("setup.review.programme")]),
    cards,
    h("h3", {}, [t.label("setup.review.previews")]),
    // Each preview folds, so the review stays one screen of decisions.
    ...parts.previews.map((x, i) =>
      h("details", { "data-preview": PREVIEW_NAMES[i] ?? "" }, [
        h("summary", {}, [ct.label(`creator.preview.${PREVIEW_NAMES[i] ?? "guide"}`)]),
        x,
      ]),
    ),
    h("h3", {}, [t.label("setup.review.next.title")]),
    h("ol", {}, [1, 2, 3, 4].map((n) => h("li", {}, [t.label(`setup.review.next.${n}`)]))),
    notice,
    overrideSlot,
    h("p", { class: "callout callout--warning" }, [t.label("setup.review.changes")]),
    h("p", { class: "text-sm" }, [t.label("setup.review.only_manager")]),
    h("p", { class: "stepup-note" }, [t.label("setup.stepup_note")]),
    h("div", { class: "btn-row" }, [
      link(SETUP_PATHS.stage(p, "communications"), t.label("setup.back", { stage: stageName("communications") }), { class: "btn btn--ghost" }),
      parts.request,
    ]),
    parts.status,
    h("p", {}, [link(SETUP_PATHS.progress(p), t.label("setup.review.progress_link"), { id: "setup-progress-link" })]),
  );
  parts.request.textContent = t.label("setup.review.request");

  void write(async () => {
    team = await loadTeam(p);
    const { draft: d, report: r } = await parts.load();
    draft = d;
    f.show(d, r, team);
    // I-67: how many tenant admins remain outside the builders.
    const counted = approverNotice(d?.approvers ?? null);
    notice.replaceWith(counted);
    notice = counted;
    // ADR-022: a tenant admin who built the programme may approve it as an override.
    await offerOverride(overrideSlot, p, alert, () => go(SETUP_PATHS.progress(p)));
    cards.replaceChildren(...reviewCards(p, statesOf(d, r), d, team));
    if (d !== null && r !== null) ready(main);
  });
}

/** One card per stage with its key values and a Change link, like a booking's review. */
function reviewCards(p: string, states: readonly StageState[], d: Draft | null, team: readonly InvitationRow[] | null): HTMLElement[] {
  const out: HTMLElement[] = [];
  for (const s of states) {
    if (s.id === "review" || s.id === "start") continue;
    out.push(
      h("section", { class: "card", "data-review-card": s.id, "aria-labelledby": `review-card-${s.id}` }, [
        h("h4", { id: `review-card-${s.id}` }, [numberedName(s.id)]),
        summaryBody(s, { programme: p, draft: d, team }),
        h("p", {}, [link(SETUP_PATHS.stage(p, s.id as DraftStageId), t.label("setup.summary.change_named", { stage: stageName(s.id) }))]),
      ]),
    );
  }
  return out;
}

// ---------------------------------------------------------------------------
// The progress page
// ---------------------------------------------------------------------------

/** The states of `call.list` for a programme, or null when unread. */
function callStates(v: unknown): ("DRAFT" | "APPROVED" | "PUBLISHED")[] | null {
  if (!Array.isArray(v)) return null;
  const out: ("DRAFT" | "APPROVED" | "PUBLISHED")[] = [];
  for (const x of v as unknown[]) {
    const s = record(x)?.["status"];
    if (s === "draft") out.push("DRAFT");
    else if (s === "approved") out.push("APPROVED");
    else if (s === "published") out.push("PUBLISHED");
    else return null;
  }
  return out;
}

/** Mounts `/app/programmes/{p}/setup/progress` (design doc 11 section 8). */
export function mountProgress(p: string): void {
  const { main, alert } = frame({ title: t.label("setup.title.progress"), alertId: "setup-error" });
  const overrideSlot = approverOverrideSlot();
  const head = h("p", { id: "setup-progress-status" });
  const body = h("div", {});
  main.append(head, body);

  void (async () => {
    const d = await loadDraft(p, alert);
    if (d === null) return;
    const r = await quietReport(p);
    const team = await loadTeam(p);
    // A call exists only once the programme is active, so a draft reads
    // no calls. The call staff read them (`call.list`); for anyone else
    // the call milestones show as not started.
    let calls: ("DRAFT" | "APPROVED" | "PUBLISHED")[] | null = [];
    if (d.status === "active") {
      const c = await call("call.list", [p], undefined, (v) => readWaitingCalls(v) !== null);
      calls = c.kind === "done" ? callStates(c.body) : null;
    }
    const status = d.status === "active" ? "active" : d.activationRequested ? "requested" : "draft";
    head.setAttribute("data-status", status);
    head.textContent = t.label("setup.progress.status", { programme: p, status: t.label(`setup.progress.status.${status}`) });
    const clean = r !== null && r.results.every((x) => x.severity === "warning" && x.acknowledged);
    const ms = milestones({ drafted: true, clean, team, requested: d.activationRequested, active: d.status === "active", calls });
    const current = ms.find((m) => m.condition === "current");
    const parts: HTMLElement[] = [milestoneStrip(ms)];
    if (current !== undefined) {
      parts.push(
        h("p", { id: "setup-next", class: "callout callout--info", "data-milestone": current.id }, [
          h("strong", {}, [t.label("setup.progress.next_title")]),
          " ",
          t.label(`setup.milestone.next.${current.id}`),
        ]),
      );
    }
    parts.push(
      h("ul", { class: "card-list" }, [
        h("li", {}, [link(SETUP_PATHS.stage(p, "programme"), t.label("setup.progress.wizard_link"), { id: "setup-wizard-link" })]),
        h("li", {}, [link(PATHS.people(p), t.label("setup.progress.people_link"), { id: "setup-people-link" })]),
        // ADR-030: the programme's logo is set on the branding page. The
        // link shows only to a viewer the page gate admits (SA-09).
        h("li", {}, [link("/app/admin/branding", t.label("setup.progress.logo_link"), { id: "setup-logo-link" })]),
      ]),
    );
    if (calls === null) parts.push(h("p", { class: "text-sm muted" }, [t.label("setup.progress.calls_unread")]));
    parts.push(
      h("section", { "aria-labelledby": "setup-milestones-title" }, [h("h2", { id: "setup-milestones-title" }, [t.label("setup.progress.milestones")]), milestoneList(ms)]),
      approverNotice(d.approvers),
      overrideSlot,
      h("section", { "aria-labelledby": "setup-team-status-title" }, [
        h("h2", { id: "setup-team-status-title" }, [t.label("setup.progress.team")]),
        h("p", {}, [t.label("setup.progress.team_intro")]),
        team === null ? h("p", {}, [t.label("setup.progress.team_unread")]) : statusTable(team, d.status === "active"),
        h("div", { class: "btn-row" }, [
          h("button", { id: "setup-remind", type: "button", class: "btn btn--secondary", disabled: true, "aria-describedby": "setup-remind-why" }, [t.label("setup.progress.remind")]),
        ]),
        h("p", { id: "setup-remind-why", class: "text-sm muted" }, [t.label("setup.progress.remind_why")]),
      ]),
    );
    body.replaceWith(h("div", { id: "setup-progress" }, parts));
    // ADR-022: a tenant admin who built the programme may approve it as an override.
    await offerOverride(overrideSlot, p, alert, () => go(SETUP_PATHS.progress(p)));
    ready(main);
  })();
}
