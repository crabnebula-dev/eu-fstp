// The committee's pages (J7, M4 design section 2.2 and change D5; lane
// W4c): the ranking view, opening a cut-off round, ballots and
// delegation, and recording the cut-off.
//
// - R-EV-08: the cut-off is set from the ranking view, with the
//   remaining budget visible, and its rationale is recorded. The view
//   has weighted scores per criterion and no findings.
// - P-02 NOTE 6 and P-17: `forms.ts` compares the server's score text
//   exactly and refuses a cut-off inside a tie without a tie-break.
// - NOTE 6 of `state-machine.md`: the committee places tied proposals in
//   the order of its P-17 tie-break, and the round is opened with that
//   order. Interim, pending Daniel.
// - R-EV-09, Q4 and P-16 NOTE 8: each member casts their own ballot.
//   The ballot form takes the viewer's vote only, with no voter choice
//   and no preset. A recused member sees no ballot or delegation.
// - Q16: a row where the viewer has a conflict shows "recused" only.
// - ADR-006: amounts are shown as the server's decimal strings.

import { h, type Child } from "../core/dom.js";
import type { I18n, Label } from "../core/i18n.js";
import {
  FormErrors,
  buttonEl,
  callOp,
  formEl,
  frame,
  guarded,
  idRoute,
  pageI18n,
  proposalName,
  radio,
  readOp,
  selectEl,
  textArea,
  textField,
  whileBusy,
  writeOp,
  type Frame,
  type JudgingPage,
  type PageEnv,
  type ShownError,
} from "../reviewer/kit.js";
import { canMoveInTie, moveInTie, readBallot, readCutOffRound, sortByScore, type CutOffRow } from "./forms.js";
import { COMMITTEE_LABELS } from "./messages.en.js";
import {
  isOpenedRound,
  isRankingView,
  isRoundView,
  type RankedRow,
  type RankingRow,
  type RoundView,
  type Vote,
} from "./models.js";

function param(params: Readonly<Record<string, string>>, name: string): string {
  return params[name] ?? "";
}

function ranked(rows: readonly RankingRow[]): RankedRow[] {
  return rows.filter((r): r is RankedRow => !r.recused);
}

/** The criterion ids of the ranked rows, in the order the server first names them. */
function criterionColumns(rows: readonly RankedRow[]): string[] {
  const out: string[] = [];
  for (const r of rows) {
    for (const c of r.criterion_scores) {
      if (!out.includes(c.criterion)) {
        out.push(c.criterion);
      }
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The ranking view (R-EV-08, Q16)
// ---------------------------------------------------------------------------

function rankingTable(t: I18n, rows: readonly RankingRow[]): HTMLElement {
  const columns = criterionColumns(ranked(rows));
  const head = [
    t.label("com.col_position"),
    t.label("com.col_proposal"),
    t.label("com.col_summary"),
    t.label("com.col_effective"),
    ...columns.map((id) => t.label("com.col_criterion", { id })),
    t.label("com.col_requested"),
    t.label("com.col_rationale"),
  ];
  const body = rows.map((r, i) => {
    const position = h("th", { scope: "row" }, [String(i + 1)]);
    if (r.recused) {
      // Q16: the position and the word, nothing of the proposal.
      return h("tr", { "data-proposal": r.proposal, "data-recused": "true" }, [
        position,
        h("td", { colspan: String(head.length - 1) }, [t.label("com.recused")]),
      ]);
    }
    const text = (v: string | null): Child => (v === null ? t.label("com.not_written") : v);
    return h("tr", { "data-proposal": r.proposal, "data-recused": "false" }, [
      position,
      h("td", {}, [proposalName(t, r.proposal)]),
      h("td", {}, [h("p", { class: "fstp-row-title" }, [text(r.title)]), h("p", {}, [text(r.neutral_summary)])]),
      h("td", {}, [r.effective]),
      ...columns.map((id) => {
        const c = r.criterion_scores.find((x) => x.criterion === id);
        return h("td", { "data-criterion": id }, [c === undefined ? t.label("com.not_scored") : c.weighted]);
      }),
      h("td", {}, [r.requested]),
      h("td", {}, [text(r.rationale)]),
    ]);
  });
  return h("table", { id: "ranking-table" }, [
    h("caption", {}, [t.label("com.ranking.caption")]),
    h("thead", {}, [h("tr", {}, head.map((x) => h("th", { scope: "col" }, [x])))]),
    h("tbody", {}, body),
  ]);
}

/** One row of the tie-order list: its position, its name and its move buttons. */
function tieItem(
  t: I18n,
  order: readonly RankedRow[],
  index: number,
  move: (index: number, up: boolean) => void,
): HTMLElement | null {
  const row = order[index];
  if (row === undefined) {
    return null;
  }
  const name = proposalName(t, row.proposal);
  const buttons: HTMLButtonElement[] = [];
  for (const up of [true, false]) {
    if (!canMoveInTie(order, index, up)) {
      continue;
    }
    const b = buttonEl(
      `tie-${up ? "up" : "down"}-${row.proposal}`,
      "button",
      up ? t.label("com.open.move_up", { proposal: name }) : t.label("com.open.move_down", { proposal: name }),
    );
    b.addEventListener("click", () => move(index, up));
    buttons.push(b);
  }
  return h("li", { "data-proposal": row.proposal }, [
    h("span", {}, [t.label("com.open.tie_item", { position: String(index + 1), proposal: name, score: row.effective })]),
    ...buttons,
  ]);
}

/**
 * The tie-order section of the open-round form. Each group of rows with
 * equal effective scores is listed with buttons that move a row within
 * its group (NOTE 6 of `state-machine.md`, P-17). Interim reading,
 * pending Daniel: the committee applies its P-17 tie-break by this order,
 * and records the reason in the tie-break text.
 */
function tieOrderSection(
  t: I18n,
  order: readonly RankedRow[],
  move: (index: number, up: boolean) => void,
): HTMLElement {
  const groups: HTMLElement[] = [];
  let start = 0;
  while (start < order.length) {
    let end = start;
    while (canMoveInTie(order, end, false)) {
      end += 1;
    }
    if (end > start) {
      const items: HTMLElement[] = [];
      for (let i = start; i <= end; i += 1) {
        const item = tieItem(t, order, i, move);
        if (item !== null) {
          items.push(item);
        }
      }
      groups.push(h("li", {}, [h("ol", {}, items)]));
    }
    start = end + 1;
  }
  return h("section", { id: "round-tie-order", "aria-labelledby": "round-tie-order-heading" }, [
    h("h3", { id: "round-tie-order-heading" }, [t.label("com.open.tie_order")]),
    groups.length === 0
      ? h("p", {}, [t.label("com.open.no_ties")])
      : h("div", {}, [h("p", {}, [t.label("com.open.tie_order_intro")]), h("ul", {}, groups)]),
  ]);
}

function openRoundForm(
  env: PageEnv,
  t: I18n,
  f: Frame,
  call: string,
  rows: readonly RankedRow[],
  reordered: (order: readonly RankedRow[]) => void,
): HTMLFormElement {
  const nominated = textField("round-nominated", t.label("com.open.nominated"), {
    inputmode: "numeric",
    spellcheck: "false",
  });
  const rationale = textArea("round-rationale", t.label("com.open.rationale"));
  const tieBreak = textArea("round-tie-break", t.label("com.open.tie_break"));
  const submit = buttonEl("round-submit", "submit", t.label("com.open.submit"));
  const heading = h("h2", { id: "round-heading" }, [t.label("com.open.heading")]);
  // The order the round is opened with: the ranking top first, with ties
  // in the order the committee sets.
  let order: readonly RankedRow[] = rows;
  const tieSlot = h("div", {});
  const move = (index: number, up: boolean): void => {
    const next = moveInTie(order, index, up);
    if (next === null) {
      return;
    }
    const moved = order[index]?.proposal ?? "";
    order = next;
    renderTies();
    reordered(order);
    // Keep focus on the moved row: on the same button when it is still offered.
    const there = up ? index - 1 : index + 1;
    const same = env.root.querySelector<HTMLButtonElement>(`#tie-${up ? "up" : "down"}-${moved}`);
    const other = env.root.querySelector<HTMLButtonElement>(`#tie-${up ? "down" : "up"}-${moved}`);
    (same ?? other)?.focus();
    f.status(t.label("com.open.moved", { proposal: proposalName(t, moved), position: String(there + 1) }));
  };
  const renderTies = (): void => {
    tieSlot.replaceChildren(tieOrderSection(t, order, move));
  };
  renderTies();
  const form = formEl("round-form", [heading, tieSlot, nominated.root, rationale.root, tieBreak.root, submit]);
  form.setAttribute("aria-labelledby", "round-heading");
  const errors = new FormErrors(form, "round-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const sent: CutOffRow[] = order.map((r) => ({ proposal: r.proposal, effective: r.effective }));
        const read = readCutOffRound(sent, {
          nominated: nominated.control.value,
          rationale: rationale.control.value,
          tie_break: tieBreak.control.value,
        });
        if (!read.ok) {
          errors.show(
            read.errors.map((e): ShownError => {
              switch (e.field) {
                case "nominated":
                  return {
                    control: nominated.control,
                    message:
                      e.reason === "out_of_range"
                        ? t.label("com.open.err_out_of_range", { count: String(order.length) })
                        : e.reason === "not_an_integer"
                          ? t.label("com.open.err_not_an_integer")
                          : t.label("com.open.err_required"),
                  };
                case "rationale":
                  return { control: rationale.control, message: t.label("com.open.err_rationale") };
                case "tie_break":
                  return { control: tieBreak.control, message: t.label("com.open.err_tie_break") };
                default:
                  return { control: heading, message: t.label("com.open.err_order") };
              }
            }),
          );
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await callOp(
          env,
          "committee.open_round",
          { call },
          {
            order: read.value.order,
            nominated: read.value.nominated,
            rationale: read.value.rationale,
            tie_breaks: read.value.tie_break,
          },
          isOpenedRound,
        );
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        env.navigate(`/app/cut-off-rounds/${answer.data.round}`);
      }),
    );
  });
  return form;
}

async function mountRanking(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COMMITTEE_LABELS);
  const call = param(params, "call");
  const f = frame(env, t, t.label("com.ranking.title"));
  await guarded(f, async () => {
    const view = await readOp(env, "committee.ranking", { call }, isRankingView);
    if (!view.ok) {
      // A view with a member it must not carry is refused whole (I-17).
      f.problem(view.problem);
      f.show([]);
      return;
    }
    const rows = view.data;
    if (rows.length === 0) {
      f.show([h("p", {}, [t.label("com.ranking.none")])]);
      return;
    }
    const readable = ranked(rows);
    const first = readable[0];
    // Interim, pending the lead: with no recused row the page orders the
    // rows by score itself, since the domain lists them in proposal
    // order. A recused row carries no score, so that view keeps the
    // server's order.
    const sorted = readable.length === rows.length ? sortByScore(readable) : null;
    const tableSlot = h("div", {}, [rankingTable(t, sorted ?? rows)]);
    const parts: Child[] = [
      first === undefined
        ? h("p", {}, [t.label("com.budget_unknown")])
        : h("p", {}, [t.label("com.budget"), h("span", { id: "remaining-budget" }, [first.remaining_budget])]),
    ];
    if (first?.shortfall !== undefined) {
      // An over-nominated call: the server spells the signed budget as a positive shortfall (ADR-006).
      parts.push(h("p", {}, [t.label("com.shortfall"), h("span", { id: "budget-shortfall" }, [first.shortfall])]));
    }
    parts.push(tableSlot);
    if (readable.length === rows.length) {
      parts.push(
        openRoundForm(env, t, f, call, sorted ?? readable, (order) => {
          tableSlot.replaceChildren(rankingTable(t, order));
        }),
      );
    } else {
      // A conflict on any ranked proposal recuses the member from the call's vote.
      parts.push(h("p", { id: "recused-notice" }, [t.label("com.recused_notice")]));
    }
    f.show(parts);
  });
}

// ---------------------------------------------------------------------------
// A cut-off round: ballots, delegation and the record (R-EV-09, D5)
// ---------------------------------------------------------------------------

const VOTES: readonly { readonly choice: "for" | "against" | "abstain"; readonly vote: Vote }[] = [
  { choice: "for", vote: "For" },
  { choice: "against", vote: "Against" },
  { choice: "abstain", vote: "Abstain" },
];

function voteLabel(t: I18n, v: Vote): Label {
  return v === "For" ? t.label("com.round.for") : v === "Against" ? t.label("com.round.against") : t.label("com.round.abstain");
}

function roundTable(t: I18n, v: RoundView): HTMLElement {
  return h("table", { id: "round-table" }, [
    h("caption", {}, [t.label("com.round.caption")]),
    h("thead", {}, [
      h(
        "tr",
        {},
        ["com.col_position", "com.col_proposal", "com.col_cutoff", "com.col_state"].map((id) =>
          h("th", { scope: "col" }, [t.label(id)]),
        ),
      ),
    ]),
    h(
      "tbody",
      {},
      v.order.map((r, i) =>
        h("tr", { "data-proposal": r.proposal, "data-state": r.state }, [
          h("th", { scope: "row" }, [String(i + 1)]),
          h("td", {}, [proposalName(t, r.proposal)]),
          h("td", {}, [i < v.nominated ? t.label("com.round.nominated") : t.label("com.round.below")]),
          h("td", {}, [t.label(`kit.state.${r.state}`)]),
        ]),
      ),
    ),
  ]);
}

/** The ballot form: the viewer's own vote, radios only, none preset. */
function ballotForm(env: PageEnv, t: I18n, f: Frame, round: string, rerender: () => Promise<void>): HTMLFormElement {
  const radios = VOTES.map((x) => ({
    ...x,
    ...radio(`ballot-${x.choice}`, "vote", x.choice, voteLabel(t, x.vote)),
  }));
  const legend = h("legend", {}, [t.label("com.round.vote_legend")]);
  const submit = buttonEl("ballot-submit", "submit", t.label("com.round.cast"));
  const form = formEl("ballot-form", [h("fieldset", {}, [legend, ...radios.map((r) => r.root)]), submit]);
  const errors = new FormErrors(form, "ballot-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const read = readBallot({ vote: radios.find((r) => r.control.checked)?.choice ?? null });
        const first = radios[0];
        if (!read.ok) {
          if (first !== undefined) {
            errors.show([{ control: first.control, message: t.label("com.round.err_vote"), after: legend }]);
          }
          return;
        }
        const chosen = VOTES.find((x) => x.choice === read.value.vote);
        if (chosen === undefined) {
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await writeOp(env, "committee.cast", { round }, { vote: chosen.vote });
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(t.label("com.round.cast_done"));
        await rerender();
      }),
    );
  });
  return form;
}

/** The delegation form, separate from the ballot. It offers no recused member (NOTE 8). */
function delegateForm(env: PageEnv, t: I18n, f: Frame, v: RoundView, rerender: () => Promise<void>): HTMLFormElement {
  const select = selectEl({ id: "delegate-to", name: "delegate-to" }, [
    h("option", { value: "" }, [t.label("com.round.choose")]),
    ...v.delegates.map((d) => h("option", { value: d.account }, [d.label])),
  ]);
  const submit = buttonEl("delegate-submit", "submit", t.label("com.round.delegate"));
  const form = formEl("delegate-form", [
    h("div", { class: "fstp-field" }, [h("label", { for: "delegate-to" }, [t.label("com.round.delegate_to")]), select]),
    submit,
  ]);
  const errors = new FormErrors(form, "delegate-errors", t);
  form.addEventListener("submit", (ev) => {
    ev.preventDefault();
    void guarded(f, () =>
      whileBusy(submit, async () => {
        const to = select.value;
        if (to === "") {
          errors.show([{ control: select, message: t.label("com.round.err_delegate") }]);
          return;
        }
        errors.clear();
        f.clearAlert();
        const answer = await writeOp(env, "committee.delegate", { round: v.round }, { to });
        if (!answer.ok) {
          f.problem(answer.problem);
          return;
        }
        f.status(t.label("com.round.delegate_done"));
        await rerender();
      }),
    );
  });
  return form;
}

async function mountRound(env: PageEnv, params: Readonly<Record<string, string>>): Promise<void> {
  const t = pageI18n(env, COMMITTEE_LABELS);
  const round = param(params, "round");
  const f = frame(env, t, t.label("com.round.title"));
  const render = async (): Promise<void> => {
    const view = await readOp(env, "committee.round", { round }, isRoundView);
    if (!view.ok) {
      f.problem(view.problem);
      f.show([]);
      return;
    }
    const v = view.data;
    const parts: Child[] = [
      roundTable(t, v),
      h("dl", {}, [
        h("dt", {}, [t.label("com.round.rationale")]),
        h("dd", {}, [v.rationale]),
        h("dt", {}, [t.label("com.round.tie_break")]),
        h("dd", {}, [v.tie_break ?? t.label("com.round.no_tie_break")]),
      ]),
      h("p", {}, [t.label("com.round.cast_count", { count: String(v.ballots_cast) })]),
    ];
    if (v.recorded) {
      parts.push(h("p", {}, [t.label("com.round.recorded")]));
    } else if (v.viewer.recused) {
      parts.push(h("p", { id: "recused-notice" }, [t.label("com.round.recused")]));
    } else {
      if (v.viewer.own_vote !== null) {
        parts.push(h("p", {}, [t.label("com.round.own_vote", { vote: voteLabel(t, v.viewer.own_vote) })]));
      } else if (v.viewer.delegated_to !== null) {
        parts.push(h("p", {}, [t.label("com.round.delegated")]));
      } else {
        parts.push(ballotForm(env, t, f, v.round, render), delegateForm(env, t, f, v, render));
      }
      const record = buttonEl("record-cutoff", "button", t.label("com.round.record"));
      record.addEventListener("click", () => {
        void guarded(f, () =>
          whileBusy(record, async () => {
            f.clearAlert();
            const answer = await writeOp(env, "committee.record_cutoff", { round: v.round }, {});
            if (!answer.ok) {
              f.problem(answer.problem);
              return;
            }
            f.status(t.label("com.round.record_done"));
            await render();
          }),
        );
      });
      parts.push(record);
    }
    f.show(parts);
  };
  await guarded(f, render);
}

/** The committee's pages (J7). */
export const COMMITTEE_PAGES: readonly JudgingPage[] = [
  { route: idRoute("committee.ranking", "/app/calls/{call}/ranking", ["call"]), mount: mountRanking },
  { route: idRoute("committee.round", "/app/cut-off-rounds/{round}", ["round"]), mount: mountRound },
];
