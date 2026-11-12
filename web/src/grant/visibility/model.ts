// The read model and request bodies of the grantee visibility screen
// (M9 lane P2; R-PB-02, R-PB-03, I-41, I-42, I-43).
//
// The spellings follow `fstp-api-core` `publicity.rs` (the reply of
// `grant.publicity.view`) and `forms.rs` (the bodies of
// `grant.publicity.set` and `grant.publicity.withdraw`). The decoder
// returns null for a value it does not accept, so the page shows nothing
// from an answer it cannot read. The cell decides every choice again.

type Rec = Readonly<Record<string, unknown>>;

/** The public visibility levels, lowest first (`public-transparency.md`). */
export const LEVELS = ["hidden", "project", "project_and_grantee", "full"] as const;

/** One visibility level. */
export type Level = (typeof LEVELS)[number];

/** The two phases a choice governs: funded (P-50) and finished (P-51). */
export const PHASES = ["funded", "finished"] as const;

/** One phase. */
export type Phase = (typeof PHASES)[number];

/** The current choice of one phase. */
export interface Choice {
  readonly level: Level;
  /** What the public pages show: the lower of the choice and the maximum, hidden for a minor (I-42, I-43). */
  readonly effective: Level;
  readonly title: string;
  readonly summary: string;
  readonly grantee: string;
  readonly deliverables: readonly string[];
}

/** One phase of the view. */
export interface PhaseView {
  /** Whether a choice of this phase can be set in the grant's state (I-41). */
  readonly open: boolean;
  readonly choice: Choice | null;
}

/** One accepted deliverable of the grant. */
export interface Deliverable {
  readonly id: string;
  readonly licence: string;
  readonly snapshot: string;
}

/** `grant.publicity.view`. */
export interface Publicity {
  readonly proposal: string;
  readonly state: string;
  /** A minor-flagged grant never appears publicly, so every level but hidden is disabled (I-42). */
  readonly minor: boolean;
  readonly maxFunded: Level;
  readonly maxFinished: Level;
  readonly funded: PhaseView;
  readonly finished: PhaseView;
  readonly deliverables: readonly Deliverable[];
}

const ID = /^(0|[1-9][0-9]{0,38})$/;

function rec(v: unknown): Rec | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Rec) : null;
}

function isId(v: unknown): v is string {
  return typeof v === "string" && ID.test(v);
}

function isText(v: unknown): v is string {
  return typeof v === "string";
}

/** Whether `v` is one of the four level tokens. */
export function isLevel(v: unknown): v is Level {
  return typeof v === "string" && (LEVELS as readonly string[]).includes(v);
}

/** The rank of `l`, 0 for hidden up to 3 for full. */
export function rank(l: Level): number {
  return LEVELS.indexOf(l);
}

function choiceOf(v: unknown): Choice | null | undefined {
  if (v === null) {
    return null;
  }
  const o = rec(v);
  if (o === null) {
    return undefined;
  }
  const ds = o["deliverables"];
  if (
    !isLevel(o["level"]) ||
    !isLevel(o["effective"]) ||
    !isText(o["title"]) ||
    !isText(o["summary"]) ||
    !isText(o["grantee"]) ||
    !Array.isArray(ds) ||
    !ds.every(isId)
  ) {
    return undefined;
  }
  return Object.freeze({
    level: o["level"],
    effective: o["effective"],
    title: o["title"],
    summary: o["summary"],
    grantee: o["grantee"],
    deliverables: Object.freeze([...(ds as string[])]),
  });
}

function phaseOf(v: unknown): PhaseView | null {
  const o = rec(v);
  if (o === null || typeof o["open"] !== "boolean") {
    return null;
  }
  const choice = choiceOf(o["choice"]);
  if (choice === undefined) {
    return null;
  }
  return Object.freeze({ open: o["open"], choice });
}

function deliverableOf(v: unknown): Deliverable | null {
  const o = rec(v);
  if (o === null || !isId(o["id"]) || !isText(o["licence"]) || !isText(o["snapshot"])) {
    return null;
  }
  return Object.freeze({ id: o["id"], licence: o["licence"], snapshot: o["snapshot"] });
}

/** Decodes `grant.publicity.view`, or null. */
export function decodePublicity(v: unknown): Publicity | null {
  const o = rec(v);
  if (
    o === null ||
    !isId(o["proposal"]) ||
    !isText(o["state"]) ||
    typeof o["minor"] !== "boolean" ||
    !isLevel(o["max_funded"]) ||
    !isLevel(o["max_finished"])
  ) {
    return null;
  }
  const funded = phaseOf(o["funded"]);
  const finished = phaseOf(o["finished"]);
  const raw = o["deliverables"];
  if (funded === null || finished === null || !Array.isArray(raw)) {
    return null;
  }
  const deliverables: Deliverable[] = [];
  for (const d of raw) {
    const x = deliverableOf(d);
    if (x === null) {
      return null;
    }
    deliverables.push(x);
  }
  return Object.freeze({
    proposal: o["proposal"],
    state: o["state"],
    minor: o["minor"],
    maxFunded: o["max_funded"],
    maxFinished: o["max_finished"],
    funded,
    finished,
    deliverables: Object.freeze(deliverables),
  });
}

/** The wire spelling of a phase in a request body: the domain's variant name. */
function phaseWire(p: Phase): string {
  return p === "funded" ? "Funded" : "Finished";
}

/** The wire spelling of a level in a request body: the domain's variant name. */
function levelWire(l: Level): string {
  switch (l) {
    case "hidden":
      return "Hidden";
    case "project":
      return "Project";
    case "project_and_grantee":
      return "ProjectAndGrantee";
    default:
      return "Full";
  }
}

/** What the grantee typed for one phase. */
export interface ChoiceInput {
  readonly level: Level;
  readonly title: string;
  readonly summary: string;
  readonly grantee: string;
  readonly deliverables: readonly string[];
}

/**
 * The body of `grant.publicity.set`, or null when a text the level shows
 * is empty or a deliverable is not an id. The texts go as text: the cell
 * stores each one as a public text of the grant (R-PB-03).
 */
export function setBody(phase: Phase, c: ChoiceInput): Readonly<Record<string, unknown>> | null {
  const title = c.title.trim();
  const summary = c.summary.trim();
  const grantee = c.grantee.trim();
  if (c.level !== "hidden" && (title === "" || summary === "")) {
    return null;
  }
  if (rank(c.level) >= rank("project_and_grantee") && grantee === "") {
    return null;
  }
  if (!c.deliverables.every(isId) || (phase === "funded" && c.deliverables.length > 0)) {
    return null;
  }
  const ids = [...new Set(c.deliverables)].sort((a, b) => (a.length === b.length ? (a < b ? -1 : a > b ? 1 : 0) : a.length - b.length));
  return {
    phase: phaseWire(phase),
    level: levelWire(c.level),
    title,
    summary,
    grantee,
    deliverables: ids,
  };
}

/** The body of `grant.publicity.withdraw`. */
export function withdrawBody(phase: Phase): Readonly<Record<string, unknown>> {
  return { phase: phaseWire(phase) };
}

/** The fields the public pages show at `l` (`public-transparency.md` levels table). */
export function shownFields(l: Level): readonly ("title" | "summary" | "call" | "status" | "grantee" | "amount")[] {
  switch (l) {
    case "hidden":
      return [];
    case "project":
      return ["title", "summary", "call", "status"];
    case "project_and_grantee":
      return ["title", "summary", "call", "status", "grantee"];
    default:
      return ["title", "summary", "call", "status", "grantee", "amount"];
  }
}
