// The field schema of the creator step pages (R-PG-01, M4 design
// sections 3.1 and 3.9, `SPEC/02-domain/programme-creator.md`).
//
// One row per field of the `fstp.programme/1` spec, in step order. A row
// names the field key `<step>.<member>` and the shape of its JSON value,
// so a step page can build one control per leaf. The shapes follow the
// codecs of `fstp-programme` (`spec.rs` `FIELDS`, `kinds.rs` and
// `value.rs`). The server decodes every value strictly, so a shape here
// only chooses the controls. It never decides what is valid.
//
// Interim, pending Daniel and the generated `web/src/gen/api.ts`: no
// design section fixes per-field widgets. When lane W3a generates the
// field schema from `fstp_programme::FIELDS`, this table goes and the
// generated one takes its place.
//
// This module is pure: it touches no DOM, so Node can load it.

/** A creator step that holds fields, as `fstp_programme::Step::name` spells it. */
export type FieldStep =
  | "funder"
  | "identity"
  | "eligibility"
  | "funding"
  | "evaluation"
  | "money"
  | "contract"
  | "support"
  | "people"
  | "comms";

/** The shape of one JSON value, and so of its controls. */
export type Shape =
  /** A string. `long` text gets a multi-line control. */
  | { readonly t: "text"; readonly long: boolean }
  /** An ADR-006 amount string, such as `"400000.00"`. */
  | { readonly t: "amount" }
  /** A JSON integer. */
  | { readonly t: "int" }
  /** A date string `YYYY-MM-DD`. */
  | { readonly t: "date" }
  /** A JSON boolean. */
  | { readonly t: "bool" }
  /** One of a closed list of tokens. */
  | { readonly t: "enum"; readonly options: readonly string[] }
  /** A list of distinct tokens from a closed list, kept in the order of `options`. */
  | { readonly t: "set"; readonly options: readonly string[] }
  /** An ordered list. */
  | { readonly t: "list"; readonly item: Shape }
  /**
   * An object. With `sparse`, a member whose control is empty is left out,
   * as for a value that is one of several member forms.
   */
  | { readonly t: "object"; readonly members: readonly Member[]; readonly sparse: boolean }
  /** An object whose `kind` member chooses its other members. */
  | { readonly t: "tagged"; readonly variants: readonly Variant[] };

/** One member of an object shape. */
export interface Member {
  readonly name: string;
  readonly shape: Shape;
  /**
   * An `id` that the page numbers itself: a list item keeps the id it was
   * loaded with, and a new item takes one more than the largest id in the
   * list. Such a member has no control.
   */
  readonly auto: boolean;
}

/** One form of a tagged object: its `kind` and its other members. */
export interface Variant {
  readonly kind: string;
  readonly members: readonly Member[];
}

/** One field of the spec. */
export interface FieldDef {
  /** `<step>.<member>`, as the spec JSON nests it. */
  readonly key: string;
  readonly step: FieldStep;
  readonly member: string;
  readonly shape: Shape;
}

const TEXT: Shape = { t: "text", long: false };
const LONG: Shape = { t: "text", long: true };
const AMOUNT: Shape = { t: "amount" };
const INT: Shape = { t: "int" };
const DATE: Shape = { t: "date" };
const BOOL: Shape = { t: "bool" };

function m(name: string, shape: Shape): Member {
  return { name, shape, auto: false };
}

/** The numbered `id` member of a keyed list item. */
const ID: Member = { name: "id", shape: TEXT, auto: true };

function obj(...members: Member[]): Shape {
  return { t: "object", members, sparse: false };
}

function list(item: Shape): Shape {
  return { t: "list", item };
}

function oneOf(...options: string[]): Shape {
  return { t: "enum", options };
}

function setOf(...options: string[]): Shape {
  return { t: "set", options };
}

/** `{"days": n}` (`fstp_domain::time::Days`). */
const DAYS: Shape = obj(m("days", INT));
/** `{"working_days": n}`. */
const WORKING_DAYS: Shape = obj(m("working_days", INT));

const WEEKDAYS = ["monday", "tuesday", "wednesday", "thursday", "friday", "saturday", "sunday"];

const FLOW_DOWN = [
  "conflict_of_interests",
  "confidentiality_and_security",
  "ethics_and_values",
  "visibility_of_eu_funding",
  "specific_rules_for_carrying_out_the_action",
  "information_obligations",
  "record_keeping",
  "access_rights",
];

const ROWS: readonly (readonly [FieldStep, string, Shape])[] = [
  // Step 1, funder and instrument.
  ["funder", "p53_funder_profile", obj(m("profile", TEXT), m("version", INT))],
  ["funder", "action_number", TEXT],
  ["funder", "action_acronym", TEXT],
  ["funder", "coordinator_name", TEXT],
  ["funder", "p56_fstp_budget", AMOUNT],
  ["funder", "p57_action_dates", obj(m("start", DATE), m("end", DATE))],
  ["funder", "p58_recipient_ceiling", AMOUNT],
  ["funder", "p41_funder_retention", obj(m("years", INT))],
  [
    "funder",
    "p22_trace_retention",
    { t: "object", members: [m("until", oneOf("P-41")), m("days", INT)], sparse: true },
  ],
  ["funder", "p46_switch_retrieval_period", DAYS],
  ["funder", "p43_licence_grace_period", DAYS],
  // Step 2, programme identity.
  ["identity", "name", TEXT],
  ["identity", "narrative", LONG],
  ["identity", "scope", LONG],
  ["identity", "public_slug", TEXT],
  ["identity", "p25_language", TEXT],
  // Step 3, eligibility.
  ["eligibility", "persons_supported", LONG],
  ["eligibility", "minors", LONG],
  ["eligibility", "p13_excluded_classes", list(obj(ID, m("description", LONG)))],
  ["eligibility", "p17_tie_break", obj(m("priority", TEXT), m("exception", TEXT))],
  ["eligibility", "p18_verification_methods", list(TEXT)],
  ["eligibility", "p19_document_retention", TEXT],
  ["eligibility", "p45_relying_party_mode", oneOf("tenant_registration", "crabnebula_intermediary")],
  // Step 4, what we fund.
  ["funding", "p55_activity_types", list(obj(ID, m("name", TEXT)))],
  ["funding", "p26_licences", list(TEXT)],
  // Step 5, evaluation.
  ["evaluation", "p01_criteria", obj(m("scale_max", INT), m("criteria", list(obj(ID, m("name", TEXT), m("weight", INT)))))],
  ["evaluation", "p02_threshold", TEXT],
  ["evaluation", "p03_reviewers", INT],
  ["evaluation", "p06_cadence", TEXT],
  ["evaluation", "p07_stage2_window", DAYS],
  ["evaluation", "p08_notification_deadline", WORKING_DAYS],
  ["evaluation", "p09_knock_outs", list(obj(ID, m("text", LONG)))],
  ["evaluation", "p10_read_access", oneOf("assigned_reviewers_only", "all_committee_members", "operator_staff_only")],
  ["evaluation", "p11_anonymity", oneOf("anonymous", "named")],
  [
    "evaluation",
    "p14_irc_exemptions",
    list({
      t: "tagged",
      variants: [
        { kind: "team_change", members: [] },
        { kind: "plan_change_without_budget_change", members: [] },
        { kind: "additional_tasks_in_scope_at_equivalent_rates", members: [m("total_below", AMOUNT)] },
      ],
    }),
  ],
  ["evaluation", "p15_irc_members", INT],
  ["evaluation", "p16_voting", obj(m("decision", oneOf("majority")), m("casting_vote", oneOf("chair")), m("delegation", BOOL))],
  ["evaluation", "p21_inference", obj(m("provider", TEXT), m("primary", TEXT), m("fallbacks", list(TEXT)))],
  [
    "evaluation",
    "p23_precheck",
    obj(
      m("enabled", BOOL),
      m("per_day_per_proposal", INT),
      m("per_call_per_proposal", INT),
      m("account_cap_across_drafts_in_call", BOOL),
    ),
  ],
  ["evaluation", "p24_effective_score", oneOf("higher_of_original_and_revised")],
  ["evaluation", "p28_rubric_bands", BOOL],
  ["evaluation", "p39_reviewer_organisations", INT],
  ["evaluation", "p42_calibration_consent", BOOL],
  ["evaluation", "p75_agent_content_reads", BOOL],
  ["evaluation", "p77_mcp_binding_actions", oneOf("draft_only", "allowed")],
  // Step 6, money.
  ["money", "amount_criteria", LONG],
  ["money", "p04_grant_range", obj(m("min", AMOUNT), m("max", AMOUNT))],
  ["money", "p05_recipient_cap", AMOUNT],
  ["money", "p27_hardship_contribution", BOOL],
  ["money", "p34_payment_evidence", list(TEXT)],
  ["money", "p36_bank_change_hold", DAYS],
  ["money", "p59_payment_target", DAYS],
  ["money", "p65_partial_claim_evidence", oneOf("public_deliverables", "progress_report_with_final_deliverables")],
  ["money", "p66_reallocation", obj(m("enabled", BOOL), m("approval", TEXT))],
  ["money", "p67_unclaimed_balances", oneOf("return_to_fstp_budget", "lapse_and_report_unspent")],
  // Step 7, contract.
  ["contract", "p29_instrument", obj(m("instrument", TEXT), m("template", obj(m("id", TEXT), m("version", INT))))],
  ["contract", "p30_signature_cascade", list(TEXT)],
  ["contract", "p44_payment_nature", TEXT],
  ["contract", "p47_seal_level", oneOf("advanced", "qualified")],
  ["contract", "p48_sealed_pdf", BOOL],
  ["contract", "p49_signing_provider", TEXT],
  ["contract", "flow_down", setOf(...FLOW_DOWN)],
  // Step 8, support and complaints.
  ["support", "p60_support_programme", list(TEXT)],
  ["support", "p61_complaint_window", WORKING_DAYS],
  ["support", "p62_coordinator_response", WORKING_DAYS],
  ["support", "p63_escalation_window", WORKING_DAYS],
  ["support", "p64_irc_response", WORKING_DAYS],
  // Step 9, people: P-12 only. People themselves are never in the spec.
  ["people", "p12_cooling_off", INT],
  // Step 10, communications.
  ["comms", "message_templates", list(obj(m("kind", TEXT), m("text", LONG)))],
  ["comms", "faq", LONG],
  ["comms", "contact", LONG],
  ["comms", "p31_reminder_offsets", obj(m("offsets_days", list(INT)))],
  [
    "comms",
    "p32_channels",
    obj(
      // Email only: Matrix (B-05) and WhatsApp (B-03) are deferred.
      m("channels", setOf("email")),
    ),
  ],
  ["comms", "p33_escalation", obj(m("after_days", INT), m("to", TEXT))],
  ["comms", "p35_group_removal_delay", TEXT],
  ["comms", "p37_inbound_messages", TEXT],
  ["comms", "p38_proximity_lists", list(obj(m("organisation", TEXT), m("list", TEXT)))],
  ["comms", "p40_working_calendar", obj(m("weekend", setOf(...WEEKDAYS)), m("holidays", list(DATE)))],
  ["comms", "p50_funded_visibility", TEXT],
  ["comms", "p51_finished_visibility", TEXT],
  ["comms", "p52_public_feed", BOOL],
  ["comms", "p54_aggregate_minimum", INT],
  ["comms", "p76_directory_listing", BOOL],
];

/** Every field of the spec, in step order. */
export const FIELDS: readonly FieldDef[] = ROWS.map(([step, member, shape]) => ({
  key: `${step}.${member}`,
  step,
  member,
  shape,
}));

const BY_KEY: ReadonlyMap<string, FieldDef> = new Map(FIELDS.map((f) => [f.key, f]));

/** The field with key `key`, or null. */
export function fieldOf(key: string): FieldDef | null {
  return BY_KEY.get(key) ?? null;
}

/** The fields of `step`, in table order. */
export function fieldsOf(step: string): FieldDef[] {
  return FIELDS.filter((f) => f.step === step);
}

/**
 * Every member name and option token the shapes use, for the catalogue
 * completeness check: each has a label.
 */
export function shapeVocabulary(): { readonly members: Set<string>; readonly options: Set<string> } {
  const members = new Set<string>();
  const options = new Set<string>();
  const walk = (s: Shape): void => {
    switch (s.t) {
      case "enum":
      case "set":
        for (const o of s.options) options.add(o);
        return;
      case "list":
        walk(s.item);
        return;
      case "object":
        for (const x of s.members) {
          members.add(x.name);
          walk(x.shape);
        }
        return;
      case "tagged":
        for (const v of s.variants) {
          options.add(v.kind);
          for (const x of v.members) {
            members.add(x.name);
            walk(x.shape);
          }
        }
        return;
      default:
        return;
    }
  };
  for (const f of FIELDS) walk(f.shape);
  return { members, options };
}
