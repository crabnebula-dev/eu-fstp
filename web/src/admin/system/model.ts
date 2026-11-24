// The pure part of the tenant admins' System page, `/app/admin/system`
// (ADR-028 record of lane L20; Daniel, 2026-11-21: "usability should win
// over security theater").
//
// - `tenant.system` answers the cell clock, whether the vault answers,
//   whether outgoing mail works, and the host status file that
//   `fstp-admin` writes: `{now, vault, mail, host_file, host}`. Instants
//   are decimal strings of UTC microseconds. Every other value is a flag,
//   a count or one word of a closed list (R-NF-02).
// - `rows` turns the reply into one row per part, each green, amber, red
//   or unknown, with one plain sentence and, when it is not green, who
//   acts (the host admin or you) and what to tell them.
//
// Thresholds (ADR-028 record of lane L20, interim, pending Daniel beyond
// those of `fstp-admin status`): the host report is old after one hour;
// a backup is late after 36 hours and missing after 72; a certificate is
// late under 2 days left and urgent under 1. A keystore snapshot is late
// after 36 hours on a host with backups, as `fstp-admin status` reads it,
// and a failed last try is a problem (ADR-028 records of lanes L27 and
// L26).
// The WAL archive is a problem while it fails, and late while a finished
// segment waits over 10 minutes, as `fstp-admin status` reads it (ADR-012
// record of lane m10/backup-health).

/** A part's state in the host report. */
export const PART_STATES = ["running", "unhealthy", "stopped"] as const;
/** One part state. */
export type PartState = (typeof PART_STATES)[number];

/** The host's one next thing, as `fstp-admin status` names it. */
export const HOST_NEXT = [
  "run_setup",
  "start_service",
  "custodian",
  "pair_custodian",
  "renew_route",
  "renew",
  "public_certificate",
  "configure_backups",
  "wal_archive",
  "backup",
  "restore_drill",
  "custodian_copy",
  "keystore_snapshot",
  "web_admins",
  "verify_admins",
  "copy_keys",
  "nothing",
] as const;
/** One next thing. */
export type HostNext = (typeof HOST_NEXT)[number];

const PARTS = ["cell", "vault", "witness", "edge", "databases", "keys"] as const;
type PartName = (typeof PARTS)[number];

/** Where a restore drill failed (ADR-012 record of lane m10/backup-health). */
export const DRILL_STEPS = ["none", "space", "restore", "recovery", "database", "keystore", "cleanup"] as const;
/** One drill step. */
export type DrillStep = (typeof DRILL_STEPS)[number];

/** The host status report, as the cell read it. */
export interface HostReport {
  readonly writtenAt: bigint;
  readonly setupDone: boolean;
  readonly parts: Readonly<Record<PartName, PartState>>;
  readonly backupsConfigured: boolean;
  readonly lastBackup: bigint | null;
  readonly lastKeyCopy: bigint | null;
  readonly lastVaultErasure: bigint | null;
  /** When the cell's keystore snapshot last verified. */
  readonly lastAppSnapshot: bigint | null;
  readonly appSnapshotFailed: boolean;
  /** When the vault's keystore snapshot last verified. */
  readonly lastVaultSnapshot: bigint | null;
  readonly vaultSnapshotFailed: boolean;
  readonly certificateDays: number | null;
  readonly selfSigned: boolean;
  readonly route: "current" | "mismatch" | "unknown";
  readonly next: HostNext;
  /** The link to the second custodian, which guards the key copies. */
  readonly custodian: "linked" | "unreachable" | "unpaired" | "not_used";
  /** A guard rotation is owed, so an erasure waits. */
  readonly guardOwed: boolean;
  /** A fresh copy is owed to the custodian: the last try failed. */
  readonly guardCopyOwed: boolean;
  /** The WAL archive of both clusters: ok, late, failing, or unknown without backups. */
  readonly walArchive: "ok" | "late" | "failing" | "unknown";
  /** The older of the two clusters' last archived segments. */
  readonly lastWalArchived: bigint | null;
  /** When a restore drill last passed. */
  readonly lastDrillPassed: bigint | null;
  /** Where the last restore drill failed, `none` when it passed or none ran. */
  readonly drillStep: DrillStep;
  /** The restore duration of the last passed drill, in seconds. */
  readonly drillSeconds: number | null;
}

/** One integrity finding (ADR-012 record of lane m10/declared-restore). */
export interface Finding {
  /** The id to acknowledge it by. */
  readonly id: string;
  /** Rows a declared restore lost, or a row the cell could not tell from a deletion. */
  readonly kind: "lost_in_restore" | "possible_deletion";
  /** The platform's audit log or the identity vault's. */
  readonly chain: "app" | "vault";
  readonly from: bigint;
  readonly to: bigint;
  /** When a tenant admin acknowledged it, or null. It stays listed either way. */
  readonly acknowledgedAt: bigint | null;
}

/** The `tenant.system` reply. */
export interface SystemReply {
  readonly now: bigint;
  readonly vault: "answers" | "silent";
  readonly mail: "works" | "fails" | "not_configured";
  /** The newest entry of the cell's erasure log, or null. */
  readonly lastCellErasure: bigint | null;
  readonly hostFile: "present" | "not_configured" | "missing" | "unreadable";
  readonly host: HostReport | null;
  /** Every integrity finding, acknowledged or not. */
  readonly findings: readonly Finding[];
}

const ID = /^(0|[1-9][0-9]{0,38})$/;

function record(v: unknown): Readonly<Record<string, unknown>> | null {
  return typeof v === "object" && v !== null && !Array.isArray(v) ? (v as Readonly<Record<string, unknown>>) : null;
}

function closed(o: Readonly<Record<string, unknown>>, names: readonly string[]): boolean {
  return Object.keys(o).every((k) => names.includes(k)) && names.every((k) => k in o);
}

function instant(v: unknown): bigint | null {
  return typeof v === "string" && ID.test(v) ? BigInt(v) : null;
}

function oneOf<T extends string>(v: unknown, words: readonly T[]): v is T {
  return typeof v === "string" && (words as readonly string[]).includes(v);
}

function host(v: unknown): HostReport | null {
  const o = record(v);
  const names = [
    "written_at",
    "setup_done",
    "parts",
    "backups_configured",
    "last_backup",
    "last_key_copy",
    "last_vault_erasure",
    "last_app_snapshot",
    "app_snapshot_failed",
    "last_vault_snapshot",
    "vault_snapshot_failed",
    "certificate_days",
    "self_signed",
    "route",
    "next",
    "custodian",
    "guard_owed",
    "guard_copy_owed",
    "wal_archive",
    "last_wal_archived",
    "last_drill_passed",
    "drill_step",
    "drill_seconds",
  ];
  if (o === null || !closed(o, names)) return null;
  const p = record(o["parts"]);
  if (p === null || !closed(p, PARTS)) return null;
  const parts: Partial<Record<PartName, PartState>> = {};
  for (const k of PARTS) {
    const s = p[k];
    if (!oneOf(s, PART_STATES)) return null;
    parts[k] = s;
  }
  const writtenAt = instant(o["written_at"]);
  const lastBackup = o["last_backup"] === null ? null : instant(o["last_backup"]);
  const lastKeyCopy = o["last_key_copy"] === null ? null : instant(o["last_key_copy"]);
  const lastVaultErasure = o["last_vault_erasure"] === null ? null : instant(o["last_vault_erasure"]);
  const lastAppSnapshot = o["last_app_snapshot"] === null ? null : instant(o["last_app_snapshot"]);
  const lastVaultSnapshot = o["last_vault_snapshot"] === null ? null : instant(o["last_vault_snapshot"]);
  const { app_snapshot_failed: appSnapshotFailed, vault_snapshot_failed: vaultSnapshotFailed } = o;
  const days = o["certificate_days"];
  const { setup_done: setupDone, backups_configured: backupsConfigured, self_signed: selfSigned, route, next } = o;
  if (writtenAt === null) return null;
  if (o["last_backup"] !== null && lastBackup === null) return null;
  if (o["last_key_copy"] !== null && lastKeyCopy === null) return null;
  if (o["last_vault_erasure"] !== null && lastVaultErasure === null) return null;
  if (o["last_app_snapshot"] !== null && lastAppSnapshot === null) return null;
  if (o["last_vault_snapshot"] !== null && lastVaultSnapshot === null) return null;
  if (typeof appSnapshotFailed !== "boolean" || typeof vaultSnapshotFailed !== "boolean") return null;
  if (days !== null && !(typeof days === "number" && Number.isSafeInteger(days) && days >= 0)) return null;
  if (typeof setupDone !== "boolean" || typeof backupsConfigured !== "boolean" || typeof selfSigned !== "boolean") return null;
  if (!oneOf(route, ["current", "mismatch", "unknown"] as const) || !oneOf(next, HOST_NEXT)) return null;
  const { custodian, guard_owed: guardOwed } = o;
  if (!oneOf(custodian, ["linked", "unreachable", "unpaired", "not_used"] as const)) return null;
  if (typeof guardOwed !== "boolean") return null;
  const guardCopyOwed = o["guard_copy_owed"];
  if (typeof guardCopyOwed !== "boolean") return null;
  const walArchive = o["wal_archive"];
  if (!oneOf(walArchive, ["ok", "late", "failing", "unknown"] as const)) return null;
  const lastWalArchived = o["last_wal_archived"] === null ? null : instant(o["last_wal_archived"]);
  if (o["last_wal_archived"] !== null && lastWalArchived === null) return null;
  const lastDrillPassed = o["last_drill_passed"] === null ? null : instant(o["last_drill_passed"]);
  if (o["last_drill_passed"] !== null && lastDrillPassed === null) return null;
  const drillStep = o["drill_step"];
  if (!oneOf(drillStep, DRILL_STEPS)) return null;
  const drillSeconds = o["drill_seconds"];
  if (drillSeconds !== null && !(typeof drillSeconds === "number" && Number.isSafeInteger(drillSeconds) && drillSeconds >= 1)) return null;
  return Object.freeze({
    writtenAt,
    setupDone,
    parts: Object.freeze(parts as Record<PartName, PartState>),
    backupsConfigured,
    lastBackup,
    lastKeyCopy,
    lastVaultErasure,
    lastAppSnapshot,
    appSnapshotFailed,
    lastVaultSnapshot,
    vaultSnapshotFailed,
    certificateDays: days,
    selfSigned,
    route,
    next,
    custodian,
    guardOwed,
    guardCopyOwed,
    walArchive,
    lastWalArchived,
    lastDrillPassed,
    drillStep,
    drillSeconds,
  });
}

function finding(v: unknown): Finding | null {
  const o = record(v);
  if (o === null || !closed(o, ["id", "kind", "chain", "from", "to", "acknowledged_at"])) return null;
  const { id, kind, chain } = o;
  const from = instant(o["from"]);
  const to = instant(o["to"]);
  const acknowledgedAt = o["acknowledged_at"] === null ? null : instant(o["acknowledged_at"]);
  if (typeof id !== "string" || !ID.test(id)) return null;
  if (!oneOf(kind, ["lost_in_restore", "possible_deletion"] as const)) return null;
  if (!oneOf(chain, ["app", "vault"] as const)) return null;
  if (from === null || to === null || to < from) return null;
  if (o["acknowledged_at"] !== null && acknowledgedAt === null) return null;
  return Object.freeze({ id, kind, chain, from, to, acknowledgedAt });
}

/** The body of `tenant.acknowledge_finding` for the finding `id`. */
export function acknowledgeBody(id: string): Readonly<Record<string, string>> {
  return Object.freeze({ finding: id });
}

/** The findings a tenant admin has not acknowledged yet. */
export function openFindings(r: SystemReply): readonly Finding[] {
  return r.findings.filter((f) => f.acknowledgedAt === null);
}

/** The `tenant.system` reply, or null when it has another shape. */
export function decodeSystem(v: unknown): SystemReply | null {
  const o = record(v);
  if (o === null || !closed(o, ["now", "vault", "mail", "last_cell_erasure", "host_file", "host", "findings"])) return null;
  const raw = o["findings"];
  if (!Array.isArray(raw)) return null;
  const findings: Finding[] = [];
  for (const x of raw) {
    const f = finding(x);
    if (f === null) return null;
    findings.push(f);
  }
  const now = instant(o["now"]);
  const lastCellErasure = o["last_cell_erasure"] === null ? null : instant(o["last_cell_erasure"]);
  if (o["last_cell_erasure"] !== null && lastCellErasure === null) return null;
  const { vault, mail, host_file: hostFile } = o;
  if (now === null) return null;
  if (!oneOf(vault, ["answers", "silent"] as const)) return null;
  if (!oneOf(mail, ["works", "fails", "not_configured"] as const)) return null;
  if (!oneOf(hostFile, ["present", "not_configured", "missing", "unreadable"] as const)) return null;
  const report = o["host"] === null ? null : host(o["host"]);
  if (o["host"] !== null && report === null) return null;
  if ((hostFile === "present") !== (report !== null)) return null;
  return Object.freeze({ now, vault, mail, lastCellErasure, hostFile, host: report, findings: Object.freeze(findings) });
}

// ---------------------------------------------------------------------------
// The rows
// ---------------------------------------------------------------------------

/** A light: green runs, amber needs attention, red is a problem, unknown has no fresh fact. */
export type Light = "green" | "amber" | "red" | "unknown";

/** Who acts on a row that is not green. */
export type Actor = "host" | "you";

/** The rows of the page, in order. */
export const ROW_IDS = [
  "report",
  "cell",
  "vault",
  "services",
  "edge",
  "mail",
  "backups",
  "archive",
  "drill",
  "keys",
  "snapshots",
  "certificates",
] as const;
/** One row id. */
export type RowId = (typeof ROW_IDS)[number];

/** One row: a light, a sentence and, when not green, who acts and what to tell them. */
export interface Row {
  readonly id: RowId;
  readonly light: Light;
  /** The label id of the sentence, `system.row.<id>.<case>`. */
  readonly text: string;
  readonly params: Readonly<Record<string, string>>;
  readonly actor: Actor | null;
  /** The label id of what to tell the actor, `system.tell.<case>`, or null. */
  readonly tell: string | null;
}

/** Microseconds in one hour. */
export const HOUR = 3_600_000_000n;
/** The age after which the host report counts as old (interim, pending Daniel). */
export const REPORT_MAX_AGE = HOUR;
/** The backup age that `fstp-admin status` calls late. */
export const BACKUP_LATE = 36n * HOUR;
/** The backup age shown as a problem (interim, pending Daniel). */
export const BACKUP_MISSING = 72n * HOUR;
/** The keystore snapshot age that `fstp-admin status` calls late (ADR-028 record of lane L27). */
export const SNAPSHOT_LATE = 36n * HOUR;
/** The age of the last passed restore drill after which the next is late: 35 days (ADR-012 record of lane m10/backup-health). */
export const DRILL_LATE = 35n * 24n * HOUR;

/** An age in plain words: the label id and its count. */
export function ageOf(micros: bigint): { readonly label: string; readonly n: string } {
  const minutes = micros < 0n ? 0n : micros / 60_000_000n;
  if (minutes < 120n) return { label: "system.age.minutes", n: minutes.toString() };
  const hours = minutes / 60n;
  if (hours < 48n) return { label: "system.age.hours", n: hours.toString() };
  return { label: "system.age.days", n: (hours / 24n).toString() };
}

/** `YYYY-MM-DD` of an instant in UTC microseconds. */
export function dayOf(micros: bigint): string {
  const d = new Date(Number(micros / 1000n));
  return Number.isFinite(d.getTime()) ? d.toISOString().slice(0, 10) : micros.toString();
}

function row(id: RowId, light: Light, kind: string, params: Record<string, string> = {}, actor: Actor | null = null, tell: string | null = null): Row {
  return Object.freeze({ id, light, text: `system.row.${id}.${kind}`, params: Object.freeze(params), actor, tell });
}

/** Whether the host report is present and fresh. */
export function fresh(r: SystemReply): boolean {
  return r.host !== null && r.now - r.host.writtenAt <= REPORT_MAX_AGE;
}

function reportRow(r: SystemReply): Row {
  if (r.host === null) {
    if (r.hostFile === "not_configured") return row("report", "amber", "not_configured", {}, "host", "system.tell.report_setup");
    return row("report", "amber", r.hostFile, {}, "host", "system.tell.report_now");
  }
  const age = ageOf(r.now - r.host.writtenAt);
  const params = { age: age.n, unit: age.label };
  return fresh(r)
    ? row("report", "green", "fresh", params)
    : row("report", "amber", "old", params, "host", "system.tell.report_timer");
}

/** The newest erasure of the cell or of the vault, or null when neither erased anything. */
export function lastErasure(r: SystemReply): bigint | null {
  const v = r.host?.lastVaultErasure ?? null;
  const c = r.lastCellErasure;
  if (v === null) return c;
  if (c === null) return v;
  return v > c ? v : c;
}

function hostRows(r: SystemReply): Row[] {
  const h = r.host;
  if (h === null) {
    return (["services", "edge", "backups", "archive", "drill", "keys", "snapshots", "certificates"] as const).map((id) => row(id, "unknown", "unknown"));
  }
  const out: Row[] = [];
  const others = [h.parts.witness, h.parts.databases, h.parts.keys];
  out.push(
    others.every((s) => s === "running")
      ? row("services", "green", "running")
      : row("services", "red", "down", {}, "host", "system.tell.start"),
  );
  if (h.parts.edge !== "running") out.push(row("edge", "red", "down", {}, "host", "system.tell.start"));
  else if (h.route === "mismatch") out.push(row("edge", "amber", "mismatch", {}, "host", "system.tell.renew"));
  else if (h.route === "unknown") out.push(row("edge", "amber", "route_unknown", {}, "host", "system.tell.status"));
  else out.push(row("edge", "green", "running"));
  const late = (t: bigint): bigint => r.now - t;
  if (!h.backupsConfigured) out.push(row("backups", "amber", "not_configured", {}, "host", "system.tell.configure_backups"));
  else if (h.lastBackup === null) out.push(row("backups", "red", "none", {}, "host", "system.tell.backup"));
  else {
    const age = ageOf(late(h.lastBackup));
    const params = { age: age.n, unit: age.label };
    const a = late(h.lastBackup);
    if (a > BACKUP_MISSING) out.push(row("backups", "red", "late", params, "host", "system.tell.backup"));
    else if (a > BACKUP_LATE) out.push(row("backups", "amber", "late", params, "host", "system.tell.backup"));
    else out.push(row("backups", "green", "fresh", params));
  }
  out.push(archiveRow(r, h));
  out.push(drillRow(r, h));
  // The runbook asks for a new key copy after each erasure: an older copy
  // still holds the erased key (ADR-028 record of lane L20).
  const erased = lastErasure(r);
  // ADR-028 record of lane `m10/guard-key`: the second custodian guards
  // the copies. While it does not answer, or a guard is still to be
  // replaced, erasures wait.
  if (h.custodian === "unreachable" || h.guardOwed) {
    out.push(row("keys", "red", "custodian_down", {}, "host", "system.tell.custodian"));
  } else if (h.custodian === "unpaired") {
    out.push(row("keys", "amber", "custodian_unpaired", {}, "host", "system.tell.pair_custodian"));
  } else if (h.guardCopyOwed) {
    out.push(row("keys", "amber", "custodian_copy_owed", {}, "host", "system.tell.custodian_copy"));
  } else if (h.lastKeyCopy === null) out.push(row("keys", "amber", "never", {}, "host", "system.tell.copy_keys"));
  else if (erased !== null && erased > h.lastKeyCopy) {
    out.push(
      row("keys", "amber", "before_erasure", { date: dayOf(h.lastKeyCopy), erased: dayOf(erased) }, "host", "system.tell.copy_keys_again"),
    );
  } else out.push(row("keys", "green", "copied", { date: dayOf(h.lastKeyCopy) }));
  out.push(snapshotRow(r, h));
  const days = h.certificateDays;
  if (days === null) out.push(row("certificates", "unknown", "unknown"));
  else if (days < 1) out.push(row("certificates", "red", "ending", { days: String(days) }, "host", "system.tell.renew"));
  else if (days < 2) out.push(row("certificates", "amber", "ending", { days: String(days) }, "host", "system.tell.renew"));
  else if (h.selfSigned) out.push(row("certificates", "amber", "self_signed", {}, "host", "system.tell.public_certificate"));
  else out.push(row("certificates", "green", "fine", { due: String(Math.max(0, days - 2)) }));
  return out;
}

/**
 * The keystore snapshots of the cell and the vault (ADR-028 records of
 * lanes L27 and L26): red when the last try of either failed, amber when
 * either has none or the older one is over 36 hours old, on a host with
 * backups. Without backups the snapshots stay on the host, and the backups
 * row already asks for them.
 */
function snapshotRow(r: SystemReply, h: HostReport): Row {
  const tell = "system.tell.keystore_snapshot";
  if (!h.backupsConfigured) return row("snapshots", "green", "off");
  if (h.appSnapshotFailed || h.vaultSnapshotFailed) return row("snapshots", "red", "failed", {}, "host", tell);
  if (h.lastAppSnapshot === null || h.lastVaultSnapshot === null) return row("snapshots", "amber", "none", {}, "host", tell);
  const oldest = h.lastAppSnapshot < h.lastVaultSnapshot ? h.lastAppSnapshot : h.lastVaultSnapshot;
  const age = ageOf(r.now - oldest);
  const params = { age: age.n, unit: age.label };
  return r.now - oldest > SNAPSHOT_LATE
    ? row("snapshots", "amber", "late", params, "host", tell)
    : row("snapshots", "green", "fresh", params);
}

/**
 * The WAL archive, the backup of recent changes (ADR-012 and ADR-028
 * records of lane `m10/backup-health`): red while it fails, amber while a
 * finished segment waits too long, green with the age of the last saved
 * change. Without backups the backups row already asks for them.
 */
function archiveRow(r: SystemReply, h: HostReport): Row {
  const tell = "system.tell.wal_archive";
  if (!h.backupsConfigured) return row("archive", "green", "off");
  if (h.walArchive === "failing") return row("archive", "red", "failing", {}, "host", tell);
  if (h.walArchive === "late") return row("archive", "amber", "late", {}, "host", tell);
  if (h.walArchive === "unknown") return row("archive", "unknown", "unknown");
  if (h.lastWalArchived === null) return row("archive", "green", "none_yet");
  const age = ageOf(r.now - h.lastWalArchived);
  return row("archive", "green", "fresh", { age: age.n, unit: age.label });
}

/**
 * The restore drill (ADR-012 and ADR-028 records of lane
 * `m10/backup-health`): red when the last one failed, naming the step;
 * amber when none passed in 35 days; green with its date and duration.
 */
function drillRow(r: SystemReply, h: HostReport): Row {
  const tell = "system.tell.drill";
  if (!h.backupsConfigured) return row("drill", "green", "off");
  if (h.drillStep !== "none") return row("drill", "red", `failed_${h.drillStep}`, {}, "host", tell);
  if (h.lastDrillPassed === null) return row("drill", "amber", "never", {}, "host", tell);
  const date = dayOf(h.lastDrillPassed);
  if (r.now - h.lastDrillPassed > DRILL_LATE) return row("drill", "amber", "late", { date }, "host", tell);
  const minutes = String(Math.max(1, Math.ceil((h.drillSeconds ?? 60) / 60)));
  return row("drill", "green", "passed", { date, minutes });
}

/** Every row of the page, in `ROW_IDS` order. */
export function rows(r: SystemReply): readonly Row[] {
  const all: Row[] = [
    reportRow(r),
    row("cell", "green", "running"),
    r.vault === "answers" ? row("vault", "green", "answers") : row("vault", "red", "silent", {}, "host", "system.tell.start"),
    r.mail === "works"
      ? row("mail", "green", "works")
      : r.mail === "fails"
        ? row("mail", "red", "fails", {}, "host", "system.tell.mail")
        : row("mail", "red", "not_configured", {}, "host", "system.tell.mail_setup"),
    ...hostRows(r),
  ];
  const at = (id: RowId): number => ROW_IDS.indexOf(id);
  return Object.freeze(all.sort((a, b) => at(a.id) - at(b.id)));
}

/** The worst light of `rs`: red, then amber, then unknown, then green. */
export function overall(rs: readonly Row[]): Light {
  for (const l of ["red", "amber", "unknown"] as const) {
    if (rs.some((x) => x.light === l)) return l;
  }
  return "green";
}

/** The host's next thing, when it is not "nothing": its label id and who acts. */
export function hostNext(r: SystemReply): { readonly text: string; readonly actor: Actor } | null {
  if (r.host === null || r.host.next === "nothing") return null;
  const actor: Actor = r.host.next === "web_admins" ? "you" : "host";
  return { text: `system.next.${r.host.next}`, actor };
}
