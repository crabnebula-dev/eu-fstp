// The pure part of the tenant admin's funder profiles page (Daniel,
// 2026-11-15 late, `docs/handoff/m9-design.md`).
//
// - `tenant.funder_profiles` answers `{profiles}`: every shipped profile
//   version and every tenant-owned version, each with its id, version,
//   owner, file hash, the shipped version it was copied from, and its
//   profile text.
// - `tenant.funder_profile.copy` takes `{id, from_profile, from_version}`
//   and makes version 1 of a tenant profile from any listed version.
// - `tenant.funder_profile.save` takes `{id, profile}`: the edited profile
//   object. The cell sets its id and the next version, and refuses a
//   profile its parser refuses.
// - A tenant profile id starts with `tenant-`, so it never names a
//   shipped profile.

/** Who owns a profile version. */
export type Owner = "shipped" | "tenant";

/** One listed profile version. */
export interface ProfileRow {
  readonly id: string;
  readonly version: string;
  readonly owner: Owner;
  readonly digest: string;
  readonly source: { readonly profile: string; readonly version: string } | null;
  readonly text: string;
}

const ID = /^[a-z][a-z0-9-]{0,63}$/;
const VERSION = /^[1-9][0-9]{0,4}$/;
const HEX = /^[0-9a-f]{64}$/;

function row(v: unknown): ProfileRow | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Readonly<Record<string, unknown>>;
  if (Object.keys(o).length !== 6) return null;
  const { id, version, owner, digest, source, text } = o;
  if (typeof id !== "string" || !ID.test(id)) return null;
  if (typeof version !== "string" || !VERSION.test(version)) return null;
  if (owner !== "shipped" && owner !== "tenant") return null;
  if (typeof digest !== "string" || !HEX.test(digest)) return null;
  if (typeof text !== "string") return null;
  let src: ProfileRow["source"] = null;
  if (source !== null) {
    if (typeof source !== "object" || source === undefined || Array.isArray(source)) return null;
    const s = source as Readonly<Record<string, unknown>>;
    const { profile, version: sv } = s;
    if (Object.keys(s).length !== 2 || typeof profile !== "string" || !ID.test(profile) || typeof sv !== "string" || !VERSION.test(sv)) return null;
    src = { profile, version: sv };
  }
  return { id, version, owner, digest, source: src, text };
}

/** The `tenant.funder_profiles` reply, or null for any other shape. */
export function decodeProfiles(v: unknown): readonly ProfileRow[] | null {
  if (typeof v !== "object" || v === null || Array.isArray(v)) return null;
  const o = v as Readonly<Record<string, unknown>>;
  if (Object.keys(o).length !== 1 || !Array.isArray(o["profiles"])) return null;
  const out: ProfileRow[] = [];
  for (const x of o["profiles"] as unknown[]) {
    const r = row(x);
    if (r === null) return null;
    out.push(r);
  }
  return out;
}

/** Whether `id` may name a tenant profile: `tenant-` and a lower-case token. */
export function isTenantId(id: string): boolean {
  return id.startsWith("tenant-") && id.length > "tenant-".length && ID.test(id);
}

/** The body of a copy, or null for an id that is not a tenant id. */
export function copyBody(id: string, from: ProfileRow): Readonly<Record<string, string>> | null {
  return isTenantId(id) ? { id, from_profile: from.id, from_version: from.version } : null;
}

/** The body of a save, or null when `text` is not one JSON object. */
export function saveBody(id: string, text: string): Readonly<Record<string, unknown>> | null {
  if (!isTenantId(id)) return null;
  try {
    const v: unknown = JSON.parse(text);
    return typeof v === "object" && v !== null && !Array.isArray(v) ? { id, profile: v } : null;
  } catch {
    return null;
  }
}

/** The latest version of each tenant profile, by id. */
export function latestTenant(rows: readonly ProfileRow[]): ProfileRow[] {
  const by = new Map<string, ProfileRow>();
  for (const r of rows) {
    if (r.owner !== "tenant") continue;
    const had = by.get(r.id);
    if (had === undefined || Number(r.version) > Number(had.version)) by.set(r.id, r);
  }
  return [...by.values()].sort((a, b) => (a.id < b.id ? -1 : a.id > b.id ? 1 : 0));
}
