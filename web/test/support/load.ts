// Loads the production modules under test.
//
// W0 left no stub below web/src/core. A static import of a missing module
// would stop tsc, so the tests import each module by a computed URL and
// type it with support/contract.ts. A missing module or export throws
// `NotImplemented`, which the runner reports as red.

import { type CoreModules, type GenApiModule, REQUIRED_EXPORTS } from "./contract.js";
import { NotImplemented } from "./harness.js";

/** Whether `e` says that the module at `url` does not exist. */
function missing(e: unknown, url: URL): boolean {
  if (typeof e !== "object" || e === null) {
    return false;
  }
  const code = (e as { code?: unknown }).code;
  const message = (e as { message?: unknown }).message;
  return code === "ERR_MODULE_NOT_FOUND" && typeof message === "string" && message.includes(url.pathname);
}

async function importOrNotImplemented(url: URL, source: string): Promise<Record<string, unknown>> {
  try {
    const mod: unknown = await import(url.href);
    return mod as Record<string, unknown>;
  } catch (e) {
    if (missing(e, url)) {
      throw new NotImplemented(`${source} does not exist yet (W0 left no stub; lane W1c implementer)`);
    }
    throw e;
  }
}

const cache = new Map<string, Record<string, unknown>>();

/** The core module `name`, with every export the contract requires. */
export async function core<K extends keyof CoreModules>(name: K): Promise<CoreModules[K]> {
  let mod = cache.get(name);
  if (mod === undefined) {
    mod = await importOrNotImplemented(new URL(`../../src/core/${name}.js`, import.meta.url), `web/src/core/${name}.ts`);
    cache.set(name, mod);
  }
  const absent = REQUIRED_EXPORTS[name].filter((k) => !(String(k) in mod));
  if (absent.length > 0) {
    throw new NotImplemented(`web/src/core/${name}.ts does not export ${absent.map(String).join(", ")}`);
  }
  return mod as unknown as CoreModules[K];
}

/** The generated validators and their schemas from web/src/gen/api.ts. */
export async function genApi(): Promise<GenApiModule> {
  const mod = await importOrNotImplemented(new URL("../../src/gen/api.js", import.meta.url), "web/src/gen/api.ts");
  const validators = mod["VALIDATORS"];
  const schemas = mod["SCHEMAS"];
  if (typeof validators !== "object" || validators === null || typeof schemas !== "object" || schemas === null) {
    throw new NotImplemented("web/src/gen/api.ts exports no VALIDATORS and SCHEMAS yet (lane W3a, tools/gen-ts)");
  }
  if (Object.keys(validators).length === 0) {
    throw new NotImplemented("web/src/gen/api.ts has an empty VALIDATORS table (the W0 registry is empty; lane W3a)");
  }
  return mod as unknown as GenApiModule;
}
