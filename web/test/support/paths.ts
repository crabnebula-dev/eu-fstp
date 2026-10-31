// Source-tree paths for the compiled tests and fuzz targets.
//
// web/test/tsconfig.json compiles web/src, web/test and web/fuzz into
// web/dist/test-build/{src,test,fuzz}. This file then sits at
// web/dist/test-build/test/support/paths.js, four levels below web/.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

/** The `web/` directory of the source tree. */
export const WEB_DIR: string = fileURLToPath(new URL("../../../../", import.meta.url));

/** The repository root. */
export const REPO_DIR: string = join(WEB_DIR, "..");

/** Fails loudly when the build layout is not the one this file expects. */
export function checkLayout(): void {
  if (!existsSync(join(WEB_DIR, "package.json")) || !existsSync(join(WEB_DIR, "test", "runner.ts"))) {
    throw new Error(
      `web/test expects its build in web/dist/test-build (tsc -p web/test); ${WEB_DIR} is not web/`,
    );
  }
}
