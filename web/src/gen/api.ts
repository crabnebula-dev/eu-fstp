// Operation types, the operation table, route segments and structural
// validators, generated from the OPS registry of fstp-access by
// tools/gen-ts (M4 design sections 1.1 and 3.9).
//
// W0 stub. This is not generator output. Lane W3a owns tools/gen-ts and
// this file, and replaces it with the output of `gen-ts`. CI then runs
// `gen-ts --check`. The W0 registry is empty, so this table holds no
// operation, and the application can call none.

/** An HTTP method of a web route. */
export type Method = "GET" | "POST" | "PUT" | "DELETE";

/** One operation of the registry, as the application sees it. */
export interface Operation {
  readonly name: string;
  readonly method: Method;
  readonly path: string;
}

/** Every operation of the registry. Empty in W0. */
export const OPERATIONS: readonly Operation[] = [];
