// The few Node.js host APIs that the in-house test runner and the fuzz
// harness use (ADR-003 amendment of 2026-10-28, Node.js 24.11.1).
//
// No `@types/node` package is allowlisted, so these declarations are
// written in-house. They cover only what web/test and web/fuzz call. The
// application in web/src never sees them: web/tsconfig.json does not
// include this file.

declare module "node:fs" {
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function readFileSync(path: string): Uint8Array;
  export function readdirSync(path: string): string[];
  export function existsSync(path: string): boolean;
  export function statSync(path: string): {
    isDirectory(): boolean;
    isFile(): boolean;
  };
}

declare module "node:crypto" {
  interface Hash {
    update(data: string | Uint8Array): Hash;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: "sha1" | "sha256"): Hash;
}

declare module "node:url" {
  export function fileURLToPath(url: string | URL): string;
  export function pathToFileURL(path: string): URL;
}

declare module "node:path" {
  export function join(...parts: string[]): string;
  export function dirname(path: string): string;
}

declare const process: {
  readonly argv: readonly string[];
  readonly env: Readonly<Record<string, string | undefined>>;
  exitCode: number | undefined;
  readonly stdout: { write(text: string): boolean };
};
