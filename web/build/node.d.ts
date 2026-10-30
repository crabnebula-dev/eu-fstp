// The few Node.js host APIs that the asset packer uses (ADR-003
// amendment of 2026-10-28, Node.js 24.11.1).
//
// No `@types/node` package is allowlisted, so these declarations are
// written in-house. They cover only what `web/build` calls. The
// application in web/src never sees them.

declare module "node:fs" {
  export function readFileSync(path: string): Uint8Array;
  export function readFileSync(path: string, encoding: "utf8"): string;
  export function writeFileSync(path: string, data: string | Uint8Array): void;
  export function readdirSync(path: string): string[];
  export function mkdirSync(path: string, options: { readonly recursive: true }): void;
  export function rmSync(path: string, options: { readonly recursive: true; readonly force: true }): void;
  export function lstatSync(path: string): {
    isDirectory(): boolean;
    isFile(): boolean;
    isSymbolicLink(): boolean;
  };
}

declare module "node:path" {
  export function join(...parts: string[]): string;
  export function dirname(path: string): string;
}

declare module "node:crypto" {
  interface Hash {
    update(data: string | Uint8Array): Hash;
    digest(encoding: "hex"): string;
  }
  export function createHash(algorithm: "sha256"): Hash;
}

declare const process: {
  readonly argv: readonly string[];
  exitCode: number | undefined;
  readonly stdout: { write(text: string): boolean };
  readonly stderr: { write(text: string): boolean };
};
