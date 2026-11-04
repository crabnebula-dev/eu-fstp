// The few Node.js host APIs that the site specs and the helpers they
// import use (ADR-003 amendment of 2026-10-28). No `@types/node` package
// is allowlisted, so these declarations are written in-house, as
// `web/test/node.d.ts` does for the web tests. They cover only what
// `e2e/site/**`, `e2e/playwright.config.ts`, `e2e/navigation/support.ts`,
// `e2e/review/*`, `e2e/applicant/support.ts` and `e2e/creator/*` call.
// Playwright loads no `.d.ts` file, so this file never runs.
//
// Type-check the site specs with `e2e/site/tsconfig.json`:
//
//   e2e/node_modules/.bin/tsc -p e2e/site

declare module 'node:fs' {
  export function readFileSync(path: string, encoding: 'utf8'): string;
  export function existsSync(path: string): boolean;
  export function mkdtempSync(prefix: string): string;
  export function rmSync(path: string, options: { readonly recursive: boolean; readonly force: boolean }): void;
  export function readdirSync(path: string): string[];
  export function statSync(path: string): { isDirectory(): boolean; isFile(): boolean };
}

declare module 'node:path' {
  export function join(...parts: string[]): string;
  export function resolve(...parts: string[]): string;
}

declare module 'node:os' {
  export function tmpdir(): string;
}

declare module 'node:child_process' {
  export interface Readable {
    on(event: 'data', listener: (chunk: { toString(): string }) => void): this;
  }
  export interface ChildProcess {
    readonly pid: number | undefined;
    readonly exitCode: number | null;
    readonly stdout: Readable | null;
    readonly stderr: Readable | null;
    kill(signal?: string): boolean;
    once(event: 'exit', listener: (code: number | null, signal: string | null) => void): this;
    once(event: 'error', listener: (e: Error) => void): this;
  }
  export function spawn(
    command: string,
    args: readonly string[],
    options: { readonly stdio: readonly ['ignore', 'pipe', 'pipe']; readonly env?: Record<string, string | undefined> },
  ): ChildProcess;
}

declare const process: {
  readonly env: Readonly<Record<string, string | undefined>>;
};

declare const __dirname: string;

declare const Buffer: {
  from(s: string, encoding: 'base64url' | 'base64' | 'utf8'): { toString(encoding: 'hex' | 'utf8' | 'base64'): string };
};
