// store.ts: the application state store (M4 design section 3.9, ADR-014).
// State is frozen, every listener sees every state in order, and nothing
// reaches browser storage.

import { assert, eq, forAll, show, test, thrown } from "./support/harness.js";
import { core } from "./support/load.js";

interface Counter {
  readonly n: number;
  readonly items: readonly { readonly id: string }[];
}

function isDeepFrozen(v: unknown): boolean {
  if (typeof v !== "object" || v === null) {
    return true;
  }
  return Object.isFrozen(v) && Object.values(v).every(isDeepFrozen);
}

/** ADR-014: `get` returns the initial state, deeply frozen. */
test("adr014_store_get_returns_initial_state_frozen", async () => {
  const { createStore } = await core("store");
  const s = createStore<Counter>({ n: 0, items: [{ id: "a" }] });
  eq(s.get(), { n: 0, items: [{ id: "a" }] }, "initial state");
  assert(isDeepFrozen(s.get()), "initial state is deeply frozen");
  s.update((c) => ({ n: c.n + 1, items: [...c.items, { id: "b" }] }));
  assert(isDeepFrozen(s.get()), "updated state is deeply frozen");
});

/** ADR-014: an update that returns the same state notifies nobody. */
test("adr014_store_same_reference_update_notifies_nobody", async () => {
  const { createStore } = await core("store");
  const s = createStore<Counter>({ n: 0, items: [] });
  let calls = 0;
  s.subscribe(() => {
    calls += 1;
  });
  s.update((c) => c);
  eq(calls, 0, "no notification");
  s.update((c) => ({ ...c, n: 1 }));
  eq(calls, 1, "one notification for one change");
});

/** ADR-014: after unsubscribing, a listener is never called again, and the others still are. */
test("adr014_store_unsubscribe_stops_notifications", async () => {
  const { createStore } = await core("store");
  const s = createStore<Counter>({ n: 0, items: [] });
  const a: number[] = [];
  const b: number[] = [];
  const offA = s.subscribe((c) => a.push(c.n));
  s.subscribe((c) => b.push(c.n));
  s.update((c) => ({ ...c, n: 1 }));
  offA();
  offA();
  s.update((c) => ({ ...c, n: 2 }));
  eq(a, [1], "a stopped after unsubscribing");
  eq(b, [1, 2], "b kept listening");
});

/** ADR-014: an update made inside a listener runs after the current round, so all listeners see states in order. */
test("adr014_store_nested_update_runs_after_current_round", async () => {
  const { createStore } = await core("store");
  const s = createStore<Counter>({ n: 0, items: [] });
  const first: number[] = [];
  const second: number[] = [];
  s.subscribe((c) => {
    first.push(c.n);
    if (c.n === 1) {
      s.update((x) => ({ ...x, n: 2 }));
    }
  });
  s.subscribe((c) => second.push(c.n));
  s.update((c) => ({ ...c, n: 1 }));
  eq(first, [1, 2], "first listener saw 1 then 2");
  eq(second, [1, 2], "second listener saw 1 before 2");
  eq(s.get().n, 2, "final state");
});

type Op = { readonly op: "update"; readonly by: number } | { readonly op: "sub" } | { readonly op: "unsub"; readonly which: number };

/**
 * ADR-014: over random sequences of updates, subscriptions and removals,
 * each listener receives exactly the states made while it was subscribed,
 * in order, and `get` always gives the latest.
 */
test("adr014_store_listeners_see_every_state_in_order", async () => {
  const { createStore } = await core("store");
  forAll(
    (r) =>
      Array.from({ length: r.between(1, 30) }, (): Op => {
        const k = r.below(4);
        return k === 0 ? { op: "sub" } : k === 1 ? { op: "unsub", which: r.below(6) } : { op: "update", by: r.below(3) };
      }),
    (ops) => {
      const s = createStore<Counter>({ n: 0, items: [] });
      const seen: number[][] = [];
      const want: number[][] = [];
      const offs: (() => void)[] = [];
      const live: boolean[] = [];
      let n = 0;
      for (const o of ops) {
        if (o.op === "sub") {
          const i = seen.length;
          seen.push([]);
          want.push([]);
          live.push(true);
          offs.push(s.subscribe((c) => seen[i]?.push(c.n)));
        } else if (o.op === "unsub") {
          if (o.which < offs.length) {
            offs[o.which]?.();
            live[o.which] = false;
          }
        } else {
          const before = s.get();
          s.update((c) => (o.by === 0 ? c : { ...c, n: c.n + o.by }));
          if (o.by !== 0) {
            n += o.by;
            live.forEach((on, i) => {
              if (on) {
                want[i]?.push(n);
              }
            });
          } else {
            assert(s.get() === before, "a same-reference update keeps the state object");
          }
        }
        eq(s.get().n, n, "get gives the latest state");
      }
      eq(seen, want, "states seen by each listener");
    },
    { runs: 400 },
  );
});

/**
 * ADR-014: the store never writes application state to browser storage.
 * Strict reading, interim pending Daniel: state that holds proposal text or
 * names must not outlive the page in the browser.
 */
test("adr014_store_never_touches_browser_storage", async () => {
  const touched: string[] = [];
  const spy = new Proxy(
    {},
    {
      get(_t, k) {
        touched.push(String(k));
        return () => undefined;
      },
    },
  );
  const g = globalThis as unknown as Record<string, unknown>;
  const saved = { l: g["localStorage"], s: g["sessionStorage"], i: g["indexedDB"] };
  g["localStorage"] = spy;
  g["sessionStorage"] = spy;
  g["indexedDB"] = spy;
  try {
    const { createStore } = await core("store");
    const s = createStore<Counter>({ n: 0, items: [{ id: "CANARY-ID-7f3a" }] });
    s.subscribe(() => undefined);
    s.update((c) => ({ ...c, n: 1 }));
    s.get();
    eq(touched, [], "browser storage accessed");
  } finally {
    g["localStorage"] = saved.l;
    g["sessionStorage"] = saved.s;
    g["indexedDB"] = saved.i;
  }
});

/**
 * ADR-014 (state is frozen; plain data, interim pending Daniel): a Map,
 * Set, Date, typed array, class instance, function or getter in state is
 * refused with `StoreError`, since freezing would not make it immutable.
 */
test("adr014_store_refuses_state_that_is_not_plain_data", async () => {
  const { createStore, StoreError } = await core("store");
  class Box {
    readonly v = 1;
  }
  const bad: readonly [string, () => unknown][] = [
    ["Map", () => ({ m: new Map<string, number>() })],
    ["Set", () => ({ s: new Set<number>() })],
    ["Date", () => ({ d: new Date(0) })],
    ["typed array", () => ({ t: new Uint8Array(2) })],
    ["class instance", () => ({ b: new Box() })],
    ["function", () => ({ f: () => 1 })],
    ["getter", () => Object.defineProperty({}, "g", { get: () => 1, enumerable: true })],
    ["nested Map", () => ({ a: [{ m: new Map<string, number>() }] })],
  ];
  for (const [what, make] of bad) {
    const e = thrown(() => createStore(make()), `createStore with a ${what}`);
    assert(e instanceof StoreError, `${what}: threw ${show(String(e))}, not a StoreError`);
  }
  const s = createStore<{ readonly n: number; readonly x?: unknown }>({ n: 0 });
  const next = { n: 1, x: { m: new Map<string, number>() } };
  const e = thrown(() => s.update(() => next), "update to a state with a Map");
  assert(e instanceof StoreError, `update: threw ${show(String(e))}, not a StoreError`);
  eq(s.get(), { n: 0 }, "the refused update leaves the state");
  eq(Object.isFrozen(next), false, "a refused state is not frozen");
  const plain = createStore({ a: [1, "b", null, true, { c: Object.create(null) as object }], u: undefined });
  eq(Object.isFrozen(plain.get().a[4]), true, "plain data and null-prototype objects pass, frozen");
});
