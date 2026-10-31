// The application state store (M4 design section 3.9, ADR-014).
//
// State is plain data and deeply frozen, so a page cannot change it
// behind the store's back. A state holding anything else is refused. Every listener sees every state in order. An
// update made while listeners run waits for the current round to end.
//
// Interim strict reading, pending Daniel: the store keeps state in memory
// only and never touches browser storage, since state can hold proposal
// text or names that must not outlive the page.

/** A store of application state. */
export interface Store<S> {
  /** The current state, deeply frozen. */
  get(): S;
  /**
   * Replaces the state with `f(current)`. When `f` returns the same
   * reference, nothing is notified. An update made inside a listener runs
   * after the current notification round, so each listener sees every
   * state in order.
   */
  update(f: (s: S) => S): void;
  /** Adds a listener. The returned function removes it, once. */
  subscribe(listener: (s: S) => void): () => void;
}

/** The error a store throws for a state that is not plain data. */
export class StoreError extends TypeError {
  constructor(message: string) {
    super(message);
    this.name = "StoreError";
  }
}

/**
 * Objects this module has checked and frozen. A frozen object's data
 * properties never change, and everything they reach was checked and
 * frozen too, so such a subtree is never walked again.
 */
const sealed = new WeakSet<object>();

/** Whether `x` is an array or an object whose prototype is `Object.prototype` or null. */
function isPlainContainer(x: object): boolean {
  if (Array.isArray(x)) {
    return Object.getPrototypeOf(x) === Array.prototype;
  }
  const proto: unknown = Object.getPrototypeOf(x);
  return proto === Object.prototype || proto === null;
}

/**
 * Checks that `v` is plain data, then freezes it and every object it
 * reaches. Plain data is a primitive, an array, or an object whose
 * prototype is `Object.prototype` or null, holding data properties only.
 * A function, a Map, a Set, a Date, a typed array, a class instance or a
 * getter is refused with `StoreError`, and then nothing is frozen.
 * Getters are never called.
 *
 * Interim, pending Daniel: ADR-014 says state is frozen, and this reads
 * it as plain JSON-like data, since a Map, Set or Date stays mutable
 * through its methods when frozen.
 */
function deepFreeze<T>(v: T): T {
  const seen = new Set<object>();
  const stack: unknown[] = [v];
  while (stack.length > 0) {
    const x = stack.pop();
    if (typeof x === "function") {
      throw new StoreError("store state holds a function");
    }
    if (typeof x !== "object" || x === null || seen.has(x) || sealed.has(x)) {
      continue;
    }
    if (!isPlainContainer(x)) {
      throw new StoreError("store state holds an object that is not a plain object or array");
    }
    seen.add(x);
    for (const key of Reflect.ownKeys(x)) {
      const d = Object.getOwnPropertyDescriptor(x, key);
      if (d === undefined) {
        continue;
      }
      if (!("value" in d)) {
        throw new StoreError(`store state has an accessor property ${String(key)}`);
      }
      stack.push(d.value);
    }
  }
  for (const x of seen) {
    Object.freeze(x);
    sealed.add(x);
  }
  return v;
}

interface Entry<S> {
  readonly listener: (s: S) => void;
  live: boolean;
}

/**
 * A store holding `initial`, deeply frozen. It throws `StoreError` when
 * `initial` is not plain data. A listener or update function that throws,
 * or an update giving a state that is not plain data, does not stop the
 * round: the state stays as it was for that update, the others still
 * run, and the first error is thrown to the caller of `update` once the
 * queue is empty.
 */
export function createStore<S>(initial: S): Store<S> {
  let state = deepFreeze(initial);
  const entries: Entry<S>[] = [];
  const queue: ((s: S) => S)[] = [];
  let draining = false;

  function drain(): void {
    draining = true;
    let failure: { readonly error: unknown } | null = null;
    try {
      for (let f = queue.shift(); f !== undefined; f = queue.shift()) {
        let next: S;
        try {
          next = f(state);
          if (Object.is(next, state)) {
            continue;
          }
          deepFreeze(next);
        } catch (error) {
          failure ??= { error };
          continue;
        }
        state = next;
        const current = next;
        for (const e of entries.slice()) {
          if (!e.live) {
            continue;
          }
          try {
            e.listener(current);
          } catch (error) {
            failure ??= { error };
          }
        }
      }
    } finally {
      draining = false;
    }
    if (failure !== null) {
      throw failure.error;
    }
  }

  return Object.freeze({
    get(): S {
      return state;
    },
    update(f: (s: S) => S): void {
      if (typeof f !== "function") {
        throw new TypeError("update takes a function");
      }
      queue.push(f);
      if (!draining) {
        drain();
      }
    },
    subscribe(listener: (s: S) => void): () => void {
      if (typeof listener !== "function") {
        throw new TypeError("subscribe takes a function");
      }
      const entry: Entry<S> = { listener, live: true };
      entries.push(entry);
      return () => {
        if (!entry.live) {
          return;
        }
        entry.live = false;
        const at = entries.indexOf(entry);
        if (at >= 0) {
          entries.splice(at, 1);
        }
      };
    },
  });
}
