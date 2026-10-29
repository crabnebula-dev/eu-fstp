// The workspace autosave (journey J4, I-21 workspace; M4 design section
// 3.9).
//
// Pure and without DOM: the save and the timer are injected. Rules:
//
// - At most one save is in flight, so an older draft can never overwrite
//   a newer one at the cell.
// - An edit schedules a save of the latest value after the delay. Edits
//   within the delay are saved once, as the latest value.
// - When a save completes and a newer edit is waiting, the newer value is
//   saved next. Its own timer starts it, or the save starts at once when
//   that timer has already fired.
// - A refused or failed save reports `failed` and keeps the value. It is
//   not retried on its own, so a refusal never repeats in a loop. The
//   next edit or a flush saves the latest value again.
// - One case is not a retry: a newer edit whose timer fired while the
//   failed save was in flight. That value was never tried, so it is saved
//   at once. Each such save is for a newer edit, so this never loops.

/** What the autosave reports. */
export type AutosaveStatus = "idle" | "pending" | "saving" | "saved" | "failed";

/** What the autosave needs from the page. */
export interface AutosaveDeps<T> {
  /** Stores `value` at the cell. True when it was stored; a rejection counts as false. */
  save(value: T): Promise<boolean>;
  /** Runs `fn` once after `ms`, and returns a handle. */
  setTimer(fn: () => void, ms: number): number;
  /** Cancels a timer that has not run. */
  clearTimer(handle: number): void;
  /** Hears every status change. */
  onStatus(status: AutosaveStatus): void;
}

/** One autosave. */
export interface Autosave<T> {
  /** Records `value` as the latest edit. A save of the latest value follows after the delay. */
  edit(value: T): void;
  /** Saves the latest unsaved value now. True when the latest value is stored. */
  flush(): Promise<boolean>;
  /** Whether the latest edit is not stored yet. */
  unsaved(): boolean;
}

/**
 * An autosave over `deps` with `delayMs` between the last edit and its
 * save. It throws a `TypeError` for a delay that is not a non-negative
 * safe integer.
 */
export function createAutosave<T>(deps: AutosaveDeps<T>, delayMs: number): Autosave<T> {
  if (!Number.isSafeInteger(delayMs) || delayMs < 0) {
    throw new TypeError("the autosave delay is a non-negative whole number of milliseconds");
  }
  /** The latest edit, boxed so that any value of T can be held. */
  let latest: { readonly value: T } | null = null;
  /** The number of edits so far. */
  let edits = 0;
  /** Whether the latest edit is not stored yet. */
  let dirty = false;
  let timer: number | null = null;
  let flight: Promise<boolean> | null = null;

  function report(s: AutosaveStatus): void {
    try {
      deps.onStatus(s);
    } catch {
      // A failing listener must not stop the save chain.
    }
  }

  function cancelTimer(): void {
    if (timer !== null) {
      deps.clearTimer(timer);
      timer = null;
    }
  }

  /** What a completed save leads to. It runs after `flight` names the save. */
  function finish(ok: boolean, at: number): boolean {
    flight = null;
    if (ok && edits === at) {
      dirty = false;
    }
    if (!ok && dirty && edits !== at && timer === null) {
      // A newer edit's timer fired while the failed save was in flight, so
      // that newer value was never tried. It gets its one attempt now.
      start();
    } else if (!ok) {
      report("failed");
    } else if (!dirty) {
      report("saved");
    } else if (timer !== null) {
      report("pending");
    } else {
      // The newer edit's timer fired while this save was in flight.
      start();
    }
    return ok;
  }

  /**
   * Starts a save of the latest value and records it as the one in
   * flight. Callers check that none is in flight. The outcome is handled
   * in a later reaction, so `flight` always names the save first, even
   * when `save` throws at once.
   */
  function start(): Promise<boolean> {
    const box = latest;
    const at = edits;
    report("saving");
    let saving: Promise<unknown>;
    try {
      saving = box === null ? Promise.resolve(false) : Promise.resolve(deps.save(box.value));
    } catch {
      saving = Promise.resolve(false);
    }
    const p = saving.then(
      (ok) => finish(ok === true, at),
      () => finish(false, at),
    );
    flight = p;
    return p;
  }

  function fire(): void {
    timer = null;
    if (flight === null && dirty) {
      start();
    }
  }

  return Object.freeze({
    edit(value: T): void {
      latest = { value };
      edits += 1;
      dirty = true;
      cancelTimer();
      timer = deps.setTimer(fire, delayMs);
      report("pending");
    },
    unsaved(): boolean {
      return dirty;
    },
    async flush(): Promise<boolean> {
      let attempted = false;
      for (;;) {
        cancelTimer();
        const f = flight;
        if (f !== null) {
          await f;
          continue;
        }
        if (!dirty) {
          return true;
        }
        if (attempted) {
          return false;
        }
        attempted = true;
        if (await start()) {
          // A newer edit may have arrived meanwhile; it gets one attempt too.
          attempted = false;
        }
      }
    },
  });
}
