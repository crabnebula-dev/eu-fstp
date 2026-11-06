/**
 * Utilities for PDF save operations.
 *
 * Provides helpers for determining save strategy (incremental vs full).
 */

/**
 * Reasons why incremental save is not possible.
 */
export type IncrementalSaveBlocker =
  | "newly-created"
  | "linearized"
  | "brute-force-recovery"
  | "encryption-changed"
  | "encryption-added"
  | "encryption-removed";

/**
 * Check if a document can be saved incrementally.
 *
 * Returns null if incremental save is possible, or a blocker reason if not.
 */
export function checkIncrementalSaveBlocker(context: {
  isNewlyCreated: boolean;
  isLinearized: boolean;
  recoveredViaBruteForce: boolean;
  encryptionChanged: boolean;
  encryptionAdded: boolean;
  encryptionRemoved: boolean;
}): IncrementalSaveBlocker | null {
  // Newly created documents have no original bytes to append to
  if (context.isNewlyCreated) {
    return "newly-created";
  }

  if (context.isLinearized) {
    return "linearized";
  }

  if (context.recoveredViaBruteForce) {
    return "brute-force-recovery";
  }

  if (context.encryptionAdded) {
    return "encryption-added";
  }

  if (context.encryptionRemoved) {
    return "encryption-removed";
  }

  if (context.encryptionChanged) {
    return "encryption-changed";
  }

  return null;
}
