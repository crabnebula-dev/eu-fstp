/**
 * Page size utilities.
 */

/** Standard page sizes in points (1 point = 1/72 inch) */
export const PAGE_SIZES = {
  letter: {
    width: 612,
    height: 792,
  },
  a4: {
    width: 595.28,
    height: 841.89,
  },
  legal: {
    width: 612,
    height: 1008,
  },
} as const;

/** Available page size presets */
export type PageSizePreset = keyof typeof PAGE_SIZES;

/** Page orientation */
export type PageOrientation = "portrait" | "landscape";

/** Options for resolving page size */
export interface PageSizeOptions {
  /** Page width in points */
  width?: number;
  /** Page height in points */
  height?: number;
  /** Use a preset size */
  size?: PageSizePreset;
  /** Page orientation (default: "portrait") */
  orientation?: PageOrientation;
}

/**
 * Resolve page dimensions from options.
 *
 * Priority:
 * 1. Explicit width/height if both provided
 * 2. Preset size (default: letter)
 * 3. Apply orientation swap if landscape
 *
 * @param options - Page size options
 * @returns Resolved width and height in points
 *
 * @example
 * ```ts
 * resolvePageSize({}) // { width: 612, height: 792 } (letter portrait)
 * resolvePageSize({ size: "a4" }) // { width: 595.28, height: 841.89 }
 * resolvePageSize({ size: "letter", orientation: "landscape" }) // { width: 792, height: 612 }
 * resolvePageSize({ width: 400, height: 600 }) // { width: 400, height: 600 }
 * ```
 */
export function resolvePageSize(options: PageSizeOptions): { width: number; height: number } {
  const preset = PAGE_SIZES[options.size ?? "letter"];

  let width: number = preset.width;
  let height: number = preset.height;

  // Swap dimensions for landscape orientation
  if (options.orientation === "landscape") {
    [width, height] = [height, width];
  }

  // If width and height are provided, use them instead
  if (options.width && options.height) {
    width = options.width;
    height = options.height;
  }

  return { width, height };
}
