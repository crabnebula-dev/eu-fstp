/**
 * The 'fvar' table - Font Variations Table.
 *
 * Defines variation axes and named instances for variable fonts.
 * Required in all variable fonts.
 *
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/fvar
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * Axis flags.
 */
export const AXIS_FLAG_HIDDEN = 0x0001;

/**
 * Common registered axis tags.
 */
export const AxisTag = {
  /** Weight axis (wght) - 1 to 1000, default 400 */
  WEIGHT: "wght",
  /** Width axis (wdth) - 50 to 200, default 100 */
  WIDTH: "wdth",
  /** Slant axis (slnt) - -90 to 90, default 0 */
  SLANT: "slnt",
  /** Italic axis (ital) - 0 or 1 */
  ITALIC: "ital",
  /** Optical size axis (opsz) - typically 6 to 144 */
  OPTICAL_SIZE: "opsz",
  /** Grade axis (GRAD) */
  GRADE: "GRAD",
} as const;

/**
 * A variation axis definition.
 */
export interface VariationAxis {
  /** 4-character axis tag (e.g., "wght", "wdth") */
  readonly tag: string;
  /** Minimum coordinate value for the axis */
  readonly minValue: number;
  /** Default coordinate value for the axis */
  readonly defaultValue: number;
  /** Maximum coordinate value for the axis */
  readonly maxValue: number;
  /** Axis flags (e.g., AXIS_FLAG_HIDDEN) */
  readonly flags: number;
  /** Name ID for entries in the 'name' table */
  readonly axisNameId: number;
}

/**
 * A named instance (predefined position in variation space).
 */
export interface NamedInstance {
  /** Name ID for the subfamily name in the 'name' table */
  readonly subfamilyNameId: number;
  /** Instance flags (reserved, should be 0) */
  readonly flags: number;
  /** Coordinate values for each axis (in axis order) */
  readonly coordinates: readonly number[];
  /** Optional name ID for PostScript name in the 'name' table */
  readonly postScriptNameId?: number;
}

/**
 * Parsed 'fvar' table data.
 */
export interface FvarTable extends TTFTable {
  readonly tag: "fvar";

  /** Major version (should be 1) */
  readonly majorVersion: number;
  /** Minor version (should be 0) */
  readonly minorVersion: number;
  /** Array of variation axes */
  readonly axes: readonly VariationAxis[];
  /** Array of named instances */
  readonly instances: readonly NamedInstance[];
}

/**
 * Parse the 'fvar' table.
 */
export function parseFvarTable(ctx: TableParseContext): FvarTable {
  const { data } = ctx;
  const tableStart = data.position;

  // Read header
  const majorVersion = data.readUint16();
  const minorVersion = data.readUint16();
  const axesArrayOffset = data.readUint16();
  const _reserved = data.readUint16(); // Should be 2
  const axisCount = data.readUint16();
  const axisSize = data.readUint16(); // Should be 20
  const instanceCount = data.readUint16();
  const instanceSize = data.readUint16();

  // Read axes array
  data.moveTo(tableStart + axesArrayOffset);
  const axes: VariationAxis[] = [];

  for (let i = 0; i < axisCount; i++) {
    const axisStart = data.position;

    // Read axis tag (4 bytes)
    const tagBytes = new Uint8Array(4);

    for (let j = 0; j < 4; j++) {
      tagBytes[j] = data.readUint8();
    }

    const tag = String.fromCharCode(...tagBytes);

    // Read Fixed values (16.16 format)
    const minValue = data.readFixed();
    const defaultValue = data.readFixed();
    const maxValue = data.readFixed();
    const flags = data.readUint16();
    const axisNameId = data.readUint16();

    axes.push({
      tag,
      minValue,
      defaultValue,
      maxValue,
      flags,
      axisNameId,
    });

    // Move to next axis record (in case axisSize > 20)
    data.moveTo(axisStart + axisSize);
  }

  // Read instances array (directly follows axes array)
  const instances: NamedInstance[] = [];
  const hasPostScriptNameId = instanceSize >= axisCount * 4 + 6;

  for (let i = 0; i < instanceCount; i++) {
    const instanceStart = data.position;

    const subfamilyNameId = data.readUint16();
    const flags = data.readUint16();

    // Read coordinates for each axis
    const coordinates: number[] = [];

    for (let j = 0; j < axisCount; j++) {
      coordinates.push(data.readFixed());
    }

    // Optional PostScript name ID
    let postScriptNameId: number | undefined;

    if (hasPostScriptNameId) {
      postScriptNameId = data.readUint16();
    }

    instances.push({
      subfamilyNameId,
      flags,
      coordinates,
      postScriptNameId,
    });

    // Move to next instance record
    data.moveTo(instanceStart + instanceSize);
  }

  return {
    tag: "fvar",
    majorVersion,
    minorVersion,
    axes,
    instances,
  };
}

/**
 * Check if an axis is hidden (not intended for direct user interaction).
 */
export function isAxisHidden(axis: VariationAxis): boolean {
  return (axis.flags & AXIS_FLAG_HIDDEN) !== 0;
}

/**
 * Find an axis by its tag.
 */
export function findAxis(table: FvarTable, tag: string): VariationAxis | undefined {
  return table.axes.find(axis => axis.tag === tag);
}

/**
 * Get the weight axis if present.
 */
export function getWeightAxis(table: FvarTable): VariationAxis | undefined {
  return findAxis(table, AxisTag.WEIGHT);
}

/**
 * Get the width axis if present.
 */
export function getWidthAxis(table: FvarTable): VariationAxis | undefined {
  return findAxis(table, AxisTag.WIDTH);
}

/**
 * Normalize a user-space coordinate to the range [-1, 1].
 *
 * @param axis - The variation axis
 * @param value - The user-space coordinate value
 * @returns Normalized coordinate in range [-1, 1]
 */
export function normalizeAxisValue(axis: VariationAxis, value: number): number {
  // Clamp to axis range
  const clamped = Math.max(axis.minValue, Math.min(axis.maxValue, value));

  if (clamped < axis.defaultValue) {
    // Below default: map [min, default] to [-1, 0]
    if (axis.defaultValue === axis.minValue) {
      return 0;
    }

    return (clamped - axis.defaultValue) / (axis.defaultValue - axis.minValue);
  } else if (clamped > axis.defaultValue) {
    // Above default: map [default, max] to [0, 1]
    if (axis.maxValue === axis.defaultValue) {
      return 0;
    }

    return (clamped - axis.defaultValue) / (axis.maxValue - axis.defaultValue);
  }

  return 0; // At default
}

/**
 * Convert a normalized coordinate back to user-space.
 *
 * @param axis - The variation axis
 * @param normalized - Normalized coordinate in range [-1, 1]
 * @returns User-space coordinate value
 */
export function denormalizeAxisValue(axis: VariationAxis, normalized: number): number {
  // Clamp to normalized range
  const clamped = Math.max(-1, Math.min(1, normalized));

  if (clamped < 0) {
    // Below default: map [-1, 0] to [min, default]
    return axis.defaultValue + clamped * (axis.defaultValue - axis.minValue);
  } else if (clamped > 0) {
    // Above default: map [0, 1] to [default, max]
    return axis.defaultValue + clamped * (axis.maxValue - axis.defaultValue);
  }

  return axis.defaultValue;
}
