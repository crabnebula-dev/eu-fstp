/**
 * The 'avar' table - Axis Variations Table.
 *
 * Modifies the coordinate normalization for variation axes.
 * Optional in variable fonts.
 *
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/avar
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * A single axis value mapping (from default normalized to modified normalized).
 */
export interface AxisValueMap {
  /** Default normalized coordinate value (F2DOT14 format, range -1 to 1) */
  readonly fromCoordinate: number;
  /** Modified normalized coordinate value (F2DOT14 format, range -1 to 1) */
  readonly toCoordinate: number;
}

/**
 * Segment map for a single axis.
 */
export interface SegmentMap {
  /** The axis value mappings for this axis */
  readonly axisValueMaps: readonly AxisValueMap[];
}

/**
 * Parsed 'avar' table data.
 */
export interface AvarTable extends TTFTable {
  readonly tag: "avar";

  /** Major version (should be 1) */
  readonly majorVersion: number;
  /** Minor version (should be 0) */
  readonly minorVersion: number;
  /** Segment maps for each axis (in fvar axis order) */
  readonly axisSegmentMaps: readonly SegmentMap[];
}

/**
 * Parse the 'avar' table.
 */
export function parseAvarTable(ctx: TableParseContext): AvarTable {
  const { data } = ctx;

  // Read header
  const majorVersion = data.readUint16();
  const minorVersion = data.readUint16();
  const _reserved = data.readUint16();
  const axisCount = data.readUint16();

  // Read segment maps for each axis
  const axisSegmentMaps: SegmentMap[] = [];

  for (let i = 0; i < axisCount; i++) {
    const positionMapCount = data.readUint16();
    const axisValueMaps: AxisValueMap[] = [];

    for (let j = 0; j < positionMapCount; j++) {
      // F2DOT14 format: signed 2.14 fixed-point
      const fromRaw = data.readInt16();
      const toRaw = data.readInt16();

      axisValueMaps.push({
        fromCoordinate: fromRaw / 16384, // Convert from F2DOT14
        toCoordinate: toRaw / 16384,
      });
    }

    axisSegmentMaps.push({ axisValueMaps });
  }

  return {
    tag: "avar",
    majorVersion,
    minorVersion,
    axisSegmentMaps,
  };
}

/**
 * Apply avar mapping to a normalized axis value.
 *
 * This takes a default-normalized value and returns the modified normalized value
 * based on the segment maps in the avar table.
 *
 * @param segmentMap - The segment map for the axis
 * @param normalizedValue - The default-normalized value (-1 to 1)
 * @returns The modified normalized value
 */
export function applyAvarMapping(segmentMap: SegmentMap, normalizedValue: number): number {
  const maps = segmentMap.axisValueMaps;

  // If no mappings or fewer than 3 (required minimum: -1→-1, 0→0, 1→1),
  // return the input value unchanged
  if (maps.length < 3) {
    return normalizedValue;
  }

  // Find the segment containing the input value
  for (let i = 1; i < maps.length; i++) {
    const prev = maps[i - 1];
    const curr = maps[i];

    if (normalizedValue <= curr.fromCoordinate) {
      // Input falls in segment [prev, curr]
      // Interpolate linearly within the segment
      const segmentRange = curr.fromCoordinate - prev.fromCoordinate;

      if (segmentRange === 0) {
        return prev.toCoordinate;
      }

      const t = (normalizedValue - prev.fromCoordinate) / segmentRange;

      return prev.toCoordinate + t * (curr.toCoordinate - prev.toCoordinate);
    }
  }

  // Value is beyond the last mapping point
  return maps[maps.length - 1].toCoordinate;
}

/**
 * Check if a segment map has valid mappings.
 *
 * A valid segment map must include at least three value maps: -1 to -1, 0 to 0, and 1 to 1.
 */
export function isValidSegmentMap(segmentMap: SegmentMap): boolean {
  const maps = segmentMap.axisValueMaps;

  if (maps.length < 3) {
    return false;
  }

  // Check for required mappings
  let hasNegOne = false;
  let hasZero = false;
  let hasPosOne = false;

  for (const map of maps) {
    if (Math.abs(map.fromCoordinate - -1) < 0.0001 && Math.abs(map.toCoordinate - -1) < 0.0001) {
      hasNegOne = true;
    }

    if (Math.abs(map.fromCoordinate) < 0.0001 && Math.abs(map.toCoordinate) < 0.0001) {
      hasZero = true;
    }

    if (Math.abs(map.fromCoordinate - 1) < 0.0001 && Math.abs(map.toCoordinate - 1) < 0.0001) {
      hasPosOne = true;
    }
  }

  return hasNegOne && hasZero && hasPosOne;
}
