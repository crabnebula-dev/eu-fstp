/**
 * The 'STAT' table - Style Attributes Table.
 *
 * Describes design attributes that distinguish font-style variants within
 * a font family. Required in variable fonts.
 *
 * @see https://learn.microsoft.com/en-us/typography/opentype/spec/stat
 */

import type { TableParseContext, TTFTable } from "../types.ts";

/**
 * Axis value flags.
 */
export const AXIS_VALUE_FLAG_OLDER_SIBLING_FONT_ATTRIBUTE = 0x0001;
export const AXIS_VALUE_FLAG_ELIDABLE = 0x0002;

/**
 * Design axis record in STAT table.
 */
export interface DesignAxisRecord {
  /** Axis tag (e.g., "wght", "wdth") */
  readonly tag: string;
  /** Name ID for the axis name in the 'name' table */
  readonly axisNameId: number;
  /** Ordering value for sorting axes */
  readonly axisOrdering: number;
}

/**
 * Base type for axis value tables.
 */
export interface AxisValueBase {
  /** Format identifier (1-4) */
  readonly format: number;
  /** Axis index in the design axes array */
  readonly axisIndex: number;
  /** Flags for the axis value */
  readonly flags: number;
  /** Name ID for the value name in the 'name' table */
  readonly valueNameId: number;
}

/**
 * Axis value table format 1 - single axis value.
 */
export interface AxisValueFormat1 extends AxisValueBase {
  readonly format: 1;
  /** The axis value */
  readonly value: number;
}

/**
 * Axis value table format 2 - range of axis values.
 */
export interface AxisValueFormat2 extends AxisValueBase {
  readonly format: 2;
  /** Nominal axis value */
  readonly nominalValue: number;
  /** Range start value */
  readonly rangeMinValue: number;
  /** Range end value */
  readonly rangeMaxValue: number;
}

/**
 * Axis value table format 3 - single axis value with linked value.
 */
export interface AxisValueFormat3 extends AxisValueBase {
  readonly format: 3;
  /** The axis value */
  readonly value: number;
  /** Linked axis value (e.g., Bold linked to Regular for RIBBI) */
  readonly linkedValue: number;
}

/**
 * Axis value record for format 4 (multiple axes).
 */
export interface AxisValueRecord {
  /** Axis index in the design axes array */
  readonly axisIndex: number;
  /** The axis value */
  readonly value: number;
}

/**
 * Axis value table format 4 - multiple axis values.
 */
export interface AxisValueFormat4 {
  readonly format: 4;
  /** Number of axis values */
  readonly axisCount: number;
  /** Flags for the axis value */
  readonly flags: number;
  /** Name ID for the value name in the 'name' table */
  readonly valueNameId: number;
  /** Array of axis value records */
  readonly values: readonly AxisValueRecord[];
}

export type AxisValue = AxisValueFormat1 | AxisValueFormat2 | AxisValueFormat3 | AxisValueFormat4;

/**
 * Parsed 'STAT' table data.
 */
export interface StatTable extends TTFTable {
  readonly tag: "STAT";

  /** Major version (should be 1) */
  readonly majorVersion: number;
  /** Minor version (1 or 2) */
  readonly minorVersion: number;
  /** Design axis records */
  readonly designAxes: readonly DesignAxisRecord[];
  /** Axis value tables */
  readonly axisValues: readonly AxisValue[];
  /** Name ID for fallback when all axis values are elidable (version >= 1.1) */
  readonly elidedFallbackNameId?: number;
}

/**
 * Parse the 'STAT' table.
 */
export function parseStatTable(ctx: TableParseContext): StatTable {
  const { data } = ctx;
  const tableStart = data.position;

  // Read header
  const majorVersion = data.readUint16();
  const minorVersion = data.readUint16();
  const designAxisSize = data.readUint16();
  const designAxisCount = data.readUint16();
  const designAxesOffset = data.readUint32();
  const axisValueCount = data.readUint16();
  const offsetToAxisValueOffsets = data.readUint32();

  // elidedFallbackNameId added in version 1.1
  let elidedFallbackNameId: number | undefined;

  if (minorVersion >= 1) {
    elidedFallbackNameId = data.readUint16();
  }

  // Read design axes array
  const designAxes: DesignAxisRecord[] = [];

  if (designAxisCount > 0 && designAxesOffset > 0) {
    data.moveTo(tableStart + designAxesOffset);

    for (let i = 0; i < designAxisCount; i++) {
      const axisStart = data.position;

      // Read axis tag (4 bytes)
      const tagBytes = new Uint8Array(4);

      for (let j = 0; j < 4; j++) {
        tagBytes[j] = data.readUint8();
      }

      const tag = String.fromCharCode(...tagBytes);

      const axisNameId = data.readUint16();
      const axisOrdering = data.readUint16();

      designAxes.push({ tag, axisNameId, axisOrdering });

      // Move to next axis record (in case designAxisSize > 8)
      data.moveTo(axisStart + designAxisSize);
    }
  }

  // Read axis value offsets array and parse axis values
  const axisValues: AxisValue[] = [];

  if (axisValueCount > 0 && offsetToAxisValueOffsets > 0) {
    data.moveTo(tableStart + offsetToAxisValueOffsets);

    // Read offsets first
    const offsets: number[] = [];

    for (let i = 0; i < axisValueCount; i++) {
      offsets.push(data.readUint16());
    }

    // Parse each axis value table
    const offsetArrayStart = tableStart + offsetToAxisValueOffsets;

    for (const offset of offsets) {
      data.moveTo(offsetArrayStart + offset);
      const axisValue = parseAxisValue(data);

      if (axisValue) {
        axisValues.push(axisValue);
      }
    }
  }

  return {
    tag: "STAT",
    majorVersion,
    minorVersion,
    designAxes,
    axisValues,
    elidedFallbackNameId,
  };
}

/**
 * Parse an axis value table at the current position.
 */
function parseAxisValue(data: {
  readUint16: () => number;
  readFixed: () => number;
}): AxisValue | undefined {
  const format = data.readUint16();

  switch (format) {
    case 1: {
      const axisIndex = data.readUint16();
      const flags = data.readUint16();
      const valueNameId = data.readUint16();
      const value = data.readFixed();

      return {
        format: 1,
        axisIndex,
        flags,
        valueNameId,
        value,
      };
    }

    case 2: {
      const axisIndex = data.readUint16();
      const flags = data.readUint16();
      const valueNameId = data.readUint16();
      const nominalValue = data.readFixed();
      const rangeMinValue = data.readFixed();
      const rangeMaxValue = data.readFixed();

      return {
        format: 2,
        axisIndex,
        flags,
        valueNameId,
        nominalValue,
        rangeMinValue,
        rangeMaxValue,
      };
    }

    case 3: {
      const axisIndex = data.readUint16();
      const flags = data.readUint16();
      const valueNameId = data.readUint16();
      const value = data.readFixed();
      const linkedValue = data.readFixed();

      return {
        format: 3,
        axisIndex,
        flags,
        valueNameId,
        value,
        linkedValue,
      };
    }

    case 4: {
      const axisCount = data.readUint16();
      const flags = data.readUint16();
      const valueNameId = data.readUint16();
      const values: AxisValueRecord[] = [];

      for (let i = 0; i < axisCount; i++) {
        const axisIndex = data.readUint16();
        const value = data.readFixed();
        values.push({ axisIndex, value });
      }

      return {
        format: 4,
        axisCount,
        flags,
        valueNameId,
        values,
      };
    }

    default:
      // Unknown format
      return undefined;
  }
}

/**
 * Check if an axis value is elidable.
 */
export function isAxisValueElidable(axisValue: AxisValue): boolean {
  return (axisValue.flags & AXIS_VALUE_FLAG_ELIDABLE) !== 0;
}

/**
 * Check if an axis value indicates an older sibling font attribute.
 */
export function isOlderSiblingFontAttribute(axisValue: AxisValue): boolean {
  return (axisValue.flags & AXIS_VALUE_FLAG_OLDER_SIBLING_FONT_ATTRIBUTE) !== 0;
}

/**
 * Find a design axis by tag.
 */
export function findDesignAxis(table: StatTable, tag: string): DesignAxisRecord | undefined {
  return table.designAxes.find(axis => axis.tag === tag);
}

/**
 * Get axis values for a specific axis index.
 */
export function getAxisValuesForAxis(table: StatTable, axisIndex: number): AxisValue[] {
  return table.axisValues.filter(value => {
    if (value.format === 4) {
      return value.values.some(v => v.axisIndex === axisIndex);
    }

    return value.axisIndex === axisIndex;
  });
}
