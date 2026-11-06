/**
 * Rotation helper for form fields.
 *
 * Provides a type-safe way to specify rotation angles for form field widgets.
 */

/**
 * Rotation angle in degrees.
 */
export interface Degrees {
  type: "degrees";
  angle: number;
}

/**
 * Create a rotation angle in degrees.
 *
 * Rotation affects how the field content is displayed within its widget.
 * Valid angles are 0, 90, 180, and 270.
 *
 * @param angle Rotation angle in degrees
 * @returns Degrees rotation object
 *
 * @example
 * ```typescript
 * const noRotation = degrees(0);
 * const rotate90 = degrees(90);
 * const upsideDown = degrees(180);
 * ```
 */
export function degrees(angle: number): Degrees {
  return { type: "degrees", angle };
}
