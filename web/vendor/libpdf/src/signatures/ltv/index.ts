/**
 * LTV (Long-Term Validation) subsystem exports.
 *
 * Provides unified interfaces for:
 * - Gathering LTV data from CMS signatures and timestamps
 * - Building and merging DSS dictionaries
 * - VRI key computation
 */

export { DSSBuilder } from "./dss-builder.js";
export type { LtvData, LtvGathererOptions, LtvWarning } from "./gatherer.js";
export { LtvDataGatherer } from "./gatherer.js";
export { computeSha1Hex, computeVriKey } from "./vri.js";
