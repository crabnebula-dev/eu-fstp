/**
 * Factory for creating security handlers based on encryption dictionary.
 *
 * Selects the appropriate handler (RC4, AES-128, or AES-256) based on
 * the encryption version, revision, and crypt filter configuration.
 */

import type { EncryptionDict } from "../encryption-dict";
import { type AbstractSecurityHandler, IdentityHandler } from "./abstract";
import { AES128Handler } from "./aes128";
import { AES256Handler } from "./aes256";
import { RC4Handler } from "./rc4";

/**
 * Handler configuration for a document.
 *
 * V4+ encryption can use different handlers for strings vs streams.
 */
export interface HandlerConfig {
  /** Handler for string encryption/decryption */
  stringHandler: AbstractSecurityHandler;

  /** Handler for stream encryption/decryption */
  streamHandler: AbstractSecurityHandler;

  /** Handler for embedded file encryption/decryption */
  embeddedFileHandler: AbstractSecurityHandler;
}

/**
 * Create security handlers from an encryption dictionary and file key.
 *
 * @param encryptDict - Parsed encryption dictionary
 * @param fileKey - File encryption key (from password verification)
 * @returns Handler configuration for strings, streams, and embedded files
 */
export function createHandlers(encryptDict: EncryptionDict, fileKey: Uint8Array): HandlerConfig {
  const { version, algorithm, stringFilter, streamFilter, embeddedFileFilter, cryptFilters } =
    encryptDict;

  // V1-V3: Same handler for everything based on algorithm
  if (version < 4) {
    const handler = createHandlerForAlgorithm(algorithm, fileKey);

    return {
      stringHandler: handler,
      streamHandler: handler,
      embeddedFileHandler: handler,
    };
  }

  // V4+: Check crypt filters for each content type
  return {
    stringHandler: createHandlerForFilter(stringFilter, cryptFilters, algorithm, fileKey),
    streamHandler: createHandlerForFilter(streamFilter, cryptFilters, algorithm, fileKey),
    embeddedFileHandler: createHandlerForFilter(
      embeddedFileFilter,
      cryptFilters,
      algorithm,
      fileKey,
    ),
  };
}

/**
 * Create a handler for a specific crypt filter.
 */
function createHandlerForFilter(
  filterName: string | undefined,
  cryptFilters: Map<string, { cfm: string }> | undefined,
  defaultAlgorithm: "RC4" | "AES-128" | "AES-256",
  fileKey: Uint8Array,
): AbstractSecurityHandler {
  // Identity filter = no encryption
  if (filterName === "Identity") {
    return new IdentityHandler();
  }

  // Look up filter in CF dictionary
  if (filterName && cryptFilters) {
    const filter = cryptFilters.get(filterName);

    if (filter) {
      switch (filter.cfm) {
        case "None":
          return new IdentityHandler();
        case "V2":
          return new RC4Handler(fileKey);
        case "AESV2":
          return new AES128Handler(fileKey);
        case "AESV3":
          return new AES256Handler(fileKey);
      }
    }
  }

  // Fall back to default algorithm
  return createHandlerForAlgorithm(defaultAlgorithm, fileKey);
}

/**
 * Create a handler for a specific algorithm.
 */
function createHandlerForAlgorithm(
  algorithm: "RC4" | "AES-128" | "AES-256",
  fileKey: Uint8Array,
): AbstractSecurityHandler {
  switch (algorithm) {
    case "RC4":
      return new RC4Handler(fileKey);
    case "AES-128":
      return new AES128Handler(fileKey);
    case "AES-256":
      return new AES256Handler(fileKey);
  }
}
