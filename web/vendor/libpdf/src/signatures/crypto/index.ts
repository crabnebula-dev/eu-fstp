/**
 * Cryptographic utilities for PDF signatures.
 *
 * This module provides legacy cipher implementations needed for PKCS#12
 * compatibility. Web Crypto API doesn't support these algorithms, so we
 * provide pure JavaScript implementations.
 */

export {
  CryptoEngine,
  decryptLegacyPbe,
  getCryptoEngine,
  getCrypto,
  isLegacyPbeOid,
  LEGACY_PBE_OIDS,
} from "./crypto-engine.js";
export { PKCS12KDF } from "./pkcs12-kdf.js";
export { RC2 } from "./rc2.js";
export { TripleDES } from "./triple-des.js";
