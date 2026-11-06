/**
 * Common OID constants for signature operations.
 *
 * These OIDs are used across CMS/PKCS#7 signature creation, timestamps,
 * certificate parsing, and revocation checking.
 */

// ─────────────────────────────────────────────────────────────────────────────
// CMS/PKCS#7 Content Types
// ─────────────────────────────────────────────────────────────────────────────

/** id-data (PKCS#7) */
export const OID_DATA = "1.2.840.113549.1.7.1";

/** id-signedData (PKCS#7) */
export const OID_SIGNED_DATA = "1.2.840.113549.1.7.2";

// ─────────────────────────────────────────────────────────────────────────────
// CMS Attributes
// ─────────────────────────────────────────────────────────────────────────────

/** id-contentType */
export const OID_CONTENT_TYPE = "1.2.840.113549.1.9.3";

/** id-messageDigest */
export const OID_MESSAGE_DIGEST = "1.2.840.113549.1.9.4";

/** id-signingTime */
export const OID_SIGNING_TIME = "1.2.840.113549.1.9.5";

/** id-aa-CMSAlgorithmProtection (RFC 6211) */
export const OID_CMS_ALGORITHM_PROTECTION = "1.2.840.113549.1.9.52";

/** id-aa-timeStampToken (RFC 3161) */
export const OID_TIMESTAMP_TOKEN = "1.2.840.113549.1.9.16.2.14";

/** id-ct-TSTInfo (RFC 3161) */
export const OID_TST_INFO = "1.2.840.113549.1.9.16.1.4";

/** id-aa-signingCertificateV2 (RFC 5035) - required for CAdES/PAdES */
export const OID_SIGNING_CERTIFICATE_V2 = "1.2.840.113549.1.9.16.2.47";

// ─────────────────────────────────────────────────────────────────────────────
// Digest Algorithms
// ─────────────────────────────────────────────────────────────────────────────

/** id-sha1 (used for OCSP certID - widely supported) */
export const OID_SHA1 = "1.3.14.3.2.26";

/** id-sha256 */
export const OID_SHA256 = "2.16.840.1.101.3.4.2.1";

/** id-sha384 */
export const OID_SHA384 = "2.16.840.1.101.3.4.2.2";

/** id-sha512 */
export const OID_SHA512 = "2.16.840.1.101.3.4.2.3";

// ─────────────────────────────────────────────────────────────────────────────
// Signature Algorithms - RSA
// ─────────────────────────────────────────────────────────────────────────────

/** rsaEncryption */
export const OID_RSA_ENCRYPTION = "1.2.840.113549.1.1.1";

/** sha256WithRSAEncryption */
export const OID_SHA256_WITH_RSA = "1.2.840.113549.1.1.11";

/** sha384WithRSAEncryption */
export const OID_SHA384_WITH_RSA = "1.2.840.113549.1.1.12";

/** sha512WithRSAEncryption */
export const OID_SHA512_WITH_RSA = "1.2.840.113549.1.1.13";

// ─────────────────────────────────────────────────────────────────────────────
// Signature Algorithms - ECDSA
// ─────────────────────────────────────────────────────────────────────────────

/** id-ecPublicKey */
export const OID_EC_PUBLIC_KEY = "1.2.840.10045.2.1";

/** ecdsa-with-SHA256 */
export const OID_ECDSA_WITH_SHA256 = "1.2.840.10045.4.3.2";

/** ecdsa-with-SHA384 */
export const OID_ECDSA_WITH_SHA384 = "1.2.840.10045.4.3.3";

/** ecdsa-with-SHA512 */
export const OID_ECDSA_WITH_SHA512 = "1.2.840.10045.4.3.4";

// ─────────────────────────────────────────────────────────────────────────────
// Elliptic Curves
// ─────────────────────────────────────────────────────────────────────────────

/** secp256r1 / prime256v1 / P-256 */
export const OID_SECP256R1 = "1.2.840.10045.3.1.7";

/** secp384r1 / P-384 */
export const OID_SECP384R1 = "1.3.132.0.34";

/** secp521r1 / P-521 */
export const OID_SECP521R1 = "1.3.132.0.35";

// ─────────────────────────────────────────────────────────────────────────────
// PKCS#12 Bag Types
// ─────────────────────────────────────────────────────────────────────────────

/** keyBag */
export const OID_KEY_BAG = "1.2.840.113549.1.12.10.1.1";

/** pkcs8ShroudedKeyBag */
export const OID_PKCS8_SHROUDED_KEY_BAG = "1.2.840.113549.1.12.10.1.2";

/** certBag */
export const OID_CERT_BAG = "1.2.840.113549.1.12.10.1.3";

// ─────────────────────────────────────────────────────────────────────────────
// X.509 Extensions
// ─────────────────────────────────────────────────────────────────────────────

/** id-pe-authorityInfoAccess */
export const OID_AUTHORITY_INFO_ACCESS = "1.3.6.1.5.5.7.1.1";

/** id-pe-crlDistributionPoints */
export const OID_CRL_DISTRIBUTION_POINTS = "2.5.29.31";

// ─────────────────────────────────────────────────────────────────────────────
// Authority Information Access Methods
// ─────────────────────────────────────────────────────────────────────────────

/** id-ad-ocsp */
export const OID_AD_OCSP = "1.3.6.1.5.5.7.48.1";

/** id-ad-caIssuers */
export const OID_AD_CA_ISSUERS = "1.3.6.1.5.5.7.48.2";

// ─────────────────────────────────────────────────────────────────────────────
// OCSP
// ─────────────────────────────────────────────────────────────────────────────

/** id-pkix-ocsp-basic */
export const OID_OCSP_BASIC = "1.3.6.1.5.5.7.48.1.1";
