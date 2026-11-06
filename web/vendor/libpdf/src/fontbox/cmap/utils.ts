/**
 * CMap utility functions.
 */

/**
 * Convert byte array to integer (big-endian).
 */
export function bytesToInt(data: Uint8Array): number {
  return bytesToIntN(data, data.length);
}

/**
 * Convert first n bytes of array to integer (big-endian).
 */
export function bytesToIntN(data: Uint8Array, length: number): number {
  let code = 0;

  for (let i = 0; i < length; i++) {
    code = (code << 8) | data[i];
  }

  return code;
}

/**
 * Convert integer to byte array of specified length (big-endian).
 */
export function intToBytes(value: number, length: number): Uint8Array {
  const bytes = new Uint8Array(length);

  for (let i = length - 1; i >= 0; i--) {
    bytes[i] = value & 0xff;
    value >>>= 8;
  }

  return bytes;
}

/**
 * Increment a byte array by 1 (treating it as a big-endian integer).
 * @param data The byte array to increment in place
 * @param position Position to start incrementing from (usually length - 1)
 * @param strictMode If true, returns false on overflow
 * @returns true if increment succeeded, false on overflow in strict mode
 */
export function incrementBytes(data: Uint8Array, position: number, strictMode: boolean): boolean {
  if (position > 0 && data[position] === 255) {
    // Would overflow this byte
    if (strictMode) {
      return false;
    }

    // Wrap around and carry
    data[position] = 0;

    return incrementBytes(data, position - 1, strictMode);
  } else {
    data[position] = data[position] + 1;

    return true;
  }
}

/**
 * Create string from UTF-16BE bytes.
 */
export function createStringFromBytes(bytes: Uint8Array): string {
  if (bytes.length <= 2) {
    // Single character - interpret as UTF-16BE code point
    let code = 0;

    for (let i = 0; i < bytes.length; i++) {
      code = (code << 8) | bytes[i];
    }

    return String.fromCharCode(code);
  }

  // Multi-byte: interpret as UTF-16BE string
  let result = "";

  for (let i = 0; i + 1 < bytes.length; i += 2) {
    result += String.fromCharCode((bytes[i] << 8) | bytes[i + 1]);
  }

  return result;
}
