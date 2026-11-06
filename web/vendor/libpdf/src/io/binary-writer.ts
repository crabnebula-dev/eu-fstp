/**
 * ByteWriter extended with big-endian binary writing methods.
 *
 * Complements BinaryScanner for writing binary formats like TrueType/OpenType
 * fonts where we need multi-byte writes, fixed-point numbers, and structured data.
 *
 * Key features:
 * - Big-endian by default (standard for font files)
 * - Fixed-point number support (16.16, 2.14)
 * - Efficient growing buffer from ByteWriter
 */

import { ByteWriter, type ByteWriterOptions } from "./byte-writer.ts";

export class BinaryWriter extends ByteWriter {
  /**
   * Create a new BinaryWriter.
   *
   * @param existingBytes - Optional existing bytes to start with
   * @param options - Configuration options
   */
  constructor(existingBytes?: Uint8Array, options: ByteWriterOptions = {}) {
    super(existingBytes, options);
  }

  /** Write uint8 */
  writeUint8(value: number): void {
    this.writeByte(value & 0xff);
  }

  /** Write int8 */
  writeInt8(value: number): void {
    this.writeByte(value & 0xff);
  }

  /** Write uint16 big-endian */
  writeUint16(value: number): void {
    this.writeByte((value >> 8) & 0xff);
    this.writeByte(value & 0xff);
  }

  /** Write int16 big-endian */
  writeInt16(value: number): void {
    this.writeUint16(value);
  }

  /** Write uint24 big-endian (3 bytes) */
  writeUint24(value: number): void {
    this.writeByte((value >> 16) & 0xff);
    this.writeByte((value >> 8) & 0xff);
    this.writeByte(value & 0xff);
  }

  /** Write uint32 big-endian */
  writeUint32(value: number): void {
    this.writeByte((value >> 24) & 0xff);
    this.writeByte((value >> 16) & 0xff);
    this.writeByte((value >> 8) & 0xff);
    this.writeByte(value & 0xff);
  }

  /** Write int32 big-endian */
  writeInt32(value: number): void {
    this.writeUint32(value);
  }

  /**
   * Write 16.16 fixed-point number.
   * The integer part is in the high 16 bits, fraction in low 16 bits.
   */
  writeFixed(value: number): void {
    const fixed = Math.round(value * 65536);
    this.writeInt32(fixed);
  }

  /**
   * Write 2.14 fixed-point number.
   * Used for glyf composite transforms.
   */
  writeF2Dot14(value: number): void {
    const fixed = Math.round(value * 16384);
    this.writeInt16(fixed);
  }

  /**
   * Write LONGDATETIME (64-bit signed, seconds since 1904-01-01).
   */
  writeLongDateTime(date: Date): void {
    // Convert from Unix epoch to Mac epoch
    // Mac epoch (1904-01-01) to Unix epoch (1970-01-01) = 2082844800 seconds
    const macToUnix = 2082844800n;
    const unixSeconds = BigInt(Math.floor(date.getTime() / 1000));
    const macSeconds = unixSeconds + macToUnix;

    // Write as two 32-bit values (high, low)
    const high = Number((macSeconds >> 32n) & 0xffffffffn);
    const low = Number(macSeconds & 0xffffffffn);

    this.writeInt32(high);
    this.writeUint32(low);
  }

  /**
   * Write 4-byte tag from string.
   * Pads with spaces if string is shorter than 4 characters.
   */
  writeTag(tag: string): void {
    for (let i = 0; i < 4; i++) {
      this.writeByte(i < tag.length ? tag.charCodeAt(i) : 0x20);
    }
  }

  /**
   * Write n bytes of padding (zeros).
   */
  writePadding(n: number): void {
    for (let i = 0; i < n; i++) {
      this.writeByte(0);
    }
  }

  /**
   * Write padding to align to n-byte boundary.
   * @param alignment - Byte alignment (e.g., 4 for 4-byte alignment)
   */
  writeAlignmentPadding(alignment: number): void {
    const remainder = this.position % alignment;
    if (remainder !== 0) {
      this.writePadding(alignment - remainder);
    }
  }

  /**
   * Write UTF-16BE string.
   */
  writeUtf16BE(str: string): void {
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i);
      this.writeByte((code >> 8) & 0xff);
      this.writeByte(code & 0xff);
    }
  }

  /**
   * Write null-terminated ASCII string.
   */
  writeNullTerminatedAscii(str: string): void {
    this.writeAscii(str);
    this.writeByte(0);
  }

  /**
   * Write an offset value with the specified size (1-4 bytes).
   * @param value - The offset value
   * @param size - Number of bytes (1, 2, 3, or 4)
   */
  writeOffset(value: number, size: number): void {
    switch (size) {
      case 1:
        this.writeUint8(value);
        break;
      case 2:
        this.writeUint16(value);
        break;
      case 3:
        this.writeUint24(value);
        break;
      case 4:
        this.writeUint32(value);
        break;
      default:
        throw new Error(`Invalid offset size: ${size}`);
    }
  }

  /**
   * Get the minimum number of bytes needed to represent an offset value.
   */
  static offsetSize(maxValue: number): number {
    if (maxValue <= 0xff) {
      return 1;
    }

    if (maxValue <= 0xffff) {
      return 2;
    }

    if (maxValue <= 0xffffff) {
      return 3;
    }

    return 4;
  }
}
