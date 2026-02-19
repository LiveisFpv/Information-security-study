export type Bit = 0 | 1;
export type BitArray = Bit[];

export class BinaryUtils {
  static byteToBits(byte: number): BitArray {
    const bits: BitArray = [];
    for (let i = 7; i >= 0; i--) {
      bits.push(((byte >> i) & 1) as Bit);
    }
    return bits;
  }

  static bitsToByte(bits: BitArray): number {
    let value = 0;
    for (const bit of bits) {
      value = (value << 1) | bit;
    }
    return value;
  }

  static bytesToBits(bytes: Uint8Array): BitArray {
    const bits: BitArray = [];
    for (const byte of bytes) {
      bits.push(...BinaryUtils.byteToBits(byte));
    }
    return bits;
  }

  static bitsToBytes(bits: BitArray): Uint8Array {
    if (bits.length % 8 !== 0) {
      const remainder = bits.length % 8;
      const bitsAdd: BitArray = [];
      for (let i = 0; i < 8 - remainder; i++) {
        bitsAdd.push(0);
      }
      bits = bitsAdd.concat(bits);
      // throw new Error("Bit length must be multiple of 8.");
    }
    const bytes = new Uint8Array(bits.length / 8);
    for (let i = 0; i < bytes.length; i++) {
      const chunk = bits.slice(i * 8, i * 8 + 8);
      bytes[i] = BinaryUtils.bitsToByte(chunk);
    }
    return bytes;
  }

  static permute(bits: BitArray, table: readonly number[]): BitArray {
    const output: BitArray = [];
    for (const position of table) {
      const bit = bits[position - 1];
      if (bit === undefined) throw new Error("Permutation index out of range.");
      output.push(bit);
    }
    return output;
  }

  static xor(a: BitArray, b: BitArray): BitArray {
    if (a.length !== b.length) throw new Error("XOR arrays must have the same length.");
    const output: BitArray = [];
    for (let i = 0; i < a.length; i++) {
      const left = a[i];
      const right = b[i];
      if (left === undefined || right === undefined) throw new Error("XOR index error.");
      output.push((left ^ right) as Bit);
    }
    return output;
  }

  static leftRotate(bits: BitArray, shift: number): BitArray {
    if (bits.length === 0) return [];
    const offset = shift % bits.length;
    return bits.slice(offset).concat(bits.slice(0, offset));
  }

  static numberToBits(value: number, bitLength: number): BitArray {
    const bits: BitArray = [];
    for (let i = bitLength - 1; i >= 0; i--) {
      bits.push(((value >> i) & 1) as Bit);
    }
    return bits;
  }

  static bigintToBits(value: bigint): BitArray {
    if (value < 0n) {
      throw new Error("Value must be non-negative.");
    }
    if (value === 0n) {
      return [0];
    }

    const bits: BitArray = [];
    let current = value;
    while (current > 0n) {
      bits.push(Number(current & 1n) as Bit);
      current >>= 1n;
    }

    return bits.reverse();
  }

  static bitsToBigInt(bits: BitArray): bigint {
    let value = 0n;
    for (const bit of bits) {
      value = (value << 1n) | BigInt(bit);
    }
    return value;
  }

  static modPow(base: bigint, exponent: bigint, modulus: bigint): bigint {
    if (modulus <= 0n) {
      throw new Error("Modulus must be positive.");
    }
    if (exponent < 0n) {
      throw new Error("Exponent must be non-negative.");
    }
    if (modulus === 1n) {
      return 0n;
    }

    let result = 1n;
    let currentBase = ((base % modulus) + modulus) % modulus;
    let currentExponent = exponent;

    while (currentExponent > 0n) {
      if ((currentExponent & 1n) === 1n) {
        result = (result * currentBase) % modulus;
      }
      currentBase = (currentBase * currentBase) % modulus;
      currentExponent >>= 1n;
    }

    return result;
  }

  static bytesToHex(bytes: Uint8Array): string {
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
  }

  static hexToBytes(hexText: string): Uint8Array {
    const clean = hexText.replace(/\s+/g, "");
    if (!/^[0-9A-Fa-f]*$/.test(clean) || clean.length % 2 !== 0) {
      throw new Error("Cipher text must contain only HEX symbols.");
    }
    const output = new Uint8Array(clean.length / 2);
    for (let i = 0; i < output.length; i++) {
      output[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    }
    return output;
  }

  static padPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
    const remainder = data.length % blockSize;
    const padValue = remainder === 0 ? blockSize : blockSize - remainder;
    const out = new Uint8Array(data.length + padValue);
    out.set(data, 0);
    out.fill(padValue, data.length);
    return out;
  }

  static unpadPkcs7(data: Uint8Array, blockSize: number): Uint8Array {
    if (data.length === 0 || data.length % blockSize !== 0) {
      throw new Error("Invalid decrypted data length.");
    }
    const padValue = data[data.length - 1];
    if (padValue === undefined || padValue < 1 || padValue > blockSize) {
      throw new Error("Invalid PKCS#7 padding.");
    }
    for (let i = data.length - padValue; i < data.length; i++) {
      const current = data[i];
      if (current === undefined || current !== padValue) {
        throw new Error("Corrupted PKCS#7 padding.");
      }
    }
    return data.slice(0, data.length - padValue);
  }
}
