import { BinaryUtils, type BitArray } from "./utils";

type DesMode = "ecb";

const BLOCK_SIZE_BYTES = 8;

const IP = [
  58, 50, 42, 34, 26, 18, 10, 2,
  60, 52, 44, 36, 28, 20, 12, 4,
  62, 54, 46, 38, 30, 22, 14, 6,
  64, 56, 48, 40, 32, 24, 16, 8,
  57, 49, 41, 33, 25, 17, 9, 1,
  59, 51, 43, 35, 27, 19, 11, 3,
  61, 53, 45, 37, 29, 21, 13, 5,
  63, 55, 47, 39, 31, 23, 15, 7,
];

const FP = [
  40, 8, 48, 16, 56, 24, 64, 32,
  39, 7, 47, 15, 55, 23, 63, 31,
  38, 6, 46, 14, 54, 22, 62, 30,
  37, 5, 45, 13, 53, 21, 61, 29,
  36, 4, 44, 12, 52, 20, 60, 28,
  35, 3, 43, 11, 51, 19, 59, 27,
  34, 2, 42, 10, 50, 18, 58, 26,
  33, 1, 41, 9, 49, 17, 57, 25,
];

const E = [
  32, 1, 2, 3, 4, 5,
  4, 5, 6, 7, 8, 9,
  8, 9, 10, 11, 12, 13,
  12, 13, 14, 15, 16, 17,
  16, 17, 18, 19, 20, 21,
  20, 21, 22, 23, 24, 25,
  24, 25, 26, 27, 28, 29,
  28, 29, 30, 31, 32, 1,
];

const P = [
  16, 7, 20, 21, 29, 12, 28, 17,
  1, 15, 23, 26, 5, 18, 31, 10,
  2, 8, 24, 14, 32, 27, 3, 9,
  19, 13, 30, 6, 22, 11, 4, 25,
];

const PC1 = [
  57, 49, 41, 33, 25, 17, 9,
  1, 58, 50, 42, 34, 26, 18,
  10, 2, 59, 51, 43, 35, 27,
  19, 11, 3, 60, 52, 44, 36,
  63, 55, 47, 39, 31, 23, 15,
  7, 62, 54, 46, 38, 30, 22,
  14, 6, 61, 53, 45, 37, 29,
  21, 13, 5, 28, 20, 12, 4,
];

const PC2 = [
  14, 17, 11, 24, 1, 5, 3, 28,
  15, 6, 21, 10, 23, 19, 12, 4,
  26, 8, 16, 7, 27, 20, 13, 2,
  41, 52, 31, 37, 47, 55, 30, 40,
  51, 45, 33, 48, 44, 49, 39, 56,
  34, 53, 46, 42, 50, 36, 29, 32,
];

const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

const S_BOX = [
  [
    [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
    [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
    [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
    [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  ],
  [
    [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
    [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
    [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
    [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  ],
  [
    [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
    [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
    [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
    [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  ],
  [
    [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
    [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
    [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
    [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  ],
  [
    [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
    [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
    [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
    [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  ],
  [
    [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
    [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
    [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
    [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  ],
  [
    [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
    [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
    [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
    [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  ],
  [
    [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
    [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
    [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
    [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
  ],
];

export class DES {
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();

  static generateDefaultKeyHex(): string {
    const key = new Uint8Array(BLOCK_SIZE_BYTES);
    if (typeof crypto !== "undefined" && typeof crypto.getRandomValues === "function") {
      crypto.getRandomValues(key);
    } else {
      for (let i = 0; i < key.length; i++) key[i] = Math.floor(Math.random() * 256);
    }
    return BinaryUtils.bytesToHex(key);
  }

  static isValidKeyHex(keyHex: string): boolean {
    return /^[0-9A-Fa-f]{16}$/.test(keyHex.trim());
  }

  encrypt(message: string, keyHex: string, mode: DesMode = "ecb"): string {
    this.ensureEcbMode(mode);
    const keyBits = this.keyHexToBits(keyHex);
    const roundKeys = this.generateRoundKeys(keyBits);

    const plainBytes = this.encoder.encode(message);
    const padded = BinaryUtils.padPkcs7(plainBytes, BLOCK_SIZE_BYTES);
    const encrypted = this.transformBytesByBlocks(padded, roundKeys);

    return BinaryUtils.bytesToHex(encrypted);
  }

  decrypt(cipherHex: string, keyHex: string, mode: DesMode = "ecb"): string {
    this.ensureEcbMode(mode);
    const cipherBytes = BinaryUtils.hexToBytes(cipherHex);
    if (cipherBytes.length === 0 || cipherBytes.length % BLOCK_SIZE_BYTES !== 0) {
      throw new Error("Cipher text HEX length must be a multiple of 16 symbols.");
    }

    const keyBits = this.keyHexToBits(keyHex);
    const roundKeys = this.generateRoundKeys(keyBits).reverse();
    const decryptedWithPadding = this.transformBytesByBlocks(cipherBytes, roundKeys);
    const decrypted = BinaryUtils.unpadPkcs7(decryptedWithPadding, BLOCK_SIZE_BYTES);

    return this.decoder.decode(decrypted);
  }

  private ensureEcbMode(mode: DesMode) {
    if (mode !== "ecb") {
      throw new Error("Only ECB mode is supported.");
    }
  }

  private keyHexToBits(keyHex: string): BitArray {
    if (!DES.isValidKeyHex(keyHex)) {
      throw new Error("DES key must be exactly 16 HEX symbols.");
    }
    const keyBytes = BinaryUtils.hexToBytes(keyHex);
    return BinaryUtils.bytesToBits(keyBytes);
  }

  private transformBytesByBlocks(input: Uint8Array, roundKeys: BitArray[]): Uint8Array {
    const allBits = BinaryUtils.bytesToBits(input);
    const outputBits: BitArray = [];

    for (let offset = 0; offset < allBits.length; offset += 64) {
      const block = allBits.slice(offset, offset + 64);
      if (block.length !== 64) throw new Error("Block size must be 64 bits.");
      const transformed = this.transformBlock(block, roundKeys);
      outputBits.push(...transformed);
    }

    return BinaryUtils.bitsToBytes(outputBits);
  }

  private transformBlock(block64: BitArray, roundKeys: BitArray[]): BitArray {
    let permuted = BinaryUtils.permute(block64, IP);
    let left = permuted.slice(0, 32);
    let right = permuted.slice(32, 64);

    for (let i = 0; i < 16; i++) {
      const roundKey = roundKeys[i];
      if (!roundKey) throw new Error("DES round key is missing.");

      const nextLeft = right;
      const f = this.feistel(right, roundKey);
      const nextRight = BinaryUtils.xor(left, f);

      left = nextLeft;
      right = nextRight;
    }

    permuted = right.concat(left);
    return BinaryUtils.permute(permuted, FP);
  }

  private feistel(right32: BitArray, roundKey48: BitArray): BitArray {
    const expanded = BinaryUtils.permute(right32, E);
    const mixed = BinaryUtils.xor(expanded, roundKey48);
    const afterSBox = this.applySBoxes(mixed);
    return BinaryUtils.permute(afterSBox, P);
  }

  private applySBoxes(bits48: BitArray): BitArray {
    const out: BitArray = [];

    for (let box = 0; box < 8; box++) {
      const chunk = bits48.slice(box * 6, box * 6 + 6);
      if (chunk.length !== 6) throw new Error("S-Box input must be 6 bits.");

      const b0 = chunk[0];
      const b1 = chunk[1];
      const b2 = chunk[2];
      const b3 = chunk[3];
      const b4 = chunk[4];
      const b5 = chunk[5];
      if (b0 === undefined || b1 === undefined || b2 === undefined || b3 === undefined || b4 === undefined || b5 === undefined) {
        throw new Error("S-Box indexing error.");
      }

      const row = b0 * 2 + b5;
      const col = b1 * 8 + b2 * 4 + b3 * 2 + b4;
      const value = S_BOX[box]?.[row]?.[col];
      if (value === undefined) throw new Error("S-Box lookup failed.");

      out.push(...BinaryUtils.numberToBits(value, 4));
    }

    return out;
  }

  private generateRoundKeys(key64: BitArray): BitArray[] {
    const key56 = BinaryUtils.permute(key64, PC1);
    let c = key56.slice(0, 28);
    let d = key56.slice(28, 56);
    const keys: BitArray[] = [];

    for (const shift of SHIFTS) {
      c = BinaryUtils.leftRotate(c, shift);
      d = BinaryUtils.leftRotate(d, shift);
      const cd = c.concat(d);
      const roundKey = BinaryUtils.permute(cd, PC2);
      keys.push(roundKey);
    }

    return keys;
  }
}
