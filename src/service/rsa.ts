import { gcd, generatePrime, modInverse, randomBetween } from "./numberTheory";
import { BinaryUtils } from "./utils";

export interface KeyRSA {
  key: bigint;
  n: bigint;
}

export interface KeysRSA {
  openkey: KeyRSA;
  closekey: KeyRSA;
}

export class RSA {
  private readonly encoder = new TextEncoder();
  private readonly decoder = new TextDecoder();

  private static getModulusByteLength(modulus: bigint): number {
    if (modulus <= 0n) {
      throw new Error("RSA modulus must be positive.");
    }
    return Math.ceil(modulus.toString(2).length / 8);
  }

  private static bytesToBigInt(bytes: Uint8Array): bigint {
    let value = 0n;
    for (const byte of bytes) {
      value = (value << 8n) | BigInt(byte);
    }
    return value;
  }

  private static bigintToFixedBytes(value: bigint, byteLength: number): Uint8Array {
    if (value < 0n) {
      throw new Error("Value must be non-negative.");
    }
    const output = new Uint8Array(byteLength);
    let current = value;
    for (let i = byteLength - 1; i >= 0 && current > 0n; i--) {
      output[i] = Number(current & 0xffn);
      current >>= 8n;
    }
    if (current > 0n) {
      throw new Error("Value does not fit in target byte length.");
    }
    return output;
  }

  static generate_keys(key_len: number): KeysRSA {
    if (!Number.isInteger(key_len) || key_len < 64) {
      throw new Error("RSA prime bit size must be an integer greater or equal to 64.");
    }

    const p = generatePrime(key_len);
    let q = generatePrime(key_len);
    while (q === p) {
      q = generatePrime(key_len);
    }

    const n = p * q;
    const phi = (p - 1n) * (q - 1n);

    let e = 65537n;
    if (e >= phi || gcd(e, phi) !== 1n) {
      do {
        e = randomBetween(3n, phi - 1n);
        if (e % 2n === 0n) {
          e += 1n;
        }
      } while (gcd(e, phi) !== 1n || e >= phi);
    }

    const d = modInverse(e, phi);
    return {
      openkey: { key: e, n },
      closekey: { key: d, n },
    };
  }

  static normalizeHash(hashValue: bigint, modulus: bigint): bigint {
    if (modulus <= 0n) {
      throw new Error("RSA modulus must be positive.");
    }
    return ((hashValue % modulus) + modulus) % modulus;
  }

  signHash(privateKey: KeyRSA, hashValue: bigint): bigint {
    const normalizedHash = RSA.normalizeHash(hashValue, privateKey.n);
    return BinaryUtils.modPow(normalizedHash, privateKey.key, privateKey.n);
  }

  verifyHash(
    publicKey: KeyRSA,
    hashValue: bigint,
    signature: bigint
  ): { valid: boolean; recoveredHash: bigint } {
    if (signature < 0n || signature >= publicKey.n) {
      return { valid: false, recoveredHash: -1n };
    }

    const normalizedHash = RSA.normalizeHash(hashValue, publicKey.n);
    const recoveredHash = BinaryUtils.modPow(signature, publicKey.key, publicKey.n);
    return {
      valid: recoveredHash === normalizedHash,
      recoveredHash,
    };
  }

  encrypt(key: KeyRSA, text: string): string {
    const plainBytes = this.encoder.encode(text);
    const modulusByteLength = RSA.getModulusByteLength(key.n);
    const plainBlockSize = modulusByteLength - 1;
    if (plainBlockSize < 1) {
      throw new Error("RSA modulus is too small for block encryption.");
    }

    const payload = new Uint8Array(4 + plainBytes.length);
    const view = new DataView(payload.buffer);
    view.setUint32(0, plainBytes.length, false);
    payload.set(plainBytes, 4);

    const blockCount = Math.ceil(payload.length / plainBlockSize);
    const encryptedBytes = new Uint8Array(blockCount * modulusByteLength);

    for (let i = 0; i < blockCount; i++) {
      const start = i * plainBlockSize;
      const end = Math.min(start + plainBlockSize, payload.length);
      const plainBlock = new Uint8Array(plainBlockSize);
      plainBlock.set(payload.slice(start, end), 0);

      const m = RSA.bytesToBigInt(plainBlock);
      if (m >= key.n) {
        throw new Error("Plaintext block is too large for RSA modulus.");
      }

      const encrypted = BinaryUtils.modPow(m, key.key, key.n);
      const encryptedBlock = RSA.bigintToFixedBytes(encrypted, modulusByteLength);
      encryptedBytes.set(encryptedBlock, i * modulusByteLength);
    }

    return BinaryUtils.bytesToHex(encryptedBytes);
  }

  decrypt(key: KeyRSA, hex: string): string {
    const encryptedBytes = BinaryUtils.hexToBytes(hex);
    const modulusByteLength = RSA.getModulusByteLength(key.n);
    const plainBlockSize = modulusByteLength - 1;
    if (plainBlockSize < 1) {
      throw new Error("RSA modulus is too small for block decryption.");
    }
    if (encryptedBytes.length % modulusByteLength !== 0) {
      throw new Error("Cipher text has invalid RSA block length.");
    }

    const blockCount = encryptedBytes.length / modulusByteLength;
    const decryptedPayload = new Uint8Array(blockCount * plainBlockSize);

    for (let i = 0; i < blockCount; i++) {
      const start = i * modulusByteLength;
      const end = start + modulusByteLength;
      const encryptedBlock = encryptedBytes.slice(start, end);
      const c = RSA.bytesToBigInt(encryptedBlock);
      if (c >= key.n) {
        throw new Error("Ciphertext block is out of RSA range.");
      }

      const decrypted = BinaryUtils.modPow(c, key.key, key.n);
      const decryptedBlock = RSA.bigintToFixedBytes(decrypted, plainBlockSize);
      decryptedPayload.set(decryptedBlock, i * plainBlockSize);
    }

    if (decryptedPayload.length < 4) {
      throw new Error("Decrypted data is too short.");
    }

    const payloadView = new DataView(
      decryptedPayload.buffer,
      decryptedPayload.byteOffset,
      decryptedPayload.byteLength
    );
    const messageLength = payloadView.getUint32(0, false);
    const payloadLength = decryptedPayload.length - 4;
    if (messageLength > payloadLength) {
      throw new Error("Decrypted message length prefix is invalid.");
    }

    const messageBytes = decryptedPayload.slice(4, 4 + messageLength);
    return this.decoder.decode(messageBytes);
  }
}
