import { BinaryUtils } from "./utils";

export interface ExtendedGcdResult {
  gcd: bigint;
  x: bigint;
  y: bigint;
}

export function modNormalize(value: bigint, modulus: bigint): bigint {
  if (modulus <= 0n) {
    throw new Error("Modulus must be positive.");
  }
  return ((value % modulus) + modulus) % modulus;
}

export function gcd(a: bigint, b: bigint): bigint {
  let left = a < 0n ? -a : a;
  let right = b < 0n ? -b : b;
  while (right !== 0n) {
    const next = left % right;
    left = right;
    right = next;
  }
  return left;
}

export function extendedGcd(a: bigint, b: bigint): ExtendedGcdResult {
  if (b === 0n) {
    return { gcd: a, x: 1n, y: 0n };
  }

  const next = extendedGcd(b, a % b);
  return {
    gcd: next.gcd,
    x: next.y,
    y: next.x - (a / b) * next.y,
  };
}

export function modInverse(value: bigint, modulus: bigint): bigint {
  const result = extendedGcd(modNormalize(value, modulus), modulus);
  if (result.gcd !== 1n) {
    throw new Error("Inverse does not exist for provided values.");
  }
  return modNormalize(result.x, modulus);
}

function getRandomBytes(size: number): Uint8Array {
  const bytes = new Uint8Array(size);
  globalThis.crypto.getRandomValues(bytes);
  return bytes;
}

function getBitLength(value: bigint): number {
  if (value < 0n) {
    throw new Error("Bit length is undefined for negative values.");
  }
  if (value === 0n) {
    return 1;
  }
  return value.toString(2).length;
}

export function randomBigInt(bits: number): bigint {
  if (!Number.isInteger(bits) || bits < 2) {
    throw new Error("Bit size must be an integer greater or equal to 2.");
  }

  const byteLength = Math.ceil(bits / 8);
  const bytes = getRandomBytes(byteLength);
  const value = BigInt(`0x${BinaryUtils.bytesToHex(bytes)}`);
  const shift = byteLength * 8 - bits;
  let normalized = shift > 0 ? value >> BigInt(shift) : value;
  normalized |= 1n << BigInt(bits - 1);
  normalized |= 1n;
  return normalized;
}

export function randomBetween(min: bigint, max: bigint): bigint {
  if (max < min) {
    throw new Error("Max must be greater or equal to min.");
  }

  const span = max - min + 1n;
  if (span === 1n) {
    return min;
  }

  const spanBits = getBitLength(span - 1n);
  const byteLength = Math.ceil(spanBits / 8);
  const extraBits = byteLength * 8 - spanBits;

  while (true) {
    const randomBytes = getRandomBytes(byteLength);
    if (extraBits > 0) {
      const firstByte = randomBytes[0];
      if (firstByte === undefined) {
        throw new Error("Failed to generate random bytes.");
      }
      const mask = 0xff >> extraBits;
      randomBytes[0] = firstByte & mask;
    }
    const sample = BigInt(`0x${BinaryUtils.bytesToHex(randomBytes)}`);
    if (sample < span) {
      return min + sample;
    }
  }
}

function isCompositeWitness(a: bigint, d: bigint, s: number, n: bigint): boolean {
  let x = BinaryUtils.modPow(a, d, n);
  if (x === 1n || x === n - 1n) {
    return false;
  }

  for (let i = 1; i < s; i++) {
    x = BinaryUtils.modPow(x, 2n, n);
    if (x === n - 1n) {
      return false;
    }
  }

  return true;
}

export function isProbablePrime(n: bigint, rounds: number = 40): boolean {
  if (n < 2n) return false;
  if (n === 2n || n === 3n) return true;
  if (n % 2n === 0n) return false;

  let d = n - 1n;
  let s = 0;
  while (d % 2n === 0n) {
    d >>= 1n;
    s++;
  }

  for (let i = 0; i < rounds; i++) {
    const a = randomBetween(2n, n - 2n);
    if (isCompositeWitness(a, d, s, n)) {
      return false;
    }
  }

  return true;
}

export function generatePrime(bits: number): bigint {
  if (!Number.isInteger(bits) || bits < 32) {
    throw new Error("Prime bit size must be an integer greater or equal to 32.");
  }

  let candidate = randomBigInt(bits);
  while (!isProbablePrime(candidate)) {
    candidate = randomBigInt(bits);
  }
  return candidate;
}

export function generateSafePrime(bits: number): { p: bigint; q: bigint } {
  if (!Number.isInteger(bits) || bits < 32) {
    throw new Error("Safe-prime bit size must be an integer greater or equal to 32.");
  }

  while (true) {
    const q = generatePrime(bits - 1);
    const p = 2n * q + 1n;
    if (isProbablePrime(p)) {
      return { p, q };
    }
  }
}

export function generateCoprime(limit: bigint): bigint {
  if (limit <= 3n) {
    throw new Error("Limit for coprime generation must be greater than 3.");
  }

  while (true) {
    const candidate = randomBetween(2n, limit - 1n);
    if (gcd(candidate, limit) === 1n) {
      return candidate;
    }
  }
}
