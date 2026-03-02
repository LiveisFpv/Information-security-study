import {
  ElGamal,
  type ElGamalPrivateKey,
  type ElGamalPublicKey,
  type ElGamalSignature,
} from "./elgamal";
import { RSA, type KeyRSA } from "./rsa";
import { BinaryUtils } from "./utils";

export interface HashedPayload {
  bytes: Uint8Array;
  hex: string;
  value: bigint;
}

function bytesToBigInt(bytes: Uint8Array): bigint {
  let value = 0n;
  for (const byte of bytes) {
    value = (value << 8n) | BigInt(byte);
  }
  return value;
}

export function parsePositiveBigInt(raw: string, fieldName: string): bigint {
  const normalized = raw.trim();
  if (!/^\d+$/.test(normalized)) {
    throw new Error(`${fieldName} must contain only decimal digits.`);
  }
  const value = BigInt(normalized);
  if (value <= 0n) {
    throw new Error(`${fieldName} must be a positive integer.`);
  }
  return value;
}

export async function hashPayload(data: Uint8Array): Promise<HashedPayload> {
  const safeBuffer = new ArrayBuffer(data.byteLength);
  new Uint8Array(safeBuffer).set(data);
  const digest = await crypto.subtle.digest("SHA-256", safeBuffer);
  const bytes = new Uint8Array(digest);
  return {
    bytes,
    hex: BinaryUtils.bytesToHex(bytes),
    value: bytesToBigInt(bytes),
  };
}

export function textToBytes(text: string): Uint8Array {
  return new TextEncoder().encode(text);
}

export function signatureToJson(payload: object): string {
  return JSON.stringify(payload, null, 2);
}

export interface RsaSignResult {
  hash: HashedPayload;
  normalizedHash: bigint;
  signature: bigint;
}

export interface RsaVerifyResult {
  hash: HashedPayload;
  normalizedHash: bigint;
  recoveredHash: bigint;
  valid: boolean;
}

export async function signRsaPayload(privateKey: KeyRSA, data: Uint8Array): Promise<RsaSignResult> {
  const rsa = new RSA();
  const hash = await hashPayload(data);
  const normalizedHash = RSA.normalizeHash(hash.value, privateKey.n);
  const signature = rsa.signHash(privateKey, hash.value);
  return { hash, normalizedHash, signature };
}

export async function verifyRsaPayload(
  publicKey: KeyRSA,
  signature: bigint,
  data: Uint8Array
): Promise<RsaVerifyResult> {
  const rsa = new RSA();
  const hash = await hashPayload(data);
  const normalizedHash = RSA.normalizeHash(hash.value, publicKey.n);
  const verification = rsa.verifyHash(publicKey, hash.value, signature);
  return {
    hash,
    normalizedHash,
    recoveredHash: verification.recoveredHash,
    valid: verification.valid,
  };
}

export interface ElGamalSignResult {
  hash: HashedPayload;
  normalizedHash: bigint;
  signature: ElGamalSignature;
  k: bigint;
}

export interface ElGamalVerifyResult {
  hash: HashedPayload;
  normalizedHash: bigint;
  valid: boolean;
}

export async function signElGamalPayload(
  privateKey: ElGamalPrivateKey,
  data: Uint8Array,
  forcedK?: bigint
): Promise<ElGamalSignResult> {
  const algorithm = new ElGamal();
  const hash = await hashPayload(data);
  const normalizedHash = ElGamal.normalizeHash(hash.value, privateKey.p);
  const { signature, k } = algorithm.signHash(privateKey, hash.value, forcedK);
  return { hash, normalizedHash, signature, k };
}

export async function verifyElGamalPayload(
  publicKey: ElGamalPublicKey,
  signature: ElGamalSignature,
  data: Uint8Array
): Promise<ElGamalVerifyResult> {
  const algorithm = new ElGamal();
  const hash = await hashPayload(data);
  const normalizedHash = ElGamal.normalizeHash(hash.value, publicKey.p);
  return {
    hash,
    normalizedHash,
    valid: algorithm.verifyHash(publicKey, hash.value, signature),
  };
}
