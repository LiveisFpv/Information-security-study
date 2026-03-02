import {
  gcd,
  generateSafePrime,
  modInverse,
  modNormalize,
  randomBetween,
} from "./numberTheory";
import { BinaryUtils } from "./utils";

export interface ElGamalParameters {
  p: bigint;
  g: bigint;
}

export interface ElGamalPrivateKey extends ElGamalParameters {
  x: bigint;
}

export interface ElGamalPublicKey extends ElGamalParameters {
  y: bigint;
}

export interface ElGamalKeyPair {
  privateKey: ElGamalPrivateKey;
  publicKey: ElGamalPublicKey;
}

export interface ElGamalSignature {
  r: bigint;
  s: bigint;
}

export class ElGamal {
  static findGenerator(p: bigint, q: bigint): bigint {
    if (p <= 3n || q <= 1n) {
      throw new Error("Invalid parameters for generator search.");
    }

    while (true) {
      const candidate = randomBetween(2n, p - 2n);
      if (BinaryUtils.modPow(candidate, 2n, p) === 1n) {
        continue;
      }
      if (BinaryUtils.modPow(candidate, q, p) === 1n) {
        continue;
      }
      return candidate;
    }
  }

  static generateParameters(bits: number): ElGamalParameters {
    if (!Number.isInteger(bits) || bits < 32) {
      throw new Error("ElGamal prime bit size must be an integer greater or equal to 32.");
    }

    const { p, q } = generateSafePrime(bits);
    const g = ElGamal.findGenerator(p, q);
    return { p, g };
  }

  static buildPublicKey(parameters: ElGamalParameters, privateExponent: bigint): ElGamalPublicKey {
    if (privateExponent <= 0n || privateExponent >= parameters.p - 1n) {
      throw new Error("Private key x must be in range 1..p-2.");
    }
    const y = BinaryUtils.modPow(parameters.g, privateExponent, parameters.p);
    return { ...parameters, y };
  }

  static generateKeyPair(bits: number): ElGamalKeyPair {
    const parameters = ElGamal.generateParameters(bits);
    const x = randomBetween(1n, parameters.p - 2n);
    const publicKey = ElGamal.buildPublicKey(parameters, x);
    const privateKey: ElGamalPrivateKey = {
      ...parameters,
      x,
    };
    return { privateKey, publicKey };
  }

  static normalizeHash(hashValue: bigint, p: bigint): bigint {
    if (p <= 2n) {
      throw new Error("ElGamal modulus must be greater than 2.");
    }
    return modNormalize(hashValue, p - 1n);
  }

  signHash(
    privateKey: ElGamalPrivateKey,
    hashValue: bigint,
    forcedK?: bigint
  ): { signature: ElGamalSignature; k: bigint } {
    const pMinusOne = privateKey.p - 1n;
    const normalizedHash = ElGamal.normalizeHash(hashValue, privateKey.p);

    const createSignatureWithK = (k: bigint): ElGamalSignature => {
      if (k <= 1n || k >= pMinusOne) {
        throw new Error("k must be in range 2..p-2.");
      }
      if (gcd(k, pMinusOne) !== 1n) {
        throw new Error("k must be coprime with p-1.");
      }

      const r = BinaryUtils.modPow(privateKey.g, k, privateKey.p);
      const kInverse = modInverse(k, pMinusOne);
      const s = modNormalize((normalizedHash - privateKey.x * r) * kInverse, pMinusOne);
      if (r <= 0n || r >= privateKey.p || s === 0n) {
        throw new Error("Generated signature is invalid. Retry with another k.");
      }
      return { r, s };
    };

    if (forcedK !== undefined) {
      return {
        signature: createSignatureWithK(forcedK),
        k: forcedK,
      };
    }

    while (true) {
      const k = randomBetween(2n, privateKey.p - 2n);
      if (gcd(k, pMinusOne) !== 1n) {
        continue;
      }
      try {
        return {
          signature: createSignatureWithK(k),
          k,
        };
      } catch {
        // retry with new k
      }
    }
  }

  verifyHash(publicKey: ElGamalPublicKey, hashValue: bigint, signature: ElGamalSignature): boolean {
    if (
      signature.r <= 0n ||
      signature.r >= publicKey.p ||
      signature.s <= 0n ||
      signature.s >= publicKey.p - 1n
    ) {
      return false;
    }

    const normalizedHash = ElGamal.normalizeHash(hashValue, publicKey.p);
    const left =
      (BinaryUtils.modPow(publicKey.y, signature.r, publicKey.p) *
        BinaryUtils.modPow(signature.r, signature.s, publicKey.p)) %
      publicKey.p;
    const right = BinaryUtils.modPow(publicKey.g, normalizedHash, publicKey.p);
    return left === right;
  }
}
