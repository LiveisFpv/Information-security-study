import { BinaryUtils } from "./utils";

interface ExtendedGCDResult {
  gcd: bigint;
  x: bigint;
  y: bigint;
}
export interface KeyRSA{
  key: bigint
  n: bigint
}
export interface KeysRSA{
  openkey:KeyRSA
  closekey:KeyRSA
}
function extendedGCD(a: bigint, b: bigint): ExtendedGCDResult {
  if (b === BigInt(0)) {
    return { gcd: a, x: BigInt(1), y: BigInt(0) };
  }
  const { gcd, x, y } = extendedGCD(b, a % b);
  return {
    gcd: gcd,
    x: y,
    y: x - BigInt(a / b) * y
  };
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
    static generate_keys(key_len: number):KeysRSA{
        const p = PrimeNum.generatePrime(key_len);
        let q = PrimeNum.generatePrime(key_len);
        while (q === p){
            q = PrimeNum.generatePrime(key_len);
        }
        const n = p*q;
        const f_e=(p-BigInt(1))*(q-BigInt(1))
        let e = PrimeNum.generateFermPrime(f_e)
        let res = extendedGCD(e,f_e)
        while (res.gcd!=BigInt(1)){
          e=PrimeNum.generateFermPrime(f_e)
          res = extendedGCD(e,f_e)
        }
        const d = ((res.x % f_e) + f_e) % f_e;
        console.log(`p = ${p}`);
        console.log(`q = ${q}`);
        console.log(`n = ${n}`);
        console.log(`f_e = ${f_e}`);
        console.log(`e = ${e}`);
        console.log(`d = ${d}`)
        return {
          openkey:{
            key: e,
            n: n,
          },
          closekey:{
            key: d,
            n: n,
          }
        }
    }
    encrypt(key: KeyRSA, text: string): string{
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
    decrypt(key: KeyRSA, hex: string): string{
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

class PrimeNum{
    static getRandomBytes(size: number): Uint8Array {
        const bytes = new Uint8Array(size);
        globalThis.crypto.getRandomValues(bytes);
        return bytes;
    }
    static generateRandomBigInt(bits: number): bigint {
        const byteLength = Math.ceil(bits / 8);
        const randomBytes = this.getRandomBytes(byteLength);

        let value = 0n;
        for (let i = 0; i < byteLength; i++) {
            value = (value << 8n) | BigInt(randomBytes[i]);
        }

        const excessBits = byteLength * 8 - bits;
        if (excessBits > 0) {
            value >>= BigInt(excessBits);
        }

        value |= 1n << BigInt(bits - 1);

        value |= 1n;

        return value;
    }
    static modPow(base: bigint, exp: bigint, mod: bigint): bigint {
        if (mod === 1n) return 0n;
        let result = 1n;
        base = base % mod;
        while (exp > 0) {
            if (exp & 1n) {
            result = (result * base) % mod;
            }
            base = (base * base) % mod;
            exp >>= 1n;
        }
        return result;
    }
    static millerRabinTest(d: bigint, n: bigint, a: bigint): boolean {
        let x = this.modPow(a, d, n);

        if (x === 1n || x === n - 1n) return true;

        while (d !== n - 1n) {
            x = (x * x) % n;
            d <<= 1n;

            if (x === 1n) return false;
            if (x === n - 1n) return true;
        }
        return false;
    }
    static isProbablePrime(n: bigint, k: number = 40): boolean {
        if (n < 2n) return false;
        if (n === 2n || n === 3n) return true;
        if (n % 2n === 0n) return false;

        let d = n - 1n;
        let s = 0;
        while (d % 2n === 0n) {
            d >>= 1n;
            s++;
        }

        for (let i = 0; i < k; i++) {
            const a = this.generateRandomBigInt(64) % (n - 3n) + 2n;
            if (!this.millerRabinTest(d, n, a)) return false;
        }
        return true;
    }

    static generatePrime(bits: number): bigint {
        if (bits < 128) throw new Error('Слишком мало бит');
        let candidate: bigint;
        do {
            candidate = this.generateRandomBigInt(bits);
        } while (!this.isProbablePrime(candidate));
        return candidate;
    }
    static generateValueOnInterval(min:number, max:number): number{
      return Math.floor(Math.random()*(max-min) + min)
    }
    static generateFermPrime(max:bigint):bigint{
      let n = this.generateValueOnInterval(1,4);
      let num = BigInt(BigInt(2)**BigInt(2**n)+BigInt(1));
      while (num>=max){
        n = this.generateValueOnInterval(2,8);
        num = BigInt(BigInt(2)**BigInt(2**n)+BigInt(1));
      }
      return num
    }

}
