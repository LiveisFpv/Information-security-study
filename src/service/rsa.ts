interface ExtendedGCDResult {
  gcd: bigint;
  x: bigint;
  y: bigint;
}
interface Key{
  key: bigint
  n: bigint
}
interface Keys{
  openkey:Key
  closekey:Key
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
    static generate_keys(key_len: number):Keys{
        const p = PrimeNum.generatePrime(key_len);
        let q = PrimeNum.generatePrime(key_len);
        while (q === p){
            q = PrimeNum.generatePrime(key_len);
        }
        const n = p*q;
        const f_e=(p-BigInt(1))*(q-BigInt(1))
        const e = PrimeNum.generateFermPrime(f_e)
        const res = extendedGCD(e,f_e)
        const d=res.x
        console.log(`p = ${p}`);
        console.log(`q = ${q}`);
        console.log(`n = ${n}`);
        console.log(`f_e = ${f_e}`);
        console.log(`e = ${e}`);
        console.log(`d = ${res.gcd},${res.x},${res.y}`)
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
      let n = this.generateValueOnInterval(2,8);
      let num = BigInt(BigInt(2)**BigInt(2**n)+BigInt(1));
      while (num>=max){
        n = this.generateValueOnInterval(2,8);
        num = BigInt(BigInt(2)**BigInt(2**n)+BigInt(1));
      }
      return num
    }

}
