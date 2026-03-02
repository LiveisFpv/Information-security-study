import { describe, expect, it } from "vitest";
import { ElGamal } from "@/service/elgamal";
import { RSA, type KeyRSA } from "@/service/rsa";
import {
  signElGamalPayload,
  signRsaPayload,
  textToBytes,
  verifyElGamalPayload,
  verifyRsaPayload,
} from "@/service/signature";

describe("RSA digital signature", () => {
  const rsa = new RSA();
  const publicKey: KeyRSA = { n: 3233n, key: 17n };
  const privateKey: KeyRSA = { n: 3233n, key: 2753n };

  it("signs and verifies a numeric hash", () => {
    const m = 65n;
    const signature = rsa.signHash(privateKey, m);
    const verification = rsa.verifyHash(publicKey, m, signature);
    expect(verification.valid).toBe(true);
  });

  it("detects forged signature", () => {
    const m = 65n;
    const signature = rsa.signHash(privateKey, m);
    const verification = rsa.verifyHash(publicKey, m + 1n, signature);
    expect(verification.valid).toBe(false);
  });

  it("signs and verifies payload hash", async () => {
    const payload = textToBytes("digital signature test");
    const signed = await signRsaPayload(privateKey, payload);
    const verification = await verifyRsaPayload(publicKey, signed.signature, payload);
    expect(verification.valid).toBe(true);
  });
});

describe("ElGamal digital signature", () => {
  const algorithm = new ElGamal();

  it("builds known signature values for fixed parameters", () => {
    const privateKey = { p: 23n, g: 5n, x: 6n };
    const publicKey = ElGamal.buildPublicKey({ p: 23n, g: 5n }, privateKey.x);
    expect(publicKey.y).toBe(8n);

    const signed = algorithm.signHash(privateKey, 13n, 7n);
    expect(signed.signature.r).toBe(17n);
    expect(signed.signature.s).toBe(3n);
    expect(algorithm.verifyHash(publicKey, 13n, signed.signature)).toBe(true);
  });

  it("detects modified signature", () => {
    const privateKey = { p: 23n, g: 5n, x: 6n };
    const publicKey = ElGamal.buildPublicKey({ p: 23n, g: 5n }, privateKey.x);
    const signed = algorithm.signHash(privateKey, 13n, 7n);
    const badSignature = { r: signed.signature.r, s: signed.signature.s + 1n };
    expect(algorithm.verifyHash(publicKey, 13n, badSignature)).toBe(false);
  });

  it("signs and verifies payload hash", async () => {
    const privateKey = { p: 23n, g: 5n, x: 6n };
    const publicKey = ElGamal.buildPublicKey({ p: 23n, g: 5n }, privateKey.x);
    const payload = textToBytes("elgamal payload");
    const signed = await signElGamalPayload(privateKey, payload, 7n);
    const verification = await verifyElGamalPayload(publicKey, signed.signature, payload);
    expect(verification.valid).toBe(true);
  });
});
