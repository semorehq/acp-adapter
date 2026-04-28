import { describe, it, expect, beforeAll } from "vitest";
import { verifyAcpToken, buildMerchantAck } from "../src/index.js";

// Helper: b64url encode
function b64url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  const b64 = typeof btoa === "function" ? btoa(bin) : Buffer.from(bin, "binary").toString("base64");
  return b64.replace(/=+$/g, "").replace(/\+/g, "-").replace(/\//g, "_");
}

async function genEd25519(): Promise<{ pub: CryptoKey; priv: CryptoKey }> {
  const kp = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  return { pub: kp.publicKey, priv: kp.privateKey };
}

function toAb(bytes: Uint8Array): ArrayBuffer {
  const ab = new ArrayBuffer(bytes.byteLength);
  new Uint8Array(ab).set(bytes);
  return ab;
}

async function mintToken(priv: CryptoKey, kid: string, body: Record<string, unknown>): Promise<string> {
  const header = { alg: "EdDSA", typ: "JWT", kid };
  const h = b64url(new TextEncoder().encode(JSON.stringify(header)));
  const p = b64url(new TextEncoder().encode(JSON.stringify(body)));
  const sig = await crypto.subtle.sign("Ed25519", priv, toAb(new TextEncoder().encode(`${h}.${p}`)));
  return `${h}.${p}.${b64url(new Uint8Array(sig))}`;
}

describe("verifyAcpToken", () => {
  let pub: CryptoKey;
  let priv: CryptoKey;
  const kid = "acp-test#key-1";
  const now = 1_780_000_000;

  beforeAll(async () => {
    ({ pub, priv } = await genEd25519());
  });

  const baseBody = () => ({
    id: "urn:uuid:token-1",
    issuer: "https://openai.com/acp",
    subject: "did:example:buyer",
    audience: "did:web:merchant.example",
    nbf: now - 10,
    exp: now + 300,
    amount: { currency: "USD", value: "42.00" },
  });

  it("accepts a valid token", async () => {
    const jws = await mintToken(priv, kid, baseBody());
    const res = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
    });
    expect(res.ok).toBe(true);
    if (res.ok) expect(res.token.amount.value).toBe("42.00");
  });

  it("rejects expired token", async () => {
    const jws = await mintToken(priv, kid, { ...baseBody(), exp: now - 3600 });
    const res = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("expired");
  });

  it("rejects bad signature", async () => {
    const jws = await mintToken(priv, kid, baseBody());
    const tampered = jws.slice(0, -4) + "AAAA";
    const res = await verifyAcpToken(tampered, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("bad_signature");
  });

  it("rejects disallowed issuer", async () => {
    const jws = await mintToken(priv, kid, { ...baseBody(), issuer: "https://evil.example" });
    const res = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("issuer_not_allowed");
  });

  it("rejects audience mismatch", async () => {
    const jws = await mintToken(priv, kid, { ...baseBody(), audience: "did:web:other.example" });
    const res = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("audience_mismatch");
  });

  it("rejects replayed token when maxAgeSec is exceeded", async () => {
    // iat well in the past relative to `now`; exp still in the future so the
    // token would otherwise be valid — maxAgeSec is the only gate.
    const jws = await mintToken(priv, kid, { ...baseBody(), iat: now - 7200 });
    const res = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
      maxAgeSec: 300,
    });
    expect(res.ok).toBe(false);
    if (!res.ok) expect(res.reason).toBe("replayed");
  });

  it("accepts fresh token within maxAgeSec and rejects when iat missing", async () => {
    const fresh = await mintToken(priv, kid, { ...baseBody(), iat: now - 10 });
    const res1 = await verifyAcpToken(fresh, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
      maxAgeSec: 300,
    });
    expect(res1.ok).toBe(true);

    // Token without iat must be rejected when maxAgeSec is in force.
    const { iat: _omit, ...noIat } = { ...baseBody(), iat: now } as Record<string, unknown>;
    void _omit;
    const jws = await mintToken(priv, kid, noIat);
    const res2 = await verifyAcpToken(jws, {
      issuers: ["https://openai.com/acp"],
      publicKeys: { [kid]: pub },
      audience: "did:web:merchant.example",
      now: () => now,
      maxAgeSec: 300,
    });
    expect(res2.ok).toBe(false);
    if (!res2.ok) expect(res2.reason).toBe("replayed");
  });
});

describe("buildMerchantAck", () => {
  it("emits accepted ACK with orderRef", () => {
    const ack = buildMerchantAck({
      tokenId: "urn:uuid:token-1",
      merchantDid: "did:web:merchant.example",
      status: "accepted",
      orderRef: "ord_123",
      now: () => 1_780_000_000,
    });
    expect(ack.status).toBe("accepted");
    expect(ack.orderRef).toBe("ord_123");
    expect(ack.issuedAt).toBe(1_780_000_000);
  });

  it("emits rejected ACK with reason", () => {
    const ack = buildMerchantAck({
      tokenId: "urn:uuid:token-1",
      merchantDid: "did:web:merchant.example",
      status: "rejected",
      reason: "cart_mismatch",
      now: () => 1_780_000_000,
    });
    expect(ack.status).toBe("rejected");
    expect(ack.reason).toBe("cart_mismatch");
  });
});
