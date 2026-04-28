// @semore/acp-adapter — public entrypoint.
// Skeleton: provides the verification contract and a minimal EdDSA/ES256 JWS check.
// Production Semore orchestration (fraud scoring, routing, settlement) is NOT open-sourced.
const SUPPORTED_ALG = new Set(["EdDSA", "ES256"]);
function b64urlToBytes(s) {
    const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
    const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
    const bin = typeof atob === "function" ? atob(b64) : Buffer.from(b64, "base64").toString("binary");
    const out = new Uint8Array(new ArrayBuffer(bin.length));
    for (let i = 0; i < bin.length; i++)
        out[i] = bin.charCodeAt(i);
    return out;
}
function toArrayBuffer(bytes) {
    const ab = new ArrayBuffer(bytes.byteLength);
    new Uint8Array(ab).set(bytes);
    return ab;
}
function decodeJsonPart(seg) {
    try {
        const bytes = b64urlToBytes(seg);
        const json = new TextDecoder().decode(bytes);
        return JSON.parse(json);
    }
    catch {
        return null;
    }
}
function fail(reason) {
    return { ok: false, reason };
}
/**
 * Verify an ACP Shared Payment Token (JWS compact form).
 * Skeleton implementation — validates structure, signature, issuer, audience, and timing.
 * Callers are expected to provide pre-imported `CryptoKey`s in `opts.publicKeys`, keyed by `kid`.
 */
export async function verifyAcpToken(jws, opts) {
    const parts = jws.split(".");
    if (parts.length !== 3)
        return fail("malformed_jws");
    const [h, p, s] = parts;
    const header = decodeJsonPart(h);
    if (!header || !header.alg || !header.kid)
        return fail("malformed_jws");
    if (!SUPPORTED_ALG.has(header.alg))
        return fail("unsupported_alg");
    const key = opts.publicKeys[header.kid];
    if (!key)
        return fail("unknown_kid");
    const signingInput = toArrayBuffer(new TextEncoder().encode(`${h}.${p}`));
    const sig = toArrayBuffer(b64urlToBytes(s));
    const algParams = header.alg === "EdDSA" ? { name: "Ed25519" } : { name: "ECDSA", hash: "SHA-256" };
    let valid = false;
    try {
        valid = await crypto.subtle.verify(algParams, key, sig, signingInput);
    }
    catch {
        return fail("bad_signature");
    }
    if (!valid)
        return fail("bad_signature");
    const body = decodeJsonPart(p);
    if (!body || typeof body !== "object")
        return fail("schema_invalid");
    const token = body;
    if (typeof token.id !== "string" ||
        typeof token.issuer !== "string" ||
        typeof token.subject !== "string" ||
        typeof token.audience !== "string" ||
        typeof token.nbf !== "number" ||
        typeof token.exp !== "number" ||
        !token.amount ||
        typeof token.amount.currency !== "string" ||
        typeof token.amount.value !== "string") {
        return fail("schema_invalid");
    }
    if (!opts.issuers.includes(token.issuer))
        return fail("issuer_not_allowed");
    if (token.audience !== opts.audience)
        return fail("audience_mismatch");
    const now = (opts.now ?? (() => Math.floor(Date.now() / 1000)))();
    const skew = opts.clockSkewSec ?? 30;
    if (now + skew < token.nbf)
        return fail("not_yet_valid");
    if (now - skew > token.exp)
        return fail("expired");
    // n8 replay defense — when opts.maxAgeSec is set, iat must exist and fall
    // within the caller's freshness window. Prevents long-lived SPTs being
    // replayed after a network capture.
    if (opts.maxAgeSec !== undefined) {
        if (typeof token.iat !== "number")
            return fail("replayed");
        if (now - skew > token.iat + opts.maxAgeSec)
            return fail("replayed");
    }
    return { ok: true, token: { ...token, jws } };
}
/**
 * Build a protocol-compliant merchant ACK envelope.
 * Transport + signing is out of scope — caller signs with their own DID key.
 */
export function buildMerchantAck(input) {
    const now = (input.now ?? (() => Math.floor(Date.now() / 1000)))();
    const ack = {
        tokenId: input.tokenId,
        merchantDid: input.merchantDid,
        status: input.status,
        issuedAt: now,
        ...(input.reason !== undefined ? { reason: input.reason } : {}),
        ...(input.orderRef !== undefined ? { orderRef: input.orderRef } : {}),
    };
    return ack;
}
