/**
 * Shared Payment Token — PAN-free envelope that an agent presents to a merchant.
 * The token itself is an RFC 7519 JWT (EdDSA / ES256) whose payload matches this shape.
 */
export interface ACPToken {
    /** Token id (jti). UUIDv4 recommended. */
    readonly id: string;
    /** Issuer DID or URL (e.g. `https://openai.com/acp`). */
    readonly issuer: string;
    /** Subject — the end-user DID the agent acts on behalf of. */
    readonly subject: string;
    /** Audience — the merchant DID / URL the token is bound to. */
    readonly audience: string;
    /** Epoch seconds — issued-at. Optional on the wire but required when the caller opts in to `maxAgeSec`. */
    readonly iat?: number;
    /** Epoch seconds — not-before. */
    readonly nbf: number;
    /** Epoch seconds — expiry. */
    readonly exp: number;
    /** Monetary binding — amount the agent is authorised to spend. */
    readonly amount: {
        readonly currency: string;
        readonly value: string;
    };
    /** Optional cart binding. When present the merchant MUST validate cart match. */
    readonly cart?: {
        readonly id: string;
        readonly hash: string;
    };
    /** Raw JWS for re-transmission. */
    readonly jws: string;
}
/**
 * Merchant ACK envelope — returned to the agent after SPT acceptance.
 */
export interface MerchantAck {
    readonly tokenId: string;
    readonly merchantDid: string;
    readonly status: "accepted" | "rejected";
    readonly reason?: string;
    readonly orderRef?: string;
    readonly issuedAt: number;
}
export interface VerifyOptions {
    /** Allowed issuers. Reject if token.iss ∉ issuers. */
    readonly issuers: readonly string[];
    /**
     * JWKS keyed by `kid`. Caller is responsible for fetching + caching (e.g. via Cloudflare KV).
     * Each entry is a `CryptoKey` for Workers Web Crypto compatibility.
     */
    readonly publicKeys: Readonly<Record<string, CryptoKey>>;
    /** Expected audience (this merchant's DID or URL). */
    readonly audience: string;
    /** Clock skew tolerance, seconds. Default 30. */
    readonly clockSkewSec?: number;
    /**
     * Replay defense. When set, the token MUST carry an `iat` claim and
     * `(now - iat) <= maxAgeSec` (with clock-skew grace). Rejects stale tokens
     * that have already been observed by a previous request. Callers should
     * additionally track `token.id` in an idempotency cache (e.g. KV with TTL
     * equal to `maxAgeSec + clockSkewSec`) for full replay protection.
     */
    readonly maxAgeSec?: number;
    /** Override `now()` for deterministic tests. */
    readonly now?: () => number;
}
export type VerifyReason = "malformed_jws" | "unknown_kid" | "bad_signature" | "unsupported_alg" | "issuer_not_allowed" | "audience_mismatch" | "not_yet_valid" | "expired" | "replayed" | "schema_invalid";
export type VerifyResult = {
    readonly ok: true;
    readonly token: ACPToken;
} | {
    readonly ok: false;
    readonly reason: VerifyReason;
};
//# sourceMappingURL=types.d.ts.map