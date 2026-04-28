export type { ACPToken, MerchantAck, VerifyOptions, VerifyReason, VerifyResult, } from "./types.js";
import type { MerchantAck, VerifyOptions, VerifyResult } from "./types.js";
/**
 * Verify an ACP Shared Payment Token (JWS compact form).
 * Skeleton implementation — validates structure, signature, issuer, audience, and timing.
 * Callers are expected to provide pre-imported `CryptoKey`s in `opts.publicKeys`, keyed by `kid`.
 */
export declare function verifyAcpToken(jws: string, opts: VerifyOptions): Promise<VerifyResult>;
/**
 * Build a protocol-compliant merchant ACK envelope.
 * Transport + signing is out of scope — caller signs with their own DID key.
 */
export declare function buildMerchantAck(input: {
    readonly tokenId: string;
    readonly merchantDid: string;
    readonly status: MerchantAck["status"];
    readonly reason?: string;
    readonly orderRef?: string;
    readonly now?: () => number;
}): MerchantAck;
//# sourceMappingURL=index.d.ts.map