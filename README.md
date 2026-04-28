# @semore/acp-adapter

[![CI](https://github.com/semore-hq/acp-adapter/actions/workflows/ci.yml/badge.svg)](https://github.com/semore-hq/acp-adapter/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)
[![npm](https://img.shields.io/npm/v/@semore/acp-adapter.svg)](https://www.npmjs.com/package/@semore/acp-adapter)
[![status](https://img.shields.io/badge/status-skeleton--v0-lightgrey.svg)](./CHANGELOG.md)

Adapter helpers for the **Agentic Commerce Protocol (ACP)** Shared Payment Token (SPT) flow.
Verify incoming SPTs, inspect merchant ACKs, and compose request envelopes in your own merchant
backend or orchestrator.

> **Source of Truth:** this directory in the Semore monorepo until repo split.
> The production verification path lives in the internal Semore API; this package exposes the
> stable, framework-agnostic contract for third-party merchants and agent orchestrators.

## Install

```bash
npm install @semore/acp-adapter
# or
pnpm add @semore/acp-adapter
```

`hono` is an optional peer dependency — only required if you mount the provided route factory.

## Usage

```ts
import { verifyAcpToken, type ACPToken } from "@semore/acp-adapter";

const result = await verifyAcpToken(token, {
  issuers: ["https://openai.com/acp"],
  publicKeys: myJwks,
  audience: "did:web:merchant.example",
  clockSkewSec: 30,
  maxAgeSec: 300, // reject any SPT whose `iat` is older than 5 minutes (replay defense)
});

if (!result.ok) {
  console.error("reject:", result.reason);
  return;
}

// result.token is a typed ACPToken
```

## What this package provides

- `verifyAcpToken(token, opts)` — header + signature + expiry + issuer validation.
- `opts.maxAgeSec` — opt-in replay defense. Requires the token to carry `iat` and
  rejects with `reason: "replayed"` when `(now - iat) > maxAgeSec + clockSkewSec`.
  Pair with an idempotency cache keyed on `token.id` for full replay protection.
- `ACPToken` / `MerchantAck` / `VerifyResult` — transport schema types (subset of the wire format).
- `buildMerchantAck(...)` — helper to emit a protocol-compliant ACK.

## What this package does **not** provide

- Private key material or secret management (use Cloudflare Workers Secrets or a KMS).
- Card PAN handling. ACP SPTs are PAN-free by design — if you are holding PAN, you are off-protocol.
- Production Semore ACP orchestration (routing, fraud scoring, settlement). That lives behind
  `api.semore.net` and is not open-source.

## Reference

- ACP spec: <https://agenticcommerce.dev>
- Semore DID: `did:web:semore.net`
- Contact: `semore.hq@gmail.com` · GitHub [@semore_hq](https://github.com/semore-hq)

## License

Apache-2.0 — see [LICENSE](./LICENSE).

Copyright (c) Semore Founding Team.
