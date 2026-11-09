---
"@credo-ts/cheqd": patch
---

Retry idempotent cheqd chain reads (`resolve`, `resolveMetadata`, `resolveResource`, `resolveCollectionResources`, `resolveResourceMetadata`) up to 3 times with exponential backoff when the failure is a transient transport error (`fetch failed`, connection reset or refused, timeout, DNS). Errors returned by the chain are not retried and transactions are never retried. This addresses intermittent `fetch failed` failures in CI and against busy RPC nodes (#2731).
