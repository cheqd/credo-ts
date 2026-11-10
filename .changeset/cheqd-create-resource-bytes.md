---
"@credo-ts/cheqd": patch
---

did:cheqd registrar: `createResource` now stores `Uint8Array` data as the same bytes. Previously a `Uint8Array` was treated as an object and written as a JSON object of byte indices.
