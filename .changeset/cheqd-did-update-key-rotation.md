---
"@credo-ts/cheqd": patch
---

did:cheqd registrar: `update` now honours `options.keys` and also signs with authentication keys that the update removes, which the ledger requires. Without this, rotating the authentication key of a did:cheqd failed.
