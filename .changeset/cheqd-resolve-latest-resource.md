---
"@credo-ts/cheqd": patch
---

did:cheqd resolver: resolving a resource by `resourceName` and `resourceType` now asks the ledger for the latest version directly instead of listing the whole collection first, and percent-encoded names and types in did url query parameters are decoded (`?resourceName=My%20List` now matches `My List`). Names written with a literal percent sequence still resolve.
