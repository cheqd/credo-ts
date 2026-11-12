---
'@credo-ts/core': minor
---

Add `UniversalDidResolver`, which resolves the listed DID methods through a Universal Resolver endpoint (`new UniversalDidResolver({ methods: ['ethr', 'ion'], url })`). A document for another DID than the one asked about is not accepted. The default endpoint is a public development instance; use your own for production.
