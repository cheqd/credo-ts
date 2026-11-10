---
"@credo-ts/cheqd": patch
---

did:cheqd registrar: updating a did whose record has no key mappings (created by older versions) now keeps the keys passed in `options.keys` or created with `createKey`. Previously they were dropped, so rotating the authentication key of such a did failed.
