---
"@credo-ts/cheqd": minor
---

did:cheqd registrar: `createKey` and `keyId` now accept P-256 keys (as `JsonWebKey2020`) in addition to Ed25519. P-256 DIDs use a uuid identifier. Updating a DID with `createKey` now adds the new key to the DID document; previously the new verification method was dropped.
