---
'@credo-ts/core': minor
---

Add the `JsonWebSignature2020` JSON-LD signature suite for `JsonWebKey2020` verification methods. It signs and verifies with Ed25519 (EdDSA), P-256 (ES256), P-384 (ES384) and secp256k1 (ES256K) keys, taking the algorithm from the key, and bundles the `https://w3id.org/security/suites/jws-2020/v1` context. Credentials signed this way by Veramo verify, and the other way round.
