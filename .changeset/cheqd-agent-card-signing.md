---
"@credo-ts/cheqd": minor
---

Agent card signing with a DID. `signAgentCardPayload` signs the canonical payload of an A2A agent card with a key of a DID the agent controls (the algorithm follows the key, `ES256` for P-256, `EdDSA` for Ed25519, and the `kid` is the DID URL), and `verifyAgentCardSignature` verifies it by resolving the DID, with any DID method the agent can resolve. The signatures are accepted by the official `@a2a-js/sdk`.
