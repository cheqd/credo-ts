---
"@credo-ts/cheqd": minor
---

Token Status Lists as did:cheqd linked resources. `agent.modules.cheqdSdk` gets `publishTokenStatusList`, `fetchTokenStatusList` (tells a JWT from a CWT by its content) and `getTokenStatusListUri`, and `createCheqdStatusListFetcher` is a `customStatusListFetcher` for the `SdJwtVcModule` that reads the list from the ledger, so credentials can be checked against a status list on cheqd without an https endpoint. The list is stored as resource type `TokenStatusList`, and every update is a new version under the same name, so the uri does not change.
