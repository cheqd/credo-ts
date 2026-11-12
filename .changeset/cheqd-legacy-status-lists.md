---
'@credo-ts/cheqd': minor
---

Read, create and update the `StatusList2021` and Bitstring status lists that cheqd Studio wrote with Veramo, as linked resources of the issuer's did:cheqd DID. `agent.modules.cheqdSdk` gets `checkLegacyCredentialStatus`, `createLegacyStatusList` and `updateLegacyStatusList`, and `createLegacyStatusEntry` makes the `credentialStatus` of a credential. The stored forms are the ones on the network today, and the plugin's own validator reads the lists written here. A list must be a resource of the credential's issuer, and only did:cheqd lists are fetched. Encrypted lists are not supported.
