---
'@credo-ts/cheqd': minor
---

`updateLegacyStatusList` accepts `{ resourceId }` instead of a name and type, and `setLegacyCredentialStatus` handles entries whose `statusListCredential` names a resource id. The change is always written on top of the latest version of the list, never on the older version the id names, so earlier changes are kept. Such an entry stays pinned to its old version, which `setLegacyCredentialStatus` reports as `pinned`. `updateLegacyStatusList` now also returns the `name` of the list.
