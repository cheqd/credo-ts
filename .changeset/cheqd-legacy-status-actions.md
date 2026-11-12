---
'@credo-ts/cheqd': minor
---

Legacy status lists: entries with several indices (`statusListIndices`, with ranges such as `'5-10'`, and `statusListRangeStart`/`statusListRangeEnd`), capped at 10,000 indices per entry. `setLegacyCredentialStatus` revokes, suspends or reinstates a credential by writing the entries of its `credentialStatus` to their lists, and `checkLegacyPresentationStatus` reads the status of every credential of a presentation, JWT credentials included.
