---
'@credo-ts/cheqd': minor
---

`publishTokenStatusList` accepts `fee` and `feeOptions`, so a large status list can set a `gasLimit`. Updates `@cheqd/sdk` to 5.6.0, which honours `feeOptions.gasLimit` for linked resources.
