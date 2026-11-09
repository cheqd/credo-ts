---
"@credo-ts/cheqd": patch
---

Bump `@cheqd/sdk` to 5.5.1. SDK 5.5.0 only used Oracle (USD-priced) fees on testnet, so on mainnet DID, schema and credential definition writes fell back to the static 50 CHEQ fee and failed with "insufficient fee" after the Oracle upgrade. 5.5.1 detects whether the Oracle module is available. Adds an opt-in live test (`CHEQD_LIVE_FEE_TEST=1`) that checks DID creation fees on mainnet and testnet without sending a transaction.
