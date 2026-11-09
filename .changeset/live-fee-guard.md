---
"@credo-ts/cheqd": patch
---

Add an opt-in, read-only live test (`CHEQD_LIVE_FEE_TEST=1`) that checks DID creation fees on cheqd mainnet and testnet use the Oracle (USD-priced) fee and not the static 50 CHEQ fee. Guards against SDK versions (5.5.0) that only used Oracle fees on testnet.
