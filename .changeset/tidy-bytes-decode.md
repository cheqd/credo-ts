---
"@credo-ts/cheqd": patch
---

`CheqdDidRegistrar.createResource` now accepts string `data` as either standard base64 or base64url. Since `TypedArrayEncoder.fromBase64` stopped accepting base64url in 0.7, a base64url payload (for example one returned by the resolver for binary resources) would fail to decode.
