---
'@credo-ts/core': minor
---

JSON-LD credential and presentation verification accepts `allowUndefinedTerms`, to check documents that have terms no `@context` defines (Veramo issues such credentials). Those terms are dropped from the data the proof signs, so their values are not protected by the signature; they are listed in `validations.vcJs.undefinedTerms` of the result. Off by default.
