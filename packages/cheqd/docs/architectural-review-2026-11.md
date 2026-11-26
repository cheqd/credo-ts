# `packages/cheqd` security review — November 2026

> **Status report, not a specification.** Covers a security review of cheqd's Credo plugin
> (`packages/cheqd`): DID resolution and registration (`didCheqdUtil.ts`,
> `CheqdDidRegistrar.ts`), agent-card signature verification (`agent-id/agentCardSignature.ts`),
> AnonCreds revocation-status binding and ledger connection handling
> (`anoncreds/CheqdAnonCredsRegistry.ts`, `ledger/CheqdLedgerService.ts`), and the legacy
> StatusList2021/Bitstring implementation (`status-list/`).
>
> Working branch is `cheqd` (current, green CI, 4100+ tests) — not `main`, which is a stale,
> unmaintained mirror of upstream Credo with its own, unrelated, failing CI.
>
> This review is part of a wider programme covering cheqd's trust-binding work across two
> repositories; the companion document for `cheqd/agent-toolkit` (Core, A2A, AP2, TypeScript and
> Python) is
> [`docs/architectural-review-2026-11.md`](https://github.com/cheqd/agent-toolkit/blob/main/docs/architectural-review-2026-11.md)
> in that repository. Read that document for the programme-wide design decisions, research, and
> the two review passes it covers — it isn't repeated here.

## What was reviewed and why

`packages/cheqd` implements the same kind of trust-sensitive logic the `agent-toolkit` programme
reviews elsewhere — DID resolution, key-binding checks, revocation/status handling — but as
cheqd's own plugin for the Credo agent framework, a separate codebase with its own maintainers
and release cycle. It was brought into this review because the same method applied to
`agent-toolkit` (read the actual code, write a failing regression test for each finding, fix,
verify empirically, PR individually) generalises directly to it, and because a defect in any of
these areas has the same shape of consequence — a forged or unauthorised DID, key, or
credential-status result being accepted as genuine.

## Findings and fixes

Four pull requests, each a self-contained fix with its own regression test, opened against the
`cheqd` branch:

### [#50 — reject deactivated and unexpected DIDs in agent card verification](https://github.com/cheqd/credo-ts/pull/50)

Two findings in `agentCardSignature.ts`:

1. **Fail-open on deactivated DIDs.** `verifyAgentCardSignature` read `didDocument` from the
   resolver but never checked `didDocumentMetadata.deactivated`, so a key belonging to a
   deactivated DID still verified agent cards.
2. **No binding between the expected DID and the signer-supplied `kid` (SSRF-shaped).** The
   function resolved whatever DID the attacker-supplied `kid` claimed — any DID method the agent
   has configured, including `did:web` — before a caller had any chance to reject it, making the
   function a blind, caller-triggered resolver/fetch for an attacker-chosen DID or host.

**Fix:** checks `didDocumentMetadata.deactivated` and fails closed; added a **required**
`expectedDid` parameter, checked against the DID parsed from `kid` *before* anything is
resolved, so an attacker-controlled `kid` can never cause resolution of a DID the caller didn't
already ask about.

### [#51 — correctness bugs in did util and registrar](https://github.com/cheqd/credo-ts/pull/51)

Four low-severity, no-security-impact logic bugs, confirmed against the current `cheqd` branch
code before fixing (none were false positives): an `&&`/`||` inversion in
`validateSpecCompliantPayload`'s id check (let a `did:key:...` id pass, and threw instead of
failing validation cleanly on a missing id); `getCosmosPayerWallet` UTF-8-encoding a hex payer
seed instead of hex-decoding it (fails closed today, but the documented input format never
actually worked); `CheqdDidRegistrar.createResource` signing with every verification method on
the DID document instead of only authentication-capable ones; and `create`/`update`/`deactivate`
silently dropping caller-supplied `fee`/`feeOptions`.

### [#52 — bind revocation status list to its registry, fix ledger setup race](https://github.com/cheqd/credo-ts/pull/52)

1. `CheqdAnonCredsRegistry.getRevocationStatusList` looked up the status-list resource by name
   only (schema name + cred-def tag + rev-reg tag), which is not guaranteed unique — two
   revocation registries could resolve to the same resource name. Fixed to verify the fetched
   resource's embedded `revRegDefId` matches the requested `revocationRegistryId`, failing
   closed on mismatch.
2. `CheqdLedgerService.initializeSdkForNetwork` had a setup race (concurrent first calls each
   independently created an SDK/RPC client; a failing setup could erase a concurrent success),
   and `disconnect()` ran the same logic as `connect()` — it never actually disconnected
   anything. Fixed: the in-flight setup promise is assigned synchronously before any `await`; a
   failed setup only clears the slot if it still holds that same failed attempt; `disconnect()`
   now awaits the client, calls `signer.disconnect()`, releases the querier's RPC connection, and
   clears the slot.

### [#53 — close races, validation gaps and bombs in the legacy status list](https://github.com/cheqd/credo-ts/pull/53)

Seven findings in the legacy StatusList2021/Bitstring implementation (the resources cheqd Studio
and `@cheqd/did-provider-cheqd` wrote with Veramo), the most significant three:

1. **Lost-update race on concurrent revocations (fail-open).** `updateLegacyStatusList` read the
   latest version, flipped bits, and published a new version with no lock and no compare-and-swap
   — two concurrent revocations could silently drop one. Fixed by serialising writes to the same
   list behind an in-process lock, with a bounded retry if a read-back doesn't show every
   intended bit.
2. **`statusSize` unvalidated.** `statusSize: 0` made every index read as status 0 ("valid"),
   including on a fully revoked list. Fixed: `parseLegacyStatusListData` requires an integer 1–8;
   `checkLegacyCredentialStatus` requires the entry's declared `statusSize` (if present) to equal
   the list's rather than silently overriding it.
3. **Gzip bomb in the bitstring decoder.** Bounded, matching the same decompression-bomb cap
   pattern used elsewhere in this trust-binding programme.

The remaining four findings in the same PR are further validation and race gaps in the same
module, each with its own regression test.

## Status

All four PRs are code-complete, individually tested, file-disjoint from one another, and green
on CI. **None can currently be merged**: GitHub refuses to let the account that opened a pull
request also approve it
(`GraphQL: Review Can not approve your own pull request`), and all four were opened under the
account used throughout this review. They need a human reviewer who is not that account —
this is the one action item this document hands over; there is no outstanding code work.

## License

Apache 2.0, matching the rest of this repository.
