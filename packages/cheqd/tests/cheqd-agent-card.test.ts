import { AgentCard, canonicalizeAgentCard, verifyAgentCardSignature as verifyWithA2aSdk } from '@a2a-js/sdk'
import type { AgentContext, DidResolutionResult, DidResolver, Kms } from '@credo-ts/core'
import {
  Agent,
  DidDocumentBuilder,
  DidKey,
  DidsApi,
  DidsModule,
  getJsonWebKey2020,
  getPublicJwkFromVerificationMethod,
  JsonEncoder,
  Kms as KmsApi,
  utils,
} from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import { signAgentCardPayload, verifyAgentCardSignature } from '../src'

/**
 * A resolver for a fake `did:deactivatedtest:...` method, used only to exercise the deactivated-DID check in
 * `verifyAgentCardSignature`. It looks the DID up among the DIDs the agent itself has created/imported (so the test
 * can sign with it via `signAgentCardPayload`, which only needs a local record), and always reports it deactivated,
 * the way a real resolver would report `didDocumentMetadata.deactivated` for a DID that has been deactivated on its
 * ledger/registry.
 */
class AlwaysDeactivatedResolver implements DidResolver {
  public readonly supportedMethods = ['deactivatedtest']
  public readonly allowsCaching = false

  public async resolve(agentContext: AgentContext, did: string): Promise<DidResolutionResult> {
    const didsApi = agentContext.dependencyManager.resolve(DidsApi)
    const [record] = await didsApi.getCreatedDids({ did })
    if (!record?.didDocument) {
      return { didDocument: null, didDocumentMetadata: {}, didResolutionMetadata: { error: 'notFound' } }
    }

    return {
      didDocument: record.didDocument,
      didDocumentMetadata: { deactivated: true },
      didResolutionMetadata: {},
    }
  }
}

const agent = new Agent(
  getAgentOptions(
    'Agent card signing',
    {},
    {},
    { dids: new DidsModule({ resolvers: [new AlwaysDeactivatedResolver()] }) }
  )
)

const createCard = (name = 'Test agent') =>
  AgentCard.fromJSON({
    name,
    description: 'An agent whose card is signed with a DID key',
    supportedInterfaces: [{ url: 'https://agent.example.com/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' }],
    version: '1.0.0',
    capabilities: {},
    defaultInputModes: ['text/plain'],
    defaultOutputModes: ['text/plain'],
    skills: [],
  })

// A did:key controlled by the agent, which needs no ledger
const createDid = async (type: Kms.KmsCreateKeyType) => {
  const key = await agent.kms.createKey({ type })
  const didKey = new DidKey(
    KmsApi.PublicJwk.fromPublicJwk(key.publicJwk as Parameters<typeof KmsApi.PublicJwk.fromPublicJwk>[0])
  )
  const didUrl = didKey.didDocument.verificationMethod?.[0].id as string
  await agent.dids.import({
    did: didKey.did,
    didDocument: didKey.didDocument,
    keys: [{ didDocumentRelativeKeyId: `#${didUrl.split('#')[1]}`, kmsKeyId: key.keyId }],
  })
  return { didUrl, did: didKey.did }
}

// A DID of the fake `deactivatedtest` method, imported locally (for signing) and always resolved as deactivated
// (for verifying), via AlwaysDeactivatedResolver above.
const createDeactivatedDid = async () => {
  const did = `did:deactivatedtest:${utils.uuid()}`
  const didUrl = `${did}#key-1`
  const key = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
  const publicJwk = KmsApi.PublicJwk.fromPublicJwk(key.publicJwk)

  const didDocument = new DidDocumentBuilder(did)
    .addController(did)
    .addAuthentication(didUrl)
    .addVerificationMethod(getJsonWebKey2020({ did, publicJwk, verificationMethodId: didUrl }))
    .build()

  await agent.dids.import({ did, didDocument, keys: [{ didDocumentRelativeKeyId: '#key-1', kmsKeyId: key.keyId }] })
  return { did, didUrl }
}

// The A2A SDK has no notion of DIDs: its verifier takes a key lookup, which here resolves the DID
const lookupKey = async (kid: string) => {
  const { didDocument } = await agent.dids.resolve(kid.split('#')[0])
  if (!didDocument) throw new Error(`could not resolve ${kid}`)
  return getPublicJwkFromVerificationMethod(didDocument.dereferenceKey(kid, ['authentication'])).toJson()
}

describe('Agent card signing', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  describe.each([
    ['P-256', { kty: 'EC', crv: 'P-256' } as const, 'ES256'],
    ['Ed25519', { kty: 'OKP', crv: 'Ed25519' } as const, 'EdDSA'],
  ])('with a %s key', (_name, keyType, expectedAlg) => {
    let didUrl: string
    let did: string

    beforeAll(async () => {
      ;({ didUrl, did } = await createDid(keyType))
    })

    it('signs with the algorithm of the key and the DID URL as kid', async () => {
      const signature = await signAgentCardPayload(agent.context, {
        didUrl,
        payload: canonicalizeAgentCard(createCard()),
      })

      expect(JsonEncoder.fromBase64Url(signature.protected)).toEqual({ alg: expectedAlg, kid: didUrl, typ: 'JOSE' })
    })

    it('is verified by our verifier and by the official A2A SDK', async () => {
      const card = createCard()
      const payload = canonicalizeAgentCard(card)
      const signature = await signAgentCardPayload(agent.context, { didUrl, payload })
      card.signatures = [{ ...signature, header: {} }]

      expect(await verifyAgentCardSignature(agent.context, { payload, signature, expectedDid: did })).toEqual({
        isValid: true,
        didUrl,
      })

      await expect(verifyWithA2aSdk(lookupKey)(card)).resolves.toBeUndefined()
    })

    it('rejects a card that was changed after signing, in both verifiers', async () => {
      const card = createCard()
      const signature = await signAgentCardPayload(agent.context, { didUrl, payload: canonicalizeAgentCard(card) })

      const changed = createCard('Evil agent')
      const result = await verifyAgentCardSignature(agent.context, {
        payload: canonicalizeAgentCard(changed),
        signature,
        expectedDid: did,
      })
      expect(result.isValid).toBe(false)

      changed.signatures = [{ ...signature, header: {} }]
      await expect(verifyWithA2aSdk(lookupKey)(changed)).rejects.toThrow()
    })
  })

  it('does not sign for a DID the agent does not control', async () => {
    const other = new DidKey(
      KmsApi.PublicJwk.fromPublicJwk((await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })).publicJwk)
    )
    await expect(
      signAgentCardPayload(agent.context, {
        didUrl: other.didDocument.verificationMethod?.[0].id as string,
        payload: 'x',
      })
    ).rejects.toThrow(/not a DID created or imported/)
  })

  it('does not verify a signature whose kid is not a DID URL', async () => {
    const protectedHeader = JsonEncoder.toBase64Url({ alg: 'ES256', kid: 'my-key', typ: 'JOSE' })
    const result = await verifyAgentCardSignature(agent.context, {
      payload: 'x',
      signature: { protected: protectedHeader, signature: 'AAAA' },
      expectedDid: 'did:key:unused',
    })
    expect(result).toMatchObject({ isValid: false, error: expect.stringContaining('not a DID URL') })
  })

  it('does not verify a signature made by a different key of another DID', async () => {
    const signer = await createDid({ kty: 'EC', crv: 'P-256' })
    const other = await createDid({ kty: 'EC', crv: 'P-256' })
    const signature = await signAgentCardPayload(agent.context, { didUrl: signer.didUrl, payload: 'payload' })

    // the same signature claiming to be from the other DID
    const claimed = JsonEncoder.fromBase64Url(signature.protected)
    const forged = {
      ...signature,
      protected: JsonEncoder.toBase64Url({ ...claimed, kid: other.didUrl }),
    }
    // the forged kid does match what we (as the caller) "expect" here, so this still exercises the JWS/key check,
    // not the expectedDid binding check below
    const result = await verifyAgentCardSignature(agent.context, {
      payload: 'payload',
      signature: forged,
      expectedDid: other.did,
    })
    expect(result.isValid).toBe(false)
  })

  // Regression test for: verifyAgentCardSignature accepted deactivated DIDs (fail-open).
  it('rejects a signature from a deactivated DID', async () => {
    const { did, didUrl } = await createDeactivatedDid()
    const signature = await signAgentCardPayload(agent.context, { didUrl, payload: 'payload' })

    const result = await verifyAgentCardSignature(agent.context, { payload: 'payload', signature, expectedDid: did })

    expect(result).toMatchObject({ isValid: false, didUrl, error: expect.stringContaining('deactivated') })
  })

  // Regression test for: verifyAgentCardSignature had no binding check (missing-binding-check / SSRF class bug).
  // A caller MUST be able to pin verification to the DID it expects, and the function must reject before resolving
  // anything for a DID that doesn't match - otherwise a caller-supplied kid can trigger resolution (and, for
  // network-backed DID methods, an outbound request) of an arbitrary, attacker-chosen DID.
  it('rejects a signature whose kid does not match the expected DID, without resolving it', async () => {
    const signer = await createDid({ kty: 'EC', crv: 'P-256' })
    const expected = await createDid({ kty: 'EC', crv: 'P-256' })
    const payload = 'payload'
    const signature = await signAgentCardPayload(agent.context, { didUrl: signer.didUrl, payload })

    const resolveSpy = vi.spyOn(agent.dids, 'resolve')
    try {
      const result = await verifyAgentCardSignature(agent.context, { payload, signature, expectedDid: expected.did })

      expect(result).toMatchObject({
        isValid: false,
        didUrl: signer.didUrl,
        error: expect.stringContaining('does not match the expected DID'),
      })
      // The mismatch must be caught before any resolution is attempted.
      expect(resolveSpy).not.toHaveBeenCalled()
    } finally {
      resolveSpy.mockRestore()
    }
  })
})
