import { AgentCard, canonicalizeAgentCard, verifyAgentCardSignature as verifyWithA2aSdk } from '@a2a-js/sdk'
import type { Kms } from '@credo-ts/core'
import { Agent, DidKey, getPublicJwkFromVerificationMethod, JsonEncoder, Kms as KmsApi } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import { signAgentCardPayload, verifyAgentCardSignature } from '../src'

const agent = new Agent(getAgentOptions('Agent card signing', {}, {}, {}))

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

    beforeAll(async () => {
      didUrl = (await createDid(keyType)).didUrl
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

      expect(await verifyAgentCardSignature(agent.context, { payload, signature })).toEqual({ isValid: true, didUrl })

      await expect(verifyWithA2aSdk(lookupKey)(card)).resolves.toBeUndefined()
    })

    it('rejects a card that was changed after signing, in both verifiers', async () => {
      const card = createCard()
      const signature = await signAgentCardPayload(agent.context, { didUrl, payload: canonicalizeAgentCard(card) })

      const changed = createCard('Evil agent')
      const result = await verifyAgentCardSignature(agent.context, {
        payload: canonicalizeAgentCard(changed),
        signature,
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
    const protectedHeader = Buffer.from(JSON.stringify({ alg: 'ES256', kid: 'my-key', typ: 'JOSE' })).toString(
      'base64url'
    )
    const result = await verifyAgentCardSignature(agent.context, {
      payload: 'x',
      signature: { protected: protectedHeader, signature: 'AAAA' },
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
      protected: Buffer.from(JSON.stringify({ ...claimed, kid: other.didUrl })).toString('base64url'),
    }
    const result = await verifyAgentCardSignature(agent.context, { payload: 'payload', signature: forged })
    expect(result.isValid).toBe(false)
  })
})
