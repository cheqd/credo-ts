import { AgentCard, canonicalizeAgentCard, verifyAgentCardSignature } from '@a2a-js/sdk'
import { Agent, getPublicJwkFromVerificationMethod, JwsService, TypedArrayEncoder } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere
const agent = new Agent(getAgentOptions('A2A agent card', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))

describe('A2A agent card signed by a did:cheqd P-256 key, verified by the official A2A SDK', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  it('signs with the cheqd key (Credo KMS) and verifies with @a2a-js/sdk resolving the DID', async () => {
    const created = await agent.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    const did = created.didState.did as string
    const didDocument = created.didState.didDocument
    const kid = `${did}#key-1`
    const keyId = (await agent.dids.getCreatedDids({ did }))[0].keys?.[0].kmsKeyId as string
    expect(didDocument).toBeDefined()

    const card = AgentCard.fromJSON({
      name: 'Test agent',
      description: 'Agent card signed with a did:cheqd key',
      supportedInterfaces: [
        { url: 'https://agent.example.com/a2a', protocolBinding: 'JSONRPC', protocolVersion: '1.0' },
      ],
      version: '1.0.0',
      capabilities: {},
      defaultInputModes: ['text/plain'],
      defaultOutputModes: ['text/plain'],
      skills: [],
    })

    // The SDK defines the payload (JCS over the card without signatures); the cheqd key signs it
    const payload = canonicalizeAgentCard(card)
    const jwsService = agent.dependencyManager.resolve(JwsService)
    const compact = await jwsService.createJwsCompact(agent.context, {
      payload: TypedArrayEncoder.fromUtf8String(payload),
      keyId,
      protectedHeaderOptions: { alg: 'ES256', kid, typ: 'JOSE' },
    })
    const [protectedHeader, , signature] = compact.split('.')
    card.signatures = [{ protected: protectedHeader, signature, header: {} }]

    const verify = verifyAgentCardSignature(async (signedKid) => {
      const { didDocument } = await agent.dids.resolve(signedKid.split('#')[0])
      if (!didDocument) throw new Error(`could not resolve ${signedKid}`)
      const jwk = getPublicJwkFromVerificationMethod(didDocument.dereferenceKey(signedKid, ['authentication']))
      return jwk.toJson()
    })

    await expect(verify(card)).resolves.toBeUndefined()

    // A changed card must no longer verify
    const tampered = AgentCard.fromJSON({ ...AgentCard.toJSON(card), name: 'Evil agent' })
    tampered.signatures = card.signatures
    await expect(verify(tampered)).rejects.toThrow()
  })
})
