import type { DidDocument } from '@credo-ts/core'
import { Agent, DidDocumentBuilder, getJsonWebKey2020, Kms } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions, CheqdDidUpdateOptions } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere
const agent = new Agent(getAgentOptions('P-256 key rotation', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))

describe('did:cheqd P-256 key rotation', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  it('replaces the authentication key with a new P-256 key and resolves the new key', async () => {
    const created = await agent.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    const did = created.didState.did as string
    const oldJwk = (created.didState.didDocument as DidDocument).verificationMethod?.[0].publicKeyJwk

    const newKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const newKeyUrl = `${did}#key-2`
    const rotated = new DidDocumentBuilder(did)
      .addContext('https://w3id.org/security/suites/jws-2020/v1')
      .addVerificationMethod(
        getJsonWebKey2020({
          did,
          publicJwk: Kms.PublicJwk.fromPublicJwk(newKey.publicJwk),
          verificationMethodId: newKeyUrl,
        })
      )
      .addAuthentication(newKeyUrl)
      .addAssertionMethod(newKeyUrl)
      .build()

    const update = await agent.dids.update<CheqdDidUpdateOptions>({
      did,
      didDocument: rotated,
      options: { keys: [{ didDocumentRelativeKeyId: '#key-2', kmsKeyId: newKey.keyId }] },
    })
    expect(update.didState).toMatchObject({ state: 'finished' })

    const resolved = await agent.dids.resolve(did)
    const methods = resolved.didDocument?.verificationMethod ?? []
    expect(methods).toHaveLength(1)
    expect(methods[0].id).toBe(newKeyUrl)
    expect(methods[0].publicKeyJwk).not.toEqual(oldJwk)

    // The new key can sign a further update
    const doc = resolved.didDocument as DidDocument
    const second = await agent.dids.update<CheqdDidUpdateOptions>({ did, didDocument: doc, options: {} })
    expect(second.didState).toMatchObject({ state: 'finished' })
  })
})
