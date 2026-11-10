import type { DidDocument } from '@credo-ts/core'
import {
  Agent,
  DidDocumentBuilder,
  getJsonWebKey2020,
  getPublicJwkFromVerificationMethod,
  JwsService,
  Kms,
  utils,
} from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere (the cached AnonCreds test using it is commented out)
const agent = new Agent(getAgentOptions('P256 spike', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))

describe('did:cheqd with a P-256 key (spike)', () => {
  beforeAll(async () => {
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  it('creates, resolves, signs ES256 and verifies via the DID', async () => {
    const created = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const did = `did:cheqd:testnet:${utils.uuid()}`
    const kid = `${did}#key-1`

    const publicJwk = Kms.PublicJwk.fromPublicJwk(created.publicJwk)
    const didDocument = new DidDocumentBuilder(did)
      .addContext('https://w3id.org/security/suites/jws-2020/v1')
      .addVerificationMethod(getJsonWebKey2020({ did, publicJwk, verificationMethodId: kid }))
      .addAuthentication(kid)
      .addAssertionMethod(kid)
      .build()

    const result = await agent.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      didDocument,
      options: { keys: [{ didDocumentRelativeKeyId: '#key-1', kmsKeyId: created.keyId }] },
    })
    expect(result.didState).toMatchObject({ state: 'finished' })

    const resolved = await agent.dids.resolve(did)
    const doc = resolved.didDocument as DidDocument
    expect(doc.verificationMethod?.[0]).toMatchObject({ type: 'JsonWebKey2020' })
    expect(doc.verificationMethod?.[0].publicKeyJwk).toMatchObject({ kty: 'EC', crv: 'P-256' })

    const jwsService = agent.dependencyManager.resolve(JwsService)
    const jws = await jwsService.createJwsCompact(agent.context, {
      payload: new TextEncoder().encode('hello'),
      keyId: created.keyId,
      protectedHeaderOptions: { alg: 'ES256', kid },
    })

    const verified = await jwsService.verifyJws(agent.context, {
      jws,
      allowedJwsSignerMethods: ['did'],
      resolveJwsSigner: async ({ protectedHeader }) => {
        const didUrl = protectedHeader.kid as string
        const { didDocument } = await agent.dids.resolve(didUrl.split('#')[0])
        if (!didDocument) throw new Error(`could not resolve ${didUrl}`)
        return {
          method: 'did',
          didUrl,
          jwk: getPublicJwkFromVerificationMethod(didDocument.dereferenceKey(didUrl, ['authentication'])),
        }
      },
    })
    expect(verified.isValid).toBe(true)
    expect(verified.jwsSigners[0].jwk.toJson()).toMatchObject({ kty: 'EC', crv: 'P-256' })

    // People-credential route: SD-JWT VC issued by the did:cheqd P-256 key, verified through DID resolution
    const { compact } = await agent.sdJwtVc.sign({
      payload: { vct: 'https://example.com/vct/test', given_name: 'Alice', family_name: 'Doe' },
      issuer: { method: 'did', didUrl: kid },
      disclosureFrame: { _sd: ['given_name', 'family_name'] },
    })
    const sdJwtResult = await agent.sdJwtVc.verify({ compactSdJwtVc: compact })
    expect(sdJwtResult.isValid).toBe(true)
    expect(sdJwtResult.sdJwtVc?.header.alg).toBe('ES256')
  })
})
