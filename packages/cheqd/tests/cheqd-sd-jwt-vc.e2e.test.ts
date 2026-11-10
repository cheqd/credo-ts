import { Agent, Kms } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere
const agent = new Agent(getAgentOptions('SD-JWT VC lifecycle', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))

describe('SD-JWT VC lifecycle with a did:cheqd P-256 issuer', () => {
  let issuerDidUrl: string
  let compact: string
  let holderKmsKeyId: string

  beforeAll(async () => {
    await agent.initialize()

    const created = await agent.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    expect(created.didState.state).toBe('finished')
    issuerDidUrl = `${created.didState.did}#key-1`

    // The holder key is a separate P-256 key (same agent for the test, so this does not show cross-agent holding)
    const holderKey = await agent.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const issued = await agent.sdJwtVc.sign({
      payload: { vct: 'https://example.com/vct/test', given_name: 'Alice', family_name: 'Doe', age: 30 },
      issuer: { method: 'did', didUrl: issuerDidUrl },
      holder: { method: 'jwk', jwk: Kms.PublicJwk.fromPublicJwk(holderKey.publicJwk) },
      disclosureFrame: { _sd: ['given_name', 'family_name', 'age'] },
    })
    compact = issued.compact
    holderKmsKeyId = holderKey.keyId
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  const verifierMetadata = {
    audience: 'https://verifier.example.com',
    nonce: 'nonce-123',
    issuedAt: Math.floor(Date.now() / 1000),
  }

  it('issues, then verifies the issuer signature through did:cheqd resolution', async () => {
    const result = await agent.sdJwtVc.verify({ compactSdJwtVc: compact })
    expect(result.isValid).toBe(true)
    expect(result.sdJwtVc?.header.alg).toBe('ES256')
  })

  it('presents selectively with a key binding JWT and verifies it', async () => {
    const presentation = await agent.sdJwtVc.present({
      sdJwtVc: { ...agent.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })

    const result = await agent.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: verifierMetadata.audience, nonce: verifierMetadata.nonce },
      requiredClaimKeys: ['given_name'],
    })
    expect(result.isValid).toBe(true)
    expect(result.sdJwtVc?.prettyClaims).toMatchObject({ given_name: 'Alice' })
    // Not disclosed in this presentation
    expect(result.sdJwtVc?.prettyClaims).not.toHaveProperty('family_name')
    expect(result.sdJwtVc?.prettyClaims).not.toHaveProperty('age')
  })

  it('rejects a presentation for a different nonce or audience', async () => {
    const presentation = await agent.sdJwtVc.present({
      sdJwtVc: { ...agent.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })

    const wrongNonce = await agent.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: verifierMetadata.audience, nonce: 'other-nonce' },
    })
    expect(wrongNonce.isValid).toBe(false)

    const wrongAudience = await agent.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: 'https://evil.example.com', nonce: verifierMetadata.nonce },
    })
    expect(wrongAudience.isValid).toBe(false)
  })

  it('rejects a presentation without a key binding JWT when one is required', async () => {
    const noBinding = await agent.sdJwtVc.present({
      sdJwtVc: { ...agent.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
    })
    const result = await agent.sdJwtVc.verify({
      compactSdJwtVc: noBinding,
      keyBinding: { audience: verifierMetadata.audience, nonce: verifierMetadata.nonce },
    })
    expect(result.isValid).toBe(false)
  })

  it('rejects a presentation missing a required claim', async () => {
    const presentation = await agent.sdJwtVc.present({
      sdJwtVc: { ...agent.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })
    const result = await agent.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: verifierMetadata.audience, nonce: verifierMetadata.nonce },
      requiredClaimKeys: ['family_name'],
    })
    expect(result.isValid).toBe(false)
  })
})
