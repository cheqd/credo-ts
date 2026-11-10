import { Agent, Kms } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere. The holder has no cheqd module: it never touches the ledger.
const issuer = new Agent(getAgentOptions('SD-JWT VC issuer', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))
const holder = new Agent(getAgentOptions('SD-JWT VC holder', {}, {}, {}))
const verifier = new Agent(getAgentOptions('SD-JWT VC verifier', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))

describe('SD-JWT VC lifecycle with a did:cheqd P-256 issuer', () => {
  let issuerDidUrl: string
  let compact: string
  let holderKmsKeyId: string

  beforeAll(async () => {
    await Promise.all([issuer.initialize(), holder.initialize(), verifier.initialize()])

    const created = await issuer.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    expect(created.didState.state).toBe('finished')
    issuerDidUrl = `${created.didState.did}#key-1`

    // The holder creates its own key and shares only the public key with the issuer
    const holderKey = await holder.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const issued = await issuer.sdJwtVc.sign({
      payload: { vct: 'https://example.com/vct/test', given_name: 'Alice', family_name: 'Doe', age: 30 },
      issuer: { method: 'did', didUrl: issuerDidUrl },
      holder: { method: 'jwk', jwk: Kms.PublicJwk.fromPublicJwk(holderKey.publicJwk) },
      disclosureFrame: { _sd: ['given_name', 'family_name', 'age'] },
    })
    compact = issued.compact
    holderKmsKeyId = holderKey.keyId
  })

  afterAll(async () => {
    await Promise.all([issuer.shutdown(), holder.shutdown(), verifier.shutdown()])
  })

  const verifierMetadata = {
    audience: 'https://verifier.example.com',
    nonce: 'nonce-123',
    issuedAt: Math.floor(Date.now() / 1000),
  }

  it('issues, then verifies the issuer signature through did:cheqd resolution', async () => {
    const result = await verifier.sdJwtVc.verify({ compactSdJwtVc: compact })
    expect(result.isValid).toBe(true)
    expect(result.sdJwtVc?.header.alg).toBe('ES256')
  })

  it('presents selectively with a key binding JWT and verifies it', async () => {
    const presentation = await holder.sdJwtVc.present({
      sdJwtVc: { ...holder.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })

    const result = await verifier.sdJwtVc.verify({
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
    const presentation = await holder.sdJwtVc.present({
      sdJwtVc: { ...holder.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })

    const wrongNonce = await verifier.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: verifierMetadata.audience, nonce: 'other-nonce' },
    })
    expect(wrongNonce.isValid).toBe(false)

    const wrongAudience = await verifier.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: 'https://evil.example.com', nonce: verifierMetadata.nonce },
    })
    expect(wrongAudience.isValid).toBe(false)
  })

  it('rejects a presentation without a key binding JWT when one is required', async () => {
    const noBinding = await holder.sdJwtVc.present({
      sdJwtVc: { ...holder.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
    })
    const result = await verifier.sdJwtVc.verify({
      compactSdJwtVc: noBinding,
      keyBinding: { audience: verifierMetadata.audience, nonce: verifierMetadata.nonce },
    })
    expect(result.isValid).toBe(false)
  })

  it('rejects a presentation missing a required claim', async () => {
    const presentation = await holder.sdJwtVc.present({
      sdJwtVc: { ...holder.sdJwtVc.fromCompact(compact), kmsKeyId: holderKmsKeyId },
      presentationFrame: { given_name: true },
      verifierMetadata,
    })
    const result = await verifier.sdJwtVc.verify({
      compactSdJwtVc: presentation,
      keyBinding: { audience: verifierMetadata.audience, nonce: verifierMetadata.nonce },
      requiredClaimKeys: ['family_name'],
    })
    expect(result.isValid).toBe(false)
  })
})
