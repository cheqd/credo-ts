import { randomBytes } from 'node:crypto'

import { Agent, Kms, SdJwtVcModule, StatusListCwt, X509Service } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { createCheqdStatusListFetcher } from '../src'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

// Payer seed [4] is unused elsewhere, and shared by the describes in this file, which run in order. The holder has no
// cheqd module: it never touches the ledger.
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

describe('Token Status List stored as a did:cheqd linked resource', () => {
  const statusListName = 'revocation list'
  let issuer: Agent<ReturnType<typeof getCheqdModules>>
  let verifier: Agent<ReturnType<typeof getCheqdModules> & { sdJwtVc: SdJwtVcModule }>
  let didUrl: string
  let did: string
  let statusListUri: string

  const signer = () => ({ method: 'did' as const, didUrl })
  const issueCredential = (idx: number) =>
    issuer.sdJwtVc.sign({
      payload: {
        vct: 'https://example.com/vct/test',
        given_name: 'Alice',
        status: { status_list: { idx, uri: statusListUri } },
      },
      issuer: { method: 'did', didUrl },
      disclosureFrame: { _sd: ['given_name'] },
    })

  beforeAll(async () => {
    issuer = new Agent(getAgentOptions('Status list issuer', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))
    verifier = new Agent(
      getAgentOptions(
        'Status list verifier',
        {},
        {},
        {
          ...getCheqdModules(cheqdPayerSeeds[4]),
          // reads the list from the ledger; the verifier never writes
          sdJwtVc: new SdJwtVcModule({ customStatusListFetcher: createCheqdStatusListFetcher(() => verifier.context) }),
        }
      )
    )
    await Promise.all([issuer.initialize(), verifier.initialize()])

    const created = await issuer.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    expect(created.didState.state).toBe('finished')
    did = created.didState.did as string
    didUrl = `${did}#key-1`
    // the name has a space, so the uri has to be percent-encoded
    statusListUri = issuer.modules.cheqdSdk.getTokenStatusListUri({ did, name: statusListName })
  })

  afterAll(async () => {
    await Promise.all([issuer.shutdown(), verifier.shutdown()])
  })

  it('publishes a JWT list, verifies a credential against it, and rejects the credential once it is revoked', async () => {
    const list = await issuer.tokenStatusList.createTokenStatusList<'jwt'>({
      format: 'jwt',
      alg: 'ES256',
      statusList: { statusListLength: 64, bitsPerStatus: 1 },
      statusListUri,
      signer: signer(),
    })
    await issuer.modules.cheqdSdk.publishTokenStatusList(did, { name: statusListName, statusList: list.statusList })

    const credential = await issueCredential(5)
    const valid = await verifier.sdJwtVc.verify({ compactSdJwtVc: credential.compact })
    expect(valid.isValid, valid.isValid ? '' : String(valid.error)).toBe(true)

    // revoke index 5 and publish the new version under the same name: the uri does not change
    const updated = await issuer.tokenStatusList.updateTokenStatusList<'jwt'>({
      format: 'jwt',
      alg: 'ES256',
      token: list.statusList,
      status: { index: 5, status: 1 },
      signer: signer(),
    })
    await issuer.modules.cheqdSdk.publishTokenStatusList(did, { name: statusListName, statusList: updated.statusList })

    expect((await verifier.sdJwtVc.verify({ compactSdJwtVc: credential.compact })).isValid).toBe(false)
    expect((await verifier.sdJwtVc.verify({ compactSdJwtVc: (await issueCredential(6)).compact })).isValid).toBe(true)

    const fetched = await verifier.modules.cheqdSdk.fetchTokenStatusList(did, statusListName)
    expect(fetched).toMatchObject({ format: 'jwt', statusList: updated.statusList })
  })

  it('needs a gas limit for a large list', async () => {
    // Incompressible, about 40 KB: more than the 1,000,000 gas the SDK sets by default (about 41 gas per byte)
    const statusList = randomBytes(30_000).toString('base64url')

    await expect(
      issuer.modules.cheqdSdk.publishTokenStatusList(did, { name: 'large list', statusList })
    ).rejects.toThrow(/out of gas/)

    const { resourceId } = await issuer.modules.cheqdSdk.publishTokenStatusList(did, {
      name: 'large list',
      statusList,
      feeOptions: { slippageBps: 1000, gasLimit: '3000000' },
    })
    expect(resourceId).toBeDefined()
  })

  it('publishes a CWT list and reads it back as the same bytes', async () => {
    // Credo signs a CWT list only with an X.509 certificate, not with a did key
    const key = await issuer.kms.createKey({ type: { kty: 'EC', crv: 'P-256' } })
    const certificate = await X509Service.createCertificate(issuer.context, {
      authorityKey: Kms.PublicJwk.fromPublicJwk(key.publicJwk),
      validity: { notBefore: new Date(Date.now() - 86_400_000), notAfter: new Date(Date.now() + 86_400_000) },
      issuer: 'C=DE',
    })
    const list = await issuer.tokenStatusList.createTokenStatusList<'cwt'>({
      format: 'cwt',
      alg: 'ES256',
      statusList: { statusListLength: 64, bitsPerStatus: 1 },
      statusListUri: issuer.modules.cheqdSdk.getTokenStatusListUri({ did, name: 'cwt list' }),
      signer: { method: 'x5c', x5c: [certificate] },
    })
    await issuer.modules.cheqdSdk.publishTokenStatusList(did, { name: 'cwt list', statusList: list.statusList })

    const fetched = await verifier.modules.cheqdSdk.fetchTokenStatusList(did, 'cwt list')
    expect(fetched.format).toBe('cwt')
    expect(fetched.statusList).toEqual(list.statusList)
    expect(StatusListCwt.fromToken(fetched.statusList as Uint8Array).payload.statusList).toBeDefined()
  })

  it('refuses a CWT list for an SD-JWT VC, and leaves other uris to the default fetcher', async () => {
    const fetcher = createCheqdStatusListFetcher(() => verifier.context)
    const unexpected = async () => {
      throw new Error('default fetcher should not be used')
    }

    await expect(
      fetcher(issuer.modules.cheqdSdk.getTokenStatusListUri({ did, name: 'cwt list' }), { defaultFetcher: unexpected })
    ).rejects.toThrow(/CWT/)
    await expect(fetcher('https://example.com/status/1', { defaultFetcher: async () => 'default' })).resolves.toBe(
      'default'
    )
  })

  it('fails for a list that was never published', async () => {
    await expect(verifier.modules.cheqdSdk.fetchTokenStatusList(did, 'never published')).rejects.toThrow()
  })
})
