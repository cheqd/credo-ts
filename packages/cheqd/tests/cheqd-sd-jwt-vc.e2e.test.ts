import { Agent, Kms, SdJwtVcModule, StatusListCwt, X509Service } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { createCheqdStatusListFetcher, createLegacyStatusEntry } from '../src'
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

describe('StatusList2021 and Bitstring status lists stored as did:cheqd linked resources', () => {
  let issuer: Agent<ReturnType<typeof getCheqdModules>>
  let did: string
  let otherDid: string

  beforeAll(async () => {
    issuer = new Agent(getAgentOptions('Legacy status list issuer', {}, {}, getCheqdModules(cheqdPayerSeeds[4])))
    await issuer.initialize()
    const create = async () => {
      const created = await issuer.dids.create<CheqdDidCreateOptions>({
        method: 'cheqd',
        options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
      })
      expect(created.didState.state).toBe('finished')
      return created.didState.did as string
    }
    did = await create()
    otherDid = await create()
  })

  afterAll(async () => {
    await issuer.shutdown()
  })

  const check = (credential: Parameters<typeof issuer.modules.cheqdSdk.checkLegacyCredentialStatus>[0]) =>
    issuer.modules.cheqdSdk.checkLegacyCredentialStatus(credential)

  it('creates a StatusList2021 revocation list, checks an entry, and sees it revoked after an update', async () => {
    const { uri, resourceType } = await issuer.modules.cheqdSdk.createLegacyStatusList(did, {
      format: 'StatusList2021',
      name: 'revocation list',
      statusPurpose: 'revocation',
    })
    expect(resourceType).toBe('StatusList2021Revocation')

    const entry = createLegacyStatusEntry({
      format: 'StatusList2021',
      statusListCredential: uri,
      statusPurpose: 'revocation',
      index: 42,
    })
    const credential = { issuer: { id: did }, credentialStatus: entry }

    expect(await check(credential)).toMatchObject([{ status: 0, valid: true, revoked: false, statusListIndex: 42 }])

    await issuer.modules.cheqdSdk.updateLegacyStatusList(did, {
      name: 'revocation list',
      resourceType,
      updates: [{ index: 42, value: 1 }],
    })

    expect(await check(credential)).toMatchObject([{ status: 1, valid: false, revoked: true, suspended: false }])
    // other entries are untouched
    expect(await check({ issuer: did, credentialStatus: { ...entry, statusListIndex: '43' } })).toMatchObject([
      { valid: true, revoked: false },
    ])

    // and the entry can be reinstated
    await issuer.modules.cheqdSdk.updateLegacyStatusList(did, {
      name: 'revocation list',
      resourceType,
      updates: [{ index: 42, value: 0 }],
    })
    expect(await check(credential)).toMatchObject([{ valid: true, revoked: false }])
  })

  it('creates a Bitstring list with 2 bits per entry, and tells revoked from suspended', async () => {
    const { uri, resourceType } = await issuer.modules.cheqdSdk.createLegacyStatusList(did, {
      format: 'BitstringStatusList',
      name: 'bitstring list',
      signerDidUrl: `${did}#key-1`,
    })
    expect(resourceType).toBe('BitstringStatusListCredential')

    const entryFor = (index: number, statusPurpose: 'revocation' | 'suspension' | 'message') =>
      createLegacyStatusEntry({ format: 'BitstringStatusList', statusListCredential: uri, statusPurpose, index })

    await issuer.modules.cheqdSdk.updateLegacyStatusList(did, {
      name: 'bitstring list',
      resourceType,
      updates: [
        { index: 10, value: 1 },
        { index: 11, value: 2 },
      ],
    })

    expect(await check({ issuer: did, credentialStatus: entryFor(10, 'message') })).toMatchObject([
      { status: 1, message: 'revoked', revoked: true, suspended: false },
    ])
    expect(await check({ issuer: did, credentialStatus: entryFor(11, 'message') })).toMatchObject([
      { status: 2, message: 'suspended', revoked: false, suspended: true },
    ])
    expect(await check({ issuer: did, credentialStatus: entryFor(12, 'revocation') })).toMatchObject([
      { status: 0, valid: true, message: 'valid' },
    ])
  })

  it('refuses a list that is not a resource of the issuer of the credential', async () => {
    const { uri } = await issuer.modules.cheqdSdk.createLegacyStatusList(did, {
      format: 'StatusList2021',
      name: 'issuer binding',
      statusPurpose: 'suspension',
    })
    const entry = createLegacyStatusEntry({
      format: 'StatusList2021',
      statusListCredential: uri,
      statusPurpose: 'suspension',
      index: 1,
    })

    await expect(check({ issuer: otherDid, credentialStatus: entry })).rejects.toThrow('not of the issuer')
    // checking with the issuer works
    await expect(check({ issuer: did, credentialStatus: entry })).resolves.toMatchObject([{ valid: true }])
  })

  it('refuses a purpose the list does not have, an index outside the list, and a url that is not a did:cheqd list', async () => {
    const { uri } = await issuer.modules.cheqdSdk.createLegacyStatusList(did, {
      format: 'StatusList2021',
      name: 'purpose and range',
      statusPurpose: 'revocation',
    })
    const entry = createLegacyStatusEntry({
      format: 'StatusList2021',
      statusListCredential: uri,
      statusPurpose: 'revocation',
      index: 0,
    })

    await expect(check({ issuer: did, credentialStatus: { ...entry, statusPurpose: 'suspension' } })).rejects.toThrow(
      "does not have the purpose 'suspension'"
    )
    await expect(check({ issuer: did, credentialStatus: { ...entry, statusListIndex: '140000' } })).rejects.toThrow(
      'out of range'
    )
    await expect(
      check({ issuer: did, credentialStatus: { ...entry, statusListCredential: 'https://example.com/status/1' } })
    ).rejects.toThrow('not the uri of a did:cheqd status list')
  })

  it('refuses a list of the other format than the entry says', async () => {
    const { uri } = await issuer.modules.cheqdSdk.createLegacyStatusList(did, {
      format: 'StatusList2021',
      name: 'format mismatch',
      statusPurpose: 'revocation',
    })
    const entry = createLegacyStatusEntry({
      format: 'BitstringStatusList',
      statusListCredential: uri,
      statusPurpose: 'revocation',
      index: 0,
    })
    await expect(check({ issuer: did, credentialStatus: entry })).rejects.toThrow('not a Bitstring list')
  })
})
