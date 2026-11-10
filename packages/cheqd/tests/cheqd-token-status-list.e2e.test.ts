import { Agent, SdJwtVcModule, TypedArrayEncoder, utils } from '@credo-ts/core'

import { getAgentOptions } from '../../core/tests/helpers'
import type { CheqdDidCreateOptions } from '../src'
import { CheqdDidRegistrar } from '../src'
import { CheqdLedgerService } from '../src/ledger'
import { cheqdPayerSeeds, getCheqdModules } from './setupCheqdModule'

const RESOURCE_NAME = 'revocation-list'
const RESOURCE_TYPE = 'TokenStatusList'

// Maps the public resolver style url used as the status list uri onto a did url with a name and type query,
// which the cheqd resolver resolves to the latest version of the resource.
const RESOLVER_PREFIX = 'https://resolver.cheqd.net/1.0/identifiers/'
const toDidUrl = (uri: string) => decodeURIComponent(uri.slice(RESOLVER_PREFIX.length))

let agent: Agent

// Payer seed [4] is unused elsewhere
const getAgent = () =>
  new Agent(
    getAgentOptions(
      'Token status list',
      {},
      {},
      {
        ...getCheqdModules(cheqdPayerSeeds[4]),
        sdJwtVc: new SdJwtVcModule({
          customStatusListFetcher: async (uri) => {
            // Latest version of the linked resource with the requested name and type, read as raw bytes
            const [did, query] = toDidUrl(uri).split('?')
            const params = new URLSearchParams(query)
            const collectionId = did.split(':')[3]
            const ledger = agent.dependencyManager.resolve(CheqdLedgerService)
            const { resources } = await ledger.resolveCollectionResources(did, collectionId)
            const latest = resources
              .filter((r) => r.name === params.get('resourceName') && r.resourceType === params.get('resourceType'))
              .sort((a, b) => Number(b.created) - Number(a.created))[0]
            if (!latest) throw new Error(`no status list resource found for ${uri}`)
            const { resource } = await ledger.resolveResource(did, collectionId, latest.id)
            return TypedArrayEncoder.toUtf8String(resource?.data ?? new Uint8Array())
          },
        }),
      }
    )
  )

describe('Token Status List stored as a did:cheqd linked resource', () => {
  beforeAll(async () => {
    agent = getAgent()
    await agent.initialize()
  })

  afterAll(async () => {
    await agent.shutdown()
  })

  it('issues, publishes, verifies and revokes through the ledger', async () => {
    const created = await agent.dids.create<CheqdDidCreateOptions>({
      method: 'cheqd',
      options: { createKey: { type: { kty: 'EC', crv: 'P-256' } }, network: 'testnet' },
    })
    const did = created.didState.did as string
    const didUrl = `${did}#key-1`
    const collectionId = did.split(':')[3]
    const statusListUri = `${RESOLVER_PREFIX}${did}?resourceName=${RESOURCE_NAME}&resourceType=${RESOURCE_TYPE}`

    const registrar = agent.dependencyManager.resolve(CheqdDidRegistrar)
    const publish = async (statusList: string, version: string) => {
      const result = await registrar.createResource(agent.context, did, {
        id: utils.uuid(),
        name: RESOURCE_NAME,
        resourceType: RESOURCE_TYPE,
        version,
        data: TypedArrayEncoder.fromUtf8String(statusList),
      })
      expect(result.resourceState, JSON.stringify(result.resourceState)).toMatchObject({ state: 'finished' })
      return (result.resourceState as { resourceId: string }).resourceId
    }

    // 1. Create and publish the signed status list (all valid)
    const list = await agent.tokenStatusList.createTokenStatusList<'jwt'>({
      format: 'jwt',
      alg: 'ES256',
      statusList: { statusListLength: 64, bitsPerStatus: 1 },
      statusListUri,
      signer: { method: 'did', didUrl },
    })
    const firstResourceId = await publish(list.statusList, '1')

    // What the ledger records as the media type of the list
    const metadata = await agent.dependencyManager
      .resolve(CheqdLedgerService)
      .resolveResourceMetadata(did, collectionId, firstResourceId)
    // The ledger sniffs the media type from the content, so the resolver cannot serve it as
    // application/statuslist+jwt, which spec conformant status list clients require
    expect(metadata.mediaType).toBe('text/plain; charset=utf-8')

    // 2. Issue a credential that points at index 5
    const issued = await agent.sdJwtVc.sign({
      payload: {
        vct: 'https://example.com/vct/test',
        given_name: 'Alice',
        status: { status_list: { idx: 5, uri: statusListUri } },
      },
      issuer: { method: 'did', didUrl },
      disclosureFrame: { _sd: ['given_name'] },
    })

    // 3. Valid while the index is 0
    const valid = await agent.sdJwtVc.verify({ compactSdJwtVc: issued.compact })
    expect(valid.isValid, valid.isValid ? '' : String((valid.error as Error)?.message ?? valid.error)).toBe(true)

    // 4. Revoke index 5 and publish the new version
    const updated = await agent.tokenStatusList.updateTokenStatusList<'jwt'>({
      format: 'jwt',
      alg: 'ES256',
      token: list.statusList,
      status: { index: 5, status: 1 },
      signer: { method: 'did', didUrl },
    })
    await publish(updated.statusList, '2')

    // 5. The same credential is now rejected
    const revoked = await agent.sdJwtVc.verify({ compactSdJwtVc: issued.compact })
    expect(revoked.isValid).toBe(false)

    // 6. Another index in the same list is still valid
    const other = await agent.sdJwtVc.sign({
      payload: {
        vct: 'https://example.com/vct/test',
        given_name: 'Bob',
        status: { status_list: { idx: 6, uri: statusListUri } },
      },
      issuer: { method: 'did', didUrl },
      disclosureFrame: { _sd: ['given_name'] },
    })
    expect((await agent.sdJwtVc.verify({ compactSdJwtVc: other.compact })).isValid).toBe(true)
  })
})
