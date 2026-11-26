import { AnonCredsRegistryService } from '@credo-ts/anoncreds'
import type { AgentContext } from '@credo-ts/core'
import { CheqdAnonCredsRegistry } from '../src/anoncreds/services/CheqdAnonCredsRegistry'
import { CheqdDidResolver } from '../src/dids'

// Same network/id shape used elsewhere in these tests (see testUtils.ts validDid), just with a
// resource path appended.
const issuerDid = 'did:cheqd:testnet:SiVQgrFZ7jFZFrTGstT4ZD'
const requestedRevocationRegistryId = `${issuerDid}/resources/aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa`
const otherRevocationRegistryId = `${issuerDid}/resources/bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb`

interface Setup {
  resolveResource: ReturnType<typeof vi.fn>
  getRevocationRegistryDefinition: ReturnType<typeof vi.fn>
}

function buildAgentContext({ resolveResource, getRevocationRegistryDefinition }: Setup): AgentContext {
  const cheqdDidResolver = { resolveResource }
  const anoncredsRegistryService = { getRevocationRegistryDefinition }

  return {
    dependencyManager: {
      resolve: (token: unknown) => {
        if (token === CheqdDidResolver) return cheqdDidResolver
        throw new Error(`Unexpected dependencyManager.resolve call in test: ${String(token)}`)
      },
    },
    resolve: (token: unknown) => {
      if (token === AnonCredsRegistryService) return anoncredsRegistryService
      throw new Error(`Unexpected agentContext.resolve call in test: ${String(token)}`)
    },
    config: {
      logger: { trace: vi.fn(), debug: vi.fn(), error: vi.fn() },
    },
  } as unknown as AgentContext
}

/** Builds a setup where the ledger resolves the status list resource with the given revRegDefId embedded. */
function setup(resolvedRevRegDefId: string) {
  const getRevocationRegistryDefinition = vi.fn().mockResolvedValue({
    revocationRegistryDefinition: {
      issuerId: issuerDid,
      revocDefType: 'CL_ACCUM',
      credDefId: `${issuerDid}/resources/cccccccc-cccc-cccc-cccc-cccccccccccc`,
      tag: 'default',
      value: {
        publicKeys: { accumKey: { z: 'z' } },
        maxCredNum: 100,
        tailsLocation: 'https://example.com/tails',
        tailsHash: 'hash',
      },
    },
    revocationRegistryDefinitionId: requestedRevocationRegistryId,
    revocationRegistryDefinitionMetadata: { name: 'resolvedresourcename' },
    resolutionMetadata: {},
  })

  const resolveResource = vi.fn().mockResolvedValue({
    resource: {
      revRegDefId: resolvedRevRegDefId,
      revocationList: [0, 0, 0],
      currentAccumulator: 'accumulator-value',
    },
    resourceMetadata: { created: new Date('2024-01-01T00:00:00.000Z') },
  })

  const agentContext = buildAgentContext({ resolveResource, getRevocationRegistryDefinition })
  const registry = new CheqdAnonCredsRegistry()

  return { registry, agentContext, resolveResource, getRevocationRegistryDefinition }
}

describe('CheqdAnonCredsRegistry.getRevocationStatusList', () => {
  it('fails closed when the resolved status list resource belongs to a different revocation registry', async () => {
    // Same resource name on the ledger can be shared by two distinct revocation registries
    // (e.g. same schema name + cred def tag + rev reg tag, different schema version). The
    // closest-version lookup can then hand back the OTHER registry's status list.
    const { registry, agentContext } = setup(otherRevocationRegistryId)

    const result = await registry.getRevocationStatusList(agentContext, requestedRevocationRegistryId, 1700000000)

    expect(result.revocationStatusList).toBeUndefined()
    expect(result.resolutionMetadata.error).toBe('notFound')
    expect(result.resolutionMetadata.message).toMatch(/belongs to revocation registry definition/i)
    expect(result.resolutionMetadata.message).toContain(otherRevocationRegistryId)
  })

  it('succeeds when the resolved status list resource matches the requested revocation registry', async () => {
    const { registry, agentContext } = setup(requestedRevocationRegistryId)

    const result = await registry.getRevocationStatusList(agentContext, requestedRevocationRegistryId, 1700000000)

    expect(result.resolutionMetadata.error).toBeUndefined()
    expect(result.revocationStatusList?.revRegDefId).toBe(requestedRevocationRegistryId)
    expect(result.revocationStatusList?.issuerId).toBe(issuerDid)
  })
})
