import type { AgentContext } from '@credo-ts/core'
import { TypedArrayEncoder } from '@credo-ts/core'

import { CheqdDidRegistrar, CheqdDidResolver } from '../src/dids'

/**
 * A tiny in-memory stand-in for the did:cheqd ledger, just enough to exercise `updateLegacyStatusList`,
 * `checkLegacyCredentialStatus` and `setLegacyCredentialStatus` without a network. It is wired in by faking
 * `agentContext.dependencyManager.resolve` to hand back plain objects in place of `CheqdDidResolver` and
 * `CheqdDidRegistrar`, so none of the real ledger, signing or DID document code is touched.
 *
 * Resources are kept both by `name::resourceType` (the "latest" a normal update reads) and by resource id (what a
 * pinned entry reads), matching how the real resolver can be asked for either.
 */
export function createFakeLegacyStatusLedger(options: { resolveDelayMs?: number; publishDelayMs?: number } = {}) {
  const byNameType = new Map<string, { resourceId: string; version: string; data: unknown }>()
  const byResourceId = new Map<string, { data: unknown; version: string; name: string; resourceType: string }>()
  let publishCount = 0
  let nextId = 0

  const delay = (ms?: number) => (ms ? new Promise((resolve) => setTimeout(resolve, ms)) : Promise.resolve())

  async function resolveResource(_agentContext: AgentContext, didUrl: string) {
    await delay(options.resolveDelayMs)

    const byId = didUrl.match(/\/resources\/([^/?#]+)$/)
    if (byId) {
      const found = byResourceId.get(byId[1])
      if (!found) return { error: 'notFound', message: `Unknown resource ${byId[1]}` }
      return {
        resource: found.data,
        resourceMetadata: { id: byId[1], version: found.version, name: found.name, resourceType: found.resourceType },
        resourceResolutionMetadata: {},
      }
    }

    const query = didUrl.split('?')[1] ?? ''
    const params = new URLSearchParams(query)
    const key = `${params.get('resourceName')}::${params.get('resourceType')}`
    const found = byNameType.get(key)
    if (!found) return { error: 'notFound', message: `Unknown resource ${key}` }
    return {
      resource: found.data,
      resourceMetadata: {
        id: found.resourceId,
        version: found.version,
        name: params.get('resourceName'),
        resourceType: params.get('resourceType'),
      },
      resourceResolutionMetadata: {},
    }
  }

  async function createResource(
    _agentContext: AgentContext,
    _did: string,
    resource: { id: string; name: string; resourceType: string; version: string; data: Uint8Array }
  ) {
    await delay(options.publishDelayMs)
    const data = JSON.parse(TypedArrayEncoder.toUtf8String(resource.data))
    const key = `${resource.name}::${resource.resourceType}`
    byNameType.set(key, { resourceId: resource.id, version: resource.version, data })
    byResourceId.set(resource.id, {
      data,
      version: resource.version,
      name: resource.name,
      resourceType: resource.resourceType,
    })
    publishCount++
    return { resourceState: { state: 'finished' as const } }
  }

  function seed(name: string, resourceType: string, data: unknown) {
    const resourceId = `seed-${++nextId}`
    const version = 'seed'
    byNameType.set(`${name}::${resourceType}`, { resourceId, version, data })
    byResourceId.set(resourceId, { data, version, name, resourceType })
    return resourceId
  }

  function latest(name: string, resourceType: string) {
    return byNameType.get(`${name}::${resourceType}`)
  }

  const resolvers = new Map<unknown, unknown>([
    [CheqdDidResolver, { resolveResource }],
    [CheqdDidRegistrar, { createResource }],
  ])

  const agentContext = {
    dependencyManager: { resolve: (token: unknown) => resolvers.get(token) },
  } as unknown as AgentContext

  return {
    agentContext,
    seed,
    latest,
    get publishCount() {
      return publishCount
    },
  }
}
