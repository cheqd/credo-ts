import { AgentContext, injectable } from '@credo-ts/core'

import { type CheqdCreateResourceOptions, CheqdDidRegistrar, CheqdDidResolver } from './dids'
import {
  fetchTokenStatusList,
  getTokenStatusListUri,
  type PublishTokenStatusListOptions,
  publishTokenStatusList,
  type TokenStatusListUriOptions,
} from './status-list'

@injectable()
export class CheqdApi {
  private agentContext: AgentContext

  public constructor(agentContext: AgentContext) {
    this.agentContext = agentContext
  }

  public async createResource(did: string, options: CheqdCreateResourceOptions) {
    const cheqdDidRegistrar = this.agentContext.dependencyManager.resolve(CheqdDidRegistrar)
    return await cheqdDidRegistrar.createResource(this.agentContext, did, options)
  }

  public async resolveResource(resourceUrl: string) {
    const cheqdDidResolver = this.agentContext.dependencyManager.resolve(CheqdDidResolver)
    return await cheqdDidResolver.resolveResource(this.agentContext, resourceUrl)
  }

  /** @see {@link publishTokenStatusList} */
  public async publishTokenStatusList(did: string, options: PublishTokenStatusListOptions) {
    return await publishTokenStatusList(this.agentContext, did, options)
  }

  /** @see {@link fetchTokenStatusList} */
  public async fetchTokenStatusList(did: string, name: string) {
    return await fetchTokenStatusList(this.agentContext, { did, name })
  }

  /** @see {@link getTokenStatusListUri} */
  public getTokenStatusListUri(options: TokenStatusListUriOptions) {
    return getTokenStatusListUri(options)
  }
}
