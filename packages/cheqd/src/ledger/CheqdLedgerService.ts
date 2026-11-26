import type { AbstractCheqdSDKModule, CheqdSDK, DIDDocument, DidFeeOptions, DidStdFee } from '@cheqd/sdk'
import { CheqdNetwork, createCheqdSDK, DIDModule, ResourceModule } from '@cheqd/sdk'
import type { QueryAllDidDocVersionsMetadataResponse, SignInfo } from '@cheqd/ts-proto/cheqd/did/v2'
import type {
  Metadata,
  MsgCreateResourcePayload,
  QueryCollectionResourcesResponse,
  ResourceWithMetadata,
} from '@cheqd/ts-proto/cheqd/resource/v2'
import type { DirectSecp256k1HdWallet, DirectSecp256k1Wallet } from '@cosmjs/proto-signing'
import type { DeliverTxResponse } from '@cosmjs/stargate'
import type { DidDocumentMetadata } from '@credo-ts/core'
import { CredoError, InjectionSymbols, inject, injectable, type Logger } from '@credo-ts/core'
import { parseCheqdDid } from '../anoncreds/utils/identifiers'
import { CheqdModuleConfig } from '../CheqdModuleConfig'
import { getCosmosPayerWallet } from '../dids/didCheqdUtil'
import { retryOnTransientError } from './retryTransient'

export interface ICheqdLedgerConfig {
  network: string
  rpcUrl: string
  readonly cosmosPayerWallet: Promise<DirectSecp256k1HdWallet | DirectSecp256k1Wallet>
  sdk?: Promise<CheqdSDK>
}

export enum DefaultRPCUrl {
  Mainnet = 'https://rpc.cheqd.net',
  Testnet = 'https://rpc.cheqd.network',
}

@injectable()
export class CheqdLedgerService {
  private networks: ICheqdLedgerConfig[]
  private logger: Logger

  public constructor(cheqdSdkModuleConfig: CheqdModuleConfig, @inject(InjectionSymbols.Logger) logger: Logger) {
    this.logger = logger
    this.networks = cheqdSdkModuleConfig.networks.map((config) => {
      const { network, rpcUrl, cosmosPayerSeed } = config
      return {
        network,
        rpcUrl: rpcUrl ? rpcUrl : network === CheqdNetwork.Mainnet ? DefaultRPCUrl.Mainnet : DefaultRPCUrl.Testnet,
        cosmosPayerWallet: getCosmosPayerWallet(cosmosPayerSeed),
      }
    })
  }

  public async connect() {
    for (const network of this.networks) {
      if (!network.sdk) {
        await this.initializeSdkForNetwork(network)
      } else {
        this.logger.debug(`Not connecting to network ${network} as SDK already initialized`)
      }
    }
  }

  public async disconnect() {
    for (const network of this.networks) {
      if (!network.sdk) continue

      // Release the slot immediately so a subsequent connect()/getSdk() call creates a fresh
      // setup rather than reusing a client we are about to tear down.
      const sdkPromise = network.sdk
      network.sdk = undefined

      let sdk: CheqdSDK | undefined
      try {
        sdk = await sdkPromise
      } catch {
        // Setup for this network had already failed; nothing to tear down.
        continue
      }
      if (!sdk) continue

      try {
        sdk.signer.disconnect()
      } catch (error) {
        this.logger.debug(`Error disconnecting cheqd signer for network ${network.network}`, { error })
      }

      // CheqdSDK does not expose a public way to close the querier's own RPC connection, so
      // release it defensively if the runtime object happens to expose one.
      const querier = sdk.querier as unknown as { cometClient?: { disconnect?: () => void } }
      try {
        querier?.cometClient?.disconnect?.()
      } catch (error) {
        this.logger.debug(`Error disconnecting cheqd querier for network ${network.network}`, { error })
      }
    }
  }

  private async getSdk(did: string) {
    const parsedDid = parseCheqdDid(did)
    if (!parsedDid) {
      throw new Error('Invalid DID')
    }
    if (this.networks.length === 0) {
      throw new Error('No cheqd networks configured')
    }

    const network = this.networks.find((network) => network.network === parsedDid.network)
    if (!network) {
      throw new Error(`Network ${network} not found in cheqd networks configuration`)
    }

    if (!network.sdk) {
      const sdk = await this.initializeSdkForNetwork(network)
      if (!sdk) throw new Error(`Cheqd SDK not initialized for network ${parsedDid.network}`)
      return sdk
    }

    try {
      const sdk = await network.sdk
      return sdk
    } catch (error) {
      throw new Error(`Error initializing cheqd sdk for network ${parsedDid.network}: ${error.message}`)
    }
  }

  private async initializeSdkForNetwork(network: ICheqdLedgerConfig) {
    // Build the setup as its own promise and assign it to `network.sdk` synchronously, before
    // awaiting anything below. This closes the race where concurrent first calls for the same
    // network would each see `network.sdk` as unset (since it was previously only assigned
    // *after* awaiting the wallet) and each go on to create their own SDK/RPC client. With the
    // assignment happening synchronously here, only the first caller starts a setup; every
    // other concurrent caller observes `network.sdk` already set and shares this same promise.
    const sdkPromise = (async () => {
      const wallet = await network.cosmosPayerWallet.catch((error) => {
        throw new CredoError(`Error initializing cosmos payer wallet: ${error.message}`, { cause: error })
      })

      return createCheqdSDK({
        modules: [DIDModule as unknown as AbstractCheqdSDKModule, ResourceModule as unknown as AbstractCheqdSDKModule],
        rpcUrl: network.rpcUrl,
        wallet,
      })
    })()
    network.sdk = sdkPromise

    try {
      return await sdkPromise
    } catch (error) {
      this.logger.error(
        `Skipping connection for network ${network.network} in cheqd sdk due to error in initialization: ${error.message}`
      )
      // Only clear the slot if it still holds *this* failed attempt. A concurrent call may have
      // already replaced it with a different (possibly successful) setup, and we must not wipe
      // that out.
      if (network.sdk === sdkPromise) {
        network.sdk = undefined
      }
      return undefined
    }
  }

  public async create(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee,
    feeOptions?: DidFeeOptions
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.createDidDocTx(
      signInputs,
      didPayload,
      '',
      fee,
      undefined,
      versionId,
      feeOptions || { slippageBps: 1000 }
    )
  }

  public async update(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee,
    feeOptions?: DidFeeOptions
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.updateDidDocTx(
      signInputs,
      didPayload,
      '',
      fee,
      undefined,
      versionId,
      feeOptions || { slippageBps: 1000 }
    )
  }

  public async deactivate(
    didPayload: DIDDocument,
    signInputs: SignInfo[],
    versionId?: string | undefined,
    fee?: DidStdFee,
    feeOptions?: DidFeeOptions
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getSdk(didPayload.id)
    return sdk.deactivateDidDocTx(
      signInputs,
      didPayload,
      '',
      fee,
      undefined,
      versionId,
      feeOptions || { slippageBps: 1000 }
    )
  }

  /** Retries idempotent chain reads on transient transport errors only. Never use for transactions. */
  private retryRead<T>(operation: () => Promise<T>): Promise<T> {
    return retryOnTransientError(operation, {
      onRetry: (error, attempt, delayMs) =>
        this.logger.debug(`Retrying cheqd read after transient error (attempt ${attempt}, in ${delayMs}ms)`, { error }),
    })
  }

  public async resolve(did: string, version?: string) {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => (version ? sdk.queryDidDocVersion(did, version) : sdk.queryDidDoc(did)))
  }

  public async resolveMetadata(did: string): Promise<{
    didDocumentVersionsMetadata: DidDocumentMetadata[]
    pagination: QueryAllDidDocVersionsMetadataResponse['pagination']
  }> {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => sdk.queryAllDidDocVersionsMetadata(did))
  }

  public async createResource(
    did: string,
    resourcePayload: Partial<MsgCreateResourcePayload>,
    signInputs: SignInfo[],
    fee?: DidStdFee,
    feeOptions?: DidFeeOptions
  ): Promise<DeliverTxResponse> {
    const sdk = await this.getSdk(did)
    return sdk.createLinkedResourceTx(
      signInputs,
      resourcePayload,
      '',
      fee,
      undefined,
      feeOptions || { slippageBps: 1000 }
    )
  }

  public async resolveResource(did: string, collectionId: string, resourceId: string): Promise<ResourceWithMetadata> {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => sdk.queryLinkedResource(collectionId, resourceId))
  }

  /** The latest version of a resource, in one request, however many resources the collection holds */
  public async resolveLatestResource(
    did: string,
    collectionId: string,
    name: string,
    type: string
  ): Promise<ResourceWithMetadata> {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => sdk.queryLatestLinkedResourceVersion(collectionId, name, type))
  }

  public async resolveCollectionResources(
    did: string,
    collectionId: string
  ): Promise<QueryCollectionResourcesResponse> {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => sdk.queryLinkedResources(collectionId))
  }

  public async resolveResourceMetadata(did: string, collectionId: string, resourceId: string): Promise<Metadata> {
    const sdk = await this.getSdk(did)
    return this.retryRead(() => sdk.queryLinkedResourceMetadata(collectionId, resourceId))
  }
}
