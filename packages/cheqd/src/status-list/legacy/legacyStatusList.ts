import type { AgentContext } from '@credo-ts/core'
import {
  CredoError,
  DidRepository,
  getKmsKeyIdForVerifiacationMethod,
  getPublicJwkFromVerificationMethod,
  JwsService,
  TypedArrayEncoder,
  utils,
} from '@credo-ts/core'

import { parseCheqdDid } from '../../anoncreds/utils/identifiers'
import { CheqdDidRegistrar, CheqdDidResolver } from '../../dids'
import { createBitstring, decodeBitstring, encodeBitstring, getBitstringStatus, setBitstringStatus } from './bitstring'

/**
 * The status list formats cheqd Studio wrote with Veramo and the `@cheqd/did-provider-cheqd` plugin, as linked
 * resources of the issuer's DID. The stored forms are read from lists already on testnet, so lists written by that
 * software can be checked and updated here, and lists written here can be read by it.
 *
 * Not covered: encrypted lists, and a list that holds several indices per entry.
 */
export const legacyStatusListResourceTypes = {
  statusList2021: { revocation: 'StatusList2021Revocation', suspension: 'StatusList2021Suspension' },
  bitstring: 'BitstringStatusListCredential',
} as const

export const defaultLegacyStatusListResolverUrl = 'https://resolver.cheqd.net/1.0/identifiers/'

export type LegacyStatusListFormat = 'StatusList2021' | 'BitstringStatusList'
export type LegacyStatusPurpose = 'revocation' | 'suspension' | 'message'

export interface LegacyStatusMessage {
  /** Hexadecimal value, for example `0x1` */
  status: string
  message: string
}

/** The messages Studio writes for a 2 bit Bitstring status list */
export const defaultBitstringStatusMessages: LegacyStatusMessage[] = [
  { status: '0x0', message: 'valid' },
  { status: '0x1', message: 'revoked' },
  { status: '0x2', message: 'suspended' },
  { status: '0x3', message: 'unknown' },
]
export const defaultBitstringStatusSize = 2
/** 16 KB of entries, the minimum of the specification */
export const defaultBitstringLength = 16 * 1024 * 8
export const defaultStatusList2021Length = 140_000

export interface LegacyStatusListUriOptions {
  did: string
  name: string
  resourceType: string
  /** Base url of a cheqd resolver, ending in `/identifiers/`. Defaults to the public resolver. */
  resolverUrl?: string
}

/** The `statusListCredential` of an entry: resolves to the latest version of the list, so it does not change on update */
export function getLegacyStatusListUri({
  did,
  name,
  resourceType,
  resolverUrl = defaultLegacyStatusListResolverUrl,
}: LegacyStatusListUriOptions) {
  if (!parseCheqdDid(did)) throw new CredoError(`'${did}' is not a valid did:cheqd did`)
  const base = resolverUrl.endsWith('/') ? resolverUrl : `${resolverUrl}/`
  return `${base}${did}?resourceName=${encodeURIComponent(name)}&resourceType=${resourceType}`
}

export type ParsedLegacyStatusListUri =
  | { did: string; resourceId: string }
  | { did: string; name: string; resourceType: string }

/**
 * Reads a `statusListCredential` of a did:cheqd list: the https url of a cheqd resolver or the did url itself, naming
 * the list by name and type, or by resource id. Returns `null` for anything else.
 */
export function parseLegacyStatusListUri(uri: string): ParsedLegacyStatusListUri | null {
  const withoutFragment = uri.split('#')[0]
  const didUrl = withoutFragment.startsWith('did:cheqd:')
    ? withoutFragment
    : withoutFragment.match(/^https?:\/\/[^?#]+\/1\.0\/identifiers\/(did:cheqd:.+)$/)?.[1]
  if (!didUrl) return null

  const byId = didUrl.match(/^(did:cheqd:[^/?#]+)\/resources\/([^/?#]+)$/)
  if (byId) return parseCheqdDid(byId[1]) ? { did: byId[1], resourceId: byId[2] } : null

  const [did, query] = didUrl.split('?')
  if (!query || !parseCheqdDid(did)) return null
  const params: Record<string, string> = {}
  for (const pair of query.split('&')) {
    const index = pair.indexOf('=')
    if (index === -1) return null
    try {
      params[decodeURIComponent(pair.slice(0, index))] = decodeURIComponent(pair.slice(index + 1))
    } catch {
      return null
    }
  }
  if (!params.resourceName || !params.resourceType) return null
  return { did, name: params.resourceName, resourceType: params.resourceType }
}

/** What `credentialStatus` of a credential holds for these lists */
export interface LegacyStatusEntry {
  id?: string
  type: 'StatusList2021Entry' | 'BitstringStatusListEntry'
  statusPurpose: LegacyStatusPurpose
  statusListIndex: string | number
  statusListCredential: string
  /** Bitstring only, bits per entry. Defaults to the size the list declares. */
  statusSize?: number
  statusMessage?: LegacyStatusMessage[]
}

export interface LegacyStatusList {
  format: LegacyStatusListFormat
  did: string
  resourceId?: string
  version?: string
  purposes: string[]
  bits: Uint8Array
  statusSize: number
  statusMessages?: LegacyStatusMessage[]
}

function asArray<T>(value: T | T[] | undefined): T[] {
  return value === undefined ? [] : Array.isArray(value) ? value : [value]
}

/** Reads the stored data of a status list resource of either format */
export function parseLegacyStatusListData(data: unknown): Omit<LegacyStatusList, 'did' | 'resourceId' | 'version'> {
  const record = (data ?? {}) as Record<string, unknown>
  const metadata = (record.metadata ?? {}) as { statusSize?: number; statusMessages?: LegacyStatusMessage[] }

  if (record.encrypted === true || (record.metadata as { encrypted?: boolean } | undefined)?.encrypted === true) {
    throw new CredoError('Encrypted status lists are not supported')
  }

  if (record.StatusList2021) {
    const list = record.StatusList2021 as { statusPurpose?: string; encodedList?: string }
    if (!list.encodedList) throw new CredoError('The status list has no encodedList')
    return {
      format: 'StatusList2021',
      purposes: asArray(list.statusPurpose),
      bits: decodeBitstring(list.encodedList),
      statusSize: 1,
    }
  }

  if (record.bitstringStatusListCredential) {
    const credential = record.bitstringStatusListCredential as {
      credentialSubject?: { statusPurpose?: string | string[]; encodedList?: string }
    }
    const subject = credential.credentialSubject
    if (!subject?.encodedList) throw new CredoError('The status list has no encodedList')
    return {
      format: 'BitstringStatusList',
      purposes: asArray(subject.statusPurpose),
      bits: decodeBitstring(subject.encodedList),
      statusSize: metadata.statusSize ?? defaultBitstringStatusSize,
      statusMessages: metadata.statusMessages,
    }
  }

  throw new CredoError('The resource is not a StatusList2021 or Bitstring status list')
}

/**
 * Reads a status list from the network. Only did:cheqd lists are fetched: the uri comes from a credential someone else
 * issued, and fetching arbitrary urls on behalf of a verifier would let that issuer make requests from your server.
 */
export async function fetchLegacyStatusList(agentContext: AgentContext, uri: string): Promise<LegacyStatusList> {
  const parsed = parseLegacyStatusListUri(uri)
  if (!parsed) throw new CredoError(`'${uri}' is not the uri of a did:cheqd status list`)

  const didUrl =
    'resourceId' in parsed
      ? `${parsed.did}/resources/${parsed.resourceId}`
      : `${parsed.did}?resourceName=${encodeURIComponent(parsed.name)}&resourceType=${encodeURIComponent(parsed.resourceType)}`

  const result = await agentContext.dependencyManager.resolve(CheqdDidResolver).resolveResource(agentContext, didUrl)
  if (result.error || result.resource === undefined) {
    throw new CredoError(`Unable to read the status list ${uri}: ${result.message ?? result.error}`)
  }

  return {
    ...parseLegacyStatusListData(result.resource),
    did: parsed.did,
    resourceId: result.resourceMetadata?.id ?? ('resourceId' in parsed ? parsed.resourceId : undefined),
    version: result.resourceMetadata?.version,
  }
}

export interface LegacyStatusResult {
  type: LegacyStatusEntry['type']
  statusPurpose: LegacyStatusPurpose
  statusListIndex: number
  /** The raw value of the entry: 0 is valid */
  status: number
  valid: boolean
  /** The entry is set on a revocation list, or its message says revoked */
  revoked: boolean
  /** The entry is set on a suspension list, or its message says suspended */
  suspended: boolean
  /** The message the list gives for the value, if it has messages */
  message?: string
  statusListCredential: string
  /** The version of the list that was read */
  resourceId?: string
}

function didOfIssuer(issuer: string | { id: string }) {
  return typeof issuer === 'string' ? issuer : issuer.id
}

/**
 * Checks the `credentialStatus` of a credential issued with a StatusList2021 or Bitstring status list.
 *
 * The list must be a resource of the DID that issued the credential: only its controller can write there, which is
 * what makes the list trustworthy. A list under another DID is refused. The proof inside a Bitstring list does not
 * cover its `encodedList`, so it is not what the result rests on.
 *
 * Verifying the credential itself is separate: this only reads the status.
 */
export async function checkLegacyCredentialStatus(
  agentContext: AgentContext,
  credential: { issuer: string | { id: string }; credentialStatus?: LegacyStatusEntry | LegacyStatusEntry[] },
  options: { requireIssuerMatch?: boolean } = {}
): Promise<LegacyStatusResult[]> {
  const issuer = didOfIssuer(credential.issuer)
  const results: LegacyStatusResult[] = []

  for (const entry of asArray(credential.credentialStatus)) {
    if (entry.type !== 'StatusList2021Entry' && entry.type !== 'BitstringStatusListEntry') {
      throw new CredoError(`Unsupported credential status type '${entry.type}'`)
    }

    const list = await fetchLegacyStatusList(agentContext, entry.statusListCredential)
    if ((options.requireIssuerMatch ?? true) && list.did !== issuer) {
      throw new CredoError(`The status list is a resource of ${list.did}, not of the issuer ${issuer}`)
    }

    const wantsBitstring = entry.type === 'BitstringStatusListEntry'
    if (wantsBitstring !== (list.format === 'BitstringStatusList')) {
      throw new CredoError(`The status list is not a ${wantsBitstring ? 'Bitstring' : 'StatusList2021'} list`)
    }
    if (!list.purposes.includes(entry.statusPurpose)) {
      throw new CredoError(`The status list does not have the purpose '${entry.statusPurpose}'`)
    }

    const statusSize = entry.statusSize ?? list.statusSize
    const index = Number.parseInt(String(entry.statusListIndex), 10)
    const status = getBitstringStatus(list.bits, index, statusSize)
    const message = (list.statusMessages ?? entry.statusMessage)?.find(
      (candidate) => candidate.status === `0x${status.toString(16)}`
    )?.message

    results.push({
      type: entry.type,
      statusPurpose: entry.statusPurpose,
      statusListIndex: index,
      status,
      valid: status === 0,
      revoked: (entry.statusPurpose === 'revocation' && status !== 0) || message === 'revoked',
      suspended: (entry.statusPurpose === 'suspension' && status !== 0) || message === 'suspended',
      message,
      statusListCredential: entry.statusListCredential,
      resourceId: list.resourceId,
    })
  }

  return results
}

/** Picks a random entry that is unset and not in `taken`, so credentials cannot be correlated by their index */
export function allocateStatusListIndex(
  list: Pick<LegacyStatusList, 'bits' | 'statusSize'>,
  taken: Iterable<number> = []
) {
  const entries = Math.floor((list.bits.length * 8) / list.statusSize)
  const used = new Set(taken)
  for (let attempt = 0; attempt < 1000; attempt++) {
    const random = new Uint32Array(1)
    globalThis.crypto.getRandomValues(random)
    const index = random[0] % entries
    if (!used.has(index) && getBitstringStatus(list.bits, index, list.statusSize) === 0) return index
  }
  throw new CredoError('Unable to find an unused entry in the status list')
}

/** The `credentialStatus` to put in a credential for the entry at `index` of a list */
export function createLegacyStatusEntry(options: {
  format: LegacyStatusListFormat
  /** See {@link getLegacyStatusListUri} */
  statusListCredential: string
  statusPurpose: LegacyStatusPurpose
  index: number
  statusSize?: number
  statusMessage?: LegacyStatusMessage[]
}): LegacyStatusEntry {
  const base = {
    id: `${options.statusListCredential}#${options.index}`,
    statusPurpose: options.statusPurpose,
    statusListIndex: String(options.index),
    statusListCredential: options.statusListCredential,
  }
  return options.format === 'StatusList2021'
    ? { ...base, type: 'StatusList2021Entry' }
    : {
        ...base,
        type: 'BitstringStatusListEntry',
        statusSize: options.statusSize ?? defaultBitstringStatusSize,
        statusMessage: options.statusMessage ?? defaultBitstringStatusMessages,
      }
}

async function publish(
  agentContext: AgentContext,
  did: string,
  options: { name: string; resourceType: string; data: unknown }
) {
  const resourceId = utils.uuid()
  const result = await agentContext.dependencyManager.resolve(CheqdDidRegistrar).createResource(agentContext, did, {
    id: resourceId,
    name: options.name,
    resourceType: options.resourceType,
    version: new Date().toISOString(),
    // As bytes: a string would be decoded as base64
    data: TypedArrayEncoder.fromUtf8String(JSON.stringify(options.data)),
  })
  if (result.resourceState.state !== 'finished') {
    throw new CredoError(`Unable to publish the status list: ${result.resourceState.reason}`)
  }
  return { resourceId }
}

/** The JWT the plugin stores as the proof of a Bitstring list. Like the plugin's, it does not cover `encodedList`. */
async function signBitstringProof(agentContext: AgentContext, did: string, signerDidUrl: string, purposes: string[]) {
  const record = await agentContext.dependencyManager.resolve(DidRepository).findCreatedDid(agentContext, did)
  if (!record?.didDocument) throw new CredoError(`${did} is not a DID created or imported by this agent`)
  const verificationMethod = record.didDocument.dereferenceKey(signerDidUrl, ['assertionMethod', 'authentication'])
  const publicJwk = getPublicJwkFromVerificationMethod(verificationMethod)
  const keyId = getKmsKeyIdForVerifiacationMethod(verificationMethod, record.keys) ?? publicJwk.legacyKeyId

  return await agentContext.dependencyManager.resolve(JwsService).createJwsCompact(agentContext, {
    keyId,
    payload: TypedArrayEncoder.fromUtf8String(
      JSON.stringify({
        vc: {
          '@context': ['https://www.w3.org/2018/credentials/v1'],
          type: ['VerifiableCredential', 'BitstringStatusListCredential'],
          credentialSubject: { type: 'BitstringStatusList', statusPurpose: purposes },
        },
        nbf: Math.floor(Date.now() / 1000),
        iss: did,
      })
    ),
    protectedHeaderOptions: { alg: publicJwk.signatureAlgorithm, typ: 'JWT', kid: signerDidUrl },
  })
}

export interface CreateLegacyStatusListOptions {
  format: LegacyStatusListFormat
  /** Name of the linked resource. Every update of the list is a new version under the same name. */
  name: string
  /** StatusList2021: `revocation` or `suspension`, one list each. Not used for Bitstring. */
  statusPurpose?: 'revocation' | 'suspension'
  /** Number of entries. Defaults to 140,000 (StatusList2021) or 131,072 (Bitstring). */
  length?: number
  /** Bitstring only, bits per entry. Defaults to 2. */
  statusSize?: number
  /** Bitstring only. Defaults to valid, revoked, suspended, unknown. */
  statusMessages?: LegacyStatusMessage[]
  /** Bitstring only: the key of the DID (a DID URL) that signs the list. */
  signerDidUrl?: string
}

/** Publishes an empty status list as a linked resource of a DID this agent controls */
export async function createLegacyStatusList(
  agentContext: AgentContext,
  did: string,
  options: CreateLegacyStatusListOptions
) {
  if (options.format === 'StatusList2021') {
    if (!options.statusPurpose) throw new CredoError('A StatusList2021 list needs a statusPurpose')
    const resourceType = legacyStatusListResourceTypes.statusList2021[options.statusPurpose]
    const length = options.length ?? defaultStatusList2021Length
    const { resourceId } = await publish(agentContext, did, {
      name: options.name,
      resourceType,
      data: {
        StatusList2021: {
          statusPurpose: options.statusPurpose,
          encodedList: encodeBitstring(createBitstring(length, 1)),
          validFrom: new Date().toISOString(),
        },
        metadata: { type: resourceType, encoding: 'base64url', encrypted: false },
      },
    })
    return { resourceId, resourceType, uri: getLegacyStatusListUri({ did, name: options.name, resourceType }) }
  }

  if (!options.signerDidUrl) throw new CredoError('A Bitstring list needs a signerDidUrl')
  const statusSize = options.statusSize ?? defaultBitstringStatusSize
  const length = options.length ?? defaultBitstringLength
  if (length < defaultBitstringLength) {
    throw new CredoError(`A Bitstring list needs at least ${defaultBitstringLength} entries`)
  }
  const purposes: LegacyStatusPurpose[] = ['revocation', 'suspension', 'message']
  const resourceType = legacyStatusListResourceTypes.bitstring
  const jwt = await signBitstringProof(agentContext, did, options.signerDidUrl, purposes)

  const { resourceId } = await publish(agentContext, did, {
    name: options.name,
    resourceType,
    data: {
      bitstringStatusListCredential: {
        '@context': ['https://www.w3.org/2018/credentials/v1'],
        type: ['VerifiableCredential', 'BitstringStatusListCredential'],
        issuer: { id: did },
        issuanceDate: new Date().toISOString(),
        credentialSubject: {
          type: 'BitstringStatusList',
          statusPurpose: purposes,
          encodedList: encodeBitstring(createBitstring(length, statusSize)),
        },
        proof: { type: 'JwtProof2020', jwt },
      },
      metadata: {
        encrypted: false,
        encoding: 'base64url',
        length,
        statusSize,
        statusMessages: options.statusMessages ?? defaultBitstringStatusMessages,
      },
    },
  })
  return { resourceId, resourceType, uri: getLegacyStatusListUri({ did, name: options.name, resourceType }) }
}

/**
 * Sets entries of the latest version of a list and publishes the result as a new version under the same name. Use value
 * 1 to revoke (or suspend) and 0 to reinstate on a StatusList2021 list, and the message values of the list on a Bitstring
 * list (by default 1 revoked, 2 suspended).
 */
export async function updateLegacyStatusList(
  agentContext: AgentContext,
  did: string,
  options: { name: string; resourceType: string; updates: { index: number; value: number }[] }
) {
  const uri = getLegacyStatusListUri({ did, name: options.name, resourceType: options.resourceType })
  const resolver = agentContext.dependencyManager.resolve(CheqdDidResolver)
  const result = await resolver.resolveResource(
    agentContext,
    `${did}?resourceName=${encodeURIComponent(options.name)}&resourceType=${encodeURIComponent(options.resourceType)}`
  )
  if (result.error || result.resource === undefined) {
    throw new CredoError(`Unable to read the status list ${uri}: ${result.message ?? result.error}`)
  }

  // Keep everything else in the stored data as it is, and only replace the list
  const data = JSON.parse(JSON.stringify(result.resource)) as Record<string, Record<string, unknown>>
  const list = parseLegacyStatusListData(data)
  for (const { index, value } of options.updates) setBitstringStatus(list.bits, index, list.statusSize, value)
  const encodedList = encodeBitstring(list.bits)

  if (data.StatusList2021) data.StatusList2021.encodedList = encodedList
  else (data.bitstringStatusListCredential.credentialSubject as { encodedList: string }).encodedList = encodedList

  return await publish(agentContext, did, { name: options.name, resourceType: options.resourceType, data })
}
