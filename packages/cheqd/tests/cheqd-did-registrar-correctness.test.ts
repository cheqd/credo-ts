import type { DidFeeOptions, DidStdFee } from '@cheqd/sdk'
import {
  DidDocumentBuilder,
  DidDocumentRole,
  DidRecord,
  DidRepository,
  getJsonWebKey2020,
  Kms,
} from '@credo-ts/core'
import type { DidDocumentKey } from '@credo-ts/core'

import { getAgentContext } from '../../core/tests/helpers'
import { CheqdDidRegistrar } from '../src'
import { CheqdLedgerService } from '../src/ledger'

const did = 'did:cheqd:testnet:fee-and-signing-test'

/**
 * Builds a did document with two verification methods:
 * - `#key-1`, which is the only key listed under `authentication`, and whose private key
 *   is created in (and therefore held by) this agent's KMS.
 * - `#key-2`, which is only used for `assertionMethod` (a purpose other than authentication,
 *   e.g. added by a different controller) and whose private key is NOT held by this agent.
 */
async function buildDidDocumentWithNonAuthenticationKey(agentContext: ReturnType<typeof getAgentContext>) {
  const kms = agentContext.dependencyManager.resolve(Kms.KeyManagementApi)

  const authKey = await kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })
  const authPublicJwk = Kms.PublicJwk.fromPublicJwk(authKey.publicJwk)

  // A key this agent does not hold: a valid public key, but never created/imported into the KMS.
  const foreignPublicJwk = Kms.PublicJwk.fromPublicKey({
    kty: 'OKP',
    crv: 'Ed25519',
    publicKey: new Uint8Array(32).fill(7),
  })

  const didDocument = new DidDocumentBuilder(did)
    .addVerificationMethod(getJsonWebKey2020({ did, publicJwk: authPublicJwk, verificationMethodId: `${did}#key-1` }))
    .addVerificationMethod(
      getJsonWebKey2020({ did, publicJwk: foreignPublicJwk, verificationMethodId: `${did}#key-2` })
    )
    .addAuthentication(`${did}#key-1`)
    .addAssertionMethod(`${did}#key-2`)
    .build()

  const keys: DidDocumentKey[] = [{ kmsKeyId: authKey.keyId, didDocumentRelativeKeyId: '#key-1' }]

  return { didDocument, keys }
}

describe('CheqdDidRegistrar correctness fixes', () => {
  describe('createResource only signs with authentication-capable verification methods', () => {
    it('succeeds when a non-authentication verification method key is not held by this agent', async () => {
      const agentContext = getAgentContext()
      const { didDocument, keys } = await buildDidDocumentWithNonAuthenticationKey(agentContext)

      const didRepository = {
        findCreatedDid: vi.fn().mockResolvedValue(new DidRecord({ did, role: DidDocumentRole.Created, keys })),
      }
      const cheqdLedgerService = {
        resolve: vi.fn().mockResolvedValue({ didDocument: didDocument.toJSON(), didDocumentMetadata: {} }),
        createResource: vi.fn().mockResolvedValue({ code: 0 }),
      }

      agentContext.dependencyManager.registerInstance(DidRepository, didRepository as unknown as DidRepository)
      agentContext.dependencyManager.registerInstance(
        CheqdLedgerService,
        cheqdLedgerService as unknown as CheqdLedgerService
      )

      const registrar = new CheqdDidRegistrar()
      const result = await registrar.createResource(agentContext, did, {
        id: 'resource-1',
        name: 'test-resource',
        resourceType: 'TestType',
        data: { hello: 'world' },
      })

      expect(result.resourceState.state).toBe('finished')

      // Only the authentication-capable verification method (#key-1) should have been signed with,
      // never the assertionMethod-only key (#key-2) that this agent does not hold.
      expect(cheqdLedgerService.createResource).toHaveBeenCalledTimes(1)
      const signInputs = cheqdLedgerService.createResource.mock.calls[0][2]
      expect(signInputs).toHaveLength(1)
      expect(signInputs[0].verificationMethodId).toBe(`${did}#key-1`)
    })
  })

  describe('fee options are forwarded to the ledger', () => {
    const fee: DidStdFee = { amount: [{ denom: 'ncheq', amount: '123' }], gas: '456' }
    const feeOptions: DidFeeOptions = { slippageBps: 2500 }

    it('forwards fee and feeOptions on create', async () => {
      const agentContext = getAgentContext()
      const kms = agentContext.dependencyManager.resolve(Kms.KeyManagementApi)
      const createKeyResult = await kms.createKey({ type: { kty: 'OKP', crv: 'Ed25519' } })

      const didRepository = { save: vi.fn().mockResolvedValue(undefined) }
      const cheqdLedgerService = { create: vi.fn().mockResolvedValue({ code: 0 }) }

      agentContext.dependencyManager.registerInstance(DidRepository, didRepository as unknown as DidRepository)
      agentContext.dependencyManager.registerInstance(
        CheqdLedgerService,
        cheqdLedgerService as unknown as CheqdLedgerService
      )

      const registrar = new CheqdDidRegistrar()
      const result = await registrar.create(agentContext, {
        method: 'cheqd',
        options: {
          keyId: createKeyResult.keyId,
          network: 'testnet',
          methodSpecificIdAlgo: 'base58btc',
          fee,
          feeOptions,
        },
      } as unknown as Parameters<typeof registrar.create>[1])

      expect(result.didState.state).toBe('finished')
      expect(cheqdLedgerService.create).toHaveBeenCalledTimes(1)
      const call = cheqdLedgerService.create.mock.calls[0]
      expect(call[3]).toEqual(fee)
      expect(call[4]).toEqual(feeOptions)
    })

    it('forwards fee and feeOptions on update', async () => {
      const agentContext = getAgentContext()
      const { didDocument, keys } = await buildDidDocumentWithNonAuthenticationKey(agentContext)
      // Only keep the authentication key so the existing/removed-authentication diff logic is trivial
      didDocument.assertionMethod = undefined
      didDocument.verificationMethod = didDocument.verificationMethod?.filter((vm) => vm.id === `${did}#key-1`)

      const didRecord = new DidRecord({ did, role: DidDocumentRole.Created, keys })
      const didRepository = {
        findCreatedDid: vi.fn().mockResolvedValue(didRecord),
        update: vi.fn().mockResolvedValue(undefined),
      }
      const cheqdLedgerService = {
        resolve: vi.fn().mockResolvedValue({ didDocument: didDocument.toJSON(), didDocumentMetadata: {} }),
        update: vi.fn().mockResolvedValue({ code: 0 }),
      }

      agentContext.dependencyManager.registerInstance(DidRepository, didRepository as unknown as DidRepository)
      agentContext.dependencyManager.registerInstance(
        CheqdLedgerService,
        cheqdLedgerService as unknown as CheqdLedgerService
      )

      const registrar = new CheqdDidRegistrar()
      const result = await registrar.update(agentContext, {
        did,
        didDocument,
        options: { fee, feeOptions },
      } as unknown as Parameters<typeof registrar.update>[1])

      expect(result.didState.state).toBe('finished')
      expect(cheqdLedgerService.update).toHaveBeenCalledTimes(1)
      const call = cheqdLedgerService.update.mock.calls[0]
      expect(call[3]).toEqual(fee)
      expect(call[4]).toEqual(feeOptions)
    })

    it('forwards fee and feeOptions on deactivate', async () => {
      const agentContext = getAgentContext()
      const { didDocument, keys } = await buildDidDocumentWithNonAuthenticationKey(agentContext)
      didDocument.assertionMethod = undefined
      didDocument.verificationMethod = didDocument.verificationMethod?.filter((vm) => vm.id === `${did}#key-1`)

      const didRecord = new DidRecord({ did, role: DidDocumentRole.Created, didDocument, keys })
      const didRepository = {
        findCreatedDid: vi.fn().mockResolvedValue(didRecord),
        update: vi.fn().mockResolvedValue(undefined),
      }
      const cheqdLedgerService = {
        resolve: vi.fn().mockResolvedValue({ didDocument: didDocument.toJSON(), didDocumentMetadata: {} }),
        deactivate: vi.fn().mockResolvedValue({ code: 0 }),
      }

      agentContext.dependencyManager.registerInstance(DidRepository, didRepository as unknown as DidRepository)
      agentContext.dependencyManager.registerInstance(
        CheqdLedgerService,
        cheqdLedgerService as unknown as CheqdLedgerService
      )

      const registrar = new CheqdDidRegistrar()
      const result = await registrar.deactivate(agentContext, {
        method: 'cheqd',
        did,
        options: { fee, feeOptions },
      })

      expect(result.didState.state).toBe('finished')
      expect(cheqdLedgerService.deactivate).toHaveBeenCalledTimes(1)
      const call = cheqdLedgerService.deactivate.mock.calls[0]
      expect(call[3]).toEqual(fee)
      expect(call[4]).toEqual(feeOptions)
    })
  })
})
