import type { DIDDocument } from '@cheqd/sdk'

import { DirectSecp256k1Wallet } from '@cosmjs/proto-signing'
import { DidDocument, TypedArrayEncoder } from '@credo-ts/core'

import {
  createMsgCreateDidDocPayloadToSign,
  createMsgDeactivateDidDocPayloadToSign,
  getCosmosPayerWallet,
  validateSpecCompliantPayload,
} from '../src/dids/didCheqdUtil'

import { validDid, validDidDoc } from './testUtils'

describe('Test Cheqd Did Utils', () => {
  it('should validate did spec compliant payload', () => {
    const didDoc = validDidDoc()
    const result = validateSpecCompliantPayload(didDoc)
    expect(result.valid).toBe(true)
    expect(result.error).toBeUndefined()
  })

  it('should detect invalid verification method', () => {
    const result = validateSpecCompliantPayload(
      new DidDocument({
        id: validDid,
        verificationMethod: [
          {
            id: `${validDid}#key-1`,
            publicKeyBase58: 'asca12e3as',
            type: 'JsonWebKey2020',
            controller: validDid,
          },
        ],
      })
    )
    expect(result.valid).toBe(false)
    expect(result.error).toBeDefined()
  })

  it('should create MsgCreateDidDocPayloadToSign', async () => {
    const result = await createMsgCreateDidDocPayloadToSign(validDidDoc().toJSON() as DIDDocument, '1.0')
    expect(result).toBeDefined()
  })

  it('should create MsgDeactivateDidDocPayloadToSign', async () => {
    const result = createMsgDeactivateDidDocPayloadToSign({ id: validDid }, '2.0')
    expect(result).toBeDefined()
  })

  it('should reject a did document whose id is not a did:cheqd did (e.g. did:key)', () => {
    const result = validateSpecCompliantPayload(
      new DidDocument({
        id: 'did:key:z6MkkBaWtQKyx7Mr54XaXyMAEpNKqphK4x7ztuBpSfR6Wqwr',
        verificationMethod: [
          {
            id: 'did:key:z6MkkBaWtQKyx7Mr54XaXyMAEpNKqphK4x7ztuBpSfR6Wqwr#key-1',
            publicKeyMultibase: 'z6MkkBaWtQKyx7Mr54XaXyMAEpNKqphK4x7ztuBpSfR6Wqwr',
            type: 'Ed25519VerificationKey2020',
            controller: 'did:key:z6MkkBaWtQKyx7Mr54XaXyMAEpNKqphK4x7ztuBpSfR6Wqwr',
          },
        ],
      })
    )
    expect(result.valid).toBe(false)
    expect(result.error).toBe('id is required')
  })

  it('should reject a did document with a missing id without throwing', () => {
    // Deliberately malformed: id is undefined, as if parsed from untrusted/external input.
    const malformedDidDocument = { id: undefined, verificationMethod: [] } as unknown as DidDocument
    expect(() => validateSpecCompliantPayload(malformedDidDocument)).not.toThrow()
    const result = validateSpecCompliantPayload(malformedDidDocument)
    expect(result.valid).toBe(false)
    expect(result.error).toBe('id is required')
  })
})

describe('getCosmosPayerWallet', () => {
  it('decodes a hex payer seed as hex bytes, not as utf-8 text', async () => {
    const privateKeyBytes = TypedArrayEncoder.fromHex('11'.repeat(32))
    const hexSeed = TypedArrayEncoder.toHex(privateKeyBytes)

    const expectedWallet = await DirectSecp256k1Wallet.fromKey(privateKeyBytes, 'cheqd')
    const [expectedAccount] = await expectedWallet.getAccounts()

    const wallet = await getCosmosPayerWallet(hexSeed)
    const [account] = await wallet.getAccounts()

    expect(account.address).toBe(expectedAccount.address)
  })

  it('also decodes a 0x-prefixed hex payer seed correctly', async () => {
    const privateKeyBytes = TypedArrayEncoder.fromHex('22'.repeat(32))
    const hexSeed = `0x${TypedArrayEncoder.toHex(privateKeyBytes)}`

    const expectedWallet = await DirectSecp256k1Wallet.fromKey(privateKeyBytes, 'cheqd')
    const [expectedAccount] = await expectedWallet.getAccounts()

    const wallet = await getCosmosPayerWallet(hexSeed)
    const [account] = await wallet.getAccounts()

    expect(account.address).toBe(expectedAccount.address)
  })
})
