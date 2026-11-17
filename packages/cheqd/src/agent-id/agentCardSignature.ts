import type { AgentContext } from '@credo-ts/core'
import {
  CredoError,
  DidRepository,
  DidsApi,
  getKmsKeyIdForVerifiacationMethod,
  getPublicJwkFromVerificationMethod,
  JsonEncoder,
  JwsService,
  TypedArrayEncoder,
} from '@credo-ts/core'

/**
 * A JWS over an agent card in the flattened JSON form A2A uses for `AgentCard.signatures`. The payload is the
 * canonical form of the card, which the verifier recomputes, so only the protected header and the signature travel.
 */
export interface AgentCardSignature {
  /** base64url protected header, with `alg`, `kid` (a DID URL) and `typ` */
  protected: string
  /** base64url signature */
  signature: string
}

/**
 * Signs the canonical payload of an agent card with a key of a DID that this agent controls. The `kid` of the signature
 * is the DID URL, so a verifier finds the public key by resolving the DID. The algorithm follows the key (`ES256` for
 * P-256, the cheqd default).
 *
 * The caller produces the payload. A2A defines it as the JCS (RFC 8785) form of the card without its `signatures`,
 * which the A2A SDKs expose (`canonicalizeAgentCard` in `@a2a-js/sdk`).
 */
export async function signAgentCardPayload(
  agentContext: AgentContext,
  options: { didUrl: string; payload: string }
): Promise<AgentCardSignature> {
  const [did] = options.didUrl.split('#')
  const record = await agentContext.dependencyManager.resolve(DidRepository).findCreatedDid(agentContext, did)
  if (!record?.didDocument) throw new CredoError(`${did} is not a DID created or imported by this agent`)

  const verificationMethod = record.didDocument.dereferenceKey(options.didUrl, ['authentication', 'assertionMethod'])
  const publicJwk = getPublicJwkFromVerificationMethod(verificationMethod)
  const keyId = getKmsKeyIdForVerifiacationMethod(verificationMethod, record.keys) ?? publicJwk.legacyKeyId

  const compact = await agentContext.dependencyManager.resolve(JwsService).createJwsCompact(agentContext, {
    payload: TypedArrayEncoder.fromUtf8String(options.payload),
    keyId,
    protectedHeaderOptions: { alg: publicJwk.signatureAlgorithm, kid: options.didUrl, typ: 'JOSE' },
  })

  const [protectedHeader, , signature] = compact.split('.')
  return { protected: protectedHeader, signature }
}

export type AgentCardSignatureVerification =
  | { isValid: true; didUrl: string }
  | { isValid: false; didUrl?: string; error: string }

/**
 * Verifies a signature over the canonical payload of an agent card. The key is found by resolving the DID URL in the
 * `kid` of the protected header, with any DID method the agent can resolve. The key must be listed for
 * authentication or assertion in the DID document, and the DID must not be deactivated.
 *
 * `expectedDid` is the DID you already trust the card to come from (e.g. the DID you discovered the card through, or
 * the DID of the agent you expect to be talking to). The signer DID parsed from `kid` is compared against it
 * *before* anything is resolved: a mismatch is rejected immediately. This is a required parameter, not an
 * afterthought the caller is trusted to apply themselves, because without it this function would resolve an
 * attacker-chosen DID URL on request. If that DID method is backed by a network resolver (e.g. `did:web`, or any
 * method handled by a configured `UniversalDidResolver`), that resolution is a blind, caller-triggered HTTP(S)
 * request to a host the attacker picked — an SSRF primitive, including against internal hosts/ports. Passing the
 * `expectedDid` you already trust closes that off: a mismatched DID is never resolved at all.
 */
export async function verifyAgentCardSignature(
  agentContext: AgentContext,
  options: { payload: string; signature: AgentCardSignature; expectedDid: string }
): Promise<AgentCardSignatureVerification> {
  const jws = `${options.signature.protected}.${TypedArrayEncoder.toBase64Url(
    TypedArrayEncoder.fromUtf8String(options.payload)
  )}.${options.signature.signature}`

  let didUrl: string | undefined
  try {
    const kid = JsonEncoder.fromBase64Url(options.signature.protected).kid
    if (typeof kid !== 'string' || !kid.startsWith('did:') || !kid.includes('#')) {
      return { isValid: false, error: 'The kid of the signature is not a DID URL' }
    }
    didUrl = kid

    // Enforce the binding to the expected signer BEFORE resolving anything. This is what stops a caller-supplied
    // kid from causing resolution (and, for did:web/UniversalDidResolver-backed methods, a network fetch) of a DID
    // the caller never asked to trust.
    const signerDid = didUrl.split('#')[0]
    if (signerDid !== options.expectedDid) {
      return {
        isValid: false,
        didUrl,
        error: `The signature's kid (${didUrl}) is for ${signerDid}, which does not match the expected DID ${options.expectedDid}`,
      }
    }

    const result = await agentContext.dependencyManager.resolve(JwsService).verifyJws(agentContext, {
      jws,
      allowedJwsSignerMethods: ['did'],
      resolveJwsSigner: async ({ protectedHeader }) => {
        const signerDidUrl = protectedHeader.kid as string
        const { didDocument, didDocumentMetadata } = await agentContext.dependencyManager
          .resolve(DidsApi)
          .resolve(signerDidUrl.split('#')[0])
        if (!didDocument) throw new CredoError(`Unable to resolve ${signerDidUrl}`)
        if (didDocumentMetadata.deactivated) {
          throw new CredoError(`${signerDidUrl.split('#')[0]} is deactivated`)
        }

        const verificationMethod = didDocument.dereferenceKey(signerDidUrl, ['authentication', 'assertionMethod'])
        return { method: 'did', didUrl: signerDidUrl, jwk: getPublicJwkFromVerificationMethod(verificationMethod) }
      },
    })

    return result.isValid ? { isValid: true, didUrl } : { isValid: false, didUrl, error: 'Invalid signature' }
  } catch (error) {
    return { isValid: false, didUrl, error: error instanceof Error ? error.message : String(error) }
  }
}
