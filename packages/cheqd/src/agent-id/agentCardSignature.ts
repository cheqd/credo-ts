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
 * authentication or assertion in the DID document.
 *
 * A valid result means the card was signed by a key of that DID. Whether that DID is the one you expect, or trusted,
 * is up to the caller: compare `didUrl` with the DID you have the card from.
 */
export async function verifyAgentCardSignature(
  agentContext: AgentContext,
  options: { payload: string; signature: AgentCardSignature }
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

    const result = await agentContext.dependencyManager.resolve(JwsService).verifyJws(agentContext, {
      jws,
      allowedJwsSignerMethods: ['did'],
      resolveJwsSigner: async ({ protectedHeader }) => {
        const signerDidUrl = protectedHeader.kid as string
        const { didDocument } = await agentContext.dependencyManager
          .resolve(DidsApi)
          .resolve(signerDidUrl.split('#')[0])
        if (!didDocument) throw new CredoError(`Unable to resolve ${signerDidUrl}`)

        const verificationMethod = didDocument.dereferenceKey(signerDidUrl, ['authentication', 'assertionMethod'])
        return { method: 'did', didUrl: signerDidUrl, jwk: getPublicJwkFromVerificationMethod(verificationMethod) }
      },
    })

    return result.isValid ? { isValid: true, didUrl } : { isValid: false, didUrl, error: 'Invalid signature' }
  } catch (error) {
    return { isValid: false, didUrl, error: error instanceof Error ? error.message : String(error) }
  }
}
