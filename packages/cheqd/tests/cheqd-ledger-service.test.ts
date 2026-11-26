import { CheqdNetwork } from '@cheqd/sdk'
import { CheqdModuleConfig } from '../src/CheqdModuleConfig'
import { CheqdLedgerService } from '../src/ledger/CheqdLedgerService'

const createCheqdSDKMock = vi.fn()

vi.mock('@cheqd/sdk', async () => {
  const actual = await vi.importActual<typeof import('@cheqd/sdk')>('@cheqd/sdk')
  return {
    ...actual,
    createCheqdSDK: (...args: unknown[]) => createCheqdSDKMock(...args),
  }
})

function makeFakeSdk() {
  return {
    signer: { disconnect: vi.fn() },
    querier: { cometClient: { disconnect: vi.fn() } },
    queryDidDoc: vi.fn().mockResolvedValue({ didDocument: {} }),
  }
}

function buildService() {
  const config = new CheqdModuleConfig({
    networks: [{ network: CheqdNetwork.Testnet }],
  })
  const logger = { trace: vi.fn(), debug: vi.fn(), info: vi.fn(), warn: vi.fn(), error: vi.fn(), fatal: vi.fn() }
  // biome-ignore lint/suspicious/noExplicitAny: minimal fake logger is enough for these tests
  return new CheqdLedgerService(config, logger as any)
}

const did = 'did:cheqd:testnet:SiVQgrFZ7jFZFrTGstT4ZD'

describe('CheqdLedgerService setup race', () => {
  beforeEach(() => {
    createCheqdSDKMock.mockReset()
  })

  it('shares one setup between concurrent first calls instead of racing to create multiple clients', async () => {
    createCheqdSDKMock.mockImplementation(() => Promise.resolve(makeFakeSdk()))

    const service = buildService()
    // biome-ignore lint/suspicious/noExplicitAny: reaching into the private method under test
    const getSdk = (service as any).getSdk.bind(service)

    const [sdkA, sdkB] = await Promise.all([getSdk(did), getSdk(did)])

    expect(createCheqdSDKMock).toHaveBeenCalledTimes(1)
    expect(sdkA).toBe(sdkB)
  })

  it('does not let a failed setup wipe a concurrent, already-replaced (e.g. successful) setup', async () => {
    const service = buildService()
    // biome-ignore lint/suspicious/noExplicitAny: reaching into private state under test
    const network = (service as any).networks[0]
    // biome-ignore lint/suspicious/noExplicitAny: reaching into the private method under test
    const initializeSdkForNetwork = (service as any).initializeSdkForNetwork.bind(service)

    createCheqdSDKMock.mockRejectedValueOnce(new Error('boom'))
    const failingInit = initializeSdkForNetwork(network)

    // Simulate another concurrent setup finishing and claiming the slot while the first
    // (failing) one is still in flight.
    const successfulSdk = makeFakeSdk()
    const successfulPromise = Promise.resolve(successfulSdk)
    network.sdk = successfulPromise

    await expect(failingInit).resolves.toBeUndefined()
    expect(network.sdk).toBe(successfulPromise)
  })

  it('disconnect() tears down the connection instead of re-running setup, and a later call reconnects fresh', async () => {
    const fakeSdk = makeFakeSdk()
    createCheqdSDKMock.mockImplementation(() => Promise.resolve(fakeSdk))

    const service = buildService()
    // biome-ignore lint/suspicious/noExplicitAny: reaching into the private method under test
    const getSdk = (service as any).getSdk.bind(service)

    await getSdk(did)
    expect(createCheqdSDKMock).toHaveBeenCalledTimes(1)

    await service.disconnect()

    // disconnect() must actually release the connection, not just run setup again
    expect(fakeSdk.signer.disconnect).toHaveBeenCalledTimes(1)
    expect(createCheqdSDKMock).toHaveBeenCalledTimes(1)

    // A later call must reconnect fresh rather than reusing the torn-down client
    await getSdk(did)
    expect(createCheqdSDKMock).toHaveBeenCalledTimes(2)
  })
})
