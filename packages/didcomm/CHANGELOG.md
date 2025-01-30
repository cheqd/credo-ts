# @credo-ts/didcomm

## 0.6.0

### Minor Changes

- 897c834: DIDComm has been extracted out of the Core. This means that now all DIDComm related modules (e.g. proofs, credentials) must be explicitly added when creating an `Agent` instance. Therefore, their API will be accesable under `agent.modules.[moduleAPI]` instead of `agent.[moduleAPI]`. Some `Agent` DIDComm-related properties and methods where also moved to the API of a new DIDComm module (e.g. `agent.registerInboundTransport` turned into `agent.modules.didcomm.registerInboundTransport`).

  **Example of DIDComm Agent**

  Previously:

  ```ts
       const config = {
        label: name,
        endpoints: ['https://myendpoint'],
        walletConfig: {
          id: name,
          key: name,
        },
      } satisfies InitConfig

      const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: {
          connections: new ConnectionsModule({
             autoAcceptConnections: true,
          })
        })
      this.agent.registerInboundTransport(new HttpInboundTransport({ port }))
      this.agent.registerOutboundTransport(new HttpOutboundTransport())

  ```

  Now:

  ```ts
       const config = {
        label: name,
        walletConfig: {
          id: name,
          key: name,
        },
      } satisfies InitConfig

      const agent = new Agent({
        config,
        dependencies: agentDependencies,
        modules: {
          ...getDefaultDidcommModules({ endpoints: ['https://myendpoint'] }),
          connections: new ConnectionsModule({
             autoAcceptConnections: true,
          })
        })
      agent.modules.didcomm.registerInboundTransport(new HttpInboundTransport({ port }))
      agent.modules.didcomm.registerOutboundTransport(new HttpOutboundTransport())
  ```

### Patch Changes

- Updated dependencies [2d10ec3]
- Updated dependencies [13cd8cb]
- Updated dependencies [14673b1]
- Updated dependencies [607659a]
- Updated dependencies [5f08bc6]
- Updated dependencies [2d10ec3]
- Updated dependencies [70c849d]
- Updated dependencies [897c834]
- Updated dependencies [edd2edc]
- Updated dependencies [e80794b]
  - @credo-ts/core@0.6.0
