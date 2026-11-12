import { defineConfig } from 'vitest/config'

// NOTE: we use vite-rolldown instead of vite. Vite is migrating from
// using ESBuild to Rolldown. The bundler we use `tsdown`, is also built
// on Rolldown, which means it has the same features. Specifically ESBuild
// does not support emitting decorator metadata, a feature we rely on heavily
// for class-transformer, class-validator and tsyringe.

export default defineConfig({
  test: {
    // Ideally we move away from globals, but this
    // makes the migration from jest a lot easier
    globals: true,
    watch: false,

    // hooks sometimes interact with ledger etc, so it needs to be longer than default 10000
    hookTimeout: 40000,
    testTimeout: 120000,

    setupFiles: ['./tests/setup.ts'],
    coverage: {
      include: ['**/*.{js,jsx,ts,tsx}'],
      exclude: ['**/build/**', '**/node_modules/**', '**/__tests__/**', 'tests', 'coverage', '**/*.d.ts'],
    },

    // Enable for debugging
    logHeapUsage: true,

    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['**/*.{test,spec}.?(c|m)[jt]s?(x)'],
          // Ignore e2e and conformance tests
          exclude: [
            '**/node_modules/**',
            '**/build/**',
            '**/*.e2e.{test,spec}.?(c|m)[jt]s?(x)',
            '**/*.conformance.{test,spec}.?(c|m)[jt]s?(x)',
          ],
        },
      },
      {
        extends: true,
        test: {
          name: 'e2e',
          // beforeAll hooks of the DIDComm e2e tests start agents and issue credentials: 6-35s on CI runners, close to the global 40s
          hookTimeout: 120000,
          include: ['**/*.e2e.{test,spec}.?(c|m)[jt]s?(x)'],
          exclude: [
            '**/node_modules/**',
            '**/build/**',
            // Ignore drizzle tests
            '**/*.drizzle.e2e.{test,spec}.?(c|m)[jt]s?(x)',
            // These hit the live Hedera testnet with a shared operator account, so they fail in CI for reasons
            // unrelated to the code. Set RUN_HEDERA_E2E=true to run them.
            ...(process.env.RUN_HEDERA_E2E === 'true' ? [] : ['packages/hedera/tests/integration/**']),
          ],
        },
      },
      {
        extends: true,
        test: {
          name: 'drizzle',
          hookTimeout: 120000,
          include: ['**/*.drizzle.e2e.{test,spec}.?(c|m)[jt]s?(x)'],
        },
      },
      {
        // OIDF conformance suite tests. These spin up the OpenID Foundation
        // conformance suite in Docker (via testcontainers) and drive credo-ts
        // against it, so they are kept in a dedicated project that is never run
        // by the default `unit`/`e2e` runs.
        extends: true,
        test: {
          name: 'conformance',
          include: ['**/*.conformance.{test,spec}.?(c|m)[jt]s?(x)'],
          // Image pulls + container boot + many sequential modules are slow.
          testTimeout: 600_000,
          hookTimeout: 600_000,
        },
      },
    ],
  },
})
