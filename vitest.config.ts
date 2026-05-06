import { defineConfig } from 'vitest/config';

// Unit tests only. Integration tests live in tests/integration/ and run via
// `npm run test:integration` (see vitest.config.integration.ts) — they spin
// up workerd via wrangler unstable_dev and require a built _worker.js.
export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    exclude: ['tests/integration/**', 'node_modules/**'],
    environment: 'node',
    globals: false,
    typecheck: { enabled: false },
  },
});
