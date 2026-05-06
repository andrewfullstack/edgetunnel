import { defineConfig } from 'vitest/config';

// Integration test config. Tests boot the actual built _worker.js inside
// workerd via wrangler's unstable_dev, so they need:
//   1. _worker.js to exist in the repo root (run `npm run build` first)
//   2. wrangler installed (it is — devDependency)
//
// Each integration suite shares one workerd instance (beforeAll/afterAll)
// because spinning up workerd takes ~3-5s. Tests are run serially within
// a single suite to avoid KV state interference.
export default defineConfig({
  test: {
    include: ['tests/integration/**/*.test.ts'],
    environment: 'node',
    globals: false,
    typecheck: { enabled: false },
    testTimeout: 30_000,
    hookTimeout: 60_000,
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
  },
});
