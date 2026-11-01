import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    // Every app is built in-process and seeded fresh per probe; nothing is shared across files,
    // but the review run builds both versions, so keep files serial for deterministic output.
    fileParallelism: false,
    testTimeout: 20_000,
  },
});
