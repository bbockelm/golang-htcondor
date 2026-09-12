import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';
import path from 'node:path';

// Component tests, distinct from the Playwright suites in e2e/.
//
// Playwright answers "does the app work against a server": it builds,
// serves, and drives a browser, which costs a container start and makes
// each case expensive enough that a suite covers a handful of paths.
// These answer "does this component render this state correctly",
// which is the cheap-and-many question: a panel that distinguishes
// "nothing happened" from "nothing could tell us" has several states
// worth pinning and none of them need a server.
//
// Excluding e2e/ matters -- Playwright's `test` and Vitest's look alike
// enough that Vitest will happily pick up a .spec.ts and fail on the
// import.
export default defineConfig({
  plugins: [react()],
  test: {
    environment: 'jsdom',
    globals: true,
    setupFiles: ['./vitest.setup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    exclude: ['e2e/**', 'node_modules/**'],
  },
  resolve: {
    alias: { '@': path.resolve(__dirname, './src') },
  },
});
