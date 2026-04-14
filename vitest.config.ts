import { defineConfig } from "vitest/config";
import path from "path";

export default defineConfig({
  test: {
    // Use jsdom for React component tests.
    environment: "jsdom",

    // Set up @testing-library/jest-dom matchers globally.
    setupFiles: ["./src/__tests__/setup.ts"],

    // Match co-located *.test.ts(x) files and __tests__/**/*.test.ts(x). The
    // setup file is loaded via `setupFiles` above — it is not a test file
    // and must not match this glob.
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "src/__tests__/**/*.test.ts", "src/__tests__/**/*.test.tsx"],

    globals: true,
  },
  resolve: {
    alias: {
      // Match the "@" alias in vite.config.ts so imports work in tests.
      "@": path.resolve(__dirname, "./src"),
    },
  },
});
