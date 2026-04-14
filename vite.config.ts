import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { TanStackRouterVite } from "@tanstack/router-plugin/vite";
import tailwindcss from "@tailwindcss/vite";
import path from "path";

// @ts-expect-error process is a nodejs global
const host = process.env.TAURI_DEV_HOST;

// https://vite.dev/config/
export default defineConfig(async () => ({
  plugins: [
    // TanStack Router file-based routing — must come before React plugin
    TanStackRouterVite({ routesDirectory: "./src/routes", generatedRouteTree: "./src/routeTree.gen.ts" }),
    react(),
    tailwindcss(),
  ],

  build: {
    rollupOptions: {
      output: {
        // Give lazy chunks human-readable names instead of hash-only blobs.
        // React.lazy() splits produce a chunk per dynamic import; manualChunks
        // below pins the heavy vendor libraries to their own stable chunks so
        // that the lazy wrapper code stays small and vendor chunks are cached
        // across app updates.
        chunkFileNames: (chunkInfo) => {
          // Named entry chunks (main, routeTree) keep their name
          if (chunkInfo.name && !chunkInfo.name.startsWith("index")) {
            return "assets/[name]-[hash].js";
          }
          return "assets/[name]-[hash].js";
        },
        manualChunks: (id: string) => {
          // Cytoscape and its extensions → vendor-cytoscape chunk
          if (id.includes("node_modules/cytoscape")) {
            return "vendor-cytoscape";
          }
          // vis-timeline (and vis-data / vis-util) → vendor-vis chunk
          if (
            id.includes("node_modules/vis-timeline") ||
            id.includes("node_modules/vis-data") ||
            id.includes("node_modules/vis-util") ||
            id.includes("node_modules/component-inherit") ||
            id.includes("node_modules/propagating-hammerjs") ||
            id.includes("node_modules/hammerjs")
          ) {
            return "vendor-vis";
          }
          // react-markdown and its remark/rehype ecosystem → vendor-markdown chunk
          if (
            id.includes("node_modules/react-markdown") ||
            id.includes("node_modules/remark") ||
            id.includes("node_modules/rehype") ||
            id.includes("node_modules/micromark") ||
            id.includes("node_modules/mdast") ||
            id.includes("node_modules/hast") ||
            id.includes("node_modules/unified") ||
            id.includes("node_modules/vfile") ||
            id.includes("node_modules/unist") ||
            id.includes("node_modules/decode-named-character-reference") ||
            id.includes("node_modules/character-entities")
          ) {
            return "vendor-markdown";
          }
        },
      },
    },
  },

  resolve: {
    alias: {
      "@": path.resolve(__dirname, "./src"),
    },
  },

  // Vite options tailored for Tauri development and only applied in `tauri dev` or `tauri build`
  //
  // 1. prevent Vite from obscuring rust errors
  clearScreen: false,
  // 2. tauri expects a fixed port, fail if that port is not available
  server: {
    port: 1420,
    strictPort: true,
    host: host || false,
    hmr: host
      ? {
          protocol: "ws",
          host,
          port: 1421,
        }
      : undefined,
    watch: {
      // 3. tell Vite to ignore watching `src-tauri`
      ignored: ["**/src-tauri/**"],
    },
  },
}));
