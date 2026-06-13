import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import type { Plugin } from "vite";

const releaseAppOrigin = "app://sentinel-guard";

function releaseOriginPlugin(): Plugin {
  return {
    name: "sentinel-release-origin",
    enforce: "post",
    renderChunk(code) {
      const nextCode = code.split("http://localhost").join(releaseAppOrigin);
      return nextCode === code ? null : { code: nextCode, map: null };
    },
  };
}

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react(), releaseOriginPlugin()],

  // Prevent Vite from obscuring Rust errors
  clearScreen: false,

  server: {
    // Tauri expects a fixed port; fail if it is already in use
    port: 1420,
    strictPort: true,
    // Allow Tauri to reach the dev server
    host: "localhost",
  },

  // Env variables starting with TAURI_ will be exposed to tauri source code
  envPrefix: ["VITE_", "TAURI_"],

  build: {
    // Tauri uses Chromium on Windows
    target: "chrome105",
    // Do not minify in debug for better error messages
    minify: !process.env.TAURI_DEBUG ? "esbuild" : false,
    // Produce sourcemaps for debugging in production
    sourcemap: !!process.env.TAURI_DEBUG,
  },
});
