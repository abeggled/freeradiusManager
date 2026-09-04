import { fileURLToPath, URL } from "node:url";

import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

// Die gebaute Oberflaeche wird vom Backend unter /static ausgeliefert (siehe app/main.py).
export default defineConfig({
  plugins: [react()],
  resolve: {
    alias: {
      "@": fileURLToPath(new URL("./src", import.meta.url)),
    },
  },
  // Relative Asset-Pfade; aufgelöst wird über das <base>-Element, das das
  // Backend auf den konfigurierten Root-Pfad setzt.
  base: "./",
  build: {
    outDir: "../backend/static",
    emptyOutDir: true,
  },
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: "http://localhost:8000",
        changeOrigin: false,
      },
    },
  },
});
