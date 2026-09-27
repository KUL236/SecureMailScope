import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Dev proxy so the app can call fetch("/api/...") with no CORS wrangling
// and the JWT session cookie flows straight to the FastAPI backend.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      "/api": {
        target: process.env.VITE_API_PROXY_TARGET || "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
});
