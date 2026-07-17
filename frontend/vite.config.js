import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Migration react-scripts (CRA) → Vite — voir CLAUDE.md "long terme".
//
// - envPrefix : on conserve les noms REACT_APP_* existants (REACT_APP_API_URL,
//   REACT_APP_REPO_URL, REACT_APP_RPM_REPO_URL) pour ne pas casser les
//   Dockerfile / docker-compose*.yml / .env*. Vite expose ces variables sur
//   `import.meta.env.REACT_APP_*` au build comme au dev.
//   IMPORTANT : REACT_APP_API_URL doit rester vide en prod pour que les
//   requêtes restent relatives (proxy nginx) — voir CLAUDE.md.
// - esbuild loader 'jsx' sur les fichiers .js du projet : tout le code source
//   CRA utilise du JSX dans des fichiers `.js` (pas `.jsx`).
// - build.outDir = "build" / build.assetsDir = "static" : conserve la même
//   arborescence de sortie que CRA, donc Dockerfile et nginx.conf restent
//   inchangés (COPY --from=build /app/build, location /static/).
export default defineConfig({
  plugins: [react()],
  envPrefix: ["VITE_", "REACT_APP_"],
  esbuild: {
    loader: "jsx",
    include: /src\/.*\.jsx?$/,
    exclude: [],
  },
  optimizeDeps: {
    esbuildOptions: {
      loader: { ".js": "jsx" },
    },
  },
  server: {
    host: true,
    port: 80,
    proxy: {
      "/api": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
      "/health": {
        target: "http://backend:8000",
        changeOrigin: true,
      },
    },
  },
  preview: {
    host: true,
    port: 80,
  },
  build: {
    outDir: "build",
    assetsDir: "static",
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/setupTests.js",
    css: true,
  },
});
