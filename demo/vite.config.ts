import { defineConfig } from "vitest/config";
import wasm from "vite-plugin-wasm";
import topLevelAwait from "vite-plugin-top-level-await";

// wasm + top-level-await are required to consume the wasm-pack --target bundler
// npm package (@konsept/cypher) - it imports the .wasm and inits via
// top-level await.
export default defineConfig({
  // Relative base so the build works under the GitHub Pages subpath
  // (konsept.github.io/cypher/) and at the root alike.
  base: "./",
  plugins: [wasm(), topLevelAwait()],
  test: { environment: "node" },
});
