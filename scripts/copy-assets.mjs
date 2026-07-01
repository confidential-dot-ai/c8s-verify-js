// Copy the generated WASM verifier runtime assets next to the compiled loader.
//
// `tsc` only emits the .ts it compiles; the WASM verifier is a generated binary
// (see scripts/build-wasm.sh) that the compiled `wasm-loader.js` loads via the
// relative path `./wasm/…`. So the `wasm/` runtime files must sit as a sibling
// of the compiled `wasm-loader.js`. tsc cannot do this (it never copies the
// .wasm binary), so mirror them here.
//
// Usage: node scripts/copy-assets.mjs [DEST_DIR]
//   DEST_DIR is the directory that will hold `wasm/` (i.e. where wasm-loader.js
//   lands). Defaults to `dist` for the flat library build (rootDir src → dist).
//   The browser-demo build (rootDir . → dist-demo) passes `dist-demo/src`.

import { copyFileSync, existsSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const src = join(root, "src", "wasm");
const dest = join(root, process.argv[2] ?? "dist", "wasm");

if (!existsSync(join(src, "attestation_wasm.js"))) {
  console.error(
    "error: src/wasm/ not built — run 'npm run build:wasm' first (see src/wasm/README.md)",
  );
  process.exit(1);
}

mkdirSync(dest, { recursive: true });

// Runtime artifacts the library imports (required).
for (const f of ["attestation_wasm.js", "attestation_wasm_bg.wasm"]) {
  copyFileSync(join(src, f), join(dest, f));
}
// Type declarations (optional — only present after a fresh build:wasm).
for (const f of ["attestation_wasm.d.ts", "attestation_wasm_bg.wasm.d.ts"]) {
  if (existsSync(join(src, f))) copyFileSync(join(src, f), join(dest, f));
}

console.log(`ok: copied src/wasm/ runtime assets into ${dest}/`);
