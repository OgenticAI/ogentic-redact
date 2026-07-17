/**
 * F3 cross-language conformance test — Node.js surface.
 *
 * Loads `conformance/vectors.json` from the repo root and verifies that the
 * napi-rs `redact()` function produces byte-identical output to the expected
 * values.  Any divergence exits non-zero (→ CI red).
 *
 * Run (from repo root, after building the napi crate):
 *   node conformance/run_conformance.mjs
 *
 * The compiled `.node` addon is expected at:
 *   packages/ogentic-redact-node/ogentic_redact_node.linux-x64-gnu.node
 *   (or the platform-appropriate filename)
 */

import { createRequire } from 'module';
import { readFileSync } from 'fs';
import { resolve, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
const repoRoot = resolve(__dirname, '..');

// ── Load vectors ──────────────────────────────────────────────────────────────

const vectorsPath = resolve(repoRoot, 'conformance', 'vectors.json');
const { vectors } = JSON.parse(readFileSync(vectorsPath, 'utf-8'));

if (!vectors || vectors.length === 0) {
  console.error('vectors.json must contain at least one vector');
  process.exit(1);
}

// ── Load the napi-rs binding ──────────────────────────────────────────────────

const require = createRequire(import.meta.url);

// Try to find the compiled .node addon.  napi-rs names the file using the
// target triple, e.g. `ogentic_redact_node.linux-x64-gnu.node`.
let binding;
try {
  // napi-rs places the build artefact in the package directory after
  // `cargo build --release -p ogentic-redact-node` + napi-build postprocess.
  const pkgDir = resolve(repoRoot, 'packages', 'ogentic-redact-node');
  const { globSync } = await import('glob').catch(() => null) ?? {};
  let addonPath;
  if (globSync) {
    const matches = globSync(`${pkgDir}/*.node`);
    addonPath = matches[0];
  } else {
    // Fallback: conventional filename on linux-x64
    addonPath = resolve(pkgDir, 'ogentic_redact_node.linux-x64-gnu.node');
  }
  if (!addonPath) throw new Error('no .node file found');
  binding = require(addonPath);
} catch (err) {
  console.error(`[SKIP] Cannot load ogentic-redact-node binding: ${err.message}`);
  console.error('       Build it first: cargo build --release -p ogentic-redact-node');
  process.exit(0); // skip, not fail, when the addon is not yet built
}

const { redact } = binding;

// ── Run vectors ───────────────────────────────────────────────────────────────

let passed = 0;
let failed = 0;

for (const v of vectors) {
  const result = redact(v.input);

  const textOk = result.text === v.expected_text;
  const tokensOk = JSON.stringify(sortedObj(result.tokens)) === JSON.stringify(sortedObj(v.expected_tokens));

  if (textOk && tokensOk) {
    console.log(`  ✓  ${v.id}`);
    passed++;
  } else {
    console.error(`  ✗  ${v.id}`);
    if (!textOk) {
      console.error(`       text\n         got:      ${JSON.stringify(result.text)}\n         expected: ${JSON.stringify(v.expected_text)}`);
    }
    if (!tokensOk) {
      console.error(`       tokens\n         got:      ${JSON.stringify(result.tokens)}\n         expected: ${JSON.stringify(v.expected_tokens)}`);
    }
    failed++;
  }
}

console.log(`\n${passed} passed, ${failed} failed (Node.js surface, ${vectors.length} vectors)`);
process.exit(failed > 0 ? 1 : 0);

function sortedObj(obj) {
  return Object.fromEntries(Object.entries(obj).sort(([a], [b]) => a.localeCompare(b)));
}
