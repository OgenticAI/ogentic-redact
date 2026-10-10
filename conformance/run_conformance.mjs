/** Cross-language safe one-way conformance, plus explicit store-backed restoration. */
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const { vectors, call_salt_hex } = JSON.parse(readFileSync(resolve(root, 'conformance/vectors.json'), 'utf8'));
assert.ok(vectors?.length, 'conformance vectors must not be empty');
assert.ok(call_salt_hex, 'fixed conformance salt is required');
const salt = Buffer.from(call_salt_hex, 'hex');
const names = {
  'darwin-arm64': 'darwin-arm64',
  'linux-x64': 'linux-x64-gnu',
  'win32-x64': 'win32-x64-msvc',
};
const platform = names[`${process.platform}-${process.arch}`];
assert.ok(platform, `unsupported test platform: ${process.platform}-${process.arch}`);
const addon = process.env.OGENTIC_REDACT_BINDING || resolve(root, `packages/ogentic-redact-node/ogentic-redact.${platform}.node`);
// A missing or incompatible binding is a test failure, never a successful skip.
const binding = createRequire(import.meta.url)(addon);
for (const vector of vectors) {
  const result = binding.redactWithSalt(vector.input, salt);
  assert.equal(result.text, vector.expected_text, `${vector.id}: safe text differs`);
  assert.deepEqual(Object.keys(result).sort(), ['redactionCount', 'text']);
  const redactor = new binding.ReversibleRedactor();
  const reversible = redactor.redact(vector.input);
  assert.deepEqual(Object.keys(reversible).sort(), ['mappingId', 'text']);
  assert.equal(redactor.unredact(reversible.text, reversible.mappingId, true), vector.input, `${vector.id}: round trip differs`);
}
console.log(`${vectors.length} vectors passed: safe default and explicit reversible mode`);
