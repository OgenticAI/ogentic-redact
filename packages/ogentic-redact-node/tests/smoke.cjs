'use strict'
const assert = require('node:assert/strict')
const path = require('node:path')
// CI can check an exact built binary; installed-package smoke uses the real loader.
const binding = process.env.OGENTIC_REDACT_BINDING
  ? require(path.resolve(process.env.OGENTIC_REDACT_BINDING))
  : require('..')
const text = 'Email alice@example.com. Call 555-867-5309. SSN 123-45-6789.'
const salt = Buffer.from('00112233445566778899aabbccddeeff', 'hex')
for (const result of [binding.redact(text), binding.redactWithSalt(text, salt)]) {
  assert.deepEqual(Object.keys(result).sort(), ['redactionCount', 'text'])
  assert.equal(result.redactionCount, 3)
  for (const secret of ['alice@example.com', '555-867-5309', '123-45-6789']) {
    assert.ok(!JSON.stringify(result).includes(secret))
  }
}
assert.deepEqual(binding.redactWithSalt(text, salt), binding.redactWithSalt(text, salt))
assert.equal(binding.redact('').text, '')
const first = new binding.ReversibleRedactor()
const other = new binding.ReversibleRedactor()
const result = first.redact(text)
assert.deepEqual(Object.keys(result).sort(), ['mappingId', 'text'])
for (const secret of ['alice@example.com', '555-867-5309', '123-45-6789']) {
  assert.ok(!JSON.stringify(result).includes(secret))
}
assert.throws(() => other.unredact(result.text, result.mappingId), /mapping not found/)
assert.equal(first.unredact(result.text, result.mappingId, true), text)
assert.throws(() => first.unredact(result.text, result.mappingId), /mapping not found/)
const discarded = first.redact(text)
assert.equal(first.delete(discarded.mappingId), true)
assert.equal(first.delete(discarded.mappingId), false)
assert.throws(() => first.unredact(discarded.text, discarded.mappingId), /mapping not found/)
console.log('Native privacy, isolation, restoration, and deletion smoke passed')

const token = '[Person_12345678]'
const explicit = { [token]: 'é' }
assert.equal(binding.unredact(token, explicit, 2, 1), 'é')
assert.throws(() => binding.unredact(token, explicit, 1, 1), /restoration limit exceeded/)
assert.throws(() => binding.unredact(token, explicit, 2, 0), /restoration limit exceeded/)
assert.equal(binding.unredact('', {}, 0, 0), '')
assert.throws(() => binding.unredact('x', {}, 0, 0), /restoration limit exceeded/)
for (const invalid of [-1, 0.5, NaN, Infinity, Number.MAX_SAFE_INTEGER + 1, true, '2']) {
  assert.throws(() => new binding.ReversibleRedactor(invalid))
  assert.throws(() => new binding.ReversibleRedactor(100, invalid))
  assert.throws(() => binding.unredact(token, explicit, invalid))
}
const bounded = new binding.ReversibleRedactor(100, 1)
const retained = bounded.redact('alice@example.com')
assert.throws(() => bounded.unredact(retained.text.repeat(2), retained.mappingId, true), /restoration limit exceeded/)
assert.equal(bounded.unredact(retained.text, retained.mappingId, true), 'alice@example.com')
assert.throws(() => bounded.unredact(retained.text, retained.mappingId), /mapping not found/)
assert.throws(() => binding.unredact(token.repeat(1024), { [token]: 'x'.repeat(64 * 1024) }), /restoration limit exceeded/)
console.log('Native restoration budgets and rejected-consume retry smoke passed')
