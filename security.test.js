import test from 'node:test';
import assert from 'node:assert/strict';
import { safeEqual, cleanText, makeCsrfToken } from '../src/security.js';

test('safeEqual compares equal strings and rejects different strings', () => {
  assert.equal(safeEqual('abc', 'abc'), true);
  assert.equal(safeEqual('abc', 'abd'), false);
  assert.equal(safeEqual('abc', 'abcd'), false);
});

test('cleanText trims and clamps input', () => {
  assert.equal(cleanText('  hello  '), 'hello');
  assert.equal(cleanText('abcdef', 3), 'abc');
  assert.equal(cleanText(null), '');
});

test('CSRF tokens are 64 hex chars and unique', () => {
  const a = makeCsrfToken(); const b = makeCsrfToken();
  assert.match(a, /^[a-f0-9]{64}$/);
  assert.notEqual(a, b);
});
