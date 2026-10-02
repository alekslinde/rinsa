// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { sanitize } from '../dist/esm/sanitize.js';
import { compilePolicy } from '../dist/esm/policy.js';
import { compileStructured } from '../dist/esm/structured.js';
import { validateValue } from '../dist/esm/validate.js';
import { hashValue } from '../dist/esm/transform.js';

/** Deterministic PRNG (mulberry32) for reproducible fuzzing. */
function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

const ALPHABET = [
  'a', 'Z', '0', ' ', '\t', '\n', '@', '.', '-', '_', 'é', 'ß', 'ﬁ', '😀',
  '\u0000', '​', '‮', 'é', 'ﬁ', '+', '/', '=', '"', "'", '<', '>', '%', '1', '.',
];

function randomString(rand, maxLen = 120) {
  const n = Math.floor(rand() * maxLen);
  let s = '';
  for (let i = 0; i < n; i++) s += ALPHABET[Math.floor(rand() * ALPHABET.length)];
  return s;
}

describe('security', () => {
  it('validation and scrub errors never contain input values', () => {
    const secret = 'hunter2-secret-value-999';
    const r = validateValue(secret, { format: 'email', maxLength: 3 });
    for (const i of r.issues) assert.ok(!JSON.stringify(i).includes(secret));
    const p = compilePolicy({ sanitize: { maxChars: 4 } });
    assert.equal(p.process(secret).length <= 4 + '…'.length, true);
  });
  it('scrubbing is deterministic across runs', () => {
    const s = compilePolicy(freeText()).process;
    const input = 'mail bob@example.com ip 10.1.2.3 card 4111111111111111';
    assert.equal(s(input), s(input));
    assert.equal(hashValue(input), hashValue(input));
    function freeText() {
      return { sanitize: {}, scrub: {} };
    }
  });
  it('adversarial inputs complete quickly and safely', () => {
    const t0 = Date.now();
    sanitize('a'.repeat(1_000_000));
    sanitize('@'.repeat(100_000) + 'a@b.co');
    sanitize('1'.repeat(200_000));
    sanitize('\u202e'.repeat(50_000) + 'x');
    sanitize('é'.repeat(20_000), { form: 'NFKC' });
    compilePolicy({ sanitize: {}, scrub: {} }).process('https://' + 'a'.repeat(50_000) + '?token=x');
    assert.ok(Date.now() - t0 < 15000, 'adversarial inputs took too long');
  });
  it('fuzz: total functions never throw, outputs well-formed and capped', () => {
    const rand = rng(42);
    const scrub = compilePolicy({ sanitize: { maxChars: 200 }, scrub: {} });
    const structured = compileStructured({ default: { sanitize: { maxChars: 200 }, scrub: {} } });
    for (let i = 0; i < 3000; i++) {
      const s = randomString(rand);
      let a;
      let b;
      assert.doesNotThrow(() => {
        a = sanitize(s);
        b = scrub.process(s);
      });
      assert.ok(typeof a === 'string' && typeof b === 'string');
      assert.ok((a).isWellFormed?.() ?? true);
      assert.ok((b).length <= Math.max(s.length, 200) + 64);
      if (i % 10 === 0) assert.doesNotThrow(() => structured.processValue({ k: s, arr: [s] }));
    }
  });
  it('large inputs: 1MB log scrub completes', () => {
    const line = '2024-01-01 user bob@example.com from 10.0.0.1 paid 4111111111111111 ok\n';
    const big = line.repeat(Math.ceil(1_000_000 / line.length));
    const t0 = Date.now();
    const out = compilePolicy({ sanitize: { trim: false, collapseWhitespace: false }, scrub: {} }).process(big);
    const dt = Date.now() - t0;
    assert.ok(!out.includes('bob@example.com'));
    assert.ok(!out.includes('4111111111111111'));
    assert.ok(dt < 15000, `1MB scrub took ${dt}ms`);
  });
});