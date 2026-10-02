// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectSecrets } from '../dist/esm/secrets.js';
import { compileScrubber, scrubPII, validateScrubPolicy } from '../dist/esm/scrub.js';

const JWT = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';

describe('secret detection', () => {
  it('bearer / jwt / private key', () => {
    assert.ok(detectSecrets('auth Bearer abcdefghijklmnop1234').some((f) => f.type === 'bearer'));
    assert.ok(detectSecrets('auth Bearer xxx').every((f) => f.type !== 'bearer' || f.confidence < 0.7));
    assert.ok(detectSecrets(`tok ${JWT} end`).some((f) => f.type === 'jwt' && f.confidence > 0.9));
    assert.ok(detectSecrets('-----BEGIN RSA PRIVATE KEY-----').some((f) => f.type === 'privateKey'));
  });
  it('cloud / service keys', () => {
    assert.ok(detectSecrets('key AKIAIOSFODNN7EXAMPLE x').some((f) => f.type === 'aws'));
    assert.ok(detectSecrets('key AIza01234567890123456789012345678901234 x').some((f) => f.type === 'gcp'));
    assert.ok(detectSecrets('ghp_123456789012345678901234567890123456 x').some((f) => f.type === 'github'));
    assert.ok(detectSecrets('glpat-abcdefghijklmnopqrst x').some((f) => f.type === 'gitlab'));
    assert.ok(detectSecrets('xoxb-123456789012-abcDEF x').some((f) => f.type === 'slack'));
    assert.ok(detectSecrets('sk_test_EXAMPLEEXAMPLEEXAMPLE0000 x').some((f) => f.type === 'stripe'));
    assert.ok(detectSecrets('sk-abcdefghijklmnopqrstuvwx1234 x').some((f) => f.type === 'openai'));
  });
  it('generic context keys + url creds', () => {
    assert.ok(detectSecrets('api_key: "abcdef1234567890"').some((f) => f.type === 'genericKey'));
    assert.ok(detectSecrets('api_key: "test"').every((f) => f.type !== 'genericKey'));
    assert.ok(detectSecrets('go https://admin:s3cret@db.internal/x').some((f) => f.type === 'urlCreds'));
  });
});

describe('scrub actions', () => {
  it('default redact', () => {
    assert.equal(scrubPII('mail bob@example.com'), 'mail [REDACTED]');
  });
  it('per-type mask with preserved tail', () => {
    const s = compileScrubber({ types: { card: { action: 'mask', preserveEnd: 4 } } });
    assert.equal(s.scrub('pay 4111111111111111 now'), 'pay ************1111 now');
  });
  it('hash / hmac / tokenize / truncate / drop', () => {
    const h = compileScrubber({ types: { email: { action: 'hash', hashLength: 8 } } });
    const out = h.scrub('a@b.co');
    assert.equal(out.length, 8);
    assert.equal(out, h.scrub('a@b.co')); // deterministic
    const hm = compileScrubber({ types: { email: { action: 'hmac', hmacKey: 'k1' } } });
    assert.ok(hm.scrub('a@b.co') !== h.scrub('a@b.co'));
    const tk = compileScrubber({ types: { email: { action: 'tokenize', tokenPrefix: 'u_' } } });
    assert.ok(tk.scrub('a@b.co').startsWith('u_'));
    const tr = compileScrubber({ types: { email: { action: 'truncate', truncateLength: 3 } } });
    assert.ok(tr.scrub('a@b.co').startsWith('a@b'));
    const dr = compileScrubber({ types: { email: { action: 'drop' } } });
    assert.equal(dr.scrub('hi a@b.co!'), 'hi !');
    const kp = compileScrubber({ types: { email: { enabled: false } } });
    assert.equal(kp.scrub('hi a@b.co'), 'hi a@b.co');
  });
  it('per-type levels and global level', () => {
    const s = compileScrubber({ level: 'strict', types: { postal: { level: 'loose' } } });
    assert.ok(!s.detect('order 94105 shipped').some((f) => f.type === 'phone'));
    assert.ok(s.detect('order 94105 shipped').some((f) => f.type === 'postal'));
  });
  it('fail-closed policy validation', () => {
    assert.throws(() => validateScrubPolicy({ types: { email: { action: 'hmac' } } }), /hmacKey/);
  });
  it('detailed results count without values', () => {
    const s = compileScrubber({});
    const r = s.scrubDetailed('a@b.co and 192.168.0.1');
    assert.equal(r.redactedCount, 2);
    assert.equal(r.findings.length, 2);
    assert.ok(!JSON.stringify(r.findings).includes('a@b.co'));
  });
  it('secrets + PII combine deterministically', () => {
    const s = compileScrubber({});
    const a = s.scrub(`token ${JWT} mail a@b.co`);
    assert.equal(a, s.scrub(`token ${JWT} mail a@b.co`));
    assert.ok(!a.includes('eyJ'));
    assert.ok(!a.includes('a@b.co'));
  });
});