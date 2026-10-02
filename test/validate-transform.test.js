// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { validateValue, validateObjectWith, compileValidator } from '../dist/esm/validate.js';
import {
  mapChars,
  replaceAll,
  replacePattern,
  filterChars,
  filterAlnum,
  mask,
  redact,
  hashValue,
  hmacValue,
  tokenize,
  truncate,
  pipe,
} from '../dist/esm/transform.js';

describe('validation', () => {
  it('required / nullable / type', () => {
    assert.equal(validateValue(undefined, { required: true }).ok, false);
    assert.equal(validateValue(undefined, {}).ok, true);
    assert.equal(validateValue(null, {}).ok, false);
    assert.equal(validateValue(null, { nullable: true }).ok, true);
    assert.equal(validateValue('x', { type: 'string' }).ok, true);
    assert.equal(validateValue(1, { type: 'string' }).ok, false);
    assert.equal(validateValue(1.5, { type: 'integer' }).ok, false);
    assert.equal(validateValue(2, { type: ['integer', 'string'] }).ok, true);
  });
  it('length / range / enum / pattern / format', () => {
    assert.equal(validateValue('ab', { minLength: 3 }).ok, false);
    assert.equal(validateValue('abcd', { maxLength: 3 }).ok, false);
    assert.equal(validateValue(5, { min: 1, max: 4 }).ok, false);
    assert.equal(validateValue('b', { enum: ['a', 'b'] }).ok, true);
    assert.equal(validateValue('c', { enum: ['a', 'b'] }).ok, false);
    assert.equal(validateValue('abc123', { pattern: /^[a-z]+\d+$/ }).ok, true);
    assert.equal(validateValue('nope', { format: 'email' }).ok, false);
    assert.equal(validateValue('a@b.co', { format: 'email' }).ok, true);
    assert.equal(validateValue('550e8400-e29b-41d4-a716-446655440000', { format: 'uuid' }).ok, true);
    assert.equal(validateValue('999.1.1.1', { format: 'ipv4' }).ok, false);
  });
  it('never echoes values in issues', () => {
    const secret = 'supersecret-password-12345';
    const r = validateValue(secret, { format: 'email', maxLength: 5, pattern: /^x/ });
    assert.ok(r.issues.length > 0);
    for (const i of r.issues) assert.ok(!i.message.includes(secret), `leak: ${i.message}`);
  });
  it('nested objects, arrays, unknown keys, custom', () => {
    const r = validateObjectWith(
      { user: { age: -1 }, tags: ['a', 1], extra: 1 },
      {
        user: { type: 'object', fields: { age: { type: 'integer', min: 0 } } },
        tags: { type: 'array', items: { type: 'string' } },
      },
      { noUnknown: true },
    );
    assert.equal(r.ok, false);
    assert.ok(r.issues.some((i) => i.code === 'range'));
    assert.ok(r.issues.some((i) => i.code === 'type'));
    assert.ok(r.issues.some((i) => i.code === 'unknown'));
    const c = validateValue('x', { custom: () => 'bad value' });
    assert.equal(c.issues[0].message, 'bad value');
  });
  it('cross-field rules', () => {
    const r = validateObjectWith(
      { start: 10, end: 5 },
      { start: { type: 'number' }, end: { type: 'number' } },
      { cross: [{ fields: ['start', 'end'], check: (o) => ((o.start <= o.end) ? null : { code: 'order', message: 'start must be <= end' }) }] },
    );
    assert.equal(r.ok, false);
    assert.equal(r.issues[0].code, 'order');
  });
  it('compiled validator + issue cap', () => {
    const v = compileValidator({ a: { type: 'string' } }, { maxIssues: 1 });
    const r = v({ a: 1, b: 2 });
    assert.ok(r.issues.length <= 1);
  });
});

describe('transforms', () => {
  it('map / replace / filter', () => {
    assert.equal(mapChars('a1b2', (c) => (/\d/.test(c) ? null : c)), 'ab');
    const s = 'xox';
    assert.ok(replaceAll(s, 'z', 'q') === s);
    assert.equal(replaceAll('aaa', 'a', 'b'), 'bbb');
    assert.equal(replacePattern('abc123', /\d+/, '#'), 'abc#');
    assert.equal(filterChars('a1b2', (c) => /[a-z]/.test(c)), 'ab');
    assert.equal(filterAlnum('a-b_c!1'), 'abc1');
  });
  it('mask / redact', () => {
    assert.equal(mask('4111111111111111', { preserveEnd: 4 }), '************1111');
    assert.equal(mask('hi', { preserveStart: 1, preserveEnd: 1 }), 'hi');
    assert.equal(redact('secret'), '[REDACTED]');
  });
  it('hash / hmac / tokenize are deterministic', () => {
    assert.equal(hashValue('abc'), 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad');
    assert.equal(hashValue('abc', 'sha256', 8), 'ba7816bf');
    assert.equal(hmacValue('m', 'k'), hmacValue('m', 'k'));
    assert.ok(hmacValue('m', 'k') !== hmacValue('m', 'k2'));
    const t1 = tokenize('user@example.com');
    assert.ok(t1.startsWith('tok_'));
    assert.equal(t1, tokenize('user@example.com'));
    const vault = new Map();
    tokenize('v', { vault });
    assert.equal(vault.get(tokenize('v', { vault })), 'v');
  });
  it('truncate / pipe', () => {
    assert.equal(truncate('hello world', { maxLength: 5, suffix: '...' }), 'hello...');
    const s = 'hi';
    assert.ok(truncate(s) === s);
    const f = pipe((x) => x.trim(), (x) => x.toUpperCase());
    assert.equal(f('  ab '), 'AB');
  });
});