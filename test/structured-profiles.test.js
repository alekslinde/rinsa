// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  compileStructured,
  processValueWith,
  processJSONWith,
  parseCSV,
  stringifyCSV,
  processCSV,
  processKV,
  SanitizationError,
} from '../dist/esm/structured.js';
import { compilePolicy, processText } from '../dist/esm/policy.js';
import {
  identifierProfile,
  emailProfile,
  phoneProfile,
  numericProfile,
  urlProfile,
  humanNameProfile,
  freeTextProfile,
  logDataProfile,
  llmInputProfile,
  analyticsProfile,
  profiles,
} from '../dist/esm/profiles.js';

describe('structured values', () => {
  it('nested objects, arrays, maps, buffers', () => {
    const cs = compileStructured({
      fields: {
        email: { scrub: { types: { email: { action: 'mask', preserveStart: 1 } } } },
        password: { drop: true },
        nick: { default: 'anon' },
      },
      default: { sanitize: { maxChars: 50 } },
    });
    const out = cs.processRecord({
      email: 'bob@example.com',
      password: 'x',
      nick: '   ',
      nested: { list: ['  a  ', 'b'] },
      m: new Map([['k', '  v  ']]),
      buf: new TextEncoder().encode('  hi  '),
    });
    assert.equal(out.email, 'b**************');
    assert.ok(!('password' in out));
    assert.equal(out.nick, 'anon');
    assert.deepEqual(out.nested, { list: ['a', 'b'] });
    assert.ok(out.m instanceof Map && out.m.get('k') === 'v');
    assert.equal(out.buf, 'hi');
  });
  it('wildcards and dotted paths', () => {
    const cs = compileStructured({ fields: { '*.ssn': { scrub: {} }, 'users.*': { sanitize: { maxChars: 3 } } } });
    const out = cs.processRecord({ user: { ssn: '078-05-1120' }, users: { name: 'abcdef' } });
    assert.equal(out.user.ssn, '[REDACTED]');
    assert.equal(out.users.name, 'abc');
  });
  it('circular, depth, size fail closed', () => {
    const cs = compileStructured({});
    const cyc = { a: 1 };
    cyc.self = cyc;
    assert.deepEqual(cs.processValue(cyc), { a: 1, self: null });
    assert.throws(() => compileStructured({ onCircular: 'throw' }).processValue(cyc), /circular/);
    const deep = { v: 1 };
    let cur = deep;
    for (let i = 0; i < 20; i++) cur = cur.n = { v: 1 };
    assert.throws(() => compileStructured({ maxDepth: 5 }).processValue(deep), /depth/);
    const big = {};
    for (let i = 0; i < 100; i++) big['k' + i] = i;
    assert.throws(() => compileStructured({ maxKeys: 10 }).processValue(big), /keys/);
  });
  it('__proto__ keys do not pollute', () => {
    const out = processValueWith(JSON.parse('{"__proto__": {"x": 1}, "a": "  b  "}'), { default: { sanitize: {} } });
    assert.equal(Object.getPrototypeOf(out), Object.prototype);
    assert.equal(out.a, 'b');
    assert.ok(Object.prototype.hasOwnProperty.call(out, '__proto__'));
    assert.deepEqual({}.x, undefined);
  });
  it('JSON round-trip + invalid JSON error', () => {
    const out = processJSONWith('{"email": "a@b.co", "n": 1}', { fields: { email: { scrub: {} } } });
    assert.equal(JSON.parse(out).email, '[REDACTED]');
    assert.throws(() => processJSONWith('{bad'), (e) => e instanceof SanitizationError && e.code === 'invalid-json');
  });
});

describe('CSV + KV', () => {
  it('rfc4180 parse/stringify round-trip', () => {
    const rows = parseCSV('a,b\n"x,y","q""q"\n');
    assert.deepEqual(rows, [['a', 'b'], ['x,y', 'q"q']]);
    assert.equal(stringifyCSV(rows), 'a,b\n"x,y","q""q"');
  });
  it('per-column rules', () => {
    const out = processCSV('name,email\n Bob ,BOB@X.CO\n', {
      columns: { email: { textCase: 'lower', scrub: false }, name: { sanitize: {} } },
    });
    assert.equal(out, 'name,email\nBob,bob@x.co');
  });
  it('kv records with drop', () => {
    assert.equal(processKV('a=1 secret=abcdef1234567890 b=2', { fields: { secret: { drop: true } } }), 'a=1 b=2');
  });
});

describe('unified policy', () => {
  it('pipeline order sanitize->case->coerce->scrub->truncate', () => {
    const p = compilePolicy({ sanitize: {}, textCase: 'lower', scrub: {}, truncate: { maxLength: 5, suffix: '' } });
    assert.equal(p.process('  HELLO WORLD  '), 'hello');
    assert.equal(compilePolicy({ sanitize: {}, scrub: {} }).process('mail bob@example.com'), 'mail [REDACTED]');
    assert.deepEqual(p.detect('a@b.co'), [{ type: 'email', start: 0, end: 6, confidence: 0.92 }]);
    assert.equal(p.validate('x').ok, true);
  });
  it('one-shot helper compiles inline', () => {
    assert.equal(processText('  Hi  ', { textCase: 'upper', scrub: false }), 'HI');
  });
});

describe('profiles', () => {
  it('all profiles build and run', () => {
    assert.equal(compilePolicy(identifierProfile()).process('  My_Key 2 '), 'my_key2');
    assert.equal(compilePolicy(emailProfile()).process('  BOB@X.CO  '), 'bob@x.co');
    assert.equal(compilePolicy(phoneProfile()).process('+1 (415) 555-0132'), '+14155550132');
    assert.equal(compilePolicy(numericProfile()).process('1,000.50'), '1000.5');
    assert.equal(compilePolicy(urlProfile()).process(' https://x.co/a '), 'https://x.co/a');
    assert.equal(compilePolicy(humanNameProfile()).process('  ada   lovelace  '), 'ada lovelace');
    assert.equal(compilePolicy(freeTextProfile()).process('mail bob@example.com'), 'mail [REDACTED]');
    assert.ok(compilePolicy(logDataProfile()).process('ip 10.0.0.1 ok').includes('[REDACTED]'));
    assert.equal(compilePolicy(llmInputProfile()).process('a‮b'), 'ab');
    const anon = compilePolicy(analyticsProfile()).process('user bob@example.com');
    assert.ok(anon.startsWith('user ') && anon.length === 5 + 16);
    assert.equal(anon, compilePolicy(analyticsProfile()).process('user bob@example.com'));
    // transparent overrides
    assert.equal(compilePolicy(emailProfile({ textCase: false })).process('BOB@X.CO'), 'BOB@X.CO');
    assert.equal(Object.keys(profiles).length, 10);
  });
  it('email profile validation flags bad input', () => {
    assert.equal(compilePolicy(emailProfile()).validate('nope').ok, false);
    assert.equal(compilePolicy(emailProfile()).validate('a@b.co').ok, true);
  });
});