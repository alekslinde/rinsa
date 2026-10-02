// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { detectPII, luhnValid, ibanValid } from '../dist/esm/pii.js';

const has = (text, type, level = 'balanced', enabled) =>
  detectPII(text, { level, ...(enabled ? { enabled } : {}) }).some((f) => f.type === type);
const none = (text, type, level = 'balanced', enabled) =>
  !detectPII(text, { level, ...(enabled ? { enabled } : {}) }).some((f) => f.type === type);

describe('PII detection positives', () => {
  it('email', () => {
    assert.ok(has('contact bob.smith@example.com today', 'email'));
    assert.ok(has('a@b.co', 'email'));
  });
  it('phone', () => {
    assert.ok(has('call +1-415-555-0132 now', 'phone'));
    assert.ok(has('tel (020) 7946 0958', 'phone'));
  });
  it('card (luhn-gated)', () => {
    assert.ok(luhnValid('4111111111111111'));
    assert.ok(!luhnValid('1234567890123456'));
    assert.ok(has('card 4111 1111 1111 1111 ok', 'card'));
    assert.ok(none('card 1234 5678 9012 3456 ok', 'card'));
  });
  it('iban (mod97-gated)', () => {
    assert.ok(ibanValid('GB29NWBK60161331926819'));
    assert.ok(has('iban GB29 NWBK 6016 1331 9268 19 done', 'iban'));
    assert.ok(none('iban GB29 NWBK 6016 1331 9268 18 done', 'iban'));
  });
  it('bank routing + account context', () => {
    assert.ok(has('routing 021000021', 'bankAcct')); // valid ABA
    assert.ok(none('routing 123456789', 'bankAcct')); // bad checksum
    assert.ok(has('account no: 48392018', 'bankAcct'));
  });
  it('ssn with area rules', () => {
    assert.ok(has('ssn 078-05-1120', 'ssn'));
    assert.ok(none('ssn 900-12-3456', 'ssn'));
    assert.ok(none('ssn 000-12-3456', 'ssn'));
  });
  it('passport needs context at strict', () => {
    assert.ok(has('passport no C1234567', 'passport', 'strict'));
    assert.ok(none('ref C1234567', 'passport', 'strict'));
  });
  it('network identifiers', () => {
    assert.ok(has('ip 192.168.1.1 x', 'ipv4'));
    assert.ok(none('v 999.1.1.1 x', 'ipv4'));
    assert.ok(has('ip fe80::1 x', 'ipv6'));
    assert.ok(has('mac AA:BB:CC:DD:EE:FF x', 'mac'));
    assert.ok(has('id 550e8400-e29b-41d4-a716-446655440000 x', 'uuid'));
  });
  it('urlSensitive', () => {
    assert.ok(has('see https://user:pass@example.com/a', 'urlSensitive'));
    assert.ok(has('see https://ex.com/?token=abc&x=1', 'urlSensitive'));
    assert.ok(none('see https://example.com/about', 'urlSensitive'));
  });
  it('dob needs context (balanced)', () => {
    assert.ok(has('DOB: 1990-05-17', 'dob'));
    assert.ok(none('shipped 1990-05-17', 'dob'));
  });
  it('postal precision by level', () => {
    assert.ok(has('zip 94105-1234', 'postal')); // ZIP+4 always
    assert.ok(has('zip code 94105', 'postal')); // 5-digit with context
    assert.ok(none('order 94105 shipped', 'postal')); // bare 5-digit at balanced
    assert.ok(has('order 94105 shipped', 'postal', 'loose'));
  });
  it('opt-in heuristics off by default', () => {
    assert.ok(none('Mr Smith arrived', 'personName'));
    assert.ok(has('Mr Smith arrived', 'personName', 'balanced', { personName: true }));
    assert.ok(none('live at 221 Baker Street', 'address'));
    assert.ok(has('live at 221 Baker Street', 'address', 'balanced', { address: true }));
  });
});

describe('PII false-positive guards', () => {
  it('ordinary numbers are not phones/cards', () => {
    assert.ok(none('meeting at 3pm', 'phone'));
    assert.ok(none('order 123456789 confirmed', 'phone'));
    assert.ok(none('version 2.0 released', 'ipv4'));
    assert.ok(none('page 1.2.3 of 9', 'ipv4'));
  });
  it('overlap resolution prefers the most specific finding', () => {
    const found = detectPII('see https://user:secret@example.com/a');
    const urls = found.filter((f) => f.type === 'urlSensitive');
    assert.equal(urls.length, 1);
    // nothing else may overlap the URL span
    for (const f of found) {
      if (f.type === 'urlSensitive') continue;
      assert.ok(f.end <= urls[0].start || f.start >= urls[0].end, `${f.type} overlaps url`);
    }
  });
  it('findings are sorted and bounded', () => {
    const found = detectPII('bob@example.com and 192.168.0.1');
    assert.ok(found[0].start <= found[1].start);
  });
});