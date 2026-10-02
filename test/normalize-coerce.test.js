// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  normalizeCase,
  normalizeWhitespace,
  normalizeNumber,
  normalizeBoolean,
  normalizeDate,
  normalizeIdentifier,
  normalizeUUID,
  normalizePhone,
  canonicalString,
  compileReplacements,
} from '../dist/esm/normalize.js';
import { lower, upper, fold, stripDiacritics, equalFold, normalizeForm } from '../dist/esm/unicode.js';
import {
  toInteger,
  toFloat,
  toBoolean,
  toDate,
  numberToString,
  withDefault,
  nullIfEmpty,
  coerceWithFallback,
} from '../dist/esm/coerce.js';

describe('unicode', () => {
  it('forms and ascii fast paths', () => {
    const ascii = 'ABC';
    assert.ok(normalizeForm(ascii, 'NFKC') === ascii);
    assert.equal(lower('ABC'), 'abc');
    assert.equal(upper('abc'), 'ABC');
    assert.ok(lower('abc') === 'abc');
    assert.equal(fold('ß'), 'ss');
    assert.equal(stripDiacritics('café naïve'), 'cafe naive');
    assert.ok(equalFold('Straße', 'strasse'));
    assert.ok(!equalFold('abc', 'abd'));
  });
});

describe('normalisation', () => {
  it('case modes', () => {
    assert.equal(normalizeCase('HeLLo', { mode: 'lower' }), 'hello');
    assert.equal(normalizeCase('HeLLo', { mode: 'upper' }), 'HELLO');
    assert.equal(normalizeCase('Straße', { mode: 'fold' }), 'strasse');
  });
  it('whitespace', () => {
    assert.equal(normalizeWhitespace('  a \t b  '), 'a b');
    assert.equal(normalizeWhitespace('a  b', { trim: false }), 'a b');
  });
  it('numbers', () => {
    assert.equal(normalizeNumber('1,000.50'), '1000.5');
    assert.equal(normalizeNumber('1.000,50'), '1000.5');
    assert.equal(normalizeNumber('+007.500'), '7.5');
    assert.equal(normalizeNumber('1E3'), '1e3');
    assert.equal(normalizeNumber('-0.0'), '0');
    assert.equal(normalizeNumber('abc'), null);
    assert.equal(normalizeNumber('1.2.3'), null);
    assert.equal(normalizeNumber(''), null);
    assert.equal(normalizeNumber('1e'), null);
  });
  it('booleans', () => {
    assert.equal(normalizeBoolean('YES'), 'true');
    assert.equal(normalizeBoolean('off'), 'false');
    assert.equal(normalizeBoolean(1, { output: 'boolean' }), true);
    assert.equal(normalizeBoolean('maybe'), null);
  });
  it('dates', () => {
    assert.equal(normalizeDate('2024-03-05'), '2024-03-05');
    assert.equal(normalizeDate('03/05/2024'), '2024-03-05');
    assert.equal(normalizeDate('05.03.2024'), '2024-03-05');
    assert.equal(normalizeDate('2024-03-05T12:00:00Z'), '2024-03-05T12:00:00.000Z');
    assert.equal(normalizeDate(0, { output: 'epoch-s' }), 0);
    assert.equal(normalizeDate('not a date'), null);
    assert.equal(normalizeDate('13/45/2024'), null);
    assert.equal(normalizeDate('2024-02-30'), null); // rolls over -> rejected
  });
  it('identifiers / uuid / phone / canonical', () => {
    assert.equal(normalizeIdentifier('  Hello_World Ref '), 'hello-world-ref');
    assert.equal(normalizeUUID('{550E8400-E29B-41D4-A716-446655440000}'), '550e8400-e29b-41d4-a716-446655440000');
    assert.equal(normalizeUUID('not-a-uuid'), null);
    assert.equal(normalizePhone('+1 (415) 555-0132'), '+14155550132');
    assert.equal(normalizePhone('415-555-0132'), '4155550132');
    assert.equal(normalizePhone('12'), null);
    assert.equal(canonicalString('  Héllo   WORLD '), 'héllo world');
  });
  it('compiled replacements', () => {
    const rep = compileReplacements([['&', 'and'], ['@', 'at']]);
    assert.equal(rep('a&b@c'), 'aandbatc');
    const noop = compileReplacements([]);
    const s = 'x';
    assert.ok(noop(s) === s);
  });
});

describe('coercion', () => {
  it('integers with policies', () => {
    assert.equal(toInteger('42'), 42);
    assert.equal(toInteger(' 1_000 ', { policy: 'lenient' }), 1000);
    assert.equal(toInteger('1_000', { policy: 'strict' }), null);
    assert.equal(toInteger('0x10'), 16);
    assert.equal(toInteger(3.5), null);
    assert.equal(toInteger('99', { max: 10 }), null);
    assert.equal(toInteger(true), 1);
    assert.equal(toInteger('x', { policy: 'off' }), null);
  });
  it('floats', () => {
    assert.equal(toFloat('1,000.5'), 1000.5);
    assert.equal(toFloat('NaN'), null);
    assert.ok(Number.isNaN(toFloat(NaN, { allowNaN: true })));
    assert.equal(toFloat(Infinity), null);
    assert.equal(toFloat('5', { min: 10 }), null);
  });
  it('booleans / dates', () => {
    assert.equal(toBoolean('yes'), true);
    assert.equal(toBoolean('0'), false);
    assert.equal(toBoolean(2, { policy: 'strict' }), null);
    assert.equal(toBoolean(null), null);
    assert.equal(toDate('2024-01-02', { output: 'date-obj' }) instanceof Date, true);
    assert.equal(toDate('junk'), null);
  });
  it('misc helpers', () => {
    assert.equal(numberToString(1.5), '1.5');
    assert.equal(numberToString(Infinity), null);
    assert.equal(withDefault('', 'd'), 'd');
    assert.equal(withDefault('v', 'd'), 'v');
    assert.equal(nullIfEmpty('   '), null);
    assert.equal(coerceWithFallback('12', 0), 12);
    assert.equal(coerceWithFallback('x', 7), 7);
    assert.equal(coerceWithFallback('yes', false), true);
  });
});