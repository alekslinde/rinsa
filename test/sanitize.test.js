// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  sanitize,
  compileSanitizer,
  sanitizeBytes,
  isValidUTF8,
  utf8ByteLength,
  charLength,
} from '../dist/esm/sanitize.js';

describe('sanitize basics', () => {
  it('trims and collapses by default', () => {
    assert.equal(sanitize('  hello   world  '), 'hello world');
    assert.equal(sanitize('\t a\nb\r\n c '), 'a b c');
  });
  it('returns identical reference when clean (zero-alloc)', () => {
    const s = 'hello world';
    assert.ok(sanitize(s) === s);
    const t = 'abc123';
    assert.ok(compileSanitizer({ trim: false, collapseWhitespace: false })('x') === 'x');
    void t;
  });
  it('trim modes', () => {
    assert.equal(sanitize('  a  ', { trim: 'start', collapseWhitespace: false }), 'a  ');
    assert.equal(sanitize('  a  ', { trim: 'end', collapseWhitespace: false }), '  a');
    assert.equal(sanitize('  a  ', { trim: false, collapseWhitespace: false }), '  a  ');
  });
  it('removes controls with optional replacement', () => {
    assert.equal(sanitize('a\x00b\x1fc'), 'abc');
    assert.equal(sanitize('a\x00b', { replacement: '?' }), 'a?b');
    assert.equal(sanitize('a\x7fb'), 'ab');
  });
  it('removes zero-width and bidi characters', () => {
    assert.equal(sanitize('a​b'), 'ab'); // ZWSP
    assert.equal(sanitize('a‌b'), 'ab'); // ZWNJ
    assert.equal(sanitize('a‍b'), 'ab'); // ZWJ
    assert.equal(sanitize('a‮b'), 'ab'); // RLO bidi
    assert.equal(sanitize('a‎b'), 'ab'); // LRM
    assert.equal(sanitize('﻿bom'), 'bom'); // BOM
    // opt-out keeps them
    assert.equal(sanitize('a​b', { removeZeroWidth: false, removeBidi: false }), 'a​b');
  });
  it('allow/block lists', () => {
    assert.equal(sanitize('abc123!@#', { allow: 'abcdefghijklmnopqrstuvwxyz0123456789' }), 'abc123');
    assert.equal(sanitize('hello world', { block: 'aeiou' }), 'hll wrld');
    assert.equal(sanitize('a1b2', { allow: /[a-z]/ }), 'ab');
  });
  it('length limits (chars and bytes)', () => {
    assert.equal(sanitize('abcdef', { maxChars: 3 }), 'abc');
    assert.equal(sanitize('héllo', { maxBytes: 3 }), 'hé'.slice(0, 2)); // 'h'(1)+'é'(2)=3
    assert.equal(charLength('😀a'), 2);
    assert.equal(utf8ByteLength('😀'), 4);
  });
  it('unicode normalisation forms', () => {
    assert.equal(sanitize('é', { form: 'NFC' }), 'é');
    assert.equal(sanitize('é', { form: 'NFD' }), 'é');
    assert.equal(sanitize('ﬁ', { form: 'NFKC' }), 'fi');
    assert.equal(sanitize('ﬁ', { form: null, collapseWhitespace: false, trim: false }), 'ﬁ');
  });
  it('repairs lone surrogates safely', () => {
    const lone = 'a\ud800b';
    const out = sanitize(lone);
    assert.ok(!out.includes('\ud800') || out === lone);
    assert.equal(out, 'a�b');
    assert.ok(sanitize('ok ✓').includes('✓'));
  });
  it('collapse to custom separator', () => {
    assert.equal(sanitize('a  b\tc', { collapseWhitespace: '-' }), 'a-b-c');
  });
});

describe('utf8 validation', () => {
  it('accepts valid, rejects invalid', () => {
    assert.equal(isValidUTF8(new TextEncoder().encode('hello ✓')), true);
    assert.equal(isValidUTF8(new Uint8Array([0xff, 0xfe])), false);
    assert.equal(isValidUTF8(new Uint8Array([0xe2, 0x82])), false); // truncated
    assert.equal(isValidUTF8(new Uint8Array([0xed, 0xa0, 0x80])), false); // surrogate
    assert.equal(isValidUTF8(new Uint8Array([0xf4, 0x90, 0x80, 0x80])), false); // >U+10FFFF
    assert.equal(isValidUTF8(new Uint8Array([0xc0, 0xaf])), false); // overlong
  });
  it('sanitizeBytes replaces invalid sequences', () => {
    const out = sanitizeBytes(new Uint8Array([0x68, 0x69, 0xff, 0x21]));
    assert.equal(out, 'hi�!');
  });
});

describe('compiled sanitizer reuse', () => {
  it('compiled closure matches one-shot', () => {
    const fn = compileSanitizer({ maxChars: 5 });
    assert.equal(fn('  abcdefgh  '), 'abcde');
    assert.equal(fn('  abcdefgh  '), sanitize('  abcdefgh  ', { maxChars: 5 }));
  });
});