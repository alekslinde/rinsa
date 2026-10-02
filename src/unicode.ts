// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Unicode helpers: normal forms, ASCII fast paths, case folding.
 * Uses built-in String.normalize (native, fast) with ASCII short-circuit.
 */

export type NormalForm = 'NFC' | 'NFD' | 'NFKC' | 'NFKD';

export function isAsciiOnly(s: string): boolean {
  for (let i = 0; i < s.length; i++) if (s.charCodeAt(i) > 127) return false;
  return true;
}

/** Normalize to the given form. Returns input unchanged when ASCII (all forms are no-ops there). */
export function normalizeForm(s: string, form: NormalForm = 'NFC'): string {
  if (s.length === 0 || isAsciiOnly(s)) return s;
  return s.normalize(form);
}

/** Unicode-aware lowercase with ASCII fast path (lazy: same ref when already lower). */
export function lower(s: string): string {
  let asciiOnly = true;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) {
      asciiOnly = false;
      break;
    }
    if (c >= 65 && c <= 90) {
      // has uppercase — need work; fall through
      asciiOnly = false; // reuse flag: means "needs slow path"
      break;
    }
  }
  if (asciiOnly) return s;
  // Check pure-ASCII quickly to use manual loop (avoids locale machinery)
  let pureAscii = true;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 127) {
      pureAscii = false;
      break;
    }
  }
  if (pureAscii) {
    let dirty = false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 65 && c <= 90) {
        dirty = true;
        break;
      }
    }
    if (!dirty) return s;
    const out = new Array<string>(s.length);
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      out[i] = c >= 65 && c <= 90 ? String.fromCharCode(c + 32) : s[i]!;
    }
    return out.join('');
  }
  const r = s.toLowerCase();
  return r === s ? s : r;
}

/** Unicode-aware uppercase with ASCII fast path. */
export function upper(s: string): string {
  let pureAscii = true;
  for (let i = 0; i < s.length; i++) {
    if (s.charCodeAt(i) > 127) {
      pureAscii = false;
      break;
    }
  }
  if (pureAscii) {
    let dirty = false;
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      if (c >= 97 && c <= 122) {
        dirty = true;
        break;
      }
    }
    if (!dirty) return s;
    const out = new Array<string>(s.length);
    for (let i = 0; i < s.length; i++) {
      const c = s.charCodeAt(i);
      out[i] = c >= 97 && c <= 122 ? String.fromCharCode(c - 32) : s[i]!;
    }
    return out.join('');
  }
  const r = s.toUpperCase();
  return r === s ? s : r;
}

/**
 * Full case folding for case-insensitive comparison (Unicode CaseFolding.txt simple + full
 * for the common special cases; remainder delegates to lowercase).
 * NFKC-then-fold is available via `fold(s, { normalize: 'NFKC' })`.
 */
export function fold(s: string, opts: { normalize?: NormalForm | false } = {}): string {
  let t = s;
  if (opts.normalize) t = normalizeForm(t, opts.normalize);
  // Fast path: ASCII lower
  let ascii = true;
  for (let i = 0; i < t.length; i++) {
    if (t.charCodeAt(i) > 127) {
      ascii = false;
      break;
    }
  }
  if (ascii) return lower(t);
  // Special-case full folds that toLowerCase misses
  let special = false;
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c === 0xdf || c === 0x130 || c === 0x17f || c === 0x212a) {
      special = true;
      break;
    }
  }
  let base = t.toLowerCase();
  if (!special) return base === s ? s : base;
  base = base
    .replace(/ß/g, 'ss')
    .replace(/ſ/g, 's')
    .replace(/K/g, 'k')
    .replace(/İ/g, 'i̇');
  return base;
}

/** Strip diacritics (NFD + remove Mn). ASCII passes through by reference. */
export function stripDiacritics(s: string): string {
  if (s.length === 0 || isAsciiOnly(s)) return s;
  const d = s.normalize('NFD');
  let dirty = false;
  for (let i = 0; i < d.length; i++) {
    const c = d.charCodeAt(i);
    if (c >= 0x300 && c <= 0x36f) {
      dirty = true;
      break;
    }
  }
  if (!dirty) return s;
  return d.replace(/[̀-ͯ]+/g, '');
}

/** Case-insensitive equality via folding (no allocation when ASCII-equal fast path hits). */
export function equalFold(a: string, b: string): boolean {
  if (a === b) return true;
  if (a.length !== b.length) {
    // lengths may differ after folds (ß→ss); fall through to full fold compare
    if (Math.abs(a.length - b.length) > 8) return fold(a) === fold(b);
    return fold(a) === fold(b);
  }
  return fold(a) === fold(b);
}