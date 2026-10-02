// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Normalisation: case, whitespace, numbers, booleans, dates, identifiers,
 * UUIDs, phones, canonical strings, configurable mappings.
 * All functions are pure, total, and return the input by reference when unchanged.
 */

import { lower as lowerText, upper as upperText, fold as foldText, normalizeForm, type NormalForm } from './unicode.js';

export interface CaseOptions {
  mode?: 'lower' | 'upper' | 'fold' | false;
  form?: NormalForm | false;
}

export function normalizeCase(s: string, opts: CaseOptions = {}): string {
  const mode = opts.mode ?? 'lower';
  let t = s;
  if (opts.form) t = normalizeForm(t, opts.form);
  if (mode === false) return t;
  if (mode === 'lower') return lowerText(t);
  if (mode === 'upper') return upperText(t);
  return foldText(t);
}

export interface WhitespaceOptions {
  collapseTo?: string;
  trim?: boolean;
}

/** Collapse all whitespace runs to a single separator (default ' ') with optional trim. */
export function normalizeWhitespace(s: string, opts: WhitespaceOptions = {}): string {
  const to = opts.collapseTo ?? ' ';
  const trim = opts.trim ?? true;
  if (s.length === 0) return s;
  // ASCII fast path
  let ascii = true;
  let hasWS = false;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if (c > 127) {
      ascii = false;
      break;
    }
    if (c === 0x20 || (c >= 0x09 && c <= 0x0d)) hasWS = true;
  }
  if (ascii && !hasWS) return s;
  // General path via single regex-free pass is in sanitize; here use compact impl:
  let r = s.replace(/[\t\n\f\r \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000\ufeff]+/g, to);
  if (trim) {
    if (r.startsWith(to)) r = r.slice(to.length);
    if (r.endsWith(to) && r.length >= to.length) r = r.slice(0, r.length - to.length);
  }
  return r === s ? s : r;
}

// ---- Numbers ----

export interface NumberNormOptions {
  decimalSeparator?: string; // output decimal sep, default '.'
  inputDecimal?: string[]; // accepted input decimal seps, default ['.', ',']
  grouping?: string[]; // chars stripped as grouping, default [' ', "'", '’', '\u00a0', '\u2009']
  trimZeros?: boolean; // strip trailing fractional zeros, default true
  lowercaseExp?: boolean; // 'E' -> 'e', default true
}

/**
 * Canonicalise a numeric string: unify decimal separator, strip grouping,
 * normalise exponent, strip redundant zeros/signs. Returns null when not numeric.
 * Never throws; returns input slice (new string) only when valid.
 */
export function normalizeNumber(s: string, opts: NumberNormOptions = {}): string | null {
  const outDec = opts.decimalSeparator ?? '.';
  const inDec = opts.inputDecimal ?? ['.', ','];
  const grouping = opts.grouping ?? [' ', "'", '’', ' ', ' '];
  const trimZeros = opts.trimZeros ?? true;
  const lowerExp = opts.lowercaseExp ?? true;
  let t = s.trim();
  if (t.length === 0 || t.length > 64) return null;
  // Fast reject: allowed chars
  let hasDigit = false;
  for (let i = 0; i < t.length; i++) {
    const c = t[i]!;
    if (c >= '0' && c <= '9') {
      hasDigit = true;
      continue;
    }
    if (c === '+' || c === '-' || c === 'e' || c === 'E') continue;
    if (inDec.includes(c) || grouping.includes(c)) continue;
    return null;
  }
  if (!hasDigit) return null;
  // Strip grouping
  let u = '';
  for (let i = 0; i < t.length; i++) {
    const c = t[i]!;
    if (grouping.includes(c)) continue;
    u += c;
  }
  // If both '.' and ',' present, last one is the decimal separator.
  let decUsed: string | null = null;
  const dotI = u.lastIndexOf('.');
  const commaI = u.lastIndexOf(',');
  if (inDec.includes('.') && inDec.includes(',')) {
    if (dotI >= 0 && commaI >= 0) decUsed = dotI > commaI ? '.' : ',';
    else if (dotI >= 0) decUsed = '.';
    else if (commaI >= 0) decUsed = ',';
  } else {
    for (const d of inDec) if (u.includes(d)) decUsed = d;
  }
  // The non-decimal separator (if any) acts as grouping: strip it.
  if (decUsed !== null) {
    for (const d of inDec) {
      if (d !== decUsed && u.includes(d)) u = u.split(d).join('');
    }
  }
  // Validate structure with a single pass state machine
  let i = 0;
  if (u[i] === '+' || u[i] === '-') i++;
  let intDigits = 0;
  let fracDigits = 0;
  let expDigits = 0;
  let seenDec = false;
  let seenExp = false;
  for (; i < u.length; i++) {
    const c = u[i]!;
    if (c >= '0' && c <= '9') {
      if (seenExp) expDigits++;
      else if (seenDec) fracDigits++;
      else intDigits++;
      continue;
    }
    if (!seenExp && !seenDec && decUsed !== null && c === decUsed) {
      seenDec = true;
      continue;
    }
    if (!seenExp && (c === 'e' || c === 'E')) {
      // exponent must follow digits and precede optional sign + digits
      if (intDigits + fracDigits === 0) return null;
      seenExp = true;
      if (u[i + 1] === '+' || u[i + 1] === '-') i++;
      continue;
    }
    return null;
  }
  if (intDigits + fracDigits === 0 || (seenExp && expDigits === 0)) return null;

  // Build canonical form
  let [mant, exp = ''] = u.split(/e/i);
  void exp;
  let m = mant!.replace(new RegExp(escapeRe(decUsed ?? '.'), 'g'), outDec);
  if (m.startsWith('+')) m = m.slice(1);
  m = m.replace(/^(-?)0+(?=\d)/, '$1'); // strip redundant leading zeros, keep one
  if (trimZeros && m.includes(outDec)) {
    const [ip, fp = ''] = m.split(outDec);
    const fpt = fp.replace(/0+$/, '');
    m = fpt.length > 0 ? (ip ?? '') + outDec + fpt : (ip ?? '');
    if (m === '' || m === '-') m = '0';
    // '-0' -> '0'
    if (/^-0+$/.test(m)) m = '0';
    void ip;
  }
  let e = '';
  const em = u.match(/[eE]([+-]?\d+)$/);
  if (em) {
    let digits = em[1]!.replace(/^\+/, '').replace(/^(-?)0+(\d)/, '$1$2');
    if (/^-0+$/.test(digits) || digits === '-0') digits = '0';
    e = (lowerExp ? 'e' : 'E') + digits;
  }
  const canon = m + e;
  return canon;
}

function escapeRe(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ---- Booleans ----

const TRUE_SET = new Set(['1', 'true', 'yes', 'y', 'on', 't', 'enabled', 'active']);
const FALSE_SET = new Set(['0', 'false', 'no', 'n', 'off', 'f', 'disabled', 'inactive']);

export interface BoolNormOptions {
  trueValues?: string[];
  falseValues?: string[];
  output?: 'string' | 'number' | 'boolean';
}

/** Normalise a boolean-ish value to canonical 'true'/'false' (or 1/0/bool). Returns null when unrecognized. */
export function normalizeBoolean(
  input: string | boolean | number,
  opts: BoolNormOptions = {},
): 'true' | 'false' | 1 | 0 | boolean | null {
  const out = opts.output ?? 'string';
  const t = opts.trueValues ? new Set(opts.trueValues.map((v) => v.toLowerCase())) : TRUE_SET;
  const f = opts.falseValues ? new Set(opts.falseValues.map((v) => v.toLowerCase())) : FALSE_SET;
  let b: boolean | null = null;
  if (typeof input === 'boolean') b = input;
  else if (typeof input === 'number') {
    if (input === 1) b = true;
    else if (input === 0) b = false;
  } else {
    const k = input.trim().toLowerCase();
    if (t.has(k)) b = true;
    else if (f.has(k)) b = false;
  }
  if (b === null) return null;
  if (out === 'boolean') return b;
  if (out === 'number') return b ? 1 : 0;
  return b ? 'true' : 'false';
}

// ---- Dates ----

export interface DateNormOptions {
  /** Output 'iso' (default) => YYYY-MM-DDTHH:mm:ss.sssZ when time present, else YYYY-MM-DD. */
  output?: 'iso' | 'date' | 'epoch-ms' | 'epoch-s';
}

/**
 * Normalise common date/time strings to ISO. Accepts ISO-8601, RFC-2822-ish,
 * 'YYYY-MM-DD', 'MM/DD/YYYY', 'DD.MM.YYYY', epoch seconds/ms. Returns null when invalid.
 * NOTE: 2-digit ambiguities resolve MDY for '/' and DMY for '.' (documented default).
 */
export function normalizeDate(input: string | number | Date, opts: DateNormOptions = {}): string | number | null {
  const output = opts.output ?? 'iso';
  let ms: number | null = null;
  if (input instanceof Date) {
    const t = input.getTime();
    ms = Number.isNaN(t) ? null : t;
  } else if (typeof input === 'number') {
    if (!Number.isFinite(input)) return null;
    ms = input < 1e12 ? input * 1000 : input; // heuristic: <1e12 => seconds
    if (ms < -62167219200000 || ms > 253402300799999) return null;
  } else {
    const t = input.trim();
    if (t.length === 0 || t.length > 64) return null;
    if (/^-?\d{10,13}$/.test(t)) {
      const n = Number(t);
      ms = t.length <= 10 ? n * 1000 : n;
    } else {
      // YYYY-MM-DD[ HH:mm[:ss]]
      let m = t.match(/^(\d{4})-(\d{2})-(\d{2})(?:[T ](\d{2}):(\d{2})(?::(\d{2})(?:\.(\d{1,3}))?)?(Z|[+-]\d{2}:?\d{2})?)?$/);
      if (m) {
        const iso = m[4]
          ? `${m[1]}-${m[2]}-${m[3]}T${m[4]}:${m[5]}:${m[6] ?? '00'}.${(m[7] ?? '000').padEnd(3, '0')}${m[8] ?? 'Z'}`
          : `${m[1]}-${m[2]}-${m[3]}T00:00:00.000Z`;
        const v = Date.parse(iso);
        if (Number.isNaN(v)) {
          ms = null;
        } else {
          // Reject impossible calendar dates that JS rolls over (e.g. Feb 30).
          const chk = new Date(v);
          ms =
            chk.getUTCFullYear() === Number(m[1]) && chk.getUTCMonth() + 1 === Number(m[2]) && chk.getUTCDate() === Number(m[3])
              ? v
              : null;
        }
      } else if ((m = t.match(/^(\d{1,2})\/(\d{1,2})\/(\d{4})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?\s*([AP]M)?)?$/i))) {
        // MM/DD/YYYY
        const mo = Number(m[1]);
        const d = Number(m[2]);
        const y = Number(m[3]);
        if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
          let hh = m[4] ? Number(m[4]) : 0;
          if (m[7]?.toUpperCase() === 'PM' && hh < 12) hh += 12;
          if (m[7]?.toUpperCase() === 'AM' && hh === 12) hh = 0;
          const v = Date.UTC(y, mo - 1, d, hh, m[5] ? Number(m[5]) : 0, m[6] ? Number(m[6]) : 0);
          const chk = new Date(v);
          ms = chk.getUTCFullYear() === y && chk.getUTCMonth() === mo - 1 && chk.getUTCDate() === d ? v : null;
        }
      } else if ((m = t.match(/^(\d{1,2})\.(\d{1,2})\.(\d{4})(?:[T ](\d{1,2}):(\d{2})(?::(\d{2}))?)?$/))) {
        // DD.MM.YYYY
        const d = Number(m[1]);
        const mo = Number(m[2]);
        const y = Number(m[3]);
        if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) {
          const v = Date.UTC(y, mo - 1, d, m[4] ? Number(m[4]) : 0, m[5] ? Number(m[5]) : 0, m[6] ? Number(m[6]) : 0);
          const chk = new Date(v);
          ms = chk.getUTCFullYear() === y && chk.getUTCMonth() === mo - 1 && chk.getUTCDate() === d ? v : null;
        }
      } else {
        const v = Date.parse(t);
        ms = Number.isNaN(v) ? null : v;
      }
    }
  }
  if (ms === null || Number.isNaN(ms)) return null;
  if (output === 'epoch-ms') return Math.trunc(ms);
  if (output === 'epoch-s') return Math.trunc(ms / 1000);
  const d = new Date(ms);
  if (output === 'date') return d.toISOString().slice(0, 10);
  // 'iso': date-only inputs stay date-only
  if (typeof input === 'string' && /^\d{4}-\d{2}-\d{2}$/.test(input.trim())) return d.toISOString().slice(0, 10);
  if (typeof input === 'string' && /^(\d{1,2})[\/.](\d{1,2})[\/.]\d{4}$/.test(input.trim())) return d.toISOString().slice(0, 10);
  return d.toISOString();
}

// ---- Identifiers / UUID / phone / canonical ----

export interface IdentifierOptions {
  case?: 'lower' | 'upper' | 'keep';
  form?: NormalForm | false;
  /** Replace these separators with `separator` (default strips '-_.: ' variants to '-'). */
  canonicalSeparator?: string | false;
  stripDiacritics?: boolean;
  maxLength?: number;
}

/** Normalise slugs/keys/handles: NFKC, separator canonicalisation, optional case/strip. */
export function normalizeIdentifier(s: string, opts: IdentifierOptions = {}): string {
  let t = s;
  if (opts.form !== false) t = normalizeForm(t, opts.form ?? 'NFKC');
  const sep = opts.canonicalSeparator ?? '-';
  if (sep !== false) {
    // Collapse runs of common separators into one `sep`, then trim edge runs.
    const r = t.replace(/[-_.:    -   　﻿]+/g, sep);
    if (r !== t) t = r;
    if (t.length > 1) {
      const esc = sep.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
      const trimmed = t.replace(new RegExp(`^${esc}+|${esc}+$`, 'g'), '');
      if (trimmed !== t) t = trimmed;
    }
  }
  if (opts.stripDiacritics) {
    // inline to avoid import cycle cost (unicode already imported for forms)
    const d = t.normalize('NFD').replace(/[̀-ͯ]+/g, '');
    t = d;
  }
  const c = opts.case ?? 'lower';
  if (c === 'lower') t = lowerText(t);
  else if (c === 'upper') t = upperText(t);
  if (opts.maxLength !== undefined && t.length > opts.maxLength) t = t.slice(0, opts.maxLength);
  return t;
}

/** Normalise UUID to lowercase hyphenated form. Returns null when invalid. */
export function normalizeUUID(s: string): string | null {
  const t = s.trim();
  if (t.length > 40) return null;
  const hex = t.replace(/[{}\s-]/g, '');
  if (hex.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(hex)) return null;
  const h = hex.toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

export interface PhoneNormOptions {
  defaultCountryPrefix?: string; // e.g. '+1'; prepended when number lacks '+'. Default: none (national kept as digits).
  extension?: boolean; // parse trailing 'x123'/'ext 123' into { number, ext }. Default false.
}

/**
 * Normalise phones to a canonical digit form: '+<digits>' when an explicit '+'
 * is present, otherwise bare digits. Strips formatting, converts leading '00' to '+'.
 * Returns null when digit count is outside 7..15 (E.164 range).
 */
export function normalizePhone(
  s: string,
  opts: PhoneNormOptions = {},
): string | { number: string; ext: string | null } | null {
  let t = s.trim();
  if (t.length === 0 || t.length > 40) return null;
  let ext: string | null = null;
  if (opts.extension) {
    const m = t.match(/(?:\s*(?:ext|x|#)\s*\.?:?\s*(\d{1,6}))\s*$/i);
    if (m) {
      ext = m[1]!;
      t = t.slice(0, m.index).trim();
    }
  }
  const hasPlus = t.startsWith('+');
  let digits = '';
  for (let i = 0; i < t.length; i++) {
    const c = t.charCodeAt(i);
    if (c >= 48 && c <= 57) digits += t[i];
    else if (c === 43 && i === 0) continue; // leading +
    else if (c === 32 || c === 45 || c === 46 || c === 40 || c === 41 || c === 47) continue; // formatting
    else return null;
  }
  if (digits.startsWith('00') && digits.length > 2) {
    digits = digits.slice(2);
    // '00' prefix means international
    const num = '+' + digits;
    if (digits.length < 7 || digits.length > 15) return null;
    return opts.extension ? { number: num, ext } : num;
  }
  if (hasPlus) {
    if (digits.length < 7 || digits.length > 15) return null;
    const num = '+' + digits;
    return opts.extension ? { number: num, ext } : num;
  }
  if (opts.defaultCountryPrefix && digits.length >= 7 && digits.length <= 15) {
    const num = opts.defaultCountryPrefix + digits.replace(new RegExp('^' + escapeRe(opts.defaultCountryPrefix.replace('+', ''))), '');
    void num;
    const full = digits.startsWith(opts.defaultCountryPrefix.replace('+', '')) ? '+' + digits : opts.defaultCountryPrefix + digits;
    return opts.extension ? { number: full, ext } : full;
  }
  if (digits.length < 7 || digits.length > 15) return null;
  return opts.extension ? { number: digits, ext } : digits;
}

/** Canonical string: NFKC + trim + collapse + optional case. Suitable for dedupe keys. */
export function canonicalString(s: string, opts: { case?: 'lower' | 'upper' | 'keep' } = {}): string {
  let t = normalizeForm(s, 'NFKC');
  t = t.trim().replace(/\s+/g, ' ');
  const c = opts.case ?? 'lower';
  if (c === 'lower') return lowerText(t);
  if (c === 'upper') return upperText(t);
  return t;
}

/** Apply a list of literal replacements (ordered) — precompile via compileReplacements for reuse. */
export function compileReplacements(pairs: Array<[string, string]>): (s: string) => string {
  if (pairs.length === 0) return (s) => s;
  return (s: string) => {
    let out: string | null = null;
    let cur = s;
    for (const [from, to] of pairs) {
      if (from === '' || !cur.includes(from)) continue;
      const next = cur.split(from).join(to);
      if (next !== cur) {
        cur = next;
        out = next;
      }
    }
    return out ?? s;
  };
}