// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Generic transforms: map, replace, filter, trim, case, char filtering,
 * defaulting, masking, redaction, hashing, HMAC, tokenization, truncation.
 * All string transforms return the input by reference when unchanged.
 */

import { createHash, createHmac } from 'node:crypto';
import { lower as lowerText, upper as upperText } from './unicode.js';

/** Map each character through `fn`. Return null/undefined from fn to drop the char. */
export function mapChars(s: string, fn: (ch: string, index: number) => string | null | undefined): string {
  if (s.length === 0) return s;
  let out: string[] | null = null;
  let pos = 0; // code-point index for fn
  for (let i = 0; i < s.length; ) {
    const cp = s.codePointAt(i)!;
    const w = cp > 0xffff ? 2 : 1;
    const ch = s.slice(i, i + w);
    const r = fn(ch, pos);
    if (r !== ch) {
      if (out === null) {
        out = [s.slice(0, i)];
      }
      if (r !== null && r !== undefined) out.push(r);
    } else if (out !== null) {
      out.push(ch);
    }
    pos++;
    i += w;
  }
  return out === null ? s : out.join('');
}

/** Literal replace-all (no regex). Returns input by reference when `from` absent. */
export function replaceAll(s: string, from: string, to: string): string {
  if (from === '' || !s.includes(from)) return s;
  return s.split(from).join(to);
}

/** Regex replace with a precompiled pattern. */
export function replacePattern(s: string, pattern: RegExp, to: string): string {
  pattern.lastIndex = 0;
  if (!pattern.test(s)) return s;
  pattern.lastIndex = 0;
  return s.replace(pattern, to);
}

/** Keep only characters for which `keep(ch)` is true. */
export function filterChars(s: string, keep: (ch: string) => boolean): string {
  if (s.length === 0) return s;
  let out: string[] | null = null;
  for (let i = 0; i < s.length; ) {
    const cp = s.codePointAt(i)!;
    const w = cp > 0xffff ? 2 : 1;
    const ch = s.slice(i, i + w);
    let k: boolean;
    try {
      k = keep(ch);
    } catch {
      k = true;
    }
    if (!k) {
      if (out === null) out = [s.slice(0, i)];
    } else if (out !== null) {
      out.push(ch);
    }
    i += w;
  }
  return out === null ? s : out.join('');
}

/** Keep only ASCII alphanumerics plus `extra`. Fast path for identifier cleanup. */
export function filterAlnum(s: string, extra = ''): string {
  if (s.length === 0) return s;
  const ex = new Set([...extra]);
  let out: string[] | null = null;
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    const ok = (c >= 48 && c <= 57) || (c >= 65 && c <= 90) || (c >= 97 && c <= 122) || ex.has(s[i]!);
    if (!ok) {
      if (out === null) out = [s.slice(0, i)];
    } else if (out !== null) {
      out.push(s[i]!);
    }
  }
  return out === null ? s : out.join('');
}

export function trimBoth(s: string): string {
  if (s.length === 0) return s;
  const t = s.trim();
  return t === s ? s : t;
}

export function toLower(s: string): string {
  return lowerText(s);
}

export function toUpper(s: string): string {
  return upperText(s);
}

/** Apply default when null/undefined/blank. */
export function withDefaultStr(value: string | null | undefined, def: string): string {
  if (value === null || value === undefined || value.trim() === '') return def;
  return value;
}

// ---- Masking / redaction ----

export interface MaskOptions {
  maskChar?: string;
  preserveStart?: number;
  preserveEnd?: number;
  preserveLength?: boolean; // default true; false => fixed 8-char mask
}

/** Mask a value, e.g. mask('4111111111111111',{preserveEnd:4}) => '************1111'. */
export function mask(s: string, opts: MaskOptions = {}): string {
  const ch = opts.maskChar ?? '*';
  const ps = opts.preserveStart ?? 0;
  const pe = opts.preserveEnd ?? 0;
  const keepLen = opts.preserveLength ?? true;
  if (s.length === 0) return s;
  const n = [...s].length; // code-point length
  if (ps + pe >= n) return s; // nothing to mask without leaking structure
  if (!keepLen) return ch.repeat(8);
  const cps = [...s];
  const out = cps.map((c, idx) => (idx < ps || idx >= n - pe ? c : ch)).join('');
  return out === s ? s : out;
}

/** Redact fully: return placeholder (default '[REDACTED]'). */
export function redact(_s: string, placeholder = '[REDACTED]'): string {
  return placeholder;
}

// ---- Hashing / HMAC / tokenize ----

export type HashAlg = 'sha256' | 'sha512';

export function hashValue(s: string, alg: HashAlg = 'sha256', outLength?: number): string {
  const h = createHash(alg).update(s, 'utf8').digest('hex');
  return outLength !== undefined ? h.slice(0, outLength) : h;
}

export function hmacValue(s: string, key: string | Uint8Array, alg: HashAlg = 'sha256', outLength?: number): string {
  const h = createHmac(alg, key).update(s, 'utf8').digest('hex');
  return outLength !== undefined ? h.slice(0, outLength) : h;
}

export interface TokenizeOptions {
  prefix?: string; // default 'tok_'
  key?: string | Uint8Array; // HMAC key; default is a fixed library constant (deterministic, NOT secret)
  length?: number; // hex chars kept, default 16
  vault?: Map<string, string>; // optional caller-owned reverse map (token -> original)
}

const DEFAULT_TOKEN_KEY = 'rinsa/token/v1';

/** Deterministic tokenization: HMAC-based token. Reversible only via caller-provided vault. */
export function tokenize(s: string, opts: TokenizeOptions = {}): string {
  const tok = (opts.prefix ?? 'tok_') + hmacValue(s, opts.key ?? DEFAULT_TOKEN_KEY, 'sha256', opts.length ?? 16);
  if (opts.vault && !opts.vault.has(tok)) opts.vault.set(tok, s);
  return tok;
}

// ---- Truncation ----

export interface TruncateOptions {
  maxLength?: number; // code points, default 8
  suffix?: string; // default '…'
  byBytes?: boolean; // truncate by UTF-8 bytes instead of code points
}

/** Truncate with suffix. Returns input by reference when within limits. */
export function truncate(s: string, opts: TruncateOptions = {}): string {
  const max = opts.maxLength ?? 8;
  const suffix = opts.suffix ?? '…';
  if (!opts.byBytes) {
    const cps = [...s];
    if (cps.length <= max) return s;
    return cps.slice(0, max).join('') + suffix;
  }
  const enc = new TextEncoder();
  const bytes = enc.encode(s);
  if (bytes.length <= max) return s;
  const dec = new TextDecoder('utf-8', { fatal: false });
  // Cut then decode (fatal:false drops the split tail safely); trim to fit suffix.
  const sufBytes = enc.encode(suffix).length;
  const cut = dec.decode(bytes.slice(0, Math.max(0, max - sufBytes)));
  return cut + suffix;
}

/** Compose transforms left-to-right into a single function (fusion-friendly). */
export function pipe(...fns: Array<(s: string) => string>): (s: string) => string {
  if (fns.length === 0) return (s) => s;
  if (fns.length === 1) return fns[0]!;
  return (s: string) => {
    let cur = s;
    for (const fn of fns) cur = fn(cur);
    return cur;
  };
}