// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Type transforms: string→int/float/bool/date, numeric→canonical string,
 * null/default handling, explicit coercion policies.
 */

import { normalizeBoolean, normalizeDate, normalizeNumber } from './normalize.js';
import type { CoercionPolicy } from './types.js';

export interface IntOptions {
  policy?: CoercionPolicy; // strict: only /^-?\d+$/ ; lenient: trims, allows '_'/' '/',' grouping
  min?: number;
  max?: number;
  base?: 10 | 16 | 8 | 2; // default 10; hex allows 0x prefix
}

function failRange(v: number, min?: number, max?: number): boolean {
  if (min !== undefined && v < min) return true;
  if (max !== undefined && v > max) return true;
  return false;
}

/** Parse integer with explicit policy. Returns null on failure (never throws, never NaN). */
export function toInteger(input: string | number | boolean | null | undefined, opts: IntOptions = {}): number | null {
  const policy = opts.policy ?? 'lenient';
  if (policy === 'off') return typeof input === 'number' && Number.isInteger(input) ? input : null;
  if (typeof input === 'number') {
    if (!Number.isInteger(input) || !Number.isSafeInteger(input)) return null;
    return failRange(input, opts.min, opts.max) ? null : input;
  }
  if (typeof input === 'boolean') {
    const v = input ? 1 : 0;
    return failRange(v, opts.min, opts.max) ? null : v;
  }
  if (input === null || input === undefined) return null;
  let t = input.trim();
  if (t.length === 0 || t.length > 32) return null;
  if (policy === 'strict') {
    if (!/^-?\d+$/.test(t)) return null;
    const v = Number(t);
    if (!Number.isSafeInteger(v)) return null;
    return failRange(v, opts.min, opts.max) ? null : v;
  }
  // lenient: strip grouping, underscores
  t = t.replace(/[_,\s'’  ]/g, '');
  if (opts.base === 16 || /^0x/i.test(t)) {
    if (!/^-?0x[0-9a-fA-F]+$/.test(t)) return null;
    const v = parseInt(t, 16);
    if (!Number.isSafeInteger(v)) return null;
    return failRange(v, opts.min, opts.max) ? null : v;
  }
  if (!/^[+-]?\d+$/.test(t)) return null;
  const v = Number(t);
  if (!Number.isSafeInteger(v)) return null;
  return failRange(v, opts.min, opts.max) ? null : v;
}

export interface FloatOptions {
  policy?: CoercionPolicy;
  min?: number;
  max?: number;
  allowNaN?: boolean; // default false
  allowInfinity?: boolean; // default false
}

/** Parse float/decimal with explicit policy. Returns null on failure. */
export function toFloat(input: string | number | boolean | null | undefined, opts: FloatOptions = {}): number | null {
  const policy = opts.policy ?? 'lenient';
  if (policy === 'off') return typeof input === 'number' ? input : null;
  if (typeof input === 'number') {
    if (Number.isNaN(input)) return opts.allowNaN === true ? input : null;
    if (!Number.isFinite(input)) return opts.allowInfinity === true ? input : null;
    if (opts.min !== undefined && input < opts.min) return null;
    if (opts.max !== undefined && input > opts.max) return null;
    return input;
  }
  if (typeof input === 'boolean') return input ? 1 : 0;
  if (input === null || input === undefined) return null;
  const canon = normalizeNumber(input);
  if (canon === null) return null;
  const v = Number(canon);
  if (Number.isNaN(v)) return opts.allowNaN ? v : null;
  if (!Number.isFinite(v)) return opts.allowInfinity ? v : null;
  if (opts.min !== undefined && v < opts.min) return null;
  if (opts.max !== undefined && v > opts.max) return null;
  return v;
}

export interface BoolOptions {
  policy?: CoercionPolicy;
  output?: 'boolean' | 'number' | 'string';
  trueValues?: string[];
  falseValues?: string[];
}

/** Coerce to boolean-ish. Returns null when unrecognized (strict never guesses). */
export function toBoolean(
  input: string | number | boolean | null | undefined,
  opts: BoolOptions = {},
): boolean | number | string | null {
  const policy = opts.policy ?? 'lenient';
  if (input === null || input === undefined) return null;
  if (typeof input === 'boolean') {
    const o = opts.output ?? 'boolean';
    return o === 'boolean' ? input : o === 'number' ? (input ? 1 : 0) : input ? 'true' : 'false';
  }
  if (typeof input === 'number') {
    if (policy === 'strict' && input !== 0 && input !== 1) return null;
    const b = input !== 0;
    const o = opts.output ?? 'boolean';
    return o === 'boolean' ? b : o === 'number' ? (b ? 1 : 0) : b ? 'true' : 'false';
  }
  const r = normalizeBoolean(input, { trueValues: opts.trueValues, falseValues: opts.falseValues, output: opts.output ?? 'boolean' });
  if (r === null) return null;
  return r as boolean | number | string;
}

export interface DateCoerceOptions {
  output?: 'iso' | 'date' | 'epoch-ms' | 'epoch-s' | 'date-obj';
}

/** Coerce to date/time. Returns null when invalid. */
export function toDate(
  input: string | number | Date | null | undefined,
  opts: DateCoerceOptions = {},
): string | number | Date | null {
  if (input === null || input === undefined) return null;
  const output = opts.output ?? 'iso';
  if (output === 'date-obj') {
    const iso = normalizeDate(input as string | number | Date, { output: 'iso' });
    if (iso === null) return null;
    return new Date(iso as string);
  }
  return normalizeDate(input as string | number | Date, { output: output as 'iso' });
}

/** Canonical string for a finite number (no trailing zeros, 'e' exponents). Null for non-finite. */
export function numberToString(n: number): string | null {
  if (!Number.isFinite(n)) return null;
  if (n === 0) return '0';
  return String(n);
}

/** Null/default handling: empty/blank/null/undefined → defaultValue. */
export function withDefault<T>(value: T | null | undefined, defaultValue: T, treatBlankAsMissing = true): T {
  if (value === null || value === undefined) return defaultValue;
  if (treatBlankAsMissing && typeof value === 'string' && value.trim() === '') return defaultValue;
  return value;
}

/** Null when value is empty/blank/null/undefined, else the value itself. */
export function nullIfEmpty<T>(value: T | null | undefined): T | null {
  if (value === null || value === undefined) return null;
  if (typeof value === 'string' && value.trim() === '') return null;
  return value;
}

/**
 * Coerce a value to the type of `fallback` when possible (explicit, documented):
 * number fallback => toFloat(lenient); boolean => toBoolean; string => String().
 */
export function coerceWithFallback<T>(value: unknown, fallback: T): T {
  if (typeof fallback === 'number') {
    if (typeof value === 'number' && Number.isFinite(value)) return value as T;
    const v = toFloat(value as string | number | boolean | null | undefined);
    return (v === null ? fallback : v) as T;
  }
  if (typeof fallback === 'boolean') {
    const v = toBoolean(value as string | number | boolean | null | undefined);
    return ((v === null ? fallback : v) as unknown) as T;
  }
  if (typeof fallback === 'string') {
    if (typeof value === 'string') return value as T;
    if (value === null || value === undefined) return fallback;
    if (typeof value === 'number' || typeof value === 'boolean') return String(value) as T;
    return fallback;
  }
  return (value ?? fallback) as T;
}