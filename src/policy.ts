// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Unified policy: sanitize → normalize → coerce → scrub → truncate.
 * compilePolicy() fuses configuration once; the hot path is allocation-free
 * when disabled stages are omitted (each stage is a null check, not a branch tree).
 */

import { compileSanitizer, type SanitizeOptions } from './sanitize.js';
import { compileScrubber, type CompiledScrubber } from './scrub.js';
import { normalizeCase } from './normalize.js';
import { normalizePhone, normalizeUUID } from './normalize.js';
import { toBoolean, toDate, toFloat, toInteger } from './coerce.js';
import { truncate as truncateStr, type TruncateOptions } from './transform.js';
import { compileStructured, type StructuredPolicy } from './structured.js';
import { validateValue, type FieldSchema, type ValidationResult } from './validate.js';
import type { Finding, ScrubPolicy } from './types.js';

export interface Policy {
  sanitize?: SanitizeOptions | false;
  textCase?: 'lower' | 'upper' | 'fold' | false;
  coerce?: 'integer' | 'float' | 'boolean' | 'date' | 'phone' | 'uuid' | 'string' | false;
  scrub?: ScrubPolicy | false;
  truncate?: TruncateOptions | false;
  /** Single-value validation schema (checked by validate(), never by process()). */
  validate?: FieldSchema;
  structured?: StructuredPolicy;
}

export interface CompiledPolicy {
  process(input: string): string;
  processValue(value: unknown): unknown;
  processJSON(json: string): string;
  validate(value: unknown): ValidationResult;
  detect(input: string): Finding[];
}

function applyCoerce(t: string, coerce: NonNullable<Policy['coerce']>): string {
  if (coerce === false || coerce === 'string') return t;
  if (coerce === 'integer') {
    const v = toInteger(t);
    return v === null ? t : String(v);
  }
  if (coerce === 'float') {
    const v = toFloat(t);
    return v === null ? t : String(v);
  }
  if (coerce === 'boolean') {
    const v = toBoolean(t, { output: 'string' });
    return v === null ? t : (v as string);
  }
  if (coerce === 'date') {
    const v = toDate(t, { output: 'iso' });
    return v === null ? t : (v as string);
  }
  if (coerce === 'phone') {
    const v = normalizePhone(t);
    return typeof v === 'string' ? v : t;
  }
  // uuid
  const v = normalizeUUID(t);
  return v === null ? t : v;
}

export function compilePolicy(policy: Policy = {}): CompiledPolicy {
  const sanitizer = policy.sanitize === false ? null : compileSanitizer(policy.sanitize ?? {});
  const textCase = policy.textCase ?? false;
  const coerce = policy.coerce ?? false;
  const scrubber: CompiledScrubber | null = policy.scrub === false ? null : compileScrubber(policy.scrub ?? {});
  const trunc: TruncateOptions | null = policy.truncate === false ? null : (policy.truncate ?? null);
  const schema: FieldSchema = policy.validate ?? {};
  const hasSchema = Object.keys(schema).length > 0;
  const structured = policy.structured ? compileStructured(policy.structured) : null;

  const process = (input: string): string => {
    let t = input;
    if (sanitizer) t = sanitizer(t);
    if (textCase) t = normalizeCase(t, { mode: textCase });
    if (coerce) t = applyCoerce(t, coerce);
    if (scrubber) t = scrubber.scrub(t);
    if (trunc) t = truncateStr(t, trunc);
    return t;
  };

  return {
    process,
    processValue: (value: unknown): unknown => {
      if (typeof value === 'string') return process(value);
      if (structured) return structured.processValue(value);
      return value;
    },
    processJSON: (json: string): string => {
      if (structured) return structured.processJSON(json);
      // Fallback: process JSON string values generically via a structured compile.
      return compileStructured({ default: {} }).processJSON(json);
    },
    validate: (value: unknown): ValidationResult => {
      if (!hasSchema) return { ok: true, issues: [] };
      return validateValue(value, schema);
    },
    detect: (input: string): Finding[] => (scrubber ? scrubber.detect(input) : []),
  };
}

/** One-shot processing (compiles the policy each call — prefer compilePolicy in loops). */
export function processText(input: string, policy: Policy = {}): string {
  return compilePolicy(policy).process(input);
}