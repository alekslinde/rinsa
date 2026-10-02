// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Validation — intentionally separate from transformation.
 * Validators never mutate and never echo raw values in issues
 * (only type name + lengths are reported).
 */

import type { ValidationIssue, ValidationResult } from './types.js';

export type { ValidationIssue, ValidationResult } from './types.js';

export type FieldType =
  | 'string'
  | 'integer'
  | 'number'
  | 'boolean'
  | 'date'
  | 'uuid'
  | 'email'
  | 'phone'
  | 'url'
  | 'array'
  | 'object';

export interface FieldSchema {
  type?: FieldType | FieldType[];
  required?: boolean;
  nullable?: boolean;
  minLength?: number;
  maxLength?: number;
  min?: number;
  max?: number;
  enum?: unknown[];
  pattern?: RegExp | string;
  format?: 'email' | 'uuid' | 'date' | 'url' | 'ipv4' | 'ipv6' | 'phone';
  custom?: (value: unknown) => boolean | string;
  /** Nested schema for object fields. */
  fields?: Schema;
  /** Item schema for arrays. */
  items?: FieldSchema;
}

export type Schema = Record<string, FieldSchema>;

export interface CrossFieldRule {
  /** Fields involved (for the path label). */
  fields: string[];
  /** Return null when valid, or an error code/message when invalid. */
  check: (obj: Record<string, unknown>) => { code: string; message: string } | null;
}

export interface ValidatorOptions {
  /** Reject unknown keys (default false). */
  noUnknown?: boolean;
  /** Stop after this many issues (default 32; caps adversarial cost). */
  maxIssues?: number;
}

function typeName(v: unknown): string {
  if (v === null) return 'null';
  if (Array.isArray(v)) return 'array';
  return typeof v;
}

function safeLen(v: unknown): number | null {
  if (typeof v === 'string' || Array.isArray(v)) return v.length;
  return null;
}

const EMAIL_RE = /^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/;
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const URL_RE = /^https?:\/\/[^\s/$.?#].[^\s]*$/i;
const IPV4_RE = /^(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const IPV6_RE = /^(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}$/;

function checkFormat(format: NonNullable<FieldSchema['format']>, v: unknown): boolean {
  if (typeof v !== 'string') return false;
  switch (format) {
    case 'email':
      return v.length <= 254 && EMAIL_RE.test(v);
    case 'uuid':
      return UUID_RE.test(v) || UUID_RE.test(canonicalUuidLoose(v) ?? '');
    case 'date':
      return !Number.isNaN(Date.parse(v));
    case 'url':
      return v.length <= 2048 && URL_RE.test(v);
    case 'ipv4':
      return IPV4_RE.test(v);
    case 'ipv6':
      return IPV6_RE.test(v) && v.includes(':');
    case 'phone': {
      const digits = v.replace(/\D/g, '');
      return digits.length >= 7 && digits.length <= 15;
    }
  }
}

function canonicalUuidLoose(v: string): string | null {
  const hex = v.trim().replace(/[{}\s-]/g, '');
  if (hex.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(hex)) return null;
  const h = hex.toLowerCase();
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function checkType(t: FieldType, v: unknown): boolean {
  switch (t) {
    case 'string':
      return typeof v === 'string';
    case 'integer':
      return typeof v === 'number' && Number.isInteger(v);
    case 'number':
      return typeof v === 'number' && Number.isFinite(v);
    case 'boolean':
      return typeof v === 'boolean';
    case 'date':
      return v instanceof Date ? !Number.isNaN(v.getTime()) : typeof v === 'string' && !Number.isNaN(Date.parse(v));
    case 'uuid':
      return typeof v === 'string' && (UUID_RE.test(v) || canonicalUuidLoose(v) !== null);
    case 'email':
      return typeof v === 'string' && checkFormat('email', v);
    case 'phone':
      return typeof v === 'string' && checkFormat('phone', v);
    case 'url':
      return typeof v === 'string' && checkFormat('url', v);
    case 'array':
      return Array.isArray(v);
    case 'object':
      return typeof v === 'object' && v !== null && !Array.isArray(v);
  }
}

function push(issues: ValidationIssue[], max: number, issue: ValidationIssue): boolean {
  if (issues.length >= max) return true;
  issues.push(issue);
  return issues.length >= max;
}

function validateField(path: string, value: unknown, sch: FieldSchema, issues: ValidationIssue[], max: number): boolean {
  // Returns true when issue cap reached (stop early).
  if (value === undefined) {
    if (sch.required) return push(issues, max, { path, code: 'required', message: `${path || 'value'} is required` });
    return false;
  }
  if (value === null) {
    if (!sch.nullable) return push(issues, max, { path, code: 'null', message: `${path || 'value'} must not be null` });
    return false;
  }
  if (sch.type !== undefined) {
    const types = Array.isArray(sch.type) ? sch.type : [sch.type];
    if (!types.some((t) => checkType(t, value))) {
      return push(issues, max, {
        path,
        code: 'type',
        message: `${path || 'value'} must be ${types.join('/')} (got ${typeName(value)})`,
      });
    }
  }
  const sl = safeLen(value);
  if (sl !== null) {
    if (sch.minLength !== undefined && sl < sch.minLength) {
      if (push(issues, max, { path, code: 'minLength', message: `${path || 'value'} is too short (length ${sl})` })) return true;
    }
    if (sch.maxLength !== undefined && sl > sch.maxLength) {
      if (push(issues, max, { path, code: 'maxLength', message: `${path || 'value'} is too long (length ${sl})` })) return true;
    }
  }
  if (typeof value === 'number') {
    if (sch.min !== undefined && value < sch.min) {
      if (push(issues, max, { path, code: 'range', message: `${path || 'value'} is below minimum` })) return true;
    }
    if (sch.max !== undefined && value > sch.max) {
      if (push(issues, max, { path, code: 'range', message: `${path || 'value'} is above maximum` })) return true;
    }
  }
  if (sch.enum !== undefined) {
    // SameValueZero comparison; objects compared by reference (documented).
    if (!sch.enum.some((e) => Object.is(e, value))) {
      if (push(issues, max, { path, code: 'enum', message: `${path || 'value'} is not an allowed value` })) return true;
    }
  }
  if (sch.pattern !== undefined && typeof value === 'string') {
    const re = typeof sch.pattern === 'string' ? new RegExp(sch.pattern) : sch.pattern;
    if (!re.test(value)) {
      if (push(issues, max, { path, code: 'pattern', message: `${path || 'value'} does not match required pattern` })) return true;
    }
  }
  if (sch.format !== undefined) {
    if (!checkFormat(sch.format, value)) {
      if (push(issues, max, { path, code: 'format', message: `${path || 'value'} is not a valid ${sch.format}` })) return true;
    }
  }
  if (sch.custom) {
    let r: boolean | string;
    try {
      r = sch.custom(value);
    } catch {
      r = false;
    }
    if (r !== true) {
      const msg = typeof r === 'string' ? r : `${path || 'value'} failed custom validation`;
      if (push(issues, max, { path, code: 'custom', message: msg })) return true;
    }
  }
  if (sch.fields !== undefined && typeof value === 'object' && value !== null && !Array.isArray(value)) {
    if (validateObject(value as Record<string, unknown>, sch.fields, issues, path, max)) return true;
  }
  if (sch.items !== undefined && Array.isArray(value)) {
    for (let idx = 0; idx < value.length; idx++) {
      if (validateField(`${path}[${idx}]`, value[idx], sch.items, issues, max)) return true;
      if (issues.length >= max) return true;
    }
  }
  return issues.length >= max;
}

function validateObject(
  obj: Record<string, unknown>,
  schema: Schema,
  issues: ValidationIssue[],
  base: string,
  max: number,
  noUnknown = false,
): boolean {
  for (const key of Object.keys(schema)) {
    const p = base ? `${base}.${key}` : key;
    if (validateField(p, obj[key], schema[key]!, issues, max)) return true;
  }
  if (noUnknown) {
    for (const key of Object.keys(obj)) {
      if (!(key in schema)) {
        const p = base ? `${base}.${key}` : key;
        if (push(issues, max, { path: p, code: 'unknown', message: `${p} is not allowed` })) return true;
      }
    }
  }
  return issues.length >= max;
}

/** Validate a single value against a field schema. */
export function validateValue(value: unknown, sch: FieldSchema, opts: ValidatorOptions = {}): ValidationResult {
  const issues: ValidationIssue[] = [];
  validateField('', value, sch, issues, opts.maxIssues ?? 32);
  return { ok: issues.length === 0, issues };
}

/** Validate an object against a schema, with optional cross-field rules. */
export function validateObjectWith(
  obj: Record<string, unknown>,
  schema: Schema,
  opts: ValidatorOptions & { cross?: CrossFieldRule[] } = {},
): ValidationResult {
  const issues: ValidationIssue[] = [];
  const max = opts.maxIssues ?? 32;
  validateObject(obj, schema, issues, '', max, opts.noUnknown ?? false);
  if (issues.length < max && opts.cross) {
    for (const rule of opts.cross) {
      let r: { code: string; message: string } | null;
      try {
        r = rule.check(obj);
      } catch {
        r = { code: 'cross', message: 'cross-field check failed' };
      }
      if (r) {
        issues.push({ path: rule.fields.join(','), code: r.code, message: r.message });
        if (issues.length >= max) break;
      }
    }
  }
  return { ok: issues.length === 0, issues };
}

/** Precompile a schema validator for reuse (caches RegExp compilation for string patterns). */
export function compileValidator(
  schema: Schema,
  opts: ValidatorOptions & { cross?: CrossFieldRule[] } = {},
): (obj: Record<string, unknown>) => ValidationResult {
  // Precompile string patterns once so hot-path validation avoids `new RegExp`.
  const compiled: Schema = {};
  for (const key of Object.keys(schema)) {
    const f = schema[key]!;
    if (typeof f.pattern === 'string') compiled[key] = { ...f, pattern: new RegExp(f.pattern) };
    else compiled[key] = f;
  }
  const cross = opts.cross ?? [];
  const noUnknown = opts.noUnknown ?? false;
  const max = opts.maxIssues ?? 32;
  return (obj: Record<string, unknown>) => {
    const issues: ValidationIssue[] = [];
    validateObject(obj, compiled, issues, '', max, noUnknown);
    if (issues.length < max) {
      for (const rule of cross) {
        let r: { code: string; message: string } | null;
        try {
          r = rule.check(obj);
        } catch {
          r = { code: 'cross', message: 'cross-field check failed' };
        }
        if (r) {
          issues.push({ path: rule.fields.join(','), code: r.code, message: r.message });
          if (issues.length >= max) break;
        }
      }
    }
    return { ok: issues.length === 0, issues };
  };
}