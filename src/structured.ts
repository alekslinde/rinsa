// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Structured data: strings, byte buffers, JSON, objects/maps, arrays,
 * CSV, key/value records — with field-specific rules and PII policies.
 * Fail-closed on depth/size/circular abuse; never echoes values in errors.
 */

import { compileSanitizer, type SanitizeOptions } from './sanitize.js';
import { normalizePhone, normalizeUUID } from './normalize.js';
import { compileScrubber, type CompiledScrubber } from './scrub.js';
import { normalizeCase } from './normalize.js';
import { toBoolean, toDate, toFloat, toInteger } from './coerce.js';
import { compileValidator, validateValue, type FieldSchema, type Schema, type ValidationResult } from './validate.js';
import type { ScrubPolicy } from './types.js';

export class SanitizationError extends Error {
  readonly code: string;
  constructor(code: string, message: string) {
    super(message);
    this.name = 'SanitizationError';
    this.code = code;
  }
}

export interface FieldRule {
  sanitize?: SanitizeOptions | false;
  /** Case normalisation for string leaves. */
  textCase?: 'lower' | 'upper' | 'fold' | false;
  coerce?: 'integer' | 'float' | 'boolean' | 'date' | 'phone' | 'uuid' | 'string' | false;
  scrub?: ScrubPolicy | false;
  /** Static replacement for the whole value (runs before other steps when value is a string). */
  replace?: string;
  /** Drop this field entirely (objects) / blank it (arrays keep length with null). */
  drop?: boolean;
  default?: unknown;
  /** Validation for this field (checked by validateRecord, never by process*). */
  validate?: FieldSchema;
  /** Nested policy for object values. */
  nested?: StructuredPolicy;
}

export interface StructuredPolicy {
  fields?: Record<string, FieldRule>;
  default?: FieldRule;
  maxDepth?: number;
  maxKeys?: number;
  maxArray?: number;
  maxStringLength?: number;
  onCircular?: 'null' | 'throw' | 'skip';
}

interface CompiledField {
  sanitizer: ((s: string) => string) | null;
  textCase: 'lower' | 'upper' | 'fold' | false;
  coerce: FieldRule['coerce'];
  scrubber: CompiledScrubber | null;
  replace: string | undefined;
  drop: boolean;
  hasDefault: boolean;
  default: unknown;
  nested: CompiledStructured | null;
}

export interface CompiledStructured {
  processValue(value: unknown): unknown;
  processRecord(obj: Record<string, unknown>): Record<string, unknown>;
  processJSON(json: string): string;
  validateRecord(obj: Record<string, unknown>): ValidationResult;
}

const SENSIBLE = { maxDepth: 10, maxKeys: 10000, maxArray: 100000, maxStringLength: 1_000_000 };

/** Own-property assignment safe against `__proto__` pollution. */
function setOwn(out: Record<string, unknown>, k: string, v: unknown): void {
  if (k === '__proto__') {
    Object.defineProperty(out, k, { value: v, enumerable: true, writable: true, configurable: true });
  } else {
    out[k] = v;
  }
}

function matchPattern(pattern: string, path: string, key: string): boolean {
  if (pattern === '*') return true;
  if (pattern === path || pattern === key) return true;
  if (pattern.endsWith('.*') && (path === pattern.slice(0, -2) || path.startsWith(pattern.slice(0, -1)))) return true;
  if (pattern.startsWith('*.') && (path.endsWith(pattern.slice(1)) || key.endsWith(pattern.slice(1)))) return true;
  return false;
}

function compileField(rule: FieldRule | undefined, def: FieldRule | undefined): CompiledField | null {
  const r = rule ?? def;
  if (!r) return null;
  return {
    sanitizer: r.sanitize === false || r.sanitize === undefined ? null : compileSanitizer(r.sanitize),
    textCase: r.textCase ?? false,
    coerce: r.coerce ?? false,
    scrubber: r.scrub === false || r.scrub === undefined ? null : compileScrubber(r.scrub),
    replace: r.replace,
    drop: r.drop ?? false,
    hasDefault: r.default !== undefined,
    default: r.default,
    nested: r.nested ? compileStructured(r.nested) : null,
  };
}

function applyString(s: string, cf: CompiledField | null, maxStr: number): string {
  if (s.length > maxStr) s = s.slice(0, maxStr);
  if (!cf) return s;
  let t = s;
  if (cf.replace !== undefined) t = cf.replace;
  if (cf.sanitizer) t = cf.sanitizer(t);
  if (cf.textCase) t = normalizeCase(t, { mode: cf.textCase });
  if (cf.coerce !== false && cf.coerce !== undefined) {
    if (cf.coerce === 'string') {
      // no-op
    } else if (cf.coerce === 'integer') {
      const v = toInteger(t);
      if (v !== null) return String(v);
    } else if (cf.coerce === 'float') {
      const v = toFloat(t);
      if (v !== null) return String(v);
    } else if (cf.coerce === 'boolean') {
      const v = toBoolean(t, { output: 'string' });
      if (v !== null) return v as string;
    } else if (cf.coerce === 'date') {
      const v = toDate(t, { output: 'iso' });
      if (v !== null) return v as string;
    } else if (cf.coerce === 'phone') {
      const v = normalizePhone(t);
      if (typeof v === 'string') return v;
    } else if (cf.coerce === 'uuid') {
      const v = normalizeUUID(t);
      if (v !== null) return v;
    }
  }
  if (cf.scrubber) t = cf.scrubber.scrub(t);
  return t;
}

function decodeBytes(v: Uint8Array): string {
  if (v.length > 8_000_000) throw new SanitizationError('too-large', 'byte input exceeds 8MB limit');
  return new TextDecoder('utf-8', { fatal: false }).decode(v);
}

export function compileStructured(policy: StructuredPolicy = {}): CompiledStructured {
  const maxDepth = policy.maxDepth ?? SENSIBLE.maxDepth;
  const maxKeys = policy.maxKeys ?? SENSIBLE.maxKeys;
  const maxArray = policy.maxArray ?? SENSIBLE.maxArray;
  const maxStr = policy.maxStringLength ?? SENSIBLE.maxStringLength;
  const onCircular = policy.onCircular ?? 'null';
  const fields = policy.fields ?? {};
  const def = policy.default;

  // Precompile per-pattern rules once.
  const patterns = Object.keys(fields);
  const compiledByPattern = new Map<string, CompiledField | null>();
  for (const p of patterns) compiledByPattern.set(p, compileField(fields[p], undefined));
  const compiledDefault = compileField(undefined, def);

  const findRule = (path: string, key: string): CompiledField | null => {
    let fallback: CompiledField | null = null;
    for (const p of patterns) {
      if (matchPattern(p, path, key)) {
        const cf = compiledByPattern.get(p);
        if (p === path || p === key) return cf ?? null; // exact wins immediately
        if (!fallback) fallback = cf ?? null;
      }
    }
    return fallback ?? compiledDefault;
  };

  const processAny = (value: unknown, path: string, key: string, depth: number, seen: Set<object>): unknown => {
    if (depth > maxDepth) throw new SanitizationError('too-deep', `input exceeds max depth of ${maxDepth}`);
    if (typeof value === 'string') {
      const cf = findRule(path, key);
      if (cf?.drop) return undefined;
      let t = applyString(value, cf, maxStr);
      if (cf?.hasDefault && t.trim() === '') return cf.default;
      return t;
    }
    if (value instanceof Uint8Array) {
      const cf = findRule(path, key);
      if (cf?.drop) return undefined;
      return applyString(decodeBytes(value), cf, maxStr);
    }
    if (typeof Buffer !== 'undefined' && Buffer.isBuffer(value)) {
      const cf = findRule(path, key);
      if (cf?.drop) return undefined;
      return applyString(decodeBytes(value as unknown as Uint8Array), cf, maxStr);
    }
    if (Array.isArray(value)) {
      if (value.length > maxArray) throw new SanitizationError('too-large', `array exceeds ${maxArray} items`);
      const out: unknown[] = new Array(value.length);
      for (let i = 0; i < value.length; i++) {
        const el = processAny(value[i], `${path}[${i}]`, key, depth + 1, seen);
        out[i] = el === undefined ? null : el; // keep length stable
      }
      return out;
    }
    if (value instanceof Map) {
      if (seen.has(value)) {
        if (onCircular === 'throw') throw new SanitizationError('circular', 'circular reference detected');
        return onCircular === 'skip' ? undefined : null;
      }
      seen.add(value);
      const out = new Map<unknown, unknown>();
      let count = 0;
      for (const [k, v] of value) {
        if (++count > maxKeys) throw new SanitizationError('too-large', `map exceeds ${maxKeys} keys`);
        const ks = String(k);
        const childPath = path ? `${path}.${ks}` : ks;
        const r = processAny(v, childPath, ks, depth + 1, seen);
        if (r !== undefined) out.set(k, r);
      }
      seen.delete(value);
      return out;
    }
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) {
        if (onCircular === 'throw') throw new SanitizationError('circular', 'circular reference detected');
        return onCircular === 'skip' ? undefined : null;
      }
      seen.add(value);
      const out: Record<string, unknown> = {};
      let count = 0;
      for (const k of Object.keys(value)) {
        if (++count > maxKeys) throw new SanitizationError('too-large', `object exceeds ${maxKeys} keys`);
        const childPath = path ? `${path}.${k}` : k;
        const cf = findRule(childPath, k);
        if (cf?.drop) continue;
        let v = (value as Record<string, unknown>)[k];
        if (cf?.nested && typeof v === 'object' && v !== null) {
          v = (cf.nested as CompiledStructured).processValue(v);
        } else {
          v = processAny(v, childPath, k, depth + 1, seen);
        }
        if (v === undefined) {
          if (cf?.hasDefault) setOwn(out, k, cf.default);
          continue;
        }
        if ((v === null || (typeof v === 'string' && v === '')) && cf?.hasDefault) {
          // keep processed value unless blank and default exists — default already handled for strings
        }
        setOwn(out, k, v);
      }
      seen.delete(value);
      return out;
    }
    return value;
  };

  const processValue = (value: unknown): unknown => processAny(value, '', '', 0, new Set());

  const processRecord = (obj: Record<string, unknown>): Record<string, unknown> => {
    const r = processAny(obj, '', '', 0, new Set());
    if (typeof r !== 'object' || r === null || Array.isArray(r)) throw new SanitizationError('type', 'record must be an object');
    return r as Record<string, unknown>;
  };

  const processJSON = (json: string): string => {
    if (json.length > 10_000_000) throw new SanitizationError('too-large', 'JSON input exceeds 10MB limit');
    let parsed: unknown;
    try {
      parsed = JSON.parse(json);
    } catch {
      throw new SanitizationError('invalid-json', 'invalid JSON input');
    }
    return JSON.stringify(processAny(parsed, '', '', 0, new Set()));
  };

  // Validation view: validate each present field against its matching rule's schema.
  const schemasByPattern = new Map<string, FieldSchema | undefined>();
  for (const p of patterns) schemasByPattern.set(p, fields[p]?.validate);
  const defaultSchema = def?.validate;
  const validateRecord = (obj: Record<string, unknown>): ValidationResult => {
    const schema: Schema = {};
    for (const k of Object.keys(obj)) {
      let picked: FieldSchema | undefined;
      for (const p of patterns) {
        if (matchPattern(p, k, k)) {
          const s = schemasByPattern.get(p);
          if (p === k) {
            picked = s;
            break;
          }
          if (picked === undefined) picked = s;
        }
      }
      schema[k] = picked ?? defaultSchema ?? {};
    }
    if (Object.keys(schema).length === 0) return { ok: true, issues: [] };
    void validateValue;
    return compileValidator(schema)({ ...obj });
  };

  return { processValue, processRecord, processJSON, validateRecord };
}

/** One-shot object processing. */
export function processValueWith(value: unknown, policy: StructuredPolicy = {}): unknown {
  return compileStructured(policy).processValue(value);
}

/** One-shot JSON processing (throws SanitizationError on invalid/oversize JSON). */
export function processJSONWith(json: string, policy: StructuredPolicy = {}): string {
  return compileStructured(policy).processJSON(json);
}

// ---- CSV ----

export interface CsvPolicy {
  hasHeader?: boolean; // default true
  delimiter?: string; // default ','
  columns?: Record<string, FieldRule> | Array<FieldRule | undefined>; // by name or index
  default?: FieldRule;
  maxRows?: number; // default 100000
  maxCellLength?: number; // default 1MB
}

/** Minimal correct CSV parser (RFC-4180-ish: quotes, escaped quotes, CRLF). */
export function parseCSV(text: string, delimiter = ','): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = '';
  let inQuotes = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i]!;
    if (inQuotes) {
      if (c === '"') {
        if (text[i + 1] === '"') {
          cell += '"';
          i++;
        } else inQuotes = false;
      } else cell += c;
    } else if (c === '"') {
      inQuotes = true;
    } else if (c === delimiter) {
      row.push(cell);
      cell = '';
    } else if (c === '\n') {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = '';
    } else if (c === '\r') {
      // skip; \n handles the break (lone \r also breaks)
      if (text[i + 1] !== '\n') {
        row.push(cell);
        rows.push(row);
        row = [];
        cell = '';
      }
    } else cell += c;
  }
  if (inQuotes) throw new SanitizationError('invalid-csv', 'unterminated quote in CSV input');
  if (cell !== '' || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows;
}

export function stringifyCSV(rows: string[][], delimiter = ','): string {
  return rows
    .map((row) =>
      row
        .map((cell) => {
          if (cell.includes('"') || cell.includes(delimiter) || cell.includes('\n') || cell.includes('\r')) {
            return '"' + cell.replace(/"/g, '""') + '"';
          }
          return cell;
        })
        .join(delimiter),
    )
    .join('\n');
}

function compileCsvRule(rule: FieldRule | undefined, def: FieldRule | undefined): CompiledField | null {
  return compileField(rule, def);
}

/** Process CSV text with per-column rules. Returns CSV text. */
export function processCSV(text: string, policy: CsvPolicy = {}): string {
  const delim = policy.delimiter ?? ',';
  const hasHeader = policy.hasHeader ?? true;
  const maxRows = policy.maxRows ?? 100000;
  const maxCell = policy.maxCellLength ?? 1_000_000;
  const rows = parseCSV(text, delim);
  if (rows.length > maxRows + (hasHeader ? 1 : 0)) throw new SanitizationError('too-large', `CSV exceeds ${maxRows} rows`);
  if (rows.length === 0) return '';
  const header = hasHeader ? rows[0]! : rows[0]!.map((_, i) => String(i));
  const dataStart = hasHeader ? 1 : 0;
  const colRules: Array<CompiledField | null> = header.map((h, i) => {
    if (Array.isArray(policy.columns)) return compileCsvRule(policy.columns[i], policy.default);
    if (policy.columns) return compileCsvRule(policy.columns[h], policy.default);
    return compileCsvRule(undefined, policy.default);
  });
  const out: string[][] = [];
  if (hasHeader) out.push(header);
  for (let r = dataStart; r < rows.length; r++) {
    const row = rows[r]!;
    const next: string[] = new Array(row.length);
    for (let c = 0; c < row.length; c++) {
      const cf = colRules[c] ?? null;
      if (cf?.drop) {
        next[c] = '';
        continue;
      }
      next[c] = applyString(row[c]!.length > maxCell ? row[c]!.slice(0, maxCell) : row[c]!, cf, maxCell);
    }
    out.push(next);
  }
  return stringifyCSV(out, delim);
}

// ---- Key/value records ----

export interface KvPolicy {
  entrySeparator?: string; // default ' '
  kvSeparator?: string; // default '='
  fields?: Record<string, FieldRule>;
  default?: FieldRule;
}

/** Process 'k=v k=v' / query-style records with per-key rules. */
export function processKV(text: string, policy: KvPolicy = {}): string {
  const entrySep = policy.entrySeparator ?? ' ';
  const kvSep = policy.kvSeparator ?? '=';
  const entries = text.split(entrySep);
  const out: string[] = [];
  for (const e of entries) {
    const idx = e.indexOf(kvSep);
    if (idx < 0) {
      out.push(e);
      continue;
    }
    const k = e.slice(0, idx);
    const v = e.slice(idx + kvSep.length);
    const rule = policy.fields?.[k];
    const cf = compileField(rule, policy.default);
    if (cf?.drop) continue;
    out.push(k + kvSep + applyString(v, cf, 1_000_000));
  }
  return out.join(entrySep);
}

export type { FieldSchema, Schema };