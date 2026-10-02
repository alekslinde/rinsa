// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * rinsa — tiny, fast sanitisation, normalisation, transformation,
 * validation and PII/secret scrubbing. Zero runtime dependencies.
 *
 * SECURITY NOTES (read before use):
 * - Sanitisation is NOT injection protection. Context-specific encoding
 *   (HTML/SQL/shell escaping, parameterized queries) remains required and is
 *   deliberately out of scope for this library.
 * - Validation issues never echo input values (type + length only).
 * - Scrubbing is deterministic; `hash` without a key is an identifier, not a
 *   secret shield — use `hmac` with a caller-held key for sensitive joins.
 */

// Core sanitisation / unicode
export { sanitize, compileSanitizer, sanitizeBytes, isValidUTF8, utf8ByteLength, charLength } from './sanitize.js';
export type { SanitizeOptions, TrimMode } from './sanitize.js';
export { normalizeForm, lower, upper, fold, stripDiacritics, equalFold, isAsciiOnly } from './unicode.js';
export type { NormalForm } from './unicode.js';

// Normalisation
export {
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
} from './normalize.js';
export type {
  CaseOptions,
  WhitespaceOptions,
  NumberNormOptions,
  BoolNormOptions,
  DateNormOptions,
  IdentifierOptions,
  PhoneNormOptions,
} from './normalize.js';

// Type coercion
export { toInteger, toFloat, toBoolean, toDate, numberToString, withDefault, nullIfEmpty, coerceWithFallback } from './coerce.js';
export type { IntOptions, FloatOptions, BoolOptions, DateCoerceOptions } from './coerce.js';

// Validation (side-effect free; separate from transformation)
export { validateValue, validateObjectWith, compileValidator } from './validate.js';
export type { FieldType, FieldSchema, Schema, CrossFieldRule, ValidatorOptions } from './validate.js';

// Generic transforms
export {
  mapChars,
  replaceAll,
  replacePattern,
  filterChars,
  filterAlnum,
  trimBoth,
  toLower,
  toUpper,
  withDefaultStr,
  mask,
  redact,
  hashValue,
  hmacValue,
  tokenize,
  truncate,
  pipe,
} from './transform.js';
export type { MaskOptions, HashAlg, TokenizeOptions, TruncateOptions } from './transform.js';

// PII + secrets
export { detectPII, resolveOverlaps, luhnValid, ibanValid, abaValid, DEFAULT_ENABLED } from './pii.js';
export { detectSecrets, DEFAULT_SECRET_ENABLED } from './secrets.js';
export { compileScrubber, scrubPII, scrubSecrets, detectAllFindings, validateScrubPolicy } from './scrub.js';
export type { ScrubResult, CompiledScrubber } from './scrub.js';

// Structured data
export {
  SanitizationError,
  compileStructured,
  processValueWith,
  processJSONWith,
  parseCSV,
  stringifyCSV,
  processCSV,
  processKV,
} from './structured.js';
export type { FieldRule, StructuredPolicy, CompiledStructured, CsvPolicy, KvPolicy } from './structured.js';

// Unified policy + profiles
export { compilePolicy, processText } from './policy.js';
export type { Policy, CompiledPolicy } from './policy.js';
export { profiles } from './profiles.js';
export {
  identifierProfile,
  emailProfile,
  phoneProfile,
  numericProfile,
  urlProfile,
  humanNameProfile,
  freeTextProfile,
  logDataProfile,
  llmInputProfile,
  analyticsProfile,
} from './profiles.js';

// Shared types
export type {
  ScrubAction,
  DetectionLevel,
  PiiType,
  SecretType,
  FindingType,
  Finding,
  ActionConfig,
  TypeRule,
  ScrubPolicy,
  ValidationIssue,
  ValidationResult,
  CoercionPolicy,
} from './types.js';

/** Library version (matches package.json). */
export const VERSION = '0.1.0';