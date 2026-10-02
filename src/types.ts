// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Shared public types for rinsa.
 * Keep this file dependency-free and small — it is imported by everything.
 */

/** Scrubbing actions applicable to any PII/secret finding. */
export type ScrubAction =
  | 'keep'
  | 'redact'
  | 'replace'
  | 'mask'
  | 'hash'
  | 'hmac'
  | 'tokenize'
  | 'truncate'
  | 'drop';

export type DetectionLevel = 'strict' | 'balanced' | 'loose';

/** All detectable PII categories. */
export type PiiType =
  | 'email'
  | 'phone'
  | 'card'
  | 'iban'
  | 'bankAcct'
  | 'ssn'
  | 'passport'
  | 'license'
  | 'ipv4'
  | 'ipv6'
  | 'mac'
  | 'uuid'
  | 'urlSensitive'
  | 'dob'
  | 'postal'
  | 'personName'
  | 'address';

/** All detectable secret categories. */
export type SecretType =
  | 'bearer'
  | 'jwt'
  | 'privateKey'
  | 'aws'
  | 'gcp'
  | 'github'
  | 'gitlab'
  | 'slack'
  | 'stripe'
  | 'openai'
  | 'genericKey'
  | 'urlCreds';

export type FindingType = PiiType | SecretType;

export interface Finding {
  /** Category, e.g. 'email', 'jwt'. */
  type: FindingType;
  /** UTF-16 start offset (inclusive) in the scanned string. */
  start: number;
  /** UTF-16 end offset (exclusive). */
  end: number;
  /** Confidence 0..1 as computed by the validator. */
  confidence: number;
}

/** Per-action configuration. Only the fields for the chosen action are read. */
export interface ActionConfig {
  action: ScrubAction;
  /** For 'redact': full placeholder, e.g. '[REDACTED]'. For 'replace': literal. */
  replacement?: string;
  /** For 'mask': masking char (default '*'). */
  maskChar?: string;
  /** Chars to leave visible at start (default 0; for mask). */
  preserveStart?: number;
  /** Chars to leave visible at end (default 0; 4 is common for cards). */
  preserveEnd?: number;
  /** Keep masked output the same length as input (default true). */
  preserveLength?: boolean;
  /** For 'hash': 'sha256' (default) — truncated hex length via hashLength. */
  hashAlg?: 'sha256' | 'sha512';
  hashLength?: number;
  /** For 'hmac': required key (string or bytes). Hex output. */
  hmacKey?: string | Uint8Array;
  hmacLength?: number;
  /** For 'tokenize': prefix, e.g. 'tok_'. Deterministic HMAC-based token. */
  tokenPrefix?: string;
  tokenKey?: string | Uint8Array;
  /** For 'truncate': max visible chars (default 8) + suffix. */
  truncateLength?: number;
  truncateSuffix?: string;
}

/** Per-type rule: enable/disable, sensitivity, and scrub action. */
export interface TypeRule extends Partial<ActionConfig> {
  enabled?: boolean;
  level?: DetectionLevel;
}

/** Policy controlling which PII/secret types are detected and how each is scrubbed. */
export interface ScrubPolicy {
  /** Fallback action for any enabled type without its own rule. Default { action: 'redact' }. */
  defaultAction?: ActionConfig;
  /** Per-type overrides. Absent type => enabled with defaultAction at 'balanced'. */
  types?: Partial<Record<FindingType, TypeRule>>;
  /** Global detection level shortcut applied to types without explicit level. */
  level?: DetectionLevel;
  /** Maximum input length scanned (chars). Longer inputs are scanned in chunks. Default 1_000_000. */
  maxLength?: number;
}

/** Result of a validation run. Values are NEVER echoed back. */
export interface ValidationIssue {
  path: string;
  code: string;
  message: string;
}

export interface ValidationResult {
  ok: boolean;
  issues: ValidationIssue[];
}

export type CoercionPolicy = 'strict' | 'lenient' | 'off';