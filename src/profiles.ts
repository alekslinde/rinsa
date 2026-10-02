// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Configurable profiles: named starting policies for common shapes.
 * Every profile is a function returning a plain Policy — override any part.
 * Profiles are transparent (no hidden behaviour); inspect or spread the result.
 */

import type { Policy } from './policy.js';
import type { SanitizeOptions } from './sanitize.js';
import type { ScrubPolicy } from './types.js';

type Override = Partial<Policy> & {
  sanitize?: SanitizeOptions | false;
  scrub?: ScrubPolicy | false;
};

function merge(base: Policy, over?: Override): Policy {
  if (!over) return base;
  const out: Policy = { ...base, ...over };
  if (typeof base.sanitize === 'object' && typeof over.sanitize === 'object') {
    out.sanitize = { ...base.sanitize, ...over.sanitize };
  }
  if (typeof base.scrub === 'object' && typeof over.scrub === 'object') {
    const b = base.scrub;
    const o = over.scrub;
    out.scrub = { ...b, ...o, types: { ...(b.types ?? {}), ...(o.types ?? {}) } };
  }
  return out;
}

/** Slugs, keys, handles, usernames. */
export function identifierProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: '', removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFKC', maxChars: 128 },
      textCase: 'lower',
      scrub: false,
      validate: { type: 'string', minLength: 1, maxLength: 128, pattern: /^[a-z0-9][a-z0-9-_]*$/ },
    },
    over,
  );
}

/** Email addresses: canonical lowercase, format-validated, never scrubbed (the value IS the email). */
export function emailProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: false, removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFC', maxChars: 254 },
      textCase: 'lower',
      scrub: false,
      validate: { type: 'string', format: 'email', maxLength: 254 },
    },
    over,
  );
}

/** Phone numbers: canonical digit form via coerce. */
export function phoneProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: ' ', removeControls: true, removeZeroWidth: true, removeBidi: true, maxChars: 40 },
      coerce: 'phone',
      scrub: false,
      validate: { type: 'string', format: 'phone' },
    },
    over,
  );
}

/** Numeric strings: canonical form ('1,000.50' -> '1000.5'). */
export function numericProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: false, removeControls: true, removeZeroWidth: true, removeBidi: true, maxChars: 64 },
      coerce: 'float',
      scrub: false,
      validate: { type: 'string', maxLength: 64 },
    },
    over,
  );
}

/** URLs: trimmed, length-capped, format-checked. (Use scrub urlSensitive to strip credentials.) */
export function urlProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: false, removeControls: true, removeZeroWidth: true, removeBidi: true, maxChars: 2048 },
      scrub: false,
      validate: { type: 'string', format: 'url', maxLength: 2048 },
    },
    over,
  );
}

/** Human names: whitespace-normalised, case preserved, capped. */
export function humanNameProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: true, removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFC', maxChars: 100 },
      scrub: false,
      validate: { type: 'string', minLength: 1, maxLength: 100 },
    },
    over,
  );
}

/** Free text / comments / bios: full sanitisation + balanced PII redaction. */
export function freeTextProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: true, removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFC', maxChars: 10000 },
      scrub: { level: 'balanced' },
    },
    over,
  );
}

/** Log lines: high-volume defaults, redact PII + secrets, keep structure. */
export function logDataProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: false, collapseWhitespace: false, removeControls: true, removeZeroWidth: true, removeBidi: true, maxChars: 100000 },
      scrub: { level: 'balanced' },
    },
    over,
  );
}

/** Untrusted LLM input: strip invisible/bidi (prompt-injection carriers), scrub secrets/PII. */
export function llmInputProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: true, removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFC', maxChars: 50000 },
      scrub: { level: 'balanced' },
    },
    over,
  );
}

/**
 * Analytics/export: sanitise + deterministically hash PII (joinable across
 * events without retaining raw values). Override defaultAction to change.
 */
export function analyticsProfile(over?: Override): Policy {
  return merge(
    {
      sanitize: { trim: true, collapseWhitespace: true, removeControls: true, removeZeroWidth: true, removeBidi: true, form: 'NFC', maxChars: 10000 },
      scrub: { level: 'balanced', defaultAction: { action: 'hash', hashAlg: 'sha256', hashLength: 16 } },
    },
    over,
  );
}

export const profiles = {
  identifier: identifierProfile,
  email: emailProfile,
  phone: phoneProfile,
  numeric: numericProfile,
  url: urlProfile,
  humanName: humanNameProfile,
  freeText: freeTextProfile,
  logData: logDataProfile,
  llmInput: llmInputProfile,
  analytics: analyticsProfile,
};