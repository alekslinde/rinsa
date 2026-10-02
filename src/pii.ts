// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * PII detectors. Each detector pairs a cheap trigger precheck with a bounded
 * precompiled pattern plus a validator (checksum/context) that assigns
 * confidence. Validators reject (confidence 0) to suppress false positives.
 */

import type { DetectionLevel, Finding, PiiType } from './types.js';

export interface PiiOptions {
  level?: DetectionLevel;
  maxLength?: number;
}

function hasTrigger(text: string, triggers: string[]): boolean {
  for (const t of triggers) if (text.includes(t)) return true;
  return false;
}

const WORD_KEYWORDS_NEAR = 40;

function hasKeywordNearby(lower: string, index: number, keywords: string[], window = WORD_KEYWORDS_NEAR): boolean {
  const from = Math.max(0, index - window);
  const to = Math.min(lower.length, index + window);
  const slice = lower.slice(from, to);
  for (const k of keywords) if (slice.includes(k)) return true;
  return false;
}

/** Luhn checksum (cards). */
export function luhnValid(digits: string): boolean {
  let sum = 0;
  let dbl = false;
  for (let i = digits.length - 1; i >= 0; i--) {
    let d = digits.charCodeAt(i) - 48;
    if (d < 0 || d > 9) return false;
    if (dbl) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
    dbl = !dbl;
  }
  return digits.length >= 13 && sum % 10 === 0;
}

/** IBAN mod-97 validation. Expects compact uppercase IBAN. */
export function ibanValid(iban: string): boolean {
  if (iban.length < 15 || iban.length > 34) return false;
  const re = iban.slice(4) + iban.slice(0, 4);
  let rem = 0;
  for (let i = 0; i < re.length; i++) {
    const c = re.charCodeAt(i);
    if (c >= 48 && c <= 57) rem = (rem * 10 + (c - 48)) % 97;
    else if (c >= 65 && c <= 90) {
      const v = c - 55;
      rem = (rem * 100 + v) % 97;
    } else return false;
  }
  return rem === 1;
}

/** ABA routing number checksum. */
export function abaValid(r: string): boolean {
  if (!/^\d{9}$/.test(r)) return false;
  const d = [...r].map(Number);
  const sum = 3 * (d[0]! + d[3]! + d[6]!) + 7 * (d[1]! + d[4]! + d[7]!) + (d[2]! + d[5]! + d[8]!);
  return sum !== 0 && sum % 10 === 0;
}

// ---- Precompiled patterns (all bounded, global) ----

const EMAIL_RE = /[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?){1,8}/g;
const PHONE_RE = /(?:\+|00)?(?:\d[.\s\-()/]*){7,20}/g;
const CARD_RE = /\b(?:\d[ \-.―‐‑]?){13,19}\b/g;
const IBAN_RE = /\b[A-Z]{2}\d{2}[ ]?(?:[A-Z0-9]{4}[ ]?){2,7}[A-Z0-9]{0,4}\b/g;
const ROUTING_RE = /\b\d{9}\b/g;
const ACCT_CTX_RE = /\b(?:account|acct\.?|a\/c)(?:\s*(?:no|number|#))?\s*:?\s*(\d{4,17})\b/gi;
const SSN_RE = /\b(?!000|666|9\d\d)\d{3}[ -]?(?!00)\d{2}[ -]?(?!0000)\d{4}\b/g;
const PASSPORT_RE = /\b[A-Z]{1,2}\d{6,9}\b/g;
const LICENSE_RE = /\b(?:[A-Z]{1,2}\d{5,9}|\d{3,4}[ -]?\d{3,4}[ -]?\d{3,4})\b/g;
const IPV4_RE = /\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b/g;
const IPV6_RE = /(?:(?:[0-9A-Fa-f]{1,4}:){7}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){1,7}:|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}|(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4})/g;
const MAC_RE = /\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b/g;
const UUID_RE = /\b[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}\b/g;
const URL_RE = /\bhttps?:\/\/(?:[^\s"'<>)|]+)/gi;
const DOB_RE = /\b(?:(?:19|20)\d{2}[-/.](?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])|(?:0[1-9]|1[0-2])[-/.](?:0[1-9]|[12]\d|3[01])[-/.](?:19|20)\d{2}|(?:0[1-9]|[12]\d|3[01])[.](?:0[1-9]|1[0-2])[.](?:19|20)\d{2})\b/g;
const ZIP_RE = /\b\d{5}(?:-\d{4})?\b/g;
const UK_POST_RE = /\b[A-Z]{1,2}\d[A-Z\d]?\s?\d[A-Z]{2}\b/g;
const NAME_HONOR_RE = /\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Mx)\.?\s+[A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30}){0,2}\b/g;
const NAME_CTX_RE = /(?:name|full[\s-]?name|customer|patient|client|contact|attn)\s*:?\s*([A-Z][a-z]{1,30}(?:\s+[A-Z][a-z]{1,30}){1,2})/g;
const ADDR_RE = /\b\d{1,6}\s+[A-Z0-9][A-Za-z0-9.'-]{1,30}(?:\s+[A-Za-z0-9.'-]{1,30}){0,4}\s+(?:St(?:reet)?|Ave(?:nue)?|Rd|Road|Blvd|Boulevard|Ln|Lane|Dr(?:ive)?|Ct|Court|Pl(?:ace)?|Ter(?:race)?|Way|Cir(?:cle)?)\b/g;

const SENSITIVE_PARAMS = ['password', 'passwd', 'pwd', 'token', 'secret', 'api_key', 'apikey', 'access_token', 'auth', 'ssn', 'dob', 'card', 'session'];
const DOB_KW = ['dob', 'date of birth', 'birthdate', 'birth date', 'born'];
const PASSPORT_KW = ['passport'];
const LICENSE_KW = ['driver', 'licence', 'license', 'dl no', 'dl#', 'id card'];
const BANK_KW = ['account', 'acct', 'routing', 'aba', 'iban', 'sort code'];
const POSTAL_KW = ['zip', 'postal', 'postcode', 'pin code'];

export const DEFAULT_ENABLED: Record<PiiType, boolean> = {
  email: true,
  phone: true,
  card: true,
  iban: true,
  bankAcct: true,
  ssn: true,
  passport: true,
  license: true,
  ipv4: true,
  ipv6: true,
  mac: true,
  uuid: true,
  urlSensitive: true,
  dob: true,
  postal: true,
  personName: false, // heuristic — opt-in to avoid false positives
  address: false, // heuristic — opt-in
};

function execAll(re: RegExp, text: string): Array<{ start: number; end: number; match: string }> {
  re.lastIndex = 0;
  const out: Array<{ start: number; end: number; match: string }> = [];
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    out.push({ start: m.index, end: m.index + m[0].length, match: m[0] });
    if (++guard > 100000) break; // adversarial cap
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  re.lastIndex = 0;
  return out;
}

function validTLD(domain: string): boolean {
  const tld = domain.split('.').pop() ?? '';
  return /^[A-Za-z]{2,24}$/.test(tld);
}

type DetectorFn = (text: string, level: DetectionLevel, lower: string) => Finding[];

const detectEmail: DetectorFn = (text, level, _lower) => {
  if (!text.includes('@')) return [];
  const out: Finding[] = [];
  for (const m of execAll(EMAIL_RE, text)) {
    if (m.match.length > 254) continue;
    const at = m.match.lastIndexOf('@');
    const domain = m.match.slice(at + 1);
    if (!domain.includes('.') || !validTLD(domain)) {
      if (level === 'strict') continue;
      out.push({ type: 'email', start: m.start, end: m.end, confidence: 0.4 });
      continue;
    }
    out.push({ type: 'email', start: m.start, end: m.end, confidence: 0.92 });
  }
  return out;
};

const detectPhone: DetectorFn = (text, level, _lower) => {
  if (!/[+\d(]/.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(PHONE_RE, text)) {
    let raw = m.match;
    // Strip trailing separators from the match (regex is greedy over separators)
    let end = m.end;
    while (end > m.start && /[.\s\-()/]/.test(text[end - 1]!)) end--;
    raw = text.slice(m.start, end);
    const digits = raw.replace(/\D/g, '');
    if (digits.length < 7 || digits.length > 15) continue;
    const hasPlus = raw.trim().startsWith('+') || raw.trim().startsWith('00');
    const hasSep = /[.\s\-()/]/.test(raw);
    const hasParen = raw.includes('(') || raw.includes(')');
    if (level === 'strict') {
      if (!(hasPlus || hasParen || (hasSep && digits.length >= 10))) continue;
      // Strict also rejects bare digit runs that look like IDs/years
      if (!hasPlus && !hasParen && digits.length < 10) continue;
      out.push({ type: 'phone', start: m.start, end, confidence: hasPlus ? 0.9 : 0.8 });
    } else if (level === 'balanced') {
      if (!hasPlus && !hasSep && digits.length < 10) continue; // bare short digit run: likely ID
      if (digits.length <= 9 && !hasPlus && !hasParen) continue;
      out.push({ type: 'phone', start: m.start, end, confidence: hasPlus || hasParen ? 0.88 : 0.65 });
    } else {
      out.push({ type: 'phone', start: m.start, end, confidence: hasPlus ? 0.85 : 0.45 });
    }
  }
  return out;
};

const detectCard: DetectorFn = (text, level, _lower) => {
  if (!/\d/.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(CARD_RE, text)) {
    // The pattern is greedy over separators; trim trailing separators first.
    let end = m.end;
    while (end > m.start && /[ \-.―‐‑]/.test(text[end - 1]!)) end--;
    const raw = text.slice(m.start, end);
    const digits = raw.replace(/[ \-.―‐‑]/g, '');
    if (!/^\d{13,19}$/.test(digits)) continue;
    // Reject when embedded in a longer digit run
    const before = m.start > 0 ? text[m.start - 1]! : '';
    const after = end < text.length ? text[end]! : '';
    if (/\d/.test(before) || /\d/.test(after)) continue;
    if (luhnValid(digits)) {
      out.push({ type: 'card', start: m.start, end, confidence: 0.95 });
    } else if (level === 'loose') {
      out.push({ type: 'card', start: m.start, end, confidence: 0.35 });
    }
  }
  return out;
};

const detectIban: DetectorFn = (text, _level, _lower) => {
  if (!/[A-Z]{2}\d/.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(IBAN_RE, text)) {
    const compact = m.match.replace(/ /g, '').toUpperCase();
    if (compact.length < 15 || compact.length > 34) continue;
    if (!/^[A-Z]{2}\d{2}[A-Z0-9]+$/.test(compact)) continue;
    if (ibanValid(compact)) out.push({ type: 'iban', start: m.start, end: m.end, confidence: 0.95 });
  }
  return out;
};

const detectBank: DetectorFn = (text, level, lower) => {
  const out: Finding[] = [];
  // ABA routing numbers (checksum-gated, precise even without context)
  if (/\d{9}/.test(text)) {
    for (const m of execAll(ROUTING_RE, text)) {
      if (!abaValid(m.match)) continue;
      const ctx = hasKeywordNearby(lower, m.start, BANK_KW, 60);
      out.push({ type: 'bankAcct', start: m.start, end: m.end, confidence: ctx ? 0.85 : 0.6 });
    }
  }
  // Account numbers require keyword context at strict/balanced
  ACCT_CTX_RE.lastIndex = 0;
  let g = 0;
  let m: RegExpExecArray | null;
  while ((m = ACCT_CTX_RE.exec(text)) !== null && g++ < 10000) {
    const full = m[0];
    const digits = m[1]!;
    const start = m.index + full.lastIndexOf(digits);
    const conf = digits.length >= 6 ? 0.75 : 0.6;
    if (level === 'strict' && digits.length < 6) continue;
    out.push({ type: 'bankAcct', start, end: start + digits.length, confidence: conf });
  }
  ACCT_CTX_RE.lastIndex = 0;
  return out;
};

const detectSsn: DetectorFn = (text, level, _lower) => {
  if (!/\d{3}/.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(SSN_RE, text)) {
    const digits = m.match.replace(/[ -]/g, '');
    if (!/^\d{9}$/.test(digits)) continue;
    const area = Number(digits.slice(0, 3));
    if (area === 0 || area === 666 || area >= 900) continue;
    if (level === 'strict' && !m.match.includes('-')) continue; // strict wants dashed form
    out.push({ type: 'ssn', start: m.start, end: m.end, confidence: m.match.includes('-') ? 0.85 : 0.6 });
  }
  return out;
};

const detectPassport: DetectorFn = (text, level, lower) => {
  if (!hasTrigger(text, ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9'])) return [];
  const out: Finding[] = [];
  for (const m of execAll(PASSPORT_RE, text)) {
    const ctx = hasKeywordNearby(lower, m.start, PASSPORT_KW, 60);
    if (level === 'strict' && !ctx) continue;
    if (level === 'balanced' && !ctx) {
      out.push({ type: 'passport', start: m.start, end: m.end, confidence: 0.35 });
      continue;
    }
    out.push({ type: 'passport', start: m.start, end: m.end, confidence: ctx ? 0.8 : 0.5 });
  }
  return out;
};

const detectLicense: DetectorFn = (text, level, lower) => {
  const out: Finding[] = [];
  for (const m of execAll(LICENSE_RE, text)) {
    if (/\d{3,}/.test(m.match) && hasKeywordNearby(lower, m.start, LICENSE_KW, 60)) {
      out.push({ type: 'license', start: m.start, end: m.end, confidence: 0.7 });
    } else if (level === 'loose') {
      // loose: pattern alone, low confidence (may overlap SSN/phone — resolved later)
      if (/[A-Z]/.test(m.match)) out.push({ type: 'license', start: m.start, end: m.end, confidence: 0.3 });
    }
  }
  return out;
};

const detectIpv4: DetectorFn = (text) => {
  if (!text.includes('.')) return [];
  return execAll(IPV4_RE, text).map((m) => ({ type: 'ipv4' as const, start: m.start, end: m.end, confidence: 0.9 }));
};

const detectIpv6: DetectorFn = (text) => {
  if (!text.includes(':')) return [];
  return execAll(IPV6_RE, text)
    .filter((m) => m.match.includes(':') && m.match.length >= 3)
    .map((m) => ({ type: 'ipv6' as const, start: m.start, end: m.end, confidence: 0.85 }));
};

const detectMac: DetectorFn = (text) => {
  if (!text.includes(':') && !text.includes('-')) return [];
  return execAll(MAC_RE, text).map((m) => ({ type: 'mac' as const, start: m.start, end: m.end, confidence: 0.9 }));
};

const detectUuid: DetectorFn = (text) => {
  if (!text.includes('-')) return [];
  return execAll(UUID_RE, text).map((m) => ({ type: 'uuid' as const, start: m.start, end: m.end, confidence: 0.95 }));
};

const detectUrlSensitive: DetectorFn = (text, level, _lower) => {
  if (!/http/i.test(text)) return [];
  const out: Finding[] = [];
  URL_RE.lastIndex = 0;
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = URL_RE.exec(text)) !== null && guard++ < 10000) {
    const url = m[0].replace(/[.,;:!?]+$/, '');
    const end = m.index + url.length;
    // credentials in authority
    const authIdx = url.indexOf('@');
    const slashIdx = url.indexOf('/', url.indexOf('://') + 3);
    if (authIdx > 0 && (slashIdx < 0 || authIdx < slashIdx)) {
      const schemeEnd = url.indexOf('://') + 3;
      const authority = url.slice(schemeEnd, slashIdx < 0 ? url.length : slashIdx);
      if (authority.includes(':')) {
        out.push({ type: 'urlSensitive', start: m.index, end, confidence: 0.92 });
        continue;
      }
    }
    // sensitive query params
    const q = url.indexOf('?');
    if (q >= 0) {
      const query = url.slice(q + 1).toLowerCase();
      if (SENSITIVE_PARAMS.some((p) => query.includes(p + '='))) {
        out.push({ type: 'urlSensitive', start: m.index, end, confidence: 0.78 });
      }
    }
  }
  URL_RE.lastIndex = 0;
  return out;
};

const detectDob: DetectorFn = (text, level, lower) => {
  if (!/\d/.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(DOB_RE, text)) {
    const ctx = hasKeywordNearby(lower, m.start, DOB_KW, 60);
    if (level === 'loose') {
      out.push({ type: 'dob', start: m.start, end: m.end, confidence: ctx ? 0.8 : 0.4 });
    } else if (ctx) {
      out.push({ type: 'dob', start: m.start, end: m.end, confidence: 0.75 });
    }
  }
  return out;
};

const detectPostal: DetectorFn = (text, level, lower) => {
  const out: Finding[] = [];
  if (/\d{5}/.test(text)) {
    for (const m of execAll(ZIP_RE, text)) {
      const ctx = hasKeywordNearby(lower, m.start, POSTAL_KW, 40);
      const zip4 = m.match.includes('-');
      if (level === 'strict') {
        if (zip4 || ctx) out.push({ type: 'postal', start: m.start, end: m.end, confidence: zip4 ? 0.8 : 0.65 });
      } else if (level === 'balanced') {
        if (zip4) out.push({ type: 'postal', start: m.start, end: m.end, confidence: 0.7 });
        else if (ctx) out.push({ type: 'postal', start: m.start, end: m.end, confidence: 0.65 });
      } else {
        out.push({ type: 'postal', start: m.start, end: m.end, confidence: zip4 || ctx ? 0.7 : 0.35 });
      }
    }
  }
  if (/[A-Z]\d/.test(text)) {
    for (const m of execAll(UK_POST_RE, text)) {
      out.push({ type: 'postal', start: m.start, end: m.end, confidence: 0.7 });
    }
  }
  return out;
};

const detectName: DetectorFn = (text, level, _lower) => {
  const out: Finding[] = [];
  for (const m of execAll(NAME_HONOR_RE, text)) {
    out.push({ type: 'personName', start: m.start, end: m.end, confidence: 0.6 });
  }
  if (level !== 'strict') {
    NAME_CTX_RE.lastIndex = 0;
    let m2: RegExpExecArray | null;
    let g = 0;
    while ((m2 = NAME_CTX_RE.exec(text)) !== null && g++ < 10000) {
      const name = m2[1]!;
      const start = m2.index + m2[0].lastIndexOf(name);
      out.push({ type: 'personName', start, end: start + name.length, confidence: 0.5 });
    }
    NAME_CTX_RE.lastIndex = 0;
  }
  return out;
};

const detectAddress: DetectorFn = (text, _level, _lower) => {
  if (!/\d/.test(text)) return [];
  return execAll(ADDR_RE, text).map((m) => ({ type: 'address' as const, start: m.start, end: m.end, confidence: 0.6 }));
};

const DETECTORS: Record<PiiType, DetectorFn> = {
  email: detectEmail,
  phone: detectPhone,
  card: detectCard,
  iban: detectIban,
  bankAcct: detectBank,
  ssn: detectSsn,
  passport: detectPassport,
  license: detectLicense,
  ipv4: detectIpv4,
  ipv6: detectIpv6,
  mac: detectMac,
  uuid: detectUuid,
  urlSensitive: detectUrlSensitive,
  dob: detectDob,
  postal: detectPostal,
  personName: detectName,
  address: detectAddress,
};

/** Detection priority for overlap resolution (higher wins ties). */
const PRIORITY: Record<PiiType, number> = {
  urlSensitive: 100,
  iban: 90,
  card: 85,
  ssn: 80,
  email: 75,
  ipv4: 70,
  ipv6: 70,
  mac: 70,
  uuid: 70,
  passport: 60,
  bankAcct: 60,
  phone: 50,
  dob: 45,
  postal: 40,
  license: 35,
  address: 30,
  personName: 20,
};

/**
 * Resolve overlapping findings greedily: sort by start, prefer higher
 * (confidence, priority, length). Deterministic.
 */
export function resolveOverlaps(findings: Finding[]): Finding[] {
  if (findings.length <= 1) return findings.slice();
  const sorted = findings.slice().sort((a, b) => {
    if (a.start !== b.start) return a.start - b.start;
    if (b.confidence !== a.confidence) return b.confidence - a.confidence;
    const pa = PRIORITY[a.type as PiiType] ?? 0;
    const pb = PRIORITY[b.type as PiiType] ?? 0;
    if (pb !== pa) return pb - pa;
    return b.end - b.start - (a.end - a.start);
  });
  const out: Finding[] = [];
  let lastEnd = -1;
  for (const f of sorted) {
    if (f.start >= lastEnd) {
      out.push(f);
      lastEnd = f.end;
    }
    // else: overlapped by an earlier, better-or-equal finding — drop
  }
  return out;
}

/**
 * Coarse necessary-condition trigger fragments for the compiled precheck
 * (see scrub.ts). Each fragment must be implied by ANY match of that type
 * (over-firing is fine; under-firing is a bug). Single cheap regex test
 * replaces ~30 detector passes on trigger-free input.
 */
export const PII_TRIGGERS: Record<PiiType, string> = {
  email: '@',
  phone: '\\d',
  card: '\\d',
  iban: '\\d',
  bankAcct: '\\d',
  ssn: '\\d',
  passport: '\\d',
  license: '\\d',
  ipv4: '\\d',
  ipv6: ':[0-9a-fA-F:]',
  mac: '[:-][0-9a-fA-F]',
  uuid: '-[0-9a-fA-F]',
  urlSensitive: 'http',
  dob: '\\d',
  postal: '\\d',
  personName: 'mr|mrs|ms|miss|dr|prof|mx|name|customer|patient|client|contact|attn',
  address: '\\d',
};

/** Minimum confidence by level: strict 0.7, balanced 0.5, loose 0.3. */
function minConf(level: DetectionLevel): number {
  return level === 'strict' ? 0.7 : level === 'balanced' ? 0.5 : 0.3;
}

/** Detectors that need case-insensitive keyword context (drive lazy lowercasing). */
const NEEDS_LOWER: ReadonlySet<PiiType> = new Set(['bankAcct', 'passport', 'license', 'dob', 'postal']);

function isEnabled(enabled: Partial<Record<PiiType, boolean>> | undefined, key: PiiType): boolean {
  return enabled ? enabled[key] !== false : DEFAULT_ENABLED[key] === true;
}

/**
 * Detect PII in text. `enabled` selects types (default: DEFAULT_ENABLED).
 * Findings are overlap-resolved and sorted by start.
 */
export function detectPII(
  text: string,
  opts: PiiOptions & { enabled?: Partial<Record<PiiType, boolean>> } = {},
): Finding[] {
  const level = opts.level ?? 'balanced';
  const enabled = opts.enabled;
  const max = opts.maxLength ?? 1_000_000;
  if (text.length === 0) return [];
  const threshold = minConf(level);
  // Lowercase once, lazily: only context-gated detectors need it.
  let needLower = false;
  for (const key of Object.keys(DETECTORS) as PiiType[]) {
    if (NEEDS_LOWER.has(key) && isEnabled(enabled, key)) {
      needLower = true;
      break;
    }
  }
  const all: Finding[] = [];
  const scan = (chunk: string, offset: number): void => {
    const chunkLower = needLower ? chunk.toLowerCase() : '';
    for (const key of Object.keys(DETECTORS) as PiiType[]) {
      if (!isEnabled(enabled, key)) continue;
      const found = DETECTORS[key]!(chunk, level, chunkLower);
      for (const f of found) {
        if (f.confidence >= threshold) all.push({ type: f.type, start: f.start + offset, end: f.end + offset, confidence: f.confidence });
      }
    }
  };
  if (text.length <= max) {
    scan(text, 0);
  } else {
    // Chunked scan with 200-char overlap so boundary-spanning values are caught.
    const overlap = 200;
    let offset = 0;
    while (offset < text.length) {
      const end = Math.min(text.length, offset + max);
      scan(text.slice(offset, end), offset);
      if (end >= text.length) break;
      offset = end - overlap;
    }
  }
  return resolveOverlaps(all).sort((a, b) => a.start - b.start);
}