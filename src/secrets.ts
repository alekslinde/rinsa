// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Secret detectors: API keys, bearer tokens, JWTs, URL credentials,
 * cloud/service credentials, generic high-entropy tokens.
 */

import type { DetectionLevel, Finding, SecretType } from './types.js';

export interface SecretOptions {
  level?: DetectionLevel;
  maxLength?: number;
}

export const DEFAULT_SECRET_ENABLED: Record<SecretType, boolean> = {
  bearer: true,
  jwt: true,
  privateKey: true,
  aws: true,
  gcp: true,
  github: true,
  gitlab: true,
  slack: true,
  stripe: true,
  openai: true,
  genericKey: true,
  urlCreds: true,
};

const BEARER_RE = /\bBearer\s+([A-Za-z0-9\-._~+/=]{16,512})/g;
const JWT_RE = /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g;
const PRIVKEY_RE = /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g;
const AWS_KEY_RE = /\bAKIA[0-9A-Z]{16}\b/g;
const AWS_SECRET_CTX_RE = /aws.{0,30}secret.{0,10}[:=]\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi;
const GCP_RE = /\bAIza[0-9A-Za-z_-]{35}\b/g;
const GITHUB_RE = /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_-]{22,255}\b/g;
const GITLAB_RE = /\bglpat-[A-Za-z0-9_-]{20,255}\b/g;
const SLACK_RE = /\bxox[baprs]-[A-Za-z0-9-]{10,255}\b/g;
const STRIPE_RE = /\b(?:sk|rk|pk|whsec)_(?:live|test)_[A-Za-z0-9]{16,255}\b/g;
const OPENAI_RE = /\bsk-(?:ant|proj)-[A-Za-z0-9_-]{16,255}\b|\bsk-[A-Za-z0-9]{20,100}\b/g;
const GENERIC_CTX_RE = /(['"]?(?:api[_-]?key|secret|passwd|password|pwd|auth[_-]?token|access[_-]?token|client[_-]?secret)['"]?\s*[:=]\s*['"]?)([A-Za-z0-9\-_+/=]{12,512})/gi;
const URL_CREDS_RE = /\bhttps?:\/\/[^\s"'<>)|]*\b/gi;
const BARE_TOKEN_RE = /\b[A-Za-z0-9\-_+/=]{32,512}\b/g;

function execAll(re: RegExp, text: string, cap = 100000): RegExpExecArray[] {
  re.lastIndex = 0;
  const out: RegExpExecArray[] = [];
  let m: RegExpExecArray | null;
  let guard = 0;
  while ((m = re.exec(text)) !== null) {
    if (m[0].length === 0) {
      re.lastIndex++;
      continue;
    }
    out.push(m);
    if (++guard > cap) break;
    if (m.index === re.lastIndex) re.lastIndex++;
  }
  re.lastIndex = 0;
  return out;
}

function b64urlDecode(s: string): string | null {
  try {
    let t = s.replace(/-/g, '+').replace(/_/g, '/');
    while (t.length % 4 !== 0) t += '=';
    if (typeof Buffer !== 'undefined') return Buffer.from(t, 'base64').toString('utf8');
    return atob(t);
  } catch {
    return null;
  }
}

function jwtConfidence(token: string): number {
  const parts = token.split('.');
  if (parts.length !== 3) return 0;
  const head = b64urlDecode(parts[0]!);
  if (!head) return 0.6;
  try {
    const o = JSON.parse(head) as { alg?: string; typ?: string };
    if (typeof o.alg === 'string') return 0.95;
    return 0.65;
  } catch {
    return 0.55;
  }
}

function shannon(s: string): number {
  const freq = new Map<string, number>();
  for (const c of s) freq.set(c, (freq.get(c) ?? 0) + 1);
  let h = 0;
  for (const f of freq.values()) {
    const p = f / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

type DetectorFn = (text: string, level: DetectionLevel) => Finding[];

const detectBearer: DetectorFn = (text, level) => {
  if (!text.includes('Bearer')) return [];
  const out: Finding[] = [];
  for (const m of execAll(BEARER_RE, text)) {
    const tok = m[1]!;
    if (/^(token|here|xxx+|\*+)$/i.test(tok)) continue; // placeholder
    const start = m.index + m[0].lastIndexOf(tok);
    out.push({ type: 'bearer', start, end: start + tok.length, confidence: tok.length >= 20 ? 0.88 : level === 'loose' ? 0.5 : 0.7 });
  }
  return out;
};

const detectJwt: DetectorFn = (text) => {
  if (!text.includes('eyJ')) return [];
  const out: Finding[] = [];
  for (const m of execAll(JWT_RE, text)) {
    const c = jwtConfidence(m[0]);
    if (c > 0) out.push({ type: 'jwt', start: m.index, end: m.index + m[0].length, confidence: c });
  }
  return out;
};

const detectPrivKey: DetectorFn = (text) => {
  if (!text.includes('PRIVATE KEY')) return [];
  return execAll(PRIVKEY_RE, text).map((m) => ({ type: 'privateKey' as const, start: m.index, end: m.index + m[0].length, confidence: 0.95 }));
};

const detectAws: DetectorFn = (text, level) => {
  const out: Finding[] = [];
  for (const m of execAll(AWS_KEY_RE, text)) {
    out.push({ type: 'aws', start: m.index, end: m.index + m[0].length, confidence: 0.92 });
  }
  for (const m of execAll(AWS_SECRET_CTX_RE, text)) {
    const sec = m[1]!;
    const start = m.index + m[0].lastIndexOf(sec);
    out.push({ type: 'aws', start, end: start + sec.length, confidence: 0.8 });
  }
  void level;
  return out;
};

const detectGcp: DetectorFn = (text) => {
  if (!text.includes('AIza')) return [];
  return execAll(GCP_RE, text).map((m) => ({ type: 'gcp' as const, start: m.index, end: m.index + m[0].length, confidence: 0.88 }));
};

const detectGithub: DetectorFn = (text) => {
  if (!text.includes('gh') && !text.includes('github_pat')) return [];
  return execAll(GITHUB_RE, text).map((m) => ({ type: 'github' as const, start: m.index, end: m.index + m[0].length, confidence: 0.95 }));
};

const detectGitlab: DetectorFn = (text) => {
  if (!text.includes('glpat')) return [];
  return execAll(GITLAB_RE, text).map((m) => ({ type: 'gitlab' as const, start: m.index, end: m.index + m[0].length, confidence: 0.92 }));
};

const detectSlack: DetectorFn = (text) => {
  if (!text.includes('xox')) return [];
  return execAll(SLACK_RE, text).map((m) => ({ type: 'slack' as const, start: m.index, end: m.index + m[0].length, confidence: 0.92 }));
};

const detectStripe: DetectorFn = (text) => {
  if (!text.includes('_live_') && !text.includes('_test_')) return [];
  return execAll(STRIPE_RE, text).map((m) => ({ type: 'stripe' as const, start: m.index, end: m.index + m[0].length, confidence: 0.9 }));
};

const detectOpenAI: DetectorFn = (text) => {
  if (!text.includes('sk-')) return [];
  return execAll(OPENAI_RE, text).map((m) => ({ type: 'openai' as const, start: m.index, end: m.index + m[0].length, confidence: 0.85 }));
};

const detectGeneric: DetectorFn = (text, level) => {
  const out: Finding[] = [];
  for (const m of execAll(GENERIC_CTX_RE, text)) {
    const secret = m[2]!;
    if (/^(xxx+|test|example|changeme|\*+)$/i.test(secret)) continue;
    const start = m.index + m[0].lastIndexOf(secret);
    out.push({ type: 'genericKey', start, end: start + secret.length, confidence: secret.length >= 16 ? 0.7 : 0.55 });
  }
  if (level === 'loose') {
    // Bare high-entropy strings (recall-oriented; lowest confidence tier).
    for (const m of execAll(BARE_TOKEN_RE, text)) {
      if (m[0].length < 32) continue;
      if (/^(?:[0-9a-fA-F]{32}|[0-9a-fA-F-]{36})$/.test(m[0])) continue; // hash/uuid lookalikes handled elsewhere
      if (shannon(m[0]) >= 4.2) out.push({ type: 'genericKey', start: m.index, end: m.index + m[0].length, confidence: 0.32 });
    }
  }
  return out;
};

const detectUrlCreds: DetectorFn = (text) => {
  if (!/http/i.test(text)) return [];
  const out: Finding[] = [];
  for (const m of execAll(URL_CREDS_RE, text)) {
    const url = m[0].replace(/[.,;:!?]+$/, '');
    const at = url.indexOf('@');
    const schemeEnd = url.indexOf('://') + 3;
    const slash = url.indexOf('/', schemeEnd);
    if (at > schemeEnd && (slash < 0 || at < slash)) {
      const authority = url.slice(schemeEnd, slash < 0 ? url.length : slash);
      if (authority.includes(':')) {
        out.push({ type: 'urlCreds', start: m.index, end: m.index + url.length, confidence: 0.92 });
      }
    }
  }
  return out;
};

const DETECTORS: Record<SecretType, DetectorFn> = {
  bearer: detectBearer,
  jwt: detectJwt,
  privateKey: detectPrivKey,
  aws: detectAws,
  gcp: detectGcp,
  github: detectGithub,
  gitlab: detectGitlab,
  slack: detectSlack,
  stripe: detectStripe,
  openai: detectOpenAI,
  genericKey: detectGeneric,
  urlCreds: detectUrlCreds,
};

/** Coarse necessary-condition trigger fragments (see PII_TRIGGERS docs). */
export function secretTrigger(type: SecretType, level: DetectionLevel): string {
  switch (type) {
    case 'bearer':
      return 'bearer';
    case 'jwt':
      return 'eyJ';
    case 'privateKey':
      return 'private';
    case 'aws':
      return 'akia|aws';
    case 'gcp':
      return 'aiza';
    case 'github':
      return 'ghp_|gho_|ghu_|ghs_|ghr_|github';
    case 'gitlab':
      return 'glpat';
    case 'slack':
      return 'xox';
    case 'stripe':
      return '_live_|_test_';
    case 'openai':
      return 'sk-';
    case 'genericKey':
      // Loose bare-entropy mode has no keyword precondition: always scan.
      if (level === 'loose') return '[\\s\\S]';
      return 'key|secret|passwd|password|pwd|token';
    case 'urlCreds':
      return 'http';
  }
}

function minConf(level: DetectionLevel): number {
  return level === 'strict' ? 0.7 : level === 'balanced' ? 0.5 : 0.3;
}

export function detectSecrets(
  text: string,
  opts: SecretOptions & { enabled?: Partial<Record<SecretType, boolean>> } = {},
): Finding[] {
  const level = opts.level ?? 'balanced';
  const enabled = opts.enabled;
  const max = opts.maxLength ?? 1_000_000;
  if (text.length === 0) return [];
  const threshold = minConf(level);
  const all: Finding[] = [];
  const scan = (chunk: string, offset: number): void => {
    for (const key of Object.keys(DETECTORS) as SecretType[]) {
      if (enabled ? enabled[key] === false : !DEFAULT_SECRET_ENABLED[key]) continue;
      for (const f of DETECTORS[key]!(chunk, level)) {
        if (f.confidence >= threshold) all.push({ ...f, start: f.start + offset, end: f.end + offset });
      }
    }
  };
  if (text.length <= max) scan(text, 0);
  else {
    const overlap = 300;
    let offset = 0;
    while (offset < text.length) {
      const end = Math.min(text.length, offset + max);
      scan(text.slice(offset, end), offset);
      if (end >= text.length) break;
      offset = end - overlap;
    }
  }
  // Resolve overlaps: prefer longer/higher-confidence.
  all.sort((a, b) => a.start - b.start || b.confidence - a.confidence || b.end - b.start - (a.end - a.start));
  const out: Finding[] = [];
  let lastEnd = -1;
  for (const f of all) {
    if (f.start >= lastEnd) {
      out.push(f);
      lastEnd = f.end;
    }
  }
  return out;
}