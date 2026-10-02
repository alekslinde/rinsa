// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/**
 * Scrub engine: applies per-type actions to PII/secret findings.
 * Deterministic; fail-closed on finding overflow; Crypto via node:crypto.
 */

import { detectPII, resolveOverlaps, DEFAULT_ENABLED, PII_TRIGGERS } from './pii.js';
import { detectSecrets, DEFAULT_SECRET_ENABLED, secretTrigger } from './secrets.js';
import { hashValue, hmacValue, mask, tokenize, truncate } from './transform.js';
import type { ActionConfig, Finding, FindingType, PiiType, ScrubPolicy, SecretType, TypeRule } from './types.js';

export interface ScrubResult {
  text: string;
  findings: Finding[];
  redactedCount: number;
}

export interface CompiledScrubber {
  scrub(input: string): string;
  scrubDetailed(input: string): ScrubResult;
  detect(input: string): Finding[];
}

const DEFAULT_ACTION: ActionConfig = { action: 'redact', replacement: '[REDACTED]' };

function resolveAction(policy: ScrubPolicy | undefined, type: FindingType): ActionConfig | null {
  const rule: TypeRule | undefined = policy?.types?.[type];
  if (rule?.enabled === false) return null;
  const action = rule?.action ?? policy?.defaultAction?.action ?? 'redact';
  if (action === 'keep') return { action: 'keep' };
  return {
    action,
    replacement: rule?.replacement ?? policy?.defaultAction?.replacement ?? '[REDACTED]',
    maskChar: rule?.maskChar ?? policy?.defaultAction?.maskChar ?? '*',
    preserveStart: rule?.preserveStart ?? policy?.defaultAction?.preserveStart ?? 0,
    preserveEnd: rule?.preserveEnd ?? policy?.defaultAction?.preserveEnd ?? 0,
    preserveLength: rule?.preserveLength ?? policy?.defaultAction?.preserveLength ?? true,
    hashAlg: rule?.hashAlg ?? policy?.defaultAction?.hashAlg ?? 'sha256',
    hashLength: rule?.hashLength ?? policy?.defaultAction?.hashLength ?? 12,
    hmacKey: rule?.hmacKey ?? policy?.defaultAction?.hmacKey,
    hmacLength: rule?.hmacLength ?? policy?.defaultAction?.hmacLength ?? 12,
    tokenPrefix: rule?.tokenPrefix ?? policy?.defaultAction?.tokenPrefix ?? 'tok_',
    tokenKey: rule?.tokenKey ?? policy?.defaultAction?.tokenKey,
    truncateLength: rule?.truncateLength ?? policy?.defaultAction?.truncateLength ?? 4,
    truncateSuffix: rule?.truncateSuffix ?? policy?.defaultAction?.truncateSuffix ?? '…',
  };
}

/** Validate policy eagerly so misconfiguration fails fast (not per-input). Throws on error. */
export function validateScrubPolicy(policy: ScrubPolicy = {}): void {
  const types = policy.types ?? {};
  for (const key of Object.keys(types)) {
    const r = types[key as FindingType]!;
    if (r.action === 'hmac' && r.hmacKey === undefined && policy.defaultAction?.hmacKey === undefined) {
      throw new Error(`rinsa: hmac action for '${key}' requires hmacKey (no default provided)`);
    }
  }
  if (policy.defaultAction?.action === 'hmac' && policy.defaultAction.hmacKey === undefined) {
    // Only throws if some enabled type actually resolves to default hmac without override.
    for (const key of Object.keys(types)) {
      const r = types[key as FindingType]!;
      if (r.action === undefined && r.enabled !== false) throw new Error(`rinsa: default hmac action requires hmacKey`);
    }
  }
}

function applyAction(value: string, cfg: ActionConfig): string {
  switch (cfg.action) {
    case 'keep':
      return value;
    case 'redact':
    case 'replace':
      return cfg.replacement ?? '[REDACTED]';
    case 'mask':
      return mask(value, { maskChar: cfg.maskChar, preserveStart: cfg.preserveStart, preserveEnd: cfg.preserveEnd, preserveLength: cfg.preserveLength });
    case 'hash':
      return hashValue(value, cfg.hashAlg ?? 'sha256', cfg.hashLength ?? 12);
    case 'hmac':
      if (cfg.hmacKey === undefined) return hashValue(value, cfg.hashAlg ?? 'sha256', cfg.hashLength ?? 12);
      return hmacValue(value, cfg.hmacKey, cfg.hashAlg ?? 'sha256', cfg.hmacLength ?? 12);
    case 'tokenize':
      return tokenize(value, { prefix: cfg.tokenPrefix ?? 'tok_', key: cfg.tokenKey, length: cfg.hmacLength ?? 12 });
    case 'truncate':
      return truncate(value, { maxLength: cfg.truncateLength ?? 4, suffix: cfg.truncateSuffix ?? '…' });
    case 'drop':
      return '';
  }
}

interface ResolvedPolicy {
  level: 'strict' | 'balanced' | 'loose';
  maxLength: number;
  maxFindings: number;
  overflow: 'redact-all' | 'leave-tail';
  piiEnabled: Partial<Record<PiiType, boolean>>;
  secEnabled: Partial<Record<SecretType, boolean>>;
  actions: Map<FindingType, ActionConfig | null>;
  types: Partial<Record<FindingType, TypeRule>>;
  /** Combined necessary-condition precheck; null when nothing (or only keep-actions) is active. */
  trigger: RegExp | null;
  activeCount: number;
}

function resolvePolicy(policy: ScrubPolicy = {}): ResolvedPolicy {
  validateScrubPolicy(policy);
  const level = policy.level ?? 'balanced';
  const piiEnabled: Partial<Record<PiiType, boolean>> = {};
  const secEnabled: Partial<Record<SecretType, boolean>> = {};
  const actions = new Map<FindingType, ActionConfig | null>();
  const types = policy.types ?? {};
  const fragments: string[] = [];
  let activeCount = 0;
  const levelOf = (t: FindingType): 'strict' | 'balanced' | 'loose' => types[t]?.level ?? level;
  for (const k of Object.keys(DEFAULT_ENABLED) as PiiType[]) {
    const r = types[k];
    piiEnabled[k] = r?.enabled ?? DEFAULT_ENABLED[k];
    actions.set(k, resolveAction(policy, k));
    if (piiEnabled[k] !== false && actions.get(k)?.action !== 'keep') {
      fragments.push(PII_TRIGGERS[k]);
      activeCount++;
    }
  }
  for (const k of Object.keys(DEFAULT_SECRET_ENABLED) as SecretType[]) {
    const r = types[k];
    secEnabled[k] = r?.enabled ?? DEFAULT_SECRET_ENABLED[k];
    actions.set(k, resolveAction(policy, k));
    if (secEnabled[k] !== false && actions.get(k)?.action !== 'keep') {
      fragments.push(secretTrigger(k, levelOf(k)));
      activeCount++;
    }
  }
  return {
    level,
    maxLength: policy.maxLength ?? 1_000_000,
    maxFindings: 5000,
    overflow: 'redact-all',
    piiEnabled,
    secEnabled,
    actions,
    types,
    trigger: activeCount > 0 ? new RegExp(fragments.join('|'), 'i') : null,
    activeCount,
  };
}

/** Per-type detection level: rule.level overrides the global level. */
function levelFor(rp: ResolvedPolicy, type: FindingType): 'strict' | 'balanced' | 'loose' {
  return rp.types[type]?.level ?? rp.level;
}

function detectAll(text: string, rp: ResolvedPolicy): Finding[] {
  if (rp.activeCount === 0 || text.length === 0) return [];
  // Combined precheck: one regex test skips all detectors when no type can fire.
  if (rp.trigger !== null && !rp.trigger.test(text)) return [];
  let uniform: ('strict' | 'balanced' | 'loose') | null = rp.level;
  for (const k of Object.keys(rp.piiEnabled) as PiiType[]) {
    if (rp.piiEnabled[k] === false) continue;
    if (levelFor(rp, k) !== uniform) {
      uniform = null;
      break;
    }
  }
  if (uniform !== null) {
    for (const k of Object.keys(rp.secEnabled) as SecretType[]) {
      if (rp.secEnabled[k] === false) continue;
      if (levelFor(rp, k) !== uniform) {
        uniform = null;
        break;
      }
    }
  }
  if (uniform !== null) {
    const lv = uniform;
    const pii = detectPII(text, { level: lv, maxLength: rp.maxLength, enabled: rp.piiEnabled });
    const sec = detectSecrets(text, { level: lv, maxLength: rp.maxLength, enabled: rp.secEnabled });
    return resolveOverlaps(pii.concat(sec)).sort((a, b) => a.start - b.start);
  }
  // Mixed per-type levels: group by level (rare; correctness over speed).
  const byLevel = new Map<string, Array<PiiType | SecretType>>();
  for (const k of Object.keys(rp.piiEnabled) as PiiType[]) {
    if (rp.piiEnabled[k] === false) continue;
    const g = 'pii:' + levelFor(rp, k);
    if (!byLevel.has(g)) byLevel.set(g, []);
    byLevel.get(g)!.push(k);
  }
  for (const k of Object.keys(rp.secEnabled) as SecretType[]) {
    if (rp.secEnabled[k] === false) continue;
    const g = 'sec:' + levelFor(rp, k);
    if (!byLevel.has(g)) byLevel.set(g, []);
    byLevel.get(g)!.push(k);
  }
  const all: Finding[] = [];
  for (const [group, types] of byLevel) {
    const [kind, lv] = group.split(':') as ['pii' | 'sec', 'strict' | 'balanced' | 'loose'];
    if (kind === 'pii') {
      const enabled: Partial<Record<PiiType, boolean>> = {};
      for (const k of Object.keys(rp.piiEnabled) as PiiType[]) enabled[k] = types.includes(k);
      all.push(...detectPII(text, { level: lv, maxLength: rp.maxLength, enabled }));
    } else {
      const enabled: Partial<Record<SecretType, boolean>> = {};
      for (const k of Object.keys(rp.secEnabled) as SecretType[]) enabled[k] = types.includes(k);
      all.push(...detectSecrets(text, { level: lv, maxLength: rp.maxLength, enabled }));
    }
  }
  return resolveOverlaps(all).sort((a, b) => a.start - b.start);
}

function applyFindings(text: string, findings: Finding[], rp: ResolvedPolicy): string {
  if (findings.length === 0) return text;
  if (findings.length > rp.maxFindings) {
    if (rp.overflow === 'redact-all') return '[REDACTED]';
    findings = findings.slice(0, rp.maxFindings);
  }
  let out: string[] | null = null;
  let pos = 0;
  for (const f of findings) {
    const cfg = rp.actions.get(f.type);
    if (!cfg || cfg.action === 'keep') continue;
    const value = text.slice(f.start, f.end);
    const rep = applyAction(value, cfg);
    if (rep === value) continue;
    if (out === null) out = [text.slice(0, f.start)];
    else out.push(text.slice(pos, f.start));
    out.push(rep);
    pos = f.end;
  }
  if (out === null) return text;
  out.push(text.slice(pos));
  return out.join('');
}

/** Compile a scrub policy once; reuse for many inputs (zero per-input config cost). */
export function compileScrubber(policy: ScrubPolicy = {}): CompiledScrubber {
  const rp = resolvePolicy(policy);
  return {
    scrub: (input: string) => {
      if (input.length === 0) return input;
      return applyFindings(input, detectAll(input, rp), rp);
    },
    scrubDetailed: (input: string) => {
      if (input.length === 0) return { text: input, findings: [], redactedCount: 0 };
      const findings = detectAll(input, rp);
      const text = applyFindings(input, findings, rp);
      let n = 0;
      for (const f of findings) {
        const cfg = rp.actions.get(f.type);
        if (cfg && cfg.action !== 'keep') n++;
      }
      return { text, findings, redactedCount: n };
    },
    detect: (input: string) => (input.length === 0 ? [] : detectAll(input, rp)),
  };
}

/** One-shot PII scrub (compiles policy each call — prefer compileScrubber in loops). */
export function scrubPII(text: string, policy: ScrubPolicy = {}): string {
  return compileScrubber(policy).scrub(text);
}

/** One-shot secret scrub. */
export function scrubSecrets(text: string, policy: ScrubPolicy = {}): string {
  return compileScrubber(policy).scrub(text);
}

/** Combined detect (PII + secrets) without scrubbing. */
export function detectAllFindings(text: string, policy: ScrubPolicy = {}): Finding[] {
  return compileScrubber(policy).detect(text);
}