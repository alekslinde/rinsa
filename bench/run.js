// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/* Benchmarks: throughput + latency across hot paths.
 * Run: npm run bench
 * Tune iterations via BENCH_SCALE env (default 1).
 */
import { performance } from 'node:perf_hooks';
import {
  sanitize,
  compileSanitizer,
  normalizeCase,
  canonicalString,
  normalizePhone,
  toFloat,
  validateObjectWith,
  compileValidator,
  compilePolicy,
  compileScrubber,
  detectPII,
  detectSecrets,
  processJSONWith,
  compileStructured,
  mask,
  hashValue,
} from '../dist/esm/index.js';

const SCALE = Number(process.env.BENCH_SCALE ?? 1);

const smallClean = 'hello world';
const smallDirty = '  Héllo   WORLD​  ';
const unicodeMixed = 'ﬁ é  Trim  ß İ ①②③ 😀👍 '.repeat(200); // ~10KB
const bigClean = 'a'.repeat(1_000_000);
const piiLine =
  'user bob.smith@example.com call +1-415-555-0132 ip 10.0.0.1 card 4111111111111111 id 550e8400-e29b-41d4-a716-446655440000 ';
const bigDirty = piiLine.repeat(4000); // ~500KB
const secretLine = 'deploy key AKIAIOSFODNN7EXAMPLE token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0In0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c done ';
const bigSecrets = secretLine.repeat(2000); // ~400KB

const bigObj = {};
for (let i = 0; i < 2000; i++) bigObj['field' + i] = `  value ${i}  `;
bigObj.email = 'bob@example.com';
bigObj.card = '4111111111111111';
const bigJson = JSON.stringify(bigObj);

const san = compileSanitizer({});
const policy = compilePolicy({ sanitize: {}, scrub: {} });
const scrubber = compileScrubber({});
const validator = compileValidator({
  email: { type: 'string', format: 'email' },
  age: { type: 'integer', min: 0, max: 150 },
  name: { type: 'string', minLength: 1, maxLength: 100 },
});
const rec = { email: 'a@b.co', age: 33, name: 'Ada' };
const structured = compileStructured({ fields: { email: { scrub: {} } }, default: { sanitize: {} } });

const cases = [
  ['sanitize/no-op small', () => sanitize(smallClean), 200000],
  ['sanitize/compiled no-op small', () => san(smallClean), 200000],
  ['sanitize/dirty small', () => sanitize(smallDirty), 100000],
  ['sanitize/dirty 1MB', () => sanitize(bigClean), 20],
  ['normalize/lower+case', () => normalizeCase('HeLLo WoRLD sTrAsSe', { mode: 'lower' }), 100000],
  ['normalize/canonical 10KB', () => canonicalString(unicodeMixed), 200],
  ['normalize/phone', () => normalizePhone('+1 (415) 555-0132'), 100000],
  ['coerce/float', () => toFloat('1,000.50'), 100000],
  ['validate/compiled small record', () => validator(rec), 100000],
  ['validate/interpreted small record', () => validateObjectWith(rec, { email: { type: 'string', format: 'email' }, age: { type: 'integer', min: 0, max: 150 }, name: { type: 'string', minLength: 1, maxLength: 100 } }), 50000],
  ['pipeline/compiled clean', () => policy.process(smallClean), 100000],
  ['pipeline/compiled pii-line', () => policy.process(piiLine), 5000],
  ['unicode/normalize 10KB', () => unicodeMixed.normalize('NFKC'), 200],
  ['json/structured 2000-field', () => structured.processJSON(bigJson), 50],
  ['json/processJSONWith one-shot', () => processJSONWith(bigJson, { fields: { email: { scrub: {} } } }), 20],
  ['pii/detect clean small', () => detectPII(smallClean), 50000],
  ['pii/detect pii-line', () => detectPII(piiLine), 2000],
  ['pii/detect 500KB dirty', () => detectPII(bigDirty), 5],
  ['pii/scrub pii-line', () => scrubber.scrub(piiLine), 2000],
  ['pii/scrub 500KB dirty', () => scrubber.scrub(bigDirty), 5],
  ['secrets/detect line', () => detectSecrets(secretLine), 5000],
  ['secrets/detect 400KB', () => detectSecrets(bigSecrets), 5],
  ['transform/mask', () => mask('4111111111111111', { preserveEnd: 4 }), 200000],
  ['transform/hash', () => hashValue('4111111111111111', 'sha256', 12), 50000],
];

function bench(name, fn, iters) {
  const n = Math.max(1, Math.floor(iters * SCALE));
  // warmup
  for (let i = 0; i < Math.min(n, 100); i++) fn();
  const t0 = performance.now();
  for (let i = 0; i < n; i++) fn();
  const dt = performance.now() - t0;
  const ns = (dt * 1e6) / n;
  // bytes throughput when input size is knowable: report via closure length where possible
  console.log(`${name.padEnd(34)} ${String(Math.round(n / (dt / 1000))).padStart(12)} ops/s  ${ns < 10000 ? ns.toFixed(0).padStart(8) + ' ns/op' : (ns / 1e6).toFixed(2).padStart(8) + ' ms/op'}`);
}

console.log(`rinsa bench (node ${process.version}, scale=${SCALE})`);
for (const [name, fn, iters] of cases) bench(name, fn, iters);

// Throughput lines for large inputs
for (const [label, text] of [['1MB clean', bigClean], ['500KB pii-dirty', bigDirty]]) {
  const t0 = performance.now();
  const iters = 10;
  for (let i = 0; i < iters; i++) scrubber.scrub(text);
  const dt = (performance.now() - t0) / 1000;
  const mb = ((text.length * iters) / (1024 * 1024) / dt).toFixed(1);
  console.log(`scrub/throughput ${label.padEnd(14)} ${String(mb).padStart(8)} MB/s`);
}