// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

/* Allocation check: heap delta per op (requires --expose-gc for precision).
 * Run: node --expose-gc bench/alloc.js   (or npm run bench:alloc)
 */
import { sanitize, compileSanitizer, compileScrubber, compilePolicy } from '../dist/esm/index.js';

const canGC = typeof global.gc === 'function';
if (!canGC) console.log('(tip: run with node --expose-gc for precise numbers)');

function heap() {
  if (canGC) global.gc();
  return process.memoryUsage().heapUsed;
}

function allocPerOp(name, fn, iters = 20000) {
  for (let i = 0; i < 1000; i++) fn(); // warmup + stabilize
  const before = heap();
  for (let i = 0; i < iters; i++) fn();
  const after = heap();
  const perOp = (after - before) / iters;
  console.log(`${name.padEnd(40)} ~${perOp < 0 ? 0 : perOp.toFixed(1).padStart(8)} bytes/op`);
}

const clean = 'hello world';
const dirty = '  hello   world  ';
const san = compileSanitizer({});
const scrubber = compileScrubber({});
const policy = compilePolicy({ sanitize: {}, scrub: {} });

allocPerOp('sanitize one-shot / clean (expect ~0)', () => sanitize(clean));
allocPerOp('sanitize compiled / clean (expect ~0)', () => san(clean));
allocPerOp('sanitize compiled / dirty', () => san(dirty));
allocPerOp('scrubber / clean (expect ~0-ish)', () => scrubber.scrub(clean));
allocPerOp('scrubber / pii-line', () => scrubber.scrub('mail bob@example.com ip 10.0.0.1'));
allocPerOp('policy.process / clean', () => policy.process(clean));

console.log('RSS: ' + (process.memoryUsage().rss / 1024 / 1024).toFixed(1) + ' MB');