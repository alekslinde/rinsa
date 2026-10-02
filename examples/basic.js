// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import {
  sanitize,
  normalizePhone,
  toFloat,
  validateObjectWith,
  compileScrubber,
  compilePolicy,
  profiles,
} from 'rinsa';

console.log(sanitize('  Héllo   WORLD\u200b  ')); // 'Héllo WORLD'
console.log(normalizePhone('+1 (415) 555-0132')); // '+14155550132'
console.log(toFloat('1,000.50')); // 1000.5

const v = validateObjectWith(
  { email: 'a@b.co', age: 33 },
  { email: { type: 'string', format: 'email' }, age: { type: 'integer', min: 0 } },
);
console.log(v); // { ok: true, issues: [] }

const scrub = compileScrubber({ types: { card: { action: 'mask', preserveEnd: 4 } } });
console.log(scrub.scrub('pay 4111111111111111 to bob@example.com'));
// 'pay ************1111 to [REDACTED]'

const process = compilePolicy(profiles.analytics()).process;
console.log(process('user bob@example.com')); // 'user 5ff860bf1190596d…'(16 hex)