// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

// Post-process dist/cjs: TS preserves ESM-style './x.js' specifiers, which
// Node CJS cannot resolve. Rewrite static require("./x.js") -> require("./x").
import { readdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const dir = fileURLToPath(new URL('../dist/cjs/', import.meta.url));
for (const f of readdirSync(dir)) {
  if (!f.endsWith('.js')) continue;
  const p = join(dir, f);
  const src = readFileSync(p, 'utf8');
  const out = src.replace(/require\("(\.[^"]*)\.js"\)/g, 'require("$1")');
  if (out !== src) writeFileSync(p, out);
}
console.log('cjs requires fixed');