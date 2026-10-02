# rinsa

Tiny, extremely fast sanitisation, normalisation, transformation, validation
and PII/secret scrubbing. **Zero runtime dependencies.** Node ≥ 18.

by [Aleks Linde](https://alekslinde.com)

```js
import { compilePolicy, profiles } from '@rinsadev/core';

const process = compilePolicy(profiles.freeText()).process;
process('  Contact  bob@example.com  '); // 'Contact [REDACTED]'
```

## Why

- **Fast**: ASCII fast paths, single-pass sanitiser, lazy allocation (clean
  input returns by reference, ~0 bytes/op), one-regex precheck that skips all
  29 PII/secret detectors on trigger-free text (~130ns).
- **Small**: ~145KB runtime JS (~40KB gzipped), no dependencies.
- **Composable**: every primitive works standalone or inside a compiled
  `Policy` (`sanitize → case → coerce → scrub → truncate`).
- **Safe**: validation never echoes values; scrubbing is deterministic and
  fail-closed; `__proto__` keys can't pollute structured output.

## Install

npm:

```sh
npm i @rinsadev/core
```

pnpm:

```sh
pnpm add @rinsadev/core
```

yarn:

```sh
yarn add @rinsadev/core
```

bun:

```sh
bun add @rinsadev/core
```

Deno (npm specifier):

```js
import { compilePolicy, profiles } from 'npm:@rinsadev/core';
```

CDN (ESM, no install):

```js
import { compilePolicy, profiles } from 'https://esm.sh/@rinsadev/core';
```

## Quick start

```js
import {
  sanitize,             // trim/collapse/controls/zero-width/bidi/limits/allow-block
  normalizePhone,       // '+1 (415) 555-0132' -> '+14155550132'
  toFloat,              // '1,000.50' -> 1000.5 (explicit policies)
  validateObjectWith,   // schema validation, values never echoed
  compileScrubber,      // PII + secrets with per-type actions
  processJSONWith,      // JSON with field-specific rules
} from '@rinsadev/core';

// Per-type scrub actions: redact | replace | mask | hash | hmac | tokenize | truncate | drop | keep
const scrub = compileScrubber({
  level: 'balanced',                       // strict | balanced | loose
  defaultAction: { action: 'redact' },
  types: {
    card:  { action: 'mask', preserveEnd: 4 },
    email: { action: 'hash', hashLength: 12 },
    jwt:   { action: 'drop' },
    ipv4:  { enabled: false },
  },
});
scrub.scrub('pay 4111111111111111 to bob@example.com');
// 'pay ************1111 to 5ff860bf1190'
```

## Compile once, run hot

One-shot helpers (`sanitize()`, `scrubPII()`, `processText()`) compile config
on every call. In loops, compile first:

```js
const clean = compileSanitizer({ maxChars: 500 }); // (s) => s
const check = compileValidator(schema);            // (obj) => { ok, issues }
const policy = compilePolicy({ sanitize: {}, scrub: {} });
```

Disabled stages cost one null-check. Clean strings return by reference.

## Profiles

Transparent starting policies (plain objects — spread/override anything):

`identifier email phone numeric url humanName freeText logData llmInput analytics`

```js
import { compilePolicy, profiles } from '@rinsadev/core';
compilePolicy(profiles.analytics()).process('user bob@example.com');
// 'user 5ff860bf1190596c'  (deterministic hash — joinable, raw value gone)
```

## Structured data

```js
processJSONWith('{"email":"a@b.co","pw":"x"}', {
  fields: { email: { scrub: {} }, pw: { drop: true } },
  default: { sanitize: { maxChars: 1000 } },
});
// '{"email":"[REDACTED]"}'
```

Objects/Maps/arrays/Buffers, CSV (`processCSV` with per-column rules),
KV records (`processKV`), depth/key/array caps, circular → `null`.

## Performance

Node 22, Apple M-series:

| case | throughput |
|---|---|
| sanitize no-op | ~10M ops/s, ~0 B/op |
| policy clean (sanitize+scrub) | ~6M ops/s |
| scrub 1MB clean | ~220 MB/s |
| scrub PII-dense | ~18 MB/s |
| JSON 2000 fields | ~1600 ops/s |

Run your own: `npm run bench`, allocations: `npm run bench:alloc`.

## Security notes

- Sanitisation is **not injection protection**. HTML/SQL/shell escaping and
  parameterized queries are still required; context encoding is out of scope.
- `hash` without a key is an identifier, not secrecy — use `hmac` with a
  caller-held key for sensitive joins. Token reversal needs your own vault.
- Heuristic types (`personName`, `address`) are **opt-in** (off by default).
- `loose` recall mode disables the detection precheck for `genericKey`.

## API map

| module | highlights |
|---|---|
| `sanitize` | `sanitize/compileSanitizer/sanitizeBytes/isValidUTF8/charLength` |
| `unicode` | `normalizeForm/lower/upper/fold/stripDiacritics/equalFold` |
| `normalize` | case/whitespace/number/boolean/date/identifier/UUID/phone/canonical |
| `coerce` | `toInteger/toFloat/toBoolean/toDate` + `withDefault/nullIfEmpty` |
| `validate` | `validateValue/validateObjectWith/compileValidator` + cross-field |
| `transform` | map/replace/filter/mask/redact/hash/hmac/tokenize/truncate/pipe |
| `pii/secrets` | `detectPII/detectSecrets` (17 PII + 12 secret types) |
| `scrub` | `compileScrubber/scrubPII/scrubSecrets/detectAllFindings` |
| `structured` | `compileStructured/processJSONWith/processCSV/processKV` |
| `policy/profiles` | `compilePolicy/processText` + 10 profiles |

## Licence

| Part | Licence |
|---|---|
| Everything in this repository | [Apache-2.0](https://github.com/alekslinde/rinsa/blob/main/LICENSE) |

Apache-2.0 rather than MIT for the explicit patent grant: contributors grant a
patent licence over their contributions, and that grant terminates for anyone
who starts patent litigation over the project. For a library meant to be
embedded, that protects both you and your users.

Copyright 2026 [Aleksandr Linde](https://alekslinde.com). Third-party credits: [NOTICE](https://github.com/alekslinde/rinsa/blob/main/NOTICE) — rinsa
has no runtime dependencies, so there are none to credit.

Licensing metadata follows [REUSE](https://reuse.software/); run `reuse lint`
to verify. Contributions are under the same licence via DCO sign-off — see
[CONTRIBUTING.md](https://github.com/alekslinde/rinsa/blob/main/CONTRIBUTING.md).

"rinsa" is the project name; the licence does not grant trademark rights
(Apache-2.0 §6).
