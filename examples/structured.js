// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

import { processJSONWith, processCSV, processKV, compileStructured } from 'rinsa';

// JSON with field-specific rules
console.log(
  processJSONWith('{"email":"BOB@X.CO","password":"hunter2","age":"33"}', {
    fields: {
      email: { textCase: 'lower', scrub: {} },
      password: { drop: true },
      age: { coerce: 'integer' },
    },
  }),
);
// '{"email":"[REDACTED]","age":"33"}'

// CSV with per-column rules
console.log(
  processCSV('name,ssn\n Bob Smith ,078-05-1120\n', {
    columns: { name: { sanitize: {} }, ssn: { scrub: {} } },
  }),
);
// 'name,ssn\nBob Smith,[REDACTED]'

// KV (logfmt-style) records
console.log(processKV('user=bob ip=10.0.0.1 msg=hello', { fields: { ip: { scrub: {} } } }));
// 'user=bob ip=[REDACTED] msg=hello'

// Nested objects with wildcards
const cs = compileStructured({ fields: { '*.token': { drop: true } }, default: { sanitize: { maxChars: 100 } } });
console.log(JSON.stringify(cs.processValue({ svc: { token: 'abc', note: '  hi  ' } })));
// '{"svc":{"note":"hi"}}'