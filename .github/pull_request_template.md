<!--
SPDX-FileCopyrightText: 2026 Aleksandr Linde
SPDX-License-Identifier: Apache-2.0
-->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- What was wrong, or what this makes possible. -->

## Type

- [ ] `fix` — corrects behaviour
- [ ] `feat` — adds capability
- [ ] `perf` — faster or smaller, behaviour identical
- [ ] `refactor` — no behavioural change
- [ ] `docs` / `test` / `chore`

## Checks

- [ ] `npm test` passes
- [ ] Commits signed off (`git commit -s`) — see CONTRIBUTING.md
- [ ] New files carry the SPDX header
- [ ] No new runtime dependencies

## Detection changes

<!-- Delete if this does not touch a PII/secret detector. -->

- [ ] Added a positive test (it matches what it should)
- [ ] Added a negative test (it does not match ordinary text)

False positives silently corrupt real user data, so say what you did to rule
them out:

<!-- e.g. "ran the detector over the fuzz corpus; no new matches" -->

## Performance

<!-- Required if this touches sanitize, scrub, or the detection precheck.
     Delete otherwise. -->

`npm run bench` before:

```
```

after:

```
```

## Breaking changes

<!-- Any change to output for the same input is breaking, including a new
     detector that matches more. Describe what breaks and who notices.
     Write "None" if none. -->

None
