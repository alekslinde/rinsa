# Contributing to rinsa

Thanks for your interest. rinsa is a small, dependency-free library, and the
bar for adding to it is deliberately high — read "What gets merged" before
writing code.

## Licence and the DCO

rinsa is licensed under **Apache-2.0**. Contributions are accepted under the
same licence. You keep copyright in what you write.

We use the [Developer Certificate of Origin](https://developercertificate.org/)
rather than a CLA. It is a statement that you have the right to submit the
code. To agree to it, sign off each commit:

```sh
git commit -s -m "fix(scrub): correct card mask boundary"
```

That appends a line to your commit message:

```
Signed-off-by: Your Name <your.email@example.com>
```

Your name and email must be real and match your git config. CI rejects commits
without a sign-off. To fix the last commit: `git commit --amend -s`. For a
branch: `git rebase --signoff main`.

New files need the SPDX header, after any shebang:

```js
// SPDX-FileCopyrightText: 2026 Your Name
// SPDX-License-Identifier: Apache-2.0
```

Run `reuse lint` to check.

## Development

```sh
npm install        # devDependencies only; rinsa itself has none
npm run build      # ESM + CJS into dist/
npm test           # builds, then runs node --test
npm run bench      # throughput
npm run bench:alloc # allocations per op
```

Requires Node >= 18.

## What gets merged

rinsa trades breadth for speed and size. Changes are weighed against both.

**Likely to be merged**

- Correctness fixes, especially a detector that misses or over-matches
- A missing PII or secret type with a precise, low-false-positive pattern
- Performance work that keeps behaviour identical
- Tests covering an untested path
- Documentation that corrects something wrong or unclear

**Likely to be rejected**

- A runtime dependency. rinsa has zero and will keep zero
- Context-specific escaping (HTML, SQL, shell). Out of scope by design — see
  the security notes in the README
- A detector that fires on ordinary prose. False positives silently corrupt
  user data, which is worse than a miss
- API surface that duplicates what a profile or policy already composes

If you are unsure whether something fits, open an issue before writing it.

## Standards for a change

- **Tests.** Every behavioural change needs a test. Detectors need both a
  positive case and a negative case that proves it does not over-match.
- **Performance.** If you touch a hot path (`sanitize`, `scrub`, the detection
  precheck), post `npm run bench` before and after. A regression needs a
  reason.
- **No new dependencies.** Including dev ones, unless they earn their place.
- **Determinism.** Scrubbing must be reproducible. Same input and config means
  same output, always.
- **Never echo values.** Validation errors and thrown messages must not contain
  the data being validated. It is routinely secrets. Check your error strings.

## Security

Do not open a public issue for a vulnerability. Report it privately through
[GitHub Security Advisories](https://github.com/alekslinde/rinsa/security/advisories/new).

A detector that fails to match something sensitive is a bug worth reporting,
but it is not a vulnerability in rinsa — the README is explicit that scrubbing
is best-effort pattern matching and not a security boundary.

## Commits and pull requests

Commit messages follow [Conventional Commits](https://www.conventionalcommits.org/):
`<type>(<scope>): <description>`, with type one of `feat`, `fix`, `refactor`,
`docs`, `test`, `chore`, `perf`.

Keep a pull request to one logical change. Fill in the template — particularly
the performance and false-positive sections, which exist because they are the
two ways a change to this library most often does harm.
