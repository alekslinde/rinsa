// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

// The docs site is generated from the README, so the build is the thing that
// can silently rot: a renamed heading, a relative link that 404s on the site,
// or a comment leaking into the page. Check the generated output rather than
// trusting the generator.
//
// Each test builds its own page. Building once at module load would pin every
// assertion to one snapshot taken before the test body runs, so a test that
// edits its input would still read the stale page and pass regardless.

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const readmePath = path.join(root, 'README.md');
const script = path.join(root, 'scripts', 'build-docs.js');

// Build into a throwaway directory so the tests never depend on, or clobber,
// whatever is currently in docs-site/.
function build() {
  const outDir = mkdtempSync(path.join(tmpdir(), 'rinsa-docs-'));
  try {
    execFileSync(process.execPath, [script], {
      cwd: root,
      env: { ...process.env, DOCS_OUT_DIR: outDir },
      stdio: 'pipe',
    });
    return readFileSync(path.join(outDir, 'index.html'), 'utf8');
  } finally {
    rmSync(outDir, { recursive: true, force: true });
  }
}

// Build with the README temporarily patched, then always put it back. Returns
// the generated page, or the build's error if it refused to run.
function buildWithReadme(transform) {
  const original = readFileSync(readmePath, 'utf8');
  writeFileSync(readmePath, transform(original));
  try {
    return { html: build(), error: null };
  } catch (error) {
    return { html: null, error };
  } finally {
    writeFileSync(readmePath, original);
  }
}

describe('docs build', () => {
  test('renders every README section as a heading', () => {
    const html = build();
    const readme = readFileSync(readmePath, 'utf8');
    const headings = [...readme.matchAll(/^##[ \t]+(.+?)[ \t]*$/gm)].map((m) => m[1]);
    assert.ok(headings.length > 5, 'expected the README to have sections');
    for (const heading of headings) {
      assert.ok(
        html.includes(`>${heading}<a class="anchor"`),
        `generated page is missing the "${heading}" heading`,
      );
    }
  });

  test('a new README section reaches the site', () => {
    const { html } = buildWithReadme((md) => `${md}\n## Totally New Section\n\nbody\n`);
    assert.ok(
      html.includes('>Totally New Section<a class="anchor"'),
      'a section added to the README did not reach the generated page',
    );
  });

  test('fails loudly when the Install heading is renamed', () => {
    // Silently rendering the README's one-line Install section would quietly
    // drop five package managers from the site.
    const { error } = buildWithReadme((md) => md.replace(/^## Install$/m, '## Installation'));
    assert.ok(error, 'build should refuse to run when it cannot find the Install section');
    assert.match(String(error.stderr ?? error), /no "## Install" section/);
  });

  test('emits no duplicate heading ids', () => {
    const ids = [...build().matchAll(/<h[1-6] id="([^"]+)"/g)].map((m) => m[1]);
    assert.deepEqual(ids, [...new Set(ids)], 'duplicate heading id would break anchors');
  });

  test('substitutes the full install section', () => {
    // The README ships the one-line npm form; the site must get every manager.
    const html = build();
    for (const manager of ['npm i', 'pnpm add', 'yarn add', 'bun add', 'esm.sh']) {
      assert.ok(html.includes(manager), `install section is missing ${manager}`);
    }
  });

  test('leaves no repo-relative links to 404 on the site', () => {
    for (const [, href] of build().matchAll(/<a[^>]+href="([^"]+)"/g)) {
      assert.ok(
        /^(?:https?:|mailto:|#)/.test(href),
        `"${href}" is relative and will not resolve off GitHub`,
      );
    }
  });

  test('rewrites a repo-relative README link to an absolute one', () => {
    const { html } = buildWithReadme((md) =>
      md.replace('[REUSE](https://reuse.software/)', '[REUSE](CONTRIBUTING.md)'),
    );
    assert.ok(
      html.includes('href="https://github.com/alekslinde/rinsa/blob/main/CONTRIBUTING.md"'),
      'a relative README link was not rewritten for the site',
    );
  });

  test('keeps HTML comments out of the rendered page', () => {
    const { html } = buildWithReadme((md) => `${md}\n<!-- updated: 2026-01-01 -->\n`);
    assert.ok(!/<!--(?!\[if)/.test(html.replace(/<!doctype[^>]*>/i, '')), 'comment reached output');
  });

  test('strips comment markers that a single pass would leave behind', () => {
    // Removing a comment can splice its surroundings into a fresh opener, so
    // stripping has to repeat to a fixed point.
    const { html, error } = buildWithReadme((md) => `${md}\n<!-<!-- x -->- spliced -->\n`);
    assert.equal(error, null, 'build should handle a spliced comment marker');
    assert.ok(!html.includes('<!--'), 'a comment opener survived into the page');
  });

  test('refuses to build on an unterminated comment', () => {
    const { error } = buildWithReadme((md) => `${md}\n<!-- never closed\n`);
    assert.ok(error, 'an unterminated comment should fail the build');
    assert.match(String(error.stderr ?? error), /unterminated HTML comment/);
  });

  test('every table header declares its scope', () => {
    const html = build();
    const headers = [...html.matchAll(/<th\b[^>]*>/g)].map((m) => m[0]);
    assert.ok(headers.length > 0, 'expected the page to have table headers');
    for (const th of headers) {
      assert.match(th, /scope="col"/, `header cell ${th} has no scope`);
    }
  });

  test('scrollable regions are keyboard reachable and named', () => {
    // A region that scrolls but cannot take focus is unusable by keyboard.
    const html = build();
    const regions = [...html.matchAll(/<(?:pre|div class="table-wrap")\b[^>]*>/g)].map((m) => m[0]);
    assert.ok(regions.length > 0, 'expected scrollable regions');
    for (const region of regions) {
      assert.match(region, /tabindex="0"/, `${region} is not keyboard reachable`);
      assert.match(region, /aria-label="[^"]+"/, `${region} has no accessible name`);
    }
  });

  test('copy buttons rely on their text for an accessible name', () => {
    // An aria-label would permanently override the text, so the "Copied"
    // confirmation would never be announced.
    const html = build();
    const buttons = [...html.matchAll(/<button\b[^>]*>/g)].map((m) => m[0]);
    assert.ok(buttons.length > 0, 'expected copy buttons');
    for (const button of buttons) {
      assert.ok(!/aria-label/.test(button), `${button} overrides its own text`);
    }
  });

  test('provides a skip link pointing at a real target', () => {
    const html = build();
    const skip = html.match(/<a class="skip-link" href="#([^"]+)"/);
    assert.ok(skip, 'page has no skip link');
    assert.ok(html.includes(`id="${skip[1]}"`), `skip link target #${skip[1]} does not exist`);
  });

  test('names every navigation landmark', () => {
    // Two unnamed <nav>s are indistinguishable in a landmark list.
    for (const nav of build().match(/<nav\b[^>]*>/g) ?? []) {
      assert.match(nav, /aria-label="[^"]+"/, `${nav} has no accessible name`);
    }
  });

  test('honours prefers-reduced-motion and defines focus styles', () => {
    const html = build();
    assert.match(html, /@media \(prefers-reduced-motion: reduce\)/);
    assert.match(html, /:focus-visible\s*\{/, 'no visible focus indicator');
  });

  test('exposes a live region for copy feedback', () => {
    const html = build();
    assert.match(html, /aria-live="polite"/, 'copy result is never announced');
    assert.match(html, /role="status"/);
  });

  test('handles clipboard failure instead of leaving a dead button', () => {
    // navigator.clipboard is absent on insecure origins and rejects when
    // permission is denied; an unhandled promise means a silent no-op.
    const html = build();
    assert.match(html, /if \(!navigator\.clipboard\)/, 'no guard for missing clipboard API');
    assert.match(html, /Copy failed/, 'no failure message for the user');
  });

  test('starts headings at h1 and never skips a level', () => {
    const levels = [...build().matchAll(/<h([1-6])\b/g)].map((m) => Number(m[1]));
    assert.equal(levels[0], 1, 'page should start at h1');
    assert.equal(levels.filter((l) => l === 1).length, 1, 'expected exactly one h1');
    for (let i = 1; i < levels.length; i++) {
      assert.ok(
        levels[i] - levels[i - 1] <= 1,
        `heading jumps from h${levels[i - 1]} to h${levels[i]}`,
      );
    }
  });

  test('does not leak absolute filesystem paths', () => {
    // Build-machine paths in a published page disclose the author's machine.
    const html = build();
    assert.ok(!html.includes(root), 'generated page contains a build-machine path');
    assert.doesNotMatch(html, /(?:\/Users\/|\/home\/|[A-Z]:\\)/);
  });
});
