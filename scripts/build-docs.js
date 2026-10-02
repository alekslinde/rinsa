// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

// Builds the docs site from the README, which is the single source of truth
// for prose: it is what npm and GitHub render, so it cannot be generated from
// something else. Two things differ on the site and are applied here rather
// than kept as a second copy of the text:
//
//   1. Repo-relative links (LICENSE, NOTICE, CONTRIBUTING.md) resolve on
//      GitHub but 404 on the site, so they are rewritten to absolute blob
//      URLs.
//   2. The README's Install section is deliberately one line; the site has
//      room for every package manager, so docs/install.md replaces it.
//
// Markdown is parsed by markdown-it, so this file holds only the page
// template and the two transforms above. Correct Markdown parsing is a solved
// problem; keeping a bespoke one here earned nothing the library needed.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';
import MarkdownIt from 'markdown-it';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
// DOCS_OUT_DIR lets the test build somewhere disposable instead of depending
// on, or clobbering, the working docs-site/.
const outDir = process.env.DOCS_OUT_DIR
  ? path.resolve(process.env.DOCS_OUT_DIR)
  : path.join(root, 'docs-site');
const outPath = path.join(outDir, 'index.html');

const readme = readFileSync(path.join(root, 'README.md'), 'utf8');
const installFragment = readFileSync(path.join(root, 'docs', 'install.md'), 'utf8');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));

// Single source of truth for the canonical origin: the CNAME this script writes.
const site = 'https://rinsa.dev';
const repo = 'https://github.com/alekslinde/rinsa';
const blob = `${repo}/blob/main`;
const pageTitle = 'rinsa — fast data sanitisation, validation and PII scrubbing for Node';
const description = pkg.description;

function escapeHtml(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Strip HTML comments from a fragment before it is parsed. markdown-it would
// pass them through as raw HTML, and a comment may hold build metadata (the
// sitemap's updated: marker) or notes that must not reach the page.
//
// Removing a comment can splice its surroundings into a new opener, so one
// pass is not enough: "<!-<!-- x -->- y -->" leaves a live "<!--" behind.
// Repeat to a fixed point, then assert no opener survived rather than
// trusting the loop — a marker reaching the page is a silent disclosure, so
// it should fail the build instead.
function stripComments(md) {
  let out = md;
  let previous;
  do {
    previous = out;
    out = out.replace(/<!--[\s\S]*?--!?>/g, '');
  } while (out !== previous);
  // An unterminated comment is the one case the loop cannot resolve: it has an
  // opener and no terminator, so nothing matches and nothing is removed.
  if (out.includes('<!--')) {
    throw new Error('unterminated HTML comment in docs source; close it with -->');
  }
  return out;
}

// Replace the section with this heading, up to the next heading of the same or
// a higher level. Throws rather than silently rendering the README's own
// Install section, so a renamed heading fails the build instead of shipping
// a page that quietly lost five package managers.
function replaceSection(md, heading, replacement) {
  const open = new RegExp(`^##[ \\t]+${heading}[ \\t]*$`, 'm');
  const start = md.search(open);
  if (start === -1) throw new Error(`README has no "## ${heading}" section to replace`);
  // Search for the terminating heading from the end of the opening heading's
  // line, not from start+1: the heading line itself starts with '##' and
  // would otherwise match as its own terminator, leaving the old body in
  // place after the replacement.
  const bodyStart = start + md.slice(start).match(open)[0].length;
  const rest = md.slice(bodyStart);
  const nextHeading = rest.search(/^#{1,2}[ \t]+\S/m);
  const end = nextHeading === -1 ? md.length : bodyStart + nextHeading;
  return md.slice(0, start) + replacement.trim() + '\n\n' + md.slice(end);
}

// Repo-relative links only resolve inside the repository. Leave anything with
// a scheme, a protocol-relative prefix or a bare fragment alone.
function absolutiseLinks(md) {
  return md.replace(/\]\(([^)]+)\)/g, (match, href) => {
    if (/^(?:[a-z][a-z0-9+.-]*:|\/\/|#)/i.test(href)) return match;
    return `](${blob}/${href.replace(/^\.?\//, '')})`;
  });
}

const source = absolutiseLinks(
  replaceSection(stripComments(readme), 'Install', stripComments(installFragment)),
);

const md = new MarkdownIt({ html: false, linkify: false, typographer: false });

// Heading ids + a hover anchor, and collect the sidebar TOC on the way past.
const toc = [];
const slugCounts = new Map();

function slugify(text) {
  const base = text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
  // Duplicate headings would otherwise produce two elements with one id, and
  // every anchor to it would land on the first.
  const seen = slugCounts.get(base) ?? 0;
  slugCounts.set(base, seen + 1);
  return seen === 0 ? base : `${base}-${seen}`;
}

md.renderer.rules.heading_open = (tokens, idx) => {
  const token = tokens[idx];
  const level = Number(token.tag.slice(1));
  const text = tokens[idx + 1].content;
  const slug = slugify(text);
  token.attrSet('id', slug);
  if (level <= 2) toc.push({ level, text, slug });
  return `<${token.tag} id="${escapeHtml(slug)}">`;
};

md.renderer.rules.heading_close = (tokens, idx) => {
  const slug = tokens[idx - 2].attrGet('id');
  const anchor = `<a class="anchor" href="#${escapeHtml(slug)}" aria-label="Link to this section">#</a>`;
  return `${anchor}</${tokens[idx].tag}>\n`;
};

// Fenced code gets a copy button; the wrapper is what the click handler walks
// up to. Two accessibility details here:
//   - <pre> scrolls horizontally, so it needs tabindex to be reachable by
//     keyboard, plus a role and name so the region is announced.
//   - The button carries no aria-label: a label would override its text
//     content permanently, so the "Copied" confirmation would never be
//     announced. Its visible text is already its accessible name.
md.renderer.rules.fence = (tokens, idx) => {
  const token = tokens[idx];
  const lang = token.info.trim() || 'text';
  const label = `Code sample (${escapeHtml(lang)})`;
  return (
    '<div class="code-block">' +
    '<button class="copy-btn" type="button">Copy</button>' +
    `<pre role="region" aria-label="${label}" tabindex="0">` +
    `<code class="lang-${escapeHtml(lang)}">${escapeHtml(token.content)}</code>` +
    '</pre>' +
    '</div>\n'
  );
};

// Tables need a scroll container on narrow screens. A scrollable region is
// only reachable by keyboard if something in it can take focus, so the
// wrapper is a labelled, tabbable group: without tabindex, a keyboard user
// cannot scroll a wide table at all. The label borrows the section heading,
// so the page's tables are told apart rather than all announced as "Table".
md.renderer.rules.table_open = () => {
  const section = toc.length ? `${toc[toc.length - 1].text} table` : 'Table';
  return `<div class="table-wrap" role="region" aria-label="${escapeHtml(section)}" tabindex="0"><table>\n`;
};
md.renderer.rules.table_close = () => '</table></div>\n';

// Every header cell in these tables labels its column, so scope="col" lets a
// screen reader announce the column name with each data cell.
md.renderer.rules.th_open = () => '<th scope="col">';

const html = md.render(source);

const navLinks = toc
  .map((t) => `<a class="nav-link lvl-${t.level}" href="#${t.slug}">${escapeHtml(t.text)}</a>`)
  .join('\n');

const page = `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(pageTitle)}</title>
<meta name="description" content="${escapeHtml(description)}">
<meta name="author" content="Aleks Linde">
<link rel="canonical" href="${site}/">
<meta name="robots" content="index, follow">
<meta property="og:type" content="website">
<meta property="og:site_name" content="rinsa">
<meta property="og:title" content="${escapeHtml(pageTitle)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:url" content="${site}/">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${escapeHtml(pageTitle)}">
<meta name="twitter:description" content="${escapeHtml(description)}">
<link rel="icon" href="data:,">
<style>
  :root {
    --bg: #ffffff;
    --fg: #1a1a1a;
    --muted: #6b6b6b;
    --border: #e5e5e5;
    --code-bg: #f6f6f6;
    --accent: #0a5cff;
    --link: #0a5cff;
    /* Focus ring, kept distinct from --accent so it stays visible against
       accent-coloured elements. */
    --focus: #0a5cff;
    --max-width: 820px;
  }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) {
      --bg: #0f0f10;
      --fg: #e8e8e8;
      --muted: #9a9a9a;
      --border: #2a2a2a;
      --code-bg: #1a1a1b;
      --accent: #5b9dff;
      --link: #5b9dff;
      --focus: #8fbcff;
    }
  }
  :root[data-theme="dark"] {
    --bg: #0f0f10;
    --fg: #e8e8e8;
    --muted: #9a9a9a;
    --border: #2a2a2a;
    --code-bg: #1a1a1b;
    --accent: #5b9dff;
    --link: #5b9dff;
    --focus: #8fbcff;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.6;
  }
  /* One visible focus indicator for everything focusable. :focus-visible
     keeps it off mouse clicks while guaranteeing keyboard users can always
     see where they are. */
  :focus-visible {
    outline: 3px solid var(--focus);
    outline-offset: 2px;
    border-radius: 2px;
  }
  .skip-link {
    position: absolute;
    left: -9999px;
    top: 0;
    z-index: 10;
    padding: 10px 16px;
    background: var(--bg);
    color: var(--link);
    border: 1px solid var(--border);
    border-radius: 0 0 6px 0;
  }
  /* Off-screen until focused, so the first Tab offers a way past the
     table-of-contents links straight to the content. */
  .skip-link:focus { left: 0; }
  @media (prefers-reduced-motion: reduce) {
    *, *::before, *::after {
      animation-duration: 0.01ms !important;
      animation-iteration-count: 1 !important;
      transition-duration: 0.01ms !important;
      scroll-behavior: auto !important;
    }
  }
  .layout {
    display: flex;
    max-width: 1100px;
    margin: 0 auto;
    padding: 0 16px;
  }
  nav.sidebar {
    flex: 0 0 200px;
    position: sticky;
    top: 0;
    align-self: flex-start;
    padding: 32px 16px 32px 0;
    display: none;
  }
  nav.sidebar .nav-link {
    display: block;
    color: var(--muted);
    text-decoration: none;
    font-size: 13px;
    padding: 4px 0;
  }
  nav.sidebar .nav-link.lvl-1 { font-weight: 600; color: var(--fg); margin-top: 10px; }
  nav.sidebar .nav-link:hover { color: var(--accent); }
  @media (min-width: 900px) {
    nav.sidebar { display: block; }
  }
  main {
    max-width: var(--max-width);
    padding: 32px 0 64px;
    min-width: 0;
    flex: 1;
  }
  h1, h2, h3 { line-height: 1.25; scroll-margin-top: 16px; }
  h1 { font-size: 1.9rem; margin-bottom: 0.3em; }
  h2 { font-size: 1.35rem; margin-top: 2.2em; border-top: 1px solid var(--border); padding-top: 0.9em; }
  h3 { font-size: 1.05rem; margin-top: 1.6em; }
  .anchor {
    margin-left: 8px;
    color: var(--muted);
    text-decoration: none;
    opacity: 0;
    font-weight: 400;
    font-size: 0.8em;
  }
  /* Revealed on hover for pointer users and on focus for keyboard users: an
     opacity-0 link is still tabbable, so without :focus-visible it would take
     focus while staying invisible. */
  h1:hover .anchor, h2:hover .anchor, h3:hover .anchor,
  .anchor:focus-visible { opacity: 1; }
  a { color: var(--link); }
  p { color: var(--fg); }
  code {
    background: var(--code-bg);
    border-radius: 4px;
    padding: 0.15em 0.4em;
    font-size: 0.9em;
    font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  }
  .code-block {
    position: relative;
    margin: 1em 0;
  }
  pre {
    background: var(--code-bg);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    overflow-x: auto;
    margin: 0;
  }
  pre code {
    background: none;
    padding: 0;
    font-size: 0.85em;
  }
  .copy-btn {
    position: absolute;
    top: 8px;
    right: 8px;
    font-size: 12px;
    padding: 4px 10px;
    border-radius: 6px;
    border: 1px solid var(--border);
    background: var(--bg);
    color: var(--muted);
    cursor: pointer;
    font-family: inherit;
  }
  .copy-btn:hover { color: var(--fg); border-color: var(--accent); }
  .copy-btn.copied { color: var(--accent); border-color: var(--accent); }
  .table-wrap { overflow-x: auto; margin: 1em 0; }
  table { border-collapse: collapse; width: 100%; font-size: 0.9em; }
  th, td { border: 1px solid var(--border); padding: 6px 10px; text-align: left; }
  th { background: var(--code-bg); }
  ul, ol { padding-left: 1.3em; }
  li { margin: 0.3em 0; }
  blockquote {
    margin: 1em 0;
    padding: 0.2em 0 0.2em 1em;
    border-left: 3px solid var(--border);
    color: var(--muted);
  }
  em { font-style: italic; }
  .top-links { display: flex; flex-wrap: wrap; gap: 14px; margin: 1em 0 2em; font-size: 0.9em; }
  /* main takes tabindex="-1" so the skip link can move focus to it; that
     must not paint a focus ring, since it is a scripted target and not a
     control the user tabbed to. */
  main:focus { outline: none; }
  /* Available to screen readers, not painted. clip-path over display:none,
     which would remove it from the accessibility tree entirely. */
  .visually-hidden {
    position: absolute;
    width: 1px;
    height: 1px;
    margin: -1px;
    padding: 0;
    overflow: hidden;
    clip-path: inset(50%);
    white-space: nowrap;
    border: 0;
  }
  footer.page-footer {
    margin-top: 3em;
    border-top: 1px solid var(--border);
    padding-top: 1em;
    color: var(--muted);
    font-size: 0.85em;
  }
</style>
</head>
<body>
<a class="skip-link" href="#content">Skip to content</a>
<div class="layout">
<nav class="sidebar" aria-label="Sections">
${navLinks}
</nav>
<main id="content" tabindex="-1">
<nav class="top-links" aria-label="Project links">
<a href="${repo}">GitHub</a>
<a href="https://www.npmjs.com/package/@rinsadev/core">npm</a>
</nav>
${html}<footer class="page-footer">
<p>rinsa &mdash; by <a href="https://alekslinde.com" rel="author">Aleks Linde</a>. Apache-2.0 licensed.</p>
</footer>
</main>
</div>
<div id="copy-status" class="visually-hidden" role="status" aria-live="polite"></div>
<script>
(function () {
  // A single polite live region announces the copy result. Changing only the
  // button's own text would not reliably be announced while focus stays on
  // it, and a failed copy would otherwise be silent for everyone.
  var status = document.getElementById('copy-status');

  function announce(message) {
    if (!status) return;
    status.textContent = '';
    // Re-setting identical text is not a change, so consecutive copies would
    // announce only once; the clear above plus this tick guarantees both.
    setTimeout(function () {
      status.textContent = message;
    }, 50);
  }

  function settle(btn, label, ok) {
    btn.textContent = label;
    btn.classList.toggle('copied', ok);
    announce(ok ? 'Code copied to clipboard' : 'Copy failed. Select the code and copy manually.');
    setTimeout(function () {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1500);
  }

  document.addEventListener('click', function (e) {
    var btn = e.target.closest('.copy-btn');
    if (!btn) return;
    var code = btn.parentElement.querySelector('code');
    if (!code) return;
    // clipboard is undefined on insecure origins and rejects when permission
    // is denied, so an unhandled promise would leave the button silent.
    if (!navigator.clipboard) {
      settle(btn, 'Failed', false);
      return;
    }
    navigator.clipboard.writeText(code.textContent).then(
      function () {
        settle(btn, 'Copied', true);
      },
      function () {
        settle(btn, 'Failed', false);
      },
    );
  });
})();
</script>
</body>
</html>
`;

// Build-time, not request-time: a stable date keeps rebuilds byte-identical,
// so an unchanged source does not churn <lastmod> on every CI run. Read from
// the raw README, before comments are stripped.
const lastmod = (readme.match(/^<!--\s*updated:\s*(\d{4}-\d{2}-\d{2})\s*--!?>$/m) || [])[1];

const robots = `User-agent: *
Allow: /

Sitemap: ${site}/sitemap.xml
`;

const sitemap = `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url>
<loc>${site}/</loc>${lastmod ? `\n<lastmod>${lastmod}</lastmod>` : ''}
</url>
</urlset>
`;

mkdirSync(outDir, { recursive: true });
writeFileSync(outPath, page);
writeFileSync(path.join(outDir, 'CNAME'), `${new URL(site).hostname}\n`);
writeFileSync(path.join(outDir, '.nojekyll'), '');
writeFileSync(path.join(outDir, 'robots.txt'), robots);
writeFileSync(path.join(outDir, 'sitemap.xml'), sitemap);
console.log(`Built ${outPath}`);
