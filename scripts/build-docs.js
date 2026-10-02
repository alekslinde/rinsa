// SPDX-FileCopyrightText: 2026 Aleksandr Linde
// SPDX-License-Identifier: Apache-2.0

// Minimal, dependency-free Markdown -> HTML for the docs site.
// Supports only what docs/index.md uses: headings, fenced code blocks,
// tables, bold/italic/code/links, lists, and paragraphs.

import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import path from 'node:path';

const root = path.dirname(path.dirname(fileURLToPath(import.meta.url)));
const srcPath = path.join(root, 'docs', 'index.md');
const outDir = path.join(root, 'docs-site');
const outPath = path.join(outDir, 'index.html');

const md = readFileSync(srcPath, 'utf8');
const pkg = JSON.parse(readFileSync(path.join(root, 'package.json'), 'utf8'));

// Single source of truth for the canonical origin: the CNAME this script writes.
const site = 'https://rinsa.dev';
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

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^\w\s-]/g, '')
    .trim()
    .replace(/\s+/g, '-');
}

function inline(text) {
  let out = escapeHtml(text);
  out = out.replace(/`([^`]+)`/g, '<code>$1</code>');
  out = out.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  out = out.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>');
  return out;
}

const lines = md.split('\n');
const toc = [];
let html = '';
let i = 0;

function closeList(openList) {
  if (openList) html += '</ul>\n';
}

let inCode = false;
let codeLang = '';
let codeBuf = [];
let openList = false;
let tableBuf = [];

function flushTable() {
  if (tableBuf.length === 0) return;
  const rows = tableBuf.filter((r, idx) => !(idx === 1 && /^\s*\|?\s*-+/.test(r)));
  html += '<div class="table-wrap"><table>\n';
  rows.forEach((row, idx) => {
    const cells = row
      .trim()
      .replace(/^\||\|$/g, '')
      .split('|')
      .map((c) => c.trim());
    const tag = idx === 0 ? 'th' : 'td';
    html += '<tr>' + cells.map((c) => `<${tag}>${inline(c)}</${tag}>`).join('') + '</tr>\n';
  });
  html += '</table></div>\n';
  tableBuf = [];
}

while (i < lines.length) {
  const line = lines[i];

  if (line.startsWith('```')) {
    if (!inCode) {
      inCode = true;
      codeLang = line.slice(3).trim();
      codeBuf = [];
    } else {
      inCode = false;
      const code = escapeHtml(codeBuf.join('\n'));
      html += `<div class="code-block"><button class="copy-btn" type="button" aria-label="Copy code">Copy</button><pre><code class="lang-${escapeHtml(codeLang || 'text')}">${code}</code></pre></div>\n`;
    }
    i++;
    continue;
  }

  if (inCode) {
    codeBuf.push(line);
    i++;
    continue;
  }

  // HTML comments carry build metadata (e.g. the sitemap's updated: marker)
  // or private notes, and must never reach the rendered page. Consume the
  // whole comment, however many lines it spans: matching only a single line
  // would let the inner lines of a multi-line comment fall through as
  // paragraphs. Both '-->' and the legacy '--!>' close a comment, so a
  // terminator check that knows only the former runs on and swallows the
  // rest of the document.
  if (/^\s*<!--/.test(line)) {
    while (i < lines.length && !/--!?>/.test(lines[i])) i++;
    i++; // the terminator's line, or past the end if unterminated
    continue;
  }

  if (/^\s*\|.*\|\s*$/.test(line)) {
    tableBuf.push(line);
    i++;
    continue;
  } else if (tableBuf.length) {
    flushTable();
  }

  const heading = line.match(/^(#{1,3})\s+(.*)$/);
  if (heading) {
    closeList(openList);
    openList = false;
    const level = heading[1].length;
    const text = heading[2].trim();
    const slug = slugify(text);
    if (level <= 2) toc.push({ level, text, slug });
    html += `<h${level} id="${slug}">${inline(text)}<a class="anchor" href="#${slug}" aria-label="Link to this section">#</a></h${level}>\n`;
    i++;
    continue;
  }

  const listItem = line.match(/^-\s+(.*)$/);
  if (listItem) {
    if (!openList) {
      html += '<ul>\n';
      openList = true;
    }
    let text = listItem[1];
    while (lines[i + 1] && /^\s{2,}\S/.test(lines[i + 1])) {
      i++;
      text += ' ' + lines[i].trim();
    }
    html += `<li>${inline(text)}</li>\n`;
    i++;
    continue;
  } else if (openList) {
    closeList(openList);
    openList = false;
  }

  if (line.trim() === '') {
    i++;
    continue;
  }

  html += `<p>${inline(line.trim())}</p>\n`;
  i++;
}
closeList(openList);
flushTable();

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
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    background: var(--bg);
    color: var(--fg);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
    line-height: 1.6;
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
  h1:hover .anchor, h2:hover .anchor, h3:hover .anchor { opacity: 1; }
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
  ul { padding-left: 1.3em; }
  li { margin: 0.3em 0; }
  .top-links { display: flex; flex-wrap: wrap; gap: 14px; margin: 1em 0 2em; font-size: 0.9em; }
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
<div class="layout">
<nav class="sidebar">
${navLinks}
</nav>
<main>
<div class="top-links">
<a href="https://github.com/alekslinde/rinsa">GitHub</a>
<a href="https://www.npmjs.com/package/@rinsadev/core">npm</a>
<a href="https://alekslinde.com" rel="author">alekslinde.com</a>
</div>
${html}
<footer class="page-footer">
<p>rinsa &mdash; by <a href="https://alekslinde.com" rel="author">Aleks Linde</a>. Apache-2.0 licensed.</p>
</footer>
</main>
</div>
<script>
document.addEventListener('click', function (e) {
  var btn = e.target.closest('.copy-btn');
  if (!btn) return;
  var code = btn.parentElement.querySelector('code');
  if (!code) return;
  navigator.clipboard.writeText(code.textContent).then(function () {
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(function () {
      btn.textContent = 'Copy';
      btn.classList.remove('copied');
    }, 1500);
  });
});
</script>
</body>
</html>
`;

// Build-time, not request-time: a stable date keeps rebuilds byte-identical,
// so an unchanged source does not churn <lastmod> on every CI run.
const lastmod = (md.match(/^<!--\s*updated:\s*(\d{4}-\d{2}-\d{2})\s*-->$/m) || [])[1];

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
