/**
 * The shared chrome for server-rendered pages.
 *
 * These pages exist because the dashboard is client-rendered: useful to a
 * person, invisible to a crawler and to anything that reads HTML rather than
 * running it. Every page here is complete in its markup, needs no JavaScript
 * to be read, and carries the metadata that makes it worth indexing.
 */
import config from '../config.js';

export const escapeHtml = (value) =>
  String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');

/** JSON-LD goes in a script tag, where `</script>` in a string would end it. */
export const jsonLdScript = (data) =>
  `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;

export const SITE_NAME = 'CVE Feed';

/** Trust SITE_URL when set; otherwise believe the request, which dev needs. */
export function originFor(req) {
  if (config.siteUrl) return config.siteUrl;
  return `${req.protocol}://${req.get('host')}`;
}

export const truncate = (text, max = 155) => {
  const clean = String(text ?? '').replace(/\s+/g, ' ').trim();
  if (clean.length <= max) return clean;
  return `${clean.slice(0, max - 1).replace(/[\s,;:.-]+\S*$/, '')}…`;
};

const nav = (current) =>
  [
    ['/', 'Feed'],
    ['/ai-stack', 'AI stack'],
    ['/exploited', 'Exploited'],
    ['/mcp', 'For agents'],
  ]
    .map(
      ([href, label]) =>
        `<a href="${href}"${href === current ? ' aria-current="page"' : ''}>${escapeHtml(label)}</a>`,
    )
    .join('');

/**
 * @param {object} page
 * @param {string} page.title      Used verbatim as <title>; already specific.
 * @param {string} page.description Meta description and OG description.
 * @param {string} page.canonical  Absolute URL this page should be indexed as.
 * @param {string} page.body       The page's own markup.
 * @param {object[]} [page.jsonLd] Structured data blocks.
 * @param {string} [page.current]  Nav path to mark as current.
 * @param {boolean} [page.noindex] For pages that should not be indexed.
 */
export function layout({ title, description, canonical, body, jsonLd = [], current = '', noindex = false, assetVersion = '' }) {
  const v = assetVersion ? `?v=${encodeURIComponent(assetVersion)}` : '';

  return `<!doctype html>
<html lang="en" data-theme="dark">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${escapeHtml(title)}</title>
<meta name="description" content="${escapeHtml(description)}">
<link rel="canonical" href="${escapeHtml(canonical)}">
${noindex ? '<meta name="robots" content="noindex,follow">' : '<meta name="robots" content="index,follow,max-snippet:-1,max-image-preview:large">'}

<meta property="og:type" content="website">
<meta property="og:site_name" content="${escapeHtml(SITE_NAME)}">
<meta property="og:title" content="${escapeHtml(title)}">
<meta property="og:description" content="${escapeHtml(description)}">
<meta property="og:url" content="${escapeHtml(canonical)}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="${escapeHtml(title)}">
<meta name="twitter:description" content="${escapeHtml(description)}">

<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Instrument+Serif:ital@0;1&family=Inter:wght@400;450;500&family=JetBrains+Mono:wght@400;500&display=swap">
<link rel="stylesheet" href="/assets/styles.css${v}">
<link rel="stylesheet" href="/assets/pages.css${v}">
${jsonLd.map(jsonLdScript).join('\n')}
</head>
<body class="page">
<div class="wrap">
  <header class="page-masthead">
    <a class="wordmark-link" href="/"><span class="wordmark">CVE <em>Feed</em></span></a>
    <nav class="page-nav">${nav(current)}</nav>
  </header>

  <main>${body}</main>

  <footer class="colophon">
    <p>Aggregated from NVD, CISA KEV, GitHub Advisories, EUVD (ENISA) and CISA advisories.
    Always confirm against the upstream advisory before acting.</p>
    <p><a href="/">Live dashboard</a> · <a href="/mcp">MCP for agents</a> · <a href="/llms.txt">llms.txt</a></p>
  </footer>
</div>
<script>
  // Match whatever the dashboard was last set to, before anything paints.
  try {
    var t = localStorage.getItem('cvefeed-theme');
    if (t) document.documentElement.dataset.theme = t;
  } catch (e) {}
</script>
</body>
</html>`;
}

/** The site-level structured data every page carries. */
export const websiteJsonLd = (origin) => ({
  '@context': 'https://schema.org',
  '@type': 'WebSite',
  name: SITE_NAME,
  url: `${origin}/`,
  description:
    'Current vulnerability disclosures merged from five public registers, with a dedicated view of the AI and agent stack.',
  potentialAction: {
    '@type': 'SearchAction',
    target: { '@type': 'EntryPoint', urlTemplate: `${origin}/?q={search_term_string}` },
    'query-input': 'required name=search_term_string',
  },
});

export const breadcrumbJsonLd = (origin, trail) => ({
  '@context': 'https://schema.org',
  '@type': 'BreadcrumbList',
  itemListElement: trail.map(([name, path], i) => ({
    '@type': 'ListItem',
    position: i + 1,
    name,
    item: `${origin}${path}`,
  })),
});
