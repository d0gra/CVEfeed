/**
 * Landing pages: the AI-stack overview, one page per category, and the
 * exploited list. These exist to be found - "vLLM CVE", "MCP server
 * vulnerability", "actively exploited CVEs" - and each one is a real list with
 * real content, not a doorway.
 */
import { breadcrumbJsonLd, escapeHtml, layout, truncate } from './layout.js';
import { STACK_CATEGORIES } from '../stack.js';

const severityWord = (item) => (item.severity === 'none' ? 'unscored' : item.severity);

const shortDate = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
};

/** One row of a rendered list, linking to the CVE's own page. */
function row(item) {
  const id = item.cveId ?? item.ghsaId ?? item.advisoryId ?? item.id;
  const score = item.score != null ? item.score.toFixed(1) : '—';
  return `<li class="row">
    <span class="row-score" data-sev="${escapeHtml(item.severity)}">${escapeHtml(score)}</span>
    <span class="row-body">
      <a class="row-title" href="/cve/${encodeURIComponent(id)}">${escapeHtml(item.title)}</a>
      <span class="row-meta">
        <span class="row-id">${escapeHtml(id)}</span>
        ${item.exploited ? '<span class="flag">Exploited</span>' : ''}
        ${item.stack?.subjects?.length ? `<span>${escapeHtml(item.stack.subjects.join(', '))}</span>` : ''}
        <span>${escapeHtml(shortDate(item.published))}</span>
      </span>
    </span>
  </li>`;
}

const listJsonLd = (name, items) => ({
  '@context': 'https://schema.org',
  '@type': 'ItemList',
  name,
  numberOfItems: items.length,
  itemListElement: items.slice(0, 50).map((item, i) => ({
    '@type': 'ListItem',
    position: i + 1,
    url: `/cve/${encodeURIComponent(item.cveId ?? item.id)}`,
    name: `${item.cveId ?? item.id}: ${truncate(item.title, 90)}`,
  })),
});

export function stackIndexPage({ stats, origin, canonical, assetVersion, exploited }) {
  const cards = STACK_CATEGORIES.map((cat) => {
    const count = stats?.byStack?.[cat.id] ?? 0;
    return `<li class="cat">
      <a href="/ai-stack/${encodeURIComponent(cat.id)}">
        <span class="cat-name">${escapeHtml(cat.name)}</span>
        <span class="cat-count">${count}</span>
      </a>
      <p>${escapeHtml(cat.blurb)}</p>
    </li>`;
  }).join('');

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>AI stack</span></nav>
    <h1>Vulnerabilities in the AI and agent stack</h1>
    <p class="lede">The software agents are built on has its own attack surface: inference servers,
    agent frameworks, MCP servers, vector stores, MLOps platforms and model runtimes. This page
    tracks what is currently disclosed across all of them, drawn from the same five public
    registers as the rest of the feed.</p>

    <p class="stat-line"><strong>${stats?.inStack ?? 0}</strong> disclosures in the current window,
    of which <strong>${exploited}</strong> ${exploited === 1 ? 'is' : 'are'}
    <a href="/exploited">already being exploited</a>.</p>

    <ul class="cats">${cards}</ul>

    <section class="block">
      <h2>How records are classified</h2>
      <p>Matching is done against package names and vendors rather than keywords, because keyword
      matching does not survive contact with real data: searching descriptions for <code>ray</code>
      finds <em>array</em>, <code>dify</code> finds <em>modify</em>, and <code>agent</code> finds
      <em>user agent</em>. Exact package names from GitHub advisories and vendor names from CISA KEV
      and EUVD decide most records; word-bounded prose is a fallback for the ones carrying neither,
      and ambiguous names require a qualifier.</p>
    </section>

    <section class="block">
      <h2>For agents</h2>
      <p>This view is available to agents through <a href="/mcp">the MCP endpoint</a> — ask
      <code>search_cves</code> with a <code>stack</code> filter, or
      <code>list_exploited</code> to get straight to what is burning.</p>
    </section>
  </article>`;

  return layout({
    title: 'AI and agent stack vulnerabilities | CVE Feed',
    description:
      'Current CVEs affecting inference servers, agent frameworks, MCP servers, vector stores and MLOps platforms, merged from NVD, CISA KEV, GitHub Advisories and EUVD.',
    canonical,
    body,
    current: '/ai-stack',
    assetVersion,
    jsonLd: [breadcrumbJsonLd(origin, [['Feed', '/'], ['AI stack', '/ai-stack']])],
  });
}

export function stackCategoryPage({ category, items, origin, canonical, assetVersion }) {
  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <a href="/ai-stack">AI stack</a> <span>/</span> <span>${escapeHtml(category.name)}</span></nav>
    <h1>Vulnerabilities in ${escapeHtml(category.name)}</h1>
    <p class="lede">${escapeHtml(category.blurb)}. ${items.length} currently disclosed, newest first.
    Each links through to the merged record for that CVE.</p>

    ${items.length ? `<ul class="rows">${items.map(row).join('')}</ul>` : '<p class="aside">Nothing currently disclosed in this category. That is a statement about the last few days, not about the software.</p>'}

    <p class="aside"><a href="/?stack=${encodeURIComponent(category.id)}">Open this in the live dashboard</a>
    to filter further, or query it with <code>search_cves</code> over <a href="/mcp">MCP</a>.</p>
  </article>`;

  return layout({
    title: `${category.name} CVEs | CVE Feed`,
    // Never lowercase the category name: it turns "MCP & tool servers" into
    // "mcp & tool servers".
    description: truncate(
      `Current CVEs affecting ${category.name}: ${category.blurb}. ${items.length} disclosed now, merged from NVD, CISA KEV, GitHub Advisories and EUVD.`,
      158,
    ),
    canonical,
    body,
    current: '/ai-stack',
    assetVersion,
    jsonLd: [
      breadcrumbJsonLd(origin, [['Feed', '/'], ['AI stack', '/ai-stack'], [category.name, `/ai-stack/${category.id}`]]),
      listJsonLd(`${category.name} vulnerabilities`, items),
    ],
  });
}

export function exploitedPage({ items, origin, canonical, assetVersion, inStack }) {
  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>Exploited</span></nav>
    <h1>Vulnerabilities being exploited right now</h1>
    <p class="lede">Every entry here appears in CISA's Known Exploited Vulnerabilities catalog,
    which means exploitation has been observed in the wild rather than merely predicted. These are
    the ones to patch first, whatever their CVSS score says.</p>

    <p class="stat-line"><strong>${items.length}</strong> in the current window,
    ${inStack ? `<strong>${inStack}</strong> of them in the <a href="/ai-stack">AI stack</a>.` : 'none of them in the AI stack.'}</p>

    ${items.length ? `<ul class="rows">${items.map(row).join('')}</ul>` : '<p class="aside">Nothing in the current window.</p>'}

    <p class="aside">Absence from this list means exploitation has not been <em>observed</em>, not
    that a vulnerability is safe. Check <a href="/">the full feed</a> for everything else.</p>
  </article>`;

  return layout({
    title: 'Actively exploited vulnerabilities | CVE Feed',
    description:
      'Vulnerabilities confirmed exploited in the wild, drawn from the CISA KEV catalog, with CVSS, EPSS and affected products merged from five public registers.',
    canonical,
    body,
    current: '/exploited',
    assetVersion,
    jsonLd: [
      breadcrumbJsonLd(origin, [['Feed', '/'], ['Exploited', '/exploited']]),
      listJsonLd('Actively exploited vulnerabilities', items),
    ],
  });
}

/** A real 404, so unknown paths are not indexable copies of the dashboard. */
export function missingPage({ canonical, assetVersion, path }) {
  return layout({
    title: 'Page not found | CVE Feed',
    description: 'No page at this address.',
    canonical,
    noindex: true,
    assetVersion,
    body: `<article class="doc">
      <h1>Nothing here</h1>
      <p class="lede">No page at <code>${escapeHtml(path)}</code>.</p>
      <ul class="linklist">
        <li><a href="/">The live feed</a></li>
        <li><a href="/ai-stack">AI and agent stack</a></li>
        <li><a href="/exploited">Actively exploited</a></li>
        <li><a href="/mcp">MCP for agents</a></li>
      </ul>
    </article>`,
  });
}
