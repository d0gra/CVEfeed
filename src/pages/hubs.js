/**
 * One page per vendor, product and package.
 *
 * These exist because "microsoft vulnerabilities" and "log4j cve" are asked
 * far more often than any single CVE identifier, and until the registers'
 * structured names were kept rather than flattened into prose there was
 * nothing to build such a page from.
 *
 * They are also the fix for crawl depth. The site has thousands of CVE pages
 * reachable only from a sitemap and a client-rendered dashboard; a hub per
 * name gives every one of them a real, topical link from a page that is
 * itself worth indexing.
 *
 * The line this must not cross is the one between an aggregation and a
 * doorway. A hub is only generated for a name that appears on more than one
 * record, it lists those records in full, and it says plainly what it does
 * and does not cover. A page per one-off name would be the mass-produced,
 * answers-nothing surface that search engines demote whole domains for.
 */
import { breadcrumbJsonLd, escapeHtml, layout, truncate } from './layout.js';

const KINDS = {
  vendor: {
    path: 'vendor',
    label: 'Vendor',
    plural: 'vendors',
    // What the page claims to be about, in the words people search with.
    heading: (name) => `${name} vulnerabilities`,
    lede: (name) =>
      `Every vulnerability this feed holds for ${name}, merged from five public registers and ordered by what warrants attention first — exploited in the wild, then CVSS, then recency.`,
  },
  product: {
    path: 'product',
    label: 'Product',
    plural: 'products',
    heading: (name) => `${name} vulnerabilities and CVEs`,
    lede: (name) =>
      `Known vulnerabilities affecting ${name}, with exploit availability attached to each one, so you can tell a flaw someone has written code for from one nobody has.`,
  },
  package: {
    path: 'package',
    label: 'Package',
    plural: 'packages',
    heading: (name) => `${name} package vulnerabilities`,
    lede: (name) =>
      `Advisories affecting the ${name} package. A list cannot tell you whether <em>your</em> installed version is affected — the dependency check can.`,
  },
};

/** A name becomes a URL segment; the lookup back is case-insensitive. */
export const slugFor = (value) => encodeURIComponent(String(value).trim().toLowerCase());

export const hubPath = (kind, value) => `/${KINDS[kind].path}/${slugFor(value)}`;

const shortDate = (value) => {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleDateString('en-GB', { day: 'numeric', month: 'short', year: 'numeric' });
};

function row(item) {
  const id = item.cveId ?? item.ghsaId ?? item.advisoryId ?? item.id;
  const score = item.score != null ? item.score.toFixed(1) : '—';
  const x = item.exploitation;
  const flag = item.exploited
    ? '<span class="flag">Exploited</span>'
    : x?.weaponized
      ? '<span class="flag">Metasploit</span>'
      : x?.publicExploit || x?.publicPoc
        ? '<span class="flag">Exploit code</span>'
        : '';

  return `<li class="row">
    <span class="row-score" data-sev="${escapeHtml(item.severity)}">${escapeHtml(score)}</span>
    <span class="row-body">
      <a class="row-title" href="/cve/${encodeURIComponent(id)}">${escapeHtml(item.title)}</a>
      <span class="row-meta">
        <span class="row-id">${escapeHtml(id)}</span>
        ${flag}
        <span>${escapeHtml(shortDate(item.published))}</span>
      </span>
    </span>
  </li>`;
}

/**
 * One hub.
 *
 * `total` is the real count and `items` the page of them actually rendered,
 * so a hub never implies it is showing more than it is.
 */
export function hubPage({ kind, name, items, total, origin, canonical, assetVersion, related = [] }) {
  const spec = KINDS[kind];
  const exploited = items.filter((i) => i.exploited).length;
  const withCode = items.filter((i) => i.exploitation).length;

  const relatedLinks = related.length
    ? `<section class="block">
        <h2>Other ${escapeHtml(spec.plural)} tracked here</h2>
        <p class="linkrow">${related
          .map((r) => `<a href="${hubPath(kind, r.value)}">${escapeHtml(r.value)}</a>`)
          .join(' ')}</p>
      </section>`
    : '';

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>${escapeHtml(spec.label)}</span>
      <span>/</span> <span>${escapeHtml(name)}</span></nav>

    <h1>${escapeHtml(spec.heading(name))}</h1>
    <p class="lede">${spec.lede(escapeHtml(name))}</p>

    <p class="stat-line">
      <strong>${total}</strong> ${total === 1 ? 'vulnerability' : 'vulnerabilities'} tracked.
      ${exploited ? `<strong>${exploited}</strong> confirmed <a href="/exploited">exploited in the wild</a>.` : ''}
      ${withCode ? `<strong>${withCode}</strong> with public exploit code.` : ''}
    </p>

    ${
      kind === 'package'
        ? `<p class="aside"><a href="/dependencies?pkg=${slugFor(name)}">Check which version you are running &rarr;</a>
           &mdash; this page lists advisories for the package; only a version check can tell you whether you are affected.</p>`
        : ''
    }

    ${items.length ? `<ul class="rows">${items.map(row).join('')}</ul>` : '<p class="aside">Nothing currently tracked.</p>'}

    ${
      total > items.length
        ? `<p class="aside">Showing the ${items.length} that warrant attention first, of ${total}.
           <a href="/?q=${slugFor(name)}">Search the full feed for ${escapeHtml(name)}</a>.</p>`
        : ''
    }

    <section class="block">
      <h2>What this covers</h2>
      <p>This feed accumulates forward from the day it started storing records, and a name search
      that finds nothing here is also looked up against the registers directly — so an older
      advisory resolves even when it predates the corpus. It is still a reading view, not a
      substitute for the vendor's own advisory, and absence from this page is not a statement that
      ${escapeHtml(name)} is free of vulnerabilities.</p>
      <p class="aside"><a href="/mcp">Query this from an agent over MCP</a> &middot;
      <a href="/dependencies">Check a lockfile by version</a></p>
    </section>

    ${relatedLinks}
  </article>`;

  const listed = items.slice(0, 50);

  return layout({
    title: `${spec.heading(name)} — ${total} known | CVE Feed`,
    description: truncate(
      `${total} known ${name} ${total === 1 ? 'vulnerability' : 'vulnerabilities'}` +
        `${exploited ? `, ${exploited} actively exploited` : ''}` +
        `${withCode ? `, ${withCode} with public exploit code` : ''}. ` +
        'Merged from NVD, CISA KEV, GitHub Advisories, EUVD and CISA advisories, with exploit availability on every record.',
      158,
    ),
    canonical,
    body,
    current: '',
    assetVersion,
    jsonLd: [
      breadcrumbJsonLd(origin, [
        ['Feed', '/'],
        [spec.label, `/${spec.path}`],
        [name, hubPath(kind, name)],
      ]),
      {
        '@context': 'https://schema.org',
        '@type': 'ItemList',
        name: spec.heading(name),
        numberOfItems: total,
        itemListElement: listed.map((item, i) => ({
          '@type': 'ListItem',
          position: i + 1,
          url: `${origin}/cve/${encodeURIComponent(item.cveId ?? item.id)}`,
          name: `${item.cveId ?? item.id}: ${truncate(item.title, 90)}`,
        })),
      },
    ],
  });
}

/** The index of hubs for one kind, so they are reachable without a sitemap. */
export function hubIndexPage({ kind, names, origin, canonical, assetVersion }) {
  const spec = KINDS[kind];

  const body = `<article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>${escapeHtml(spec.label)}s</span></nav>
    <h1>Vulnerabilities by ${escapeHtml(spec.label.toLowerCase())}</h1>
    <p class="lede">Every ${escapeHtml(spec.label.toLowerCase())} this feed currently tracks more than
    one vulnerability for, with how many. Names appearing on a single record do not get a page of
    their own — there would be nothing on it worth reading.</p>

    <ul class="hub-index">${names
      .map(
        (n) =>
          `<li><a href="${hubPath(kind, n.value)}">${escapeHtml(n.value)}</a><span>${n.count}</span></li>`,
      )
      .join('')}</ul>
  </article>`;

  return layout({
    title: `Vulnerabilities by ${spec.label.toLowerCase()} | CVE Feed`,
    description: `Browse known vulnerabilities by ${spec.label.toLowerCase()} — ${names.length} tracked, each with exploit availability, CVSS and EPSS merged from five public registers.`,
    canonical,
    body,
    current: '',
    assetVersion,
    jsonLd: [breadcrumbJsonLd(origin, [['Feed', '/'], [`${spec.label}s`, `/${spec.path}`]])],
  });
}

export const HUB_KINDS = KINDS;
export default { hubPage, hubIndexPage, hubPath, slugFor, HUB_KINDS };
