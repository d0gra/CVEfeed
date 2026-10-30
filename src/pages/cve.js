/**
 * One page per vulnerability.
 *
 * This is the part of the site worth indexing: people search for a CVE number,
 * and a page that merges what five registers say about it - with exploitation
 * status, EPSS and the AI-stack classification - is worth more than any of them
 * alone. Rendered on the server so it is readable without JavaScript.
 */
import { breadcrumbJsonLd, escapeHtml, layout, truncate } from './layout.js';

const SOURCE_LABELS = {
  nvd: 'NVD',
  kev: 'CISA KEV',
  github: 'GitHub Advisories',
  euvd: 'EUVD (ENISA)',
  cisa: 'CISA Advisories',
};

const fullDate = (value) => {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime())
    ? null
    : date.toLocaleDateString('en-GB', { day: 'numeric', month: 'long', year: 'numeric' });
};

const severityWord = (item) => (item.severity === 'none' ? 'Unscored' : item.severity.replace(/^./, (c) => c.toUpperCase()));

/** A one-line summary that works as a meta description and as a page lede. */
export function cveSummary(item, id) {
  const bits = [];
  bits.push(item.score != null ? `CVSS ${item.score} ${severityWord(item).toLowerCase()}` : 'Unscored');
  if (item.exploited) bits.push('known exploited');
  if (item.stack?.subjects?.length) bits.push(`affects ${item.stack.subjects.join(', ')}`);
  const head = `${id}: ${bits.join(', ')}.`;
  return truncate(`${head} ${item.description || item.title || ''}`, 158);
}

function factsTable(item) {
  const rows = [
    ['CVSS', item.score != null ? `${item.score}${item.scoreVersion ? ` (v${item.scoreVersion})` : ''}` : 'Not yet scored'],
    ['Severity', severityWord(item)],
    ['EPSS', Number.isFinite(item.epss) ? `${item.epss}% chance of exploitation in the next 30 days` : null],
    ['Known exploited', item.exploited ? 'Yes — listed in the CISA KEV catalog' : 'Not listed in CISA KEV'],
    ['Published', fullDate(item.published)],
    ['Last updated', fullDate(item.modified)],
    ['Affected', [item.vendor, item.product].filter(Boolean).join(' · ') || null],
    ['Weakness', item.cwes?.length ? item.cwes.join(', ') : null],
    ['Assigner', item.assigner],
  ].filter(([, v]) => v);

  return `<dl class="facts-table">${rows
    .map(([k, v]) => `<div><dt>${escapeHtml(k)}</dt><dd>${escapeHtml(v)}</dd></div>`)
    .join('')}</dl>`;
}

function kevBlock(item) {
  if (!item.kev) return '';
  const terms = [
    item.kev.dateAdded ? `Catalogued ${fullDate(item.kev.dateAdded)}` : null,
    item.kev.dueDate ? `US federal remediation deadline ${fullDate(item.kev.dueDate)}` : null,
    item.kev.ransomware ? 'Known use in ransomware campaigns' : null,
  ].filter(Boolean);

  return `<section class="callout">
    <h2>Being exploited in the wild</h2>
    ${terms.length ? `<p class="terms">${terms.map(escapeHtml).join(' · ')}</p>` : ''}
    ${item.kev.requiredAction ? `<p>${escapeHtml(item.kev.requiredAction)}</p>` : ''}
  </section>`;
}

function stackBlock(item) {
  if (!item.stack) return '';
  const cats = item.stack.categories
    .map((c, i) => `<a href="/ai-stack/${encodeURIComponent(c)}">${escapeHtml(item.stack.categoryNames[i])}</a>`)
    .join(', ');
  return `<section class="block">
    <h2>Part of the AI stack</h2>
    <p>This affects <strong>${escapeHtml(item.stack.subjects.join(', '))}</strong>, in ${cats}.</p>
  </section>`;
}

export function cvePage({ item, id, origin, canonical, lookedUp, assetVersion }) {
  // Search results cut titles near 60 characters, and these advisories carry
  // long machine-written ones, so the headline is trimmed hard. The full title
  // is still the <h1>.
  const title = `${id}: ${truncate(item.title, 46)}`;
  const description = cveSummary(item, id);

  const links = Object.entries(item.links ?? {}).filter(([, url]) => url);
  const refs = (item.references ?? []).filter((r) => r.url).slice(0, 12);

  const body = `
  <article class="doc">
    <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>${escapeHtml(id)}</span></nav>

    <header class="doc-head">
      <div class="doc-score" data-sev="${escapeHtml(item.severity)}">
        <span class="doc-score-num">${item.score != null ? item.score.toFixed(1) : '—'}</span>
        <span class="doc-score-sev">${escapeHtml(severityWord(item))}</span>
      </div>
      <div>
        <h1>${escapeHtml(item.title)}</h1>
        <p class="doc-id">${escapeHtml(id)}${
          item.exploited ? ' <span class="flag">Exploited</span>' : ''
        }</p>
      </div>
    </header>

    ${item.description ? `<p class="lede">${escapeHtml(item.description)}</p>` : ''}

    ${kevBlock(item)}
    ${stackBlock(item)}

    <section class="block">
      <h2>Assessment</h2>
      ${factsTable(item)}
      ${item.vector ? `<p class="vector-line"><span>CVSS vector</span><code>${escapeHtml(item.vector)}</code></p>` : ''}
    </section>

    ${
      links.length
        ? `<section class="block"><h2>At the source</h2><ul class="linklist">${links
            .map(
              ([sid, url]) =>
                `<li><a href="${escapeHtml(url)}" rel="noopener nofollow" target="_blank">${escapeHtml(
                  SOURCE_LABELS[sid] ?? sid,
                )}</a></li>`,
            )
            .join('')}</ul></section>`
        : ''
    }

    ${
      refs.length
        ? `<section class="block"><h2>References</h2><ul class="linklist refs-list">${refs
            .map(
              (r) =>
                `<li><a href="${escapeHtml(r.url)}" rel="noopener nofollow" target="_blank">${escapeHtml(
                  r.url,
                )}</a></li>`,
            )
            .join('')}</ul></section>`
        : ''
    }

    ${
      lookedUp
        ? `<p class="aside">Outside the current feed window — resolved directly from ${escapeHtml(
            lookedUp.join(', '),
          )} when you asked for it.</p>`
        : ''
    }

    <section class="block">
      <h2>Query this programmatically</h2>
      <p>Agents can read this through <a href="/mcp">the MCP endpoint</a>, or over HTTP:</p>
      <pre><code>curl ${escapeHtml(origin)}/api/cve/${escapeHtml(id)}</code></pre>
    </section>
  </article>`;

  // There is no schema.org type for a vulnerability advisory, and inventing
  // ratings or authors to fit one would be dishonest. TechArticle describes
  // what this page actually is.
  const article = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: title,
    description,
    url: canonical,
    mainEntityOfPage: canonical,
    ...(item.published ? { datePublished: item.published } : {}),
    ...(item.modified ? { dateModified: item.modified } : {}),
    about: { '@type': 'Thing', name: id, identifier: id },
    isAccessibleForFree: true,
    publisher: { '@type': 'Organization', name: 'CVE Feed', url: `${origin}/` },
    ...(item.sourceIds?.length
      ? { citation: item.sourceIds.map((sid) => SOURCE_LABELS[sid] ?? sid) }
      : {}),
  };

  return layout({
    title: `${title} | CVE Feed`,
    description,
    canonical,
    body,
    current: '',
    assetVersion,
    jsonLd: [article, breadcrumbJsonLd(origin, [['Feed', '/'], [id, `/cve/${encodeURIComponent(id)}`]])],
  });
}

export function notFoundPage({ id, origin, canonical, assetVersion }) {
  return layout({
    title: `${id} not found | CVE Feed`,
    description: `${id} was not found in the current feed window or at NVD, CISA KEV, GitHub Advisories or EUVD.`,
    canonical,
    noindex: true,
    assetVersion,
    body: `<article class="doc">
      <nav class="crumbs"><a href="/">Feed</a> <span>/</span> <span>${escapeHtml(id)}</span></nav>
      <h1>No record for ${escapeHtml(id)}</h1>
      <p class="lede">Nothing came back from NVD, CISA KEV, GitHub Advisories or EUVD for this
      identifier. It may not exist, may be reserved but unpublished, or may be withheld.</p>
      <p><a href="/">Search the live feed</a></p>
    </article>`,
  });
}
