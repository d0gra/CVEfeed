/**
 * One page per vulnerability.
 *
 * This is the part of the site worth indexing: people search for a CVE number,
 * and a page that merges what five registers say about it - with exploitation
 * status, EPSS and the AI-stack classification - is worth more than any of them
 * alone. Rendered on the server so it is readable without JavaScript.
 */
import { breadcrumbJsonLd, escapeHtml, layout, truncate } from './layout.js';
import { pocSection } from './pocSection.js';
import { slugFor } from './hubs.js';

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
  else if (item.exploitation?.weaponized) bits.push('Metasploit module available');
  else if (item.exploitation?.publicExploit) bits.push('public exploit available');
  else if (item.exploitation?.publicPoc) bits.push('public PoC available');
  if (item.stack?.subjects?.length) bits.push(`affects ${item.stack.subjects.join(', ')}`);
  const head = `${id}: ${bits.join(', ')}.`;
  return truncate(`${head} ${item.description || item.title || ''}`, 158);
}

/**
 * The affected software, linked to its own page where one exists.
 *
 * This is the internal linking that makes thousands of CVE pages crawlable:
 * without it they are reachable only from a sitemap and a client-rendered
 * dashboard, which is a poor structure however good each page is. Rendered as
 * raw HTML, so this value skips the table's escaping and does its own.
 */
function affectedLinks(item) {
  const parts = [];
  for (const vendor of item.vendors ?? []) {
    parts.push(`<a href="/vendor/${slugFor(vendor)}">${escapeHtml(vendor)}</a>`);
  }
  for (const product of (item.products ?? []).slice(0, 4)) {
    parts.push(`<a href="/product/${slugFor(product)}">${escapeHtml(product)}</a>`);
  }
  for (const pkg of (item.packages ?? []).slice(0, 4)) {
    parts.push(`<a href="/package/${slugFor(pkg.name)}">${escapeHtml(pkg.name)}</a>`);
  }
  if (parts.length) return { html: parts.join(' \u00b7 ') };

  // Older records predate the structured names and only have the joined
  // strings; they still deserve a line, just without links.
  const plain = [item.vendor, item.product].filter(Boolean).join(' \u00b7 ');
  return plain || null;
}

function factsTable(item) {
  const rows = [
    ['CVSS', item.score != null ? `${item.score}${item.scoreVersion ? ` (v${item.scoreVersion})` : ''}` : 'Not yet scored'],
    ['Severity', severityWord(item)],
    ['EPSS', Number.isFinite(item.epss) ? `${item.epss}% chance of exploitation in the next 30 days` : null],
    ['Known exploited', item.exploited ? 'Yes — listed in the CISA KEV catalog' : 'Not listed in CISA KEV'],
    ['Exploit availability', item.exploitation ? item.exploitation.evidence.join(', ') : 'Nothing found in Exploit-DB, Metasploit, Nuclei or public PoC repositories'],
    ['Published', fullDate(item.published)],
    ['Last updated', fullDate(item.modified)],
    ['Affected', affectedLinks(item)],
    ['Weakness', item.cwes?.length ? item.cwes.join(', ') : null],
    ['Assigner', item.assigner],
  ].filter(([, v]) => v);

  return `<dl class="facts-table">${rows
    .map(
      ([k, v]) =>
        `<div><dt>${escapeHtml(k)}</dt><dd>${v?.html ? v.html : escapeHtml(v)}</dd></div>`,
    )
    .join('')}</dl>`;
}

function kevBlock(item, pocRepos = []) {
  if (!item.kev) return '';
  const terms = [
    item.kev.dateAdded ? `Catalogued ${fullDate(item.kev.dateAdded)}` : null,
    item.kev.dueDate ? `US federal remediation deadline ${fullDate(item.kev.dueDate)}` : null,
    item.kev.ransomware ? 'Known use in ransomware campaigns' : null,
  ].filter(Boolean);

  const evidence = item.exploitation?.evidence?.filter((e) => e !== 'CISA KEV') ?? [];

  return `<section class="callout">
    <h2>Being exploited in the wild</h2>
    ${terms.length ? `<p class="terms">${terms.map(escapeHtml).join(' · ')}</p>` : ''}
    ${item.kev.requiredAction ? `<p>${escapeHtml(item.kev.requiredAction)}</p>` : ''}
    ${
      evidence.length
        ? `<p class="terms">Exploit code is also public: ${evidence.map(escapeHtml).join(' · ')}</p>`
        : ''
    }
    ${exploitLinks(item.exploitation ?? {}, pocRepos)}
  </section>`;
}

function exploitBlock(item, pocRepos = []) {
  const x = item.exploitation;
  if (!x) return '';

  const headline = {
    observed: 'Exploited in the wild',
    weaponized: 'A ready-made exploit module exists',
    'public-exploit': 'A public exploit is available',
    'proof-of-concept': 'Proof-of-concept code is published',
    none: 'Scanned for across the internet',
  }[x.maturity];

  return `<section class="callout callout-exploit">
    <h2>${escapeHtml(headline)}</h2>
    <p class="terms">${x.evidence.map((e) => escapeHtml(e)).join(' · ')}</p>
    ${exploitLinks(x, pocRepos)}
    ${
      x.scannable
        ? '<p>A Nuclei detection template exists for this, which means it is scanned for at internet scale rather than looked for deliberately.</p>'
        : ''
    }
    <p class="aside">Signals come from Exploit-DB, Metasploit, Nuclei and published proof-of-concept
    repositories. Their absence means nothing was found, not that nothing exists.</p>
  </section>`;
}

/** The links themselves. Naming a source is not much use without them. */
function exploitLinks(x, pocRepos = []) {
  const rows = [];

  for (const link of x.links ?? []) {
    // The index listing is redundant once the repositories themselves are here.
    if (link.kind === 'poc-index' && pocRepos.length) continue;
    rows.push(
      `<li><span class="xsrc">${escapeHtml(link.source)}</span><a href="${escapeHtml(
        link.url,
      )}" rel="noopener nofollow" target="_blank">${escapeHtml(link.label ?? link.url)}</a></li>`,
    );
  }

  for (const repo of pocRepos) {
    rows.push(
      `<li><span class="xsrc">Public PoC</span><a href="${escapeHtml(
        repo.url,
      )}" rel="noopener nofollow" target="_blank">${escapeHtml(repo.label)}</a>${
        repo.stars ? `<span class="xstars">${repo.stars.toLocaleString()} stars</span>` : ''
      }</li>`,
    );
  }

  if (!rows.length) return '';
  return `<ul class="exploit-links">${rows.join('')}</ul>`;
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

/**
 * The headline, chosen by what the page can actually answer.
 *
 * "CVE-X exploit" and "CVE-X PoC" are what people type, and a page carrying a
 * Metasploit module and three PoC repositories genuinely deserves those
 * words. Putting them on the other nine records in ten would be the
 * mass-produced, promises-nothing page that search engines demote whole
 * domains for - and it would be a lie besides, which is the better reason.
 *
 * So the claim follows the evidence, strongest first. The reward for being
 * accurate is that the pages which do rank are the ones that answer the
 * query.
 */
function headlineFor(item, id) {
  const x = item.exploitation;
  const has = (kind) => x?.[kind] === true;

  if (item.exploited) return `${id} — actively exploited in the wild`;
  if (has('weaponized')) return `${id} — Metasploit module and public exploit`;
  if (has('publicExploit')) return `${id} — public exploit available`;
  if (has('publicPoc')) return `${id} — proof of concept and exploit details`;
  if (has('scannable')) return `${id} — detection template and advisory`;
  if (item.score != null) return `${id} — CVSS ${item.score} ${severityWord(item).toLowerCase()} advisory`;
  return `${id} — advisory, affected versions and detection`;
}

/**
 * Questions this page can answer, as structured data.
 *
 * Only ever questions with a real answer on the page - "is there a public
 * exploit" is worth marking up precisely because the answer is sometimes no,
 * and a confident no is a useful result.
 */
function faqFor(item, id, pocRepos, communityPocs) {
  const x = item.exploitation;
  const qa = [];

  const exploitAnswer = item.exploited
    ? `Yes. ${id} is listed in the CISA Known Exploited Vulnerabilities catalog, meaning exploitation has been observed in the wild.`
    : x?.weaponized
      ? `Yes. A Metasploit module exists for ${id}, so a working exploit is available in a standard testing framework.`
      : x?.publicExploit
        ? `Yes. An exploit for ${id} is archived and downloadable from Exploit-DB.`
        : x?.publicPoc
          ? `Yes. Proof-of-concept code for ${id} has been published publicly.`
          : `No public exploit for ${id} was found in Exploit-DB, Metasploit, Nuclei templates or public proof-of-concept repositories. That is an absence of evidence rather than proof that none exists.`;

  qa.push([`Is there a public exploit for ${id}?`, exploitAnswer]);

  const pocCount = (pocRepos?.length ?? 0) + (communityPocs?.length ?? 0);
  if (pocCount) {
    qa.push([
      `Is there a proof of concept for ${id}?`,
      `Yes — ${pocCount} proof-of-concept ${pocCount === 1 ? 'entry is' : 'entries are'} linked on this page, from public repositories and community submissions. They are listed for authorised testing only.`,
    ]);
  }

  if (item.score != null) {
    qa.push([
      `How severe is ${id}?`,
      `${id} scores CVSS ${item.score}${item.scoreVersion ? ` (v${item.scoreVersion})` : ''}, rated ${severityWord(item).toLowerCase()}.` +
        (Number.isFinite(item.epss) ? ` EPSS puts the chance of exploitation in the next 30 days at ${item.epss}%.` : ''),
    ]);
  }

  if (item.vendor || item.product) {
    qa.push([
      `What does ${id} affect?`,
      `${id} affects ${[item.vendor, item.product].filter(Boolean).join(' ')}.` +
        (item.stack?.subjects?.length ? ` It is part of the AI and agent stack (${item.stack.subjects.join(', ')}).` : ''),
    ]);
  }

  return {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    mainEntity: qa.map(([question, answer]) => ({
      '@type': 'Question',
      name: question,
      acceptedAnswer: { '@type': 'Answer', text: answer },
    })),
  };
}

export function cvePage({ item, id, origin, canonical, lookedUp, assetVersion, pocRepos = [], communityPocs = [], captcha }) {
  // Search results cut titles near 60 characters, and these advisories carry
  // long machine-written ones, so the headline leads with what the page
  // answers and the full advisory title stays as the <h1>.
  const title = headlineFor(item, id);
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

    ${kevBlock(item, pocRepos)}
    ${item.exploited ? '' : exploitBlock(item, pocRepos)}
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

    ${captcha ? pocSection({ id, pocs: communityPocs, captcha }) : ''}

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
    jsonLd: [
      article,
      faqFor(item, id, pocRepos, communityPocs),
      breadcrumbJsonLd(origin, [['Feed', '/'], [id, `/cve/${encodeURIComponent(id)}`]]),
    ],
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
