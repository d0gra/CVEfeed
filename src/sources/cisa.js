import { XMLParser } from 'fast-xml-parser';
import { fetchText } from '../lib/http.js';
import { extractCveIds, toIso, toPlainText } from '../lib/text.js';

const FEED = 'https://www.cisa.gov/cybersecurity-advisories/all.xml';
const MAX_ITEMS = 150;

export const meta = {
  id: 'cisa',
  name: 'CISA Advisories',
  label: 'CISA cybersecurity, ICS and medical device advisories',
  homepage: 'https://www.cisa.gov/news-events/cybersecurity-advisories',
};

const parser = new XMLParser({
  ignoreAttributes: false,
  attributeNamePrefix: '@_',
  trimValues: true,
  // The feed is large and entity-heavy; toPlainText() decodes entities itself,
  // so skip the parser's expansion handling and its size guard.
  processEntities: false,
});

const asArray = (value) => (Array.isArray(value) ? value : value ? [value] : []);

/** Advisory kind is encoded in the URL path, e.g. /ics-advisories/icsa-26-302-03. */
function classify(link = '') {
  if (link.includes('/ics-medical-advisories/')) return 'ics-medical';
  if (link.includes('/ics-advisories/')) return 'ics';
  if (link.includes('/alerts/')) return 'alert';
  if (link.includes('/cybersecurity-advisories/')) return 'advisory';
  return 'advisory';
}

function normalize(item) {
  const link = typeof item.link === 'string' ? item.link : item.link?.['#text'];
  const title = toPlainText(item.title, 300);
  if (!link || !title) return null;

  const description = toPlainText(item.description, 1200);
  const cveIds = [...new Set([...extractCveIds(description), ...extractCveIds(title)])];
  const published = toIso(item.pubDate ?? item['dc:date']);
  const kind = classify(link);

  // The advisory's own id, e.g. icsa-26-302-03.
  const slug = link.split('/').filter(Boolean).pop() ?? link;

  return {
    id: cveIds[0] ?? slug,
    cveId: cveIds[0] ?? null,
    advisoryId: slug,
    title,
    description,
    // Advisories carry no CVSS of their own; severity comes from merged CVE data.
    severity: 'none',
    score: null,
    scoreVersion: null,
    vector: null,
    published,
    modified: published,
    url: link,
    relatedCves: cveIds,
    references: [{ url: link, tags: ['CISA advisory'] }],
    tags: [kind],
    source: meta.id,
  };
}

export async function fetchItems() {
  const xml = await fetchText(FEED, { retries: 2 });
  const parsed = parser.parse(xml);
  const items = asArray(parsed?.rss?.channel?.item);

  return items
    .slice(0, MAX_ITEMS)
    .map(normalize)
    .filter(Boolean);
}

export default { meta, fetchItems };
