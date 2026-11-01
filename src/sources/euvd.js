import { fetchJson } from '../lib/http.js';
import { normalizeSeverity } from '../lib/severity.js';
import { extractCveIds, summarizeTitle, toIso, toPlainText } from '../lib/text.js';

const BASE = 'https://euvdservices.enisa.europa.eu/api';
const PAGE_SIZE = 100;
const MAX_PAGES = 2;

export const meta = {
  id: 'euvd',
  name: 'EUVD (ENISA)',
  label: 'European Union Vulnerability Database',
  homepage: 'https://euvd.enisa.europa.eu/',
};

/** EUVD emits "Oct 19, 2026, 9:28:08 AM" style stamps, which are UTC. */
function parseEuvdDate(value) {
  if (!value) return null;
  const direct = toIso(value);
  if (/^\d{4}-\d{2}-\d{2}/.test(String(value))) return direct;
  const asUtc = toIso(`${value} UTC`);
  return asUtc ?? direct;
}

const splitLines = (value) =>
  String(value ?? '')
    .split(/[\n,]/)
    .map((line) => line.trim())
    .filter(Boolean);

function normalize(entry, { exploited = false } = {}) {
  if (!entry?.id) return null;

  const aliases = splitLines(entry.aliases);
  const cveId = aliases.find((a) => /^CVE-\d{4}-\d{4,}$/i.test(a)) ?? extractCveIds(entry.aliases)[0] ?? null;
  const score = Number(entry.baseScore);
  const epss = Number(entry.epss);

  const vendors = [
    ...new Set((entry.enisaIdVendor ?? []).map((v) => v?.vendor?.name).filter(Boolean)),
  ];
  // enisaIdProduct was being ignored entirely, though the /search endpoint we
  // already call returns it in full - product name and version both. It is
  // the only structured product data any source gives us for software that
  // is not in a package registry.
  const products = [
    ...new Set((entry.enisaIdProduct ?? []).map((p) => p?.product?.name).filter(Boolean)),
  ];
  const vendor = vendors.join(', ') || null;

  const plain = toPlainText(entry.description);

  return {
    id: cveId || entry.id,
    cveId,
    euvdId: entry.id,
    title: summarizeTitle(plain) || cveId || entry.id,
    description: plain,
    severity: normalizeSeverity(null, score),
    score: Number.isFinite(score) && score > 0 ? score : null,
    scoreVersion: entry.baseScoreVersion || null,
    vector: entry.baseScoreVector || null,
    published: parseEuvdDate(entry.datePublished),
    modified: parseEuvdDate(entry.dateUpdated ?? entry.datePublished),
    url: `https://euvd.enisa.europa.eu/vulnerability/${entry.id}`,
    vendor,
    product: products.slice(0, 6).join(', ') || null,
    vendors,
    products,
    assigner: entry.assigner ?? null,
    references: splitLines(entry.references)
      .slice(0, 12)
      .map((url) => ({ url, tags: [] })),
    epss: Number.isFinite(epss) && epss > 0 ? epss : null,
    tags: exploited ? ['exploited'] : [],
    source: meta.id,
  };
}

export async function fetchItems() {
  const items = [];

  for (let page = 0; page < MAX_PAGES; page += 1) {
    const data = await fetchJson(`${BASE}/search?size=${PAGE_SIZE}&page=${page}`, { retries: 2 });
    const batch = Array.isArray(data?.items) ? data.items : [];
    if (batch.length === 0) break;
    items.push(...batch.map((entry) => normalize(entry)).filter(Boolean));
  }

  // Overlay ENISA's exploited list so those records carry the flag.
  try {
    const exploited = await fetchJson(`${BASE}/exploitedvulnerabilities`, { retries: 1 });
    if (Array.isArray(exploited)) {
      items.push(...exploited.map((entry) => normalize(entry, { exploited: true })).filter(Boolean));
    }
  } catch {
    /* the exploited overlay is optional */
  }

  return items;
}

/**
 * EUVD has no by-CVE endpoint, so search by text and keep only records whose
 * aliases actually contain the CVE - the search is fuzzy enough to return
 * neighbours otherwise.
 */
export async function lookupById(cveId) {
  const data = await fetchJson(
    `${BASE}/search?text=${encodeURIComponent(cveId)}&size=10`,
    { retries: 1 },
  );
  const items = Array.isArray(data?.items) ? data.items : [];
  const wanted = cveId.toUpperCase();

  return items
    .map((entry) => normalize(entry))
    .filter(Boolean)
    .filter((item) => item.cveId?.toUpperCase() === wanted);
}

export default { meta, fetchItems, lookupById };
