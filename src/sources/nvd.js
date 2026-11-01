import config from '../config.js';
import { fetchJson } from '../lib/http.js';
import { normalizeSeverity, severityFromScore } from '../lib/severity.js';
import { summarizeTitle, toIso, toPlainText } from '../lib/text.js';

const API = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const PAGE_SIZE = 500;

export const meta = {
  id: 'nvd',
  name: 'NVD',
  label: 'NIST National Vulnerability Database',
  homepage: 'https://nvd.nist.gov/',
};

/** NVD publishes several CVSS blocks; prefer the newest version and a primary source. */
function pickMetric(metrics = {}) {
  const groups = [
    { key: 'cvssMetricV40', version: '4.0' },
    { key: 'cvssMetricV31', version: '3.1' },
    { key: 'cvssMetricV30', version: '3.0' },
    { key: 'cvssMetricV2', version: '2.0' },
  ];

  for (const { key, version } of groups) {
    const entries = metrics[key];
    if (!Array.isArray(entries) || entries.length === 0) continue;
    const chosen = entries.find((e) => e.type === 'Primary') ?? entries[0];
    const data = chosen?.cvssData ?? {};
    const score = Number(data.baseScore);
    if (!Number.isFinite(score)) continue;
    return {
      score,
      scoreVersion: data.version || version,
      vector: data.vectorString || null,
      severity: normalizeSeverity(data.baseSeverity ?? chosen.baseSeverity, score),
    };
  }

  return { score: null, scoreVersion: null, vector: null, severity: 'none' };
}

function normalize(entry) {
  const cve = entry?.cve;
  if (!cve?.id) return null;

  const description =
    cve.descriptions?.find((d) => d.lang === 'en')?.value ?? cve.descriptions?.[0]?.value ?? '';
  const metric = pickMetric(cve.metrics);

  const cwes = [
    ...new Set(
      (cve.weaknesses ?? [])
        .flatMap((w) => w.description ?? [])
        .map((d) => d.value)
        .filter((value) => /^CWE-\d+$/.test(value ?? '')),
    ),
  ];

  const references = (cve.references ?? [])
    .map((ref) => ({ url: ref.url, tags: ref.tags ?? [] }))
    .filter((ref) => ref.url)
    .slice(0, 12);

  const plain = toPlainText(description);

  return {
    id: cve.id,
    cveId: cve.id,
    title: summarizeTitle(plain) || cve.id,
    description: plain,
    severity: metric.severity,
    score: metric.score,
    scoreVersion: metric.scoreVersion,
    vector: metric.vector,
    published: toIso(cve.published),
    modified: toIso(cve.lastModified),
    url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
    cwes,
    references,
    status: cve.vulnStatus ?? null,
    assigner: cve.sourceIdentifier ?? null,
    source: meta.id,
  };
}

export async function fetchItems() {
  const end = new Date();
  const start = new Date(end.getTime() - config.nvdDays * 86_400_000);
  // NVD wants an extended-format local timestamp without the trailing Z.
  const stamp = (date) => date.toISOString().replace('Z', '');

  const headers = config.nvdApiKey ? { apiKey: config.nvdApiKey } : {};
  // Unauthenticated callers get 5 requests / 30s; stay well inside that.
  const pageDelayMs = config.nvdApiKey ? 800 : 6500;

  const items = [];
  let startIndex = 0;

  const maxPages = config.nvdMaxPages;

  for (let page = 0; page < maxPages; page += 1) {
    const url =
      `${API}?resultsPerPage=${PAGE_SIZE}&startIndex=${startIndex}` +
      `&pubStartDate=${encodeURIComponent(stamp(start))}` +
      `&pubEndDate=${encodeURIComponent(stamp(end))}`;

    const data = await fetchJson(url, { headers, retries: 2 });
    const batch = (data.vulnerabilities ?? []).map(normalize).filter(Boolean);
    items.push(...batch);

    startIndex += data.resultsPerPage ?? batch.length;
    const total = Number(data.totalResults ?? 0);
    if (startIndex >= total || batch.length === 0) break;

    if (page < maxPages - 1) {
      await new Promise((resolve) => setTimeout(resolve, pageDelayMs));
    }
  }

  return items;
}

/**
 * Find CVEs by software name.
 *
 * The feed is a forward-accumulating window, so anything published before the
 * store started holding records is invisible to a name search however good
 * the matching is - and for most software the last CVE is months old. This is
 * the way out: NVD's keyword search covers the whole catalogue, so a name
 * nobody has asked about before can still be answered once.
 *
 * `keywordSearch` ANDs the words, which suits a product name and would make
 * a sentence match nothing - the caller is expected to pass a name, and
 * guards for that before spending a request here.
 */
export async function searchByName(term, { limit = 40 } = {}) {
  const headers = config.nvdApiKey ? { apiKey: config.nvdApiKey } : {};
  const data = await fetchJson(
    `${API}?resultsPerPage=${Math.min(limit, 100)}&keywordSearch=${encodeURIComponent(term)}`,
    { headers, retries: 1 },
  );
  return (data.vulnerabilities ?? []).map(normalize).filter(Boolean);
}

/** Fetch one CVE directly, for lookups outside the feed window. */
export async function lookupById(cveId) {
  const headers = config.nvdApiKey ? { apiKey: config.nvdApiKey } : {};
  const data = await fetchJson(`${API}?cveId=${encodeURIComponent(cveId)}`, {
    headers,
    retries: 1,
  });
  return (data.vulnerabilities ?? []).map(normalize).filter(Boolean);
}

export default { meta, fetchItems, lookupById, searchByName };
