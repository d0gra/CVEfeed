import config from '../config.js';
import { fetchWithRetry } from '../lib/http.js';
import { normalizeSeverity } from '../lib/severity.js';
import { toIso, toPlainText } from '../lib/text.js';

const API = 'https://api.github.com/advisories';
const PER_PAGE = 100;
const MAX_PAGES = 3;

export const meta = {
  id: 'github',
  name: 'GitHub Advisories',
  label: 'GitHub Security Advisory database',
  homepage: 'https://github.com/advisories',
};

/** The REST payload carries v3 and v4 blocks plus a legacy top-level score. */
function pickScore(advisory) {
  const candidates = [
    [advisory.cvss_severities?.cvss_v4?.score, '4.0', advisory.cvss_severities?.cvss_v4?.vector_string],
    [advisory.cvss_severities?.cvss_v3?.score, '3.1', advisory.cvss_severities?.cvss_v3?.vector_string],
    [advisory.cvss?.score, '3.1', advisory.cvss?.vector_string],
  ];

  for (const [score, version, vector] of candidates) {
    const n = Number(score);
    if (Number.isFinite(n) && n > 0) return { score: n, scoreVersion: version, vector: vector || null };
  }

  return { score: null, scoreVersion: null, vector: null };
}

function normalize(advisory) {
  if (!advisory?.ghsa_id || advisory.withdrawn_at) return null;

  const { score, scoreVersion, vector } = pickScore(advisory);
  const packages = [
    ...new Set((advisory.vulnerabilities ?? []).map((v) => v.package?.name).filter(Boolean)),
  ];
  const ecosystems = [
    ...new Set((advisory.vulnerabilities ?? []).map((v) => v.package?.ecosystem).filter(Boolean)),
  ];

  const epss = Number(advisory.epss?.percentage);

  return {
    id: advisory.cve_id || advisory.ghsa_id,
    cveId: advisory.cve_id || null,
    ghsaId: advisory.ghsa_id,
    title: advisory.summary || advisory.ghsa_id,
    description: toPlainText(advisory.description || advisory.summary),
    severity: normalizeSeverity(advisory.severity, score),
    score,
    scoreVersion,
    vector,
    published: toIso(advisory.published_at),
    modified: toIso(advisory.updated_at || advisory.published_at),
    url: advisory.html_url || `https://github.com/advisories/${advisory.ghsa_id}`,
    vendor: ecosystems.join(', ') || null,
    product: packages.slice(0, 6).join(', ') || null,
    cwes: (advisory.cwes ?? []).map((c) => c.cwe_id).filter(Boolean),
    references: (advisory.references ?? []).slice(0, 12).map((url) => ({ url, tags: [] })),
    epss: Number.isFinite(epss) ? epss : null,
    tags: ecosystems.map((e) => e.toLowerCase()),
    source: meta.id,
  };
}

export async function fetchItems() {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (config.githubToken) headers.Authorization = `Bearer ${config.githubToken}`;

  const items = [];
  // The advisories API is keyset-paginated via the Link header.
  let url = `${API}?per_page=${PER_PAGE}&sort=published&direction=desc&type=reviewed`;

  for (let page = 0; page < MAX_PAGES && url; page += 1) {
    const response = await fetchWithRetry(url, { headers, retries: 2 });
    const batch = await response.json();
    if (!Array.isArray(batch) || batch.length === 0) break;

    items.push(...batch.map(normalize).filter(Boolean));

    const link = response.headers.get('link') ?? '';
    const next = link.match(/<([^>]+)>;\s*rel="next"/);
    url = next ? next[1] : null;
  }

  return items;
}

/** Advisories that reference one CVE. */
export async function lookupById(cveId) {
  const headers = {
    Accept: 'application/vnd.github+json',
    'X-GitHub-Api-Version': '2022-11-28',
  };
  if (config.githubToken) headers.Authorization = `Bearer ${config.githubToken}`;

  const response = await fetchWithRetry(
    `${API}?cve_id=${encodeURIComponent(cveId)}&per_page=10`,
    { headers, retries: 1 },
  );
  const batch = await response.json();
  return Array.isArray(batch) ? batch.map(normalize).filter(Boolean) : [];
}

export default { meta, fetchItems, lookupById };
