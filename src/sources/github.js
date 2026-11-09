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
  // Without this the advisories API allows 60 requests an hour per IP, shared
  // with every other tenant on a shared host - a budget a refresh every 20
  // minutes cannot rely on, and the reason an unauthenticated deployment sees
  // 403s that look like an outage at GitHub. With it, 5,000.
  authEnv: 'GITHUB_TOKEN',
  // Without the token the whole deployment gets 60 requests an hour here.
  // The refresh needs 3 of them every 20 minutes and serves every visitor;
  // a single-CVE lookup serves one. So when there is no token the refresh
  // takes the budget and lookups skip this register - the alternative is a
  // handful of lookups spending the hour's allowance and the feed itself
  // going 403, which is how an anonymous deployment ends up looking broken.
  lookupNeedsAuth: true,
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
  // GitHub is the one source that hands over real registry coordinates. They
  // used to be flattened into comma-joined strings here, which threw away the
  // ecosystem/name pairing - and npm `zip` and crates.io `zip` are unrelated
  // software, so the pairing is the part that matters.
  const coordinates = [];
  const seen = new Set();
  for (const vuln of advisory.vulnerabilities ?? []) {
    const name = vuln?.package?.name;
    if (!name) continue;
    const key = `${vuln.package.ecosystem ?? ''}|${name.toLowerCase()}`;
    if (seen.has(key)) continue;
    seen.add(key);
    coordinates.push({ name, ecosystem: vuln.package.ecosystem ?? null });
  }

  const packages = [...new Set(coordinates.map((c) => c.name))];
  const ecosystems = [...new Set(coordinates.map((c) => c.ecosystem).filter(Boolean))];

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
    // Deliberately null. This used to hold the ecosystem list, which meant
    // every GitHub advisory claimed a vendor of "npm" or "pip" - and `vendor`
    // is in the text index at weight 4, so a search for "npm" matched every
    // JavaScript advisory in the corpus. The ecosystem travels in `packages`
    // and `tags`, where it belongs.
    vendor: null,
    product: packages.slice(0, 6).join(', ') || null,
    packages: coordinates,
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
