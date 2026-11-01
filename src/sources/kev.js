import { cached } from '../lib/cache.js';
import { fetchJson } from '../lib/http.js';
import { toIso, toPlainText } from '../lib/text.js';

const FEED = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export const meta = {
  id: 'kev',
  name: 'CISA KEV',
  label: 'CISA Known Exploited Vulnerabilities catalog',
  homepage: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
};

function normalize(entry) {
  if (!entry?.cveID) return null;

  const ransomware = String(entry.knownRansomwareCampaignUse ?? '').toLowerCase() === 'known';

  return {
    id: entry.cveID,
    cveId: entry.cveID,
    title: entry.vulnerabilityName || entry.cveID,
    description: toPlainText(entry.shortDescription),
    // No CVSS of its own; severity is merged in from NVD/EUVD/GitHub data.
    severity: 'none',
    score: null,
    scoreVersion: null,
    vector: null,
    published: toIso(entry.dateAdded),
    modified: toIso(entry.dateAdded),
    url: `https://nvd.nist.gov/vuln/detail/${entry.cveID}`,
    vendor: entry.vendorProject ?? null,
    product: entry.product ?? null,
    vendors: entry.vendorProject ? [entry.vendorProject] : [],
    // KEV products are things like "Internet Explorer" - real names people
    // search for, but not registry coordinates. They must never become
    // `packages`, or the dependency cross-link would offer to version-check
    // Windows.
    products: entry.product ? [entry.product] : [],
    cwes: (entry.cwes ?? []).filter((c) => /^CWE-\d+$/.test(c ?? '')),
    references: [
      {
        url: 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
        tags: ['CISA KEV'],
      },
    ],
    exploited: true,
    kev: {
      dateAdded: toIso(entry.dateAdded),
      dueDate: toIso(entry.dueDate),
      requiredAction: toPlainText(entry.requiredAction, 400),
      ransomware,
      notes: toPlainText(entry.notes, 400),
    },
    tags: ransomware ? ['exploited', 'ransomware'] : ['exploited'],
    source: meta.id,
  };
}

export async function fetchItems() {
  const data = await fetchJson(FEED, { retries: 2 });
  return (data.vulnerabilities ?? []).map(normalize).filter(Boolean);
}

/**
 * The whole catalog is a single cached document, so a lookup costs nothing
 * beyond the fetch the feed already performs - exploitation status is
 * available for any CVE, however old.
 */
export async function lookupById(cveId) {
  const items = await cached('kev-catalog', fetchItems);
  const wanted = cveId.toUpperCase();
  return items.value.filter((item) => item.cveId?.toUpperCase() === wanted);
}

export default { meta, fetchItems, lookupById };
