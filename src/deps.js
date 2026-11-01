/**
 * The dependency sweep: "which of the things I depend on are vulnerable, and
 * which of those can actually be exploited?"
 *
 * Why this is a separate thing from search_cves
 * ---------------------------------------------
 * Free-text search over advisory prose cannot answer that question, and it is
 * worth being precise about why rather than papering over it. Searching for
 * "lodash" matches advisories whose *text* happens to contain the word, which
 * is neither the set of advisories affecting the npm package lodash nor a
 * subset of it. It has no ecosystem (npm `zip` and crates.io `zip` are
 * unrelated software), no version awareness (4.17.21 is fine where 4.17.15 is
 * not), and no way to ask about ninety packages at once. Those are not gaps
 * that better ranking fixes; they are a different query.
 *
 * So this resolves coordinates, not words, against OSV.dev - the database the
 * ecosystems themselves publish into, which knows affected version ranges -
 * and then adds the thing OSV does not have and `npm audit` cannot tell you:
 * whether an exploit for the advisory actually exists, and how reachable it
 * is. That is the whole proposition. `npm audit` gives you forty advisories
 * sorted by a severity label; this gives you the three with a Metasploit
 * module or a public proof of concept, first.
 *
 * Cost control
 * ------------
 * One batched upstream call covers up to a thousand coordinates. Advisory
 * details are then fetched once each, concurrency-limited, and both halves are
 * cached in Atlas (see store/osvStore.js) so the second sweep of the same
 * lockfile is almost free and the host holds nothing between requests.
 */
import config from './config.js';
import { fetchJson } from './lib/http.js';
import { normalizeSeverity, severityRank } from './lib/severity.js';
import { MATURITY, attachSignals } from './exploits.js';
import { findRecordsByIds } from './store/cveStore.js';
import { cached } from './lib/cache.js';
import {
  coordinateKey,
  getCachedQueries,
  getCachedVulns,
  putQueries,
  putVulns,
} from './store/osvStore.js';

const OSV_BATCH = 'https://api.osv.dev/v1/querybatch';
const OSV_VULN = 'https://api.osv.dev/v1/vulns/';

// OSV documents 1,000 queries per batch request.
const BATCH_SIZE = 1000;

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;

/* ---------- upstream ---------- */

/** Resolve coordinates to OSV advisory ids, in batches. */
async function queryBatch(coordinates) {
  const ids = new Array(coordinates.length).fill(null);

  for (let i = 0; i < coordinates.length; i += BATCH_SIZE) {
    const slice = coordinates.slice(i, i + BATCH_SIZE);
    const body = {
      queries: slice.map(({ name, ecosystem, version }) => ({
        package: { name, ecosystem },
        version,
      })),
    };

    const response = await fetchJson(OSV_BATCH, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body),
      // The batch endpoint is the expensive one to repeat, and a sweep that
      // half-answers is worse than one that reports a failed source.
      retries: 2,
    });

    // Results are positional, and a package with nothing against it comes
    // back as an empty object rather than an empty list.
    const results = Array.isArray(response?.results) ? response.results : [];
    for (let j = 0; j < slice.length; j += 1) {
      ids[i + j] = (results[j]?.vulns ?? []).map((v) => v.id).filter(Boolean);
    }
  }

  return ids;
}

/**
 * Keep only the fields the sweep reports.
 *
 * The raw records are several kilobytes each, mostly references and version
 * ranges for packages other than the one asked about. Extracting here is what
 * keeps both the cache and the response small.
 */
function extractVuln(raw) {
  const aliases = (raw?.aliases ?? []).filter((a) => typeof a === 'string');
  const vectors = (raw?.severity ?? [])
    .map((s) => s?.score)
    .filter((s) => typeof s === 'string' && s.startsWith('CVSS:'));

  // Affected ranges, per package, so the fix version reported is the one for
  // the caller's own package rather than some sibling in the same advisory.
  const affected = [];
  for (const entry of raw?.affected ?? []) {
    const name = entry?.package?.name;
    const ecosystem = entry?.package?.ecosystem;
    if (!name) continue;

    const fixed = [];
    const introduced = [];
    for (const range of entry.ranges ?? []) {
      for (const event of range.events ?? []) {
        if (event?.fixed) fixed.push(event.fixed);
        if (event?.introduced && event.introduced !== '0') introduced.push(event.introduced);
      }
    }
    if (fixed.length || introduced.length) {
      affected.push({ name, ecosystem, fixed: [...new Set(fixed)], introduced: [...new Set(introduced)] });
    }
  }

  return {
    id: raw.id,
    aliases,
    summary: typeof raw?.summary === 'string' ? raw.summary.slice(0, 300) : undefined,
    // GitHub-sourced records carry a qualitative rating; others may not.
    rating: raw?.database_specific?.severity ?? undefined,
    vector: vectors[0],
    cwes: raw?.database_specific?.cwe_ids ?? undefined,
    published: raw?.published ?? undefined,
    withdrawn: raw?.withdrawn ?? undefined,
    affected,
  };
}

/** Fetch advisory details, bounded in both concurrency and total count. */
async function fetchVulnDetails(ids, { concurrency = 6 } = {}) {
  const out = new Map();
  const failed = [];
  const queue = [...ids];

  const worker = async () => {
    for (;;) {
      const id = queue.shift();
      if (!id) return;
      try {
        // Also memoised in-process for the life of a request burst, which
        // matters when several callers sweep overlapping lockfiles at once.
        const entry = await cached(
          `ev_osv_vuln_${id}`,
          async () => extractVuln(await fetchJson(`${OSV_VULN}${encodeURIComponent(id)}`, { retries: 1 })),
          { ttlMs: 6 * 3_600_000, evictable: true },
        );
        if (entry.value?.id) out.set(id, entry.value);
      } catch (error) {
        failed.push({ id, error: error.message });
      }
    }
  };

  await Promise.all(Array.from({ length: Math.min(concurrency, queue.length) }, worker));
  return { details: out, failed };
}

/* ---------- assembly ---------- */

const maturityRank = (maturity) => {
  const index = MATURITY.indexOf(maturity);
  return index === -1 ? MATURITY.length : index;
};

/**
 * Pick the identifier to lead with.
 *
 * A CVE if the advisory has one, because that is what the rest of this service
 * - and the caller's other tooling - is keyed on. Otherwise the OSV id, which
 * is what RUSTSEC-only and unassigned advisories have.
 */
function canonicalId(vuln) {
  const cve = (vuln.aliases ?? []).find((a) => CVE_ID.test(a));
  if (cve) return cve.toUpperCase();
  return CVE_ID.test(vuln.id) ? vuln.id.toUpperCase() : vuln.id;
}

function fixVersionsFor(vuln, pkg) {
  const lower = pkg.name.toLowerCase();
  const match = vuln.affected?.find(
    (a) => a.name?.toLowerCase() === lower && (!a.ecosystem || a.ecosystem === pkg.ecosystem),
  );
  return match?.fixed ?? [];
}

/**
 * One package's vulnerabilities, deduplicated and enriched.
 *
 * Deduplication matters more than it looks: the same flaw is routinely
 * published as a GHSA and a RUSTSEC entry that alias each other, and reporting
 * it twice makes a sweep read as worse than it is.
 */
function describe(pkg, osvIds, details, records, signals) {
  const byCanonical = new Map();

  for (const osvId of osvIds) {
    const vuln = details.get(osvId);
    if (!vuln || vuln.withdrawn) continue;

    const id = canonicalId(vuln);
    const existing = byCanonical.get(id);
    // Prefer the record that actually names this package, so the fix version
    // and summary come from the advisory that knows about it.
    if (existing && fixVersionsFor(existing, pkg).length >= fixVersionsFor(vuln, pkg).length) continue;
    byCanonical.set(id, vuln);
  }

  const out = [];
  for (const [id, vuln] of byCanonical) {
    const record = records.get(id);
    const exploitation = signals.get(id);
    const fixed = fixVersionsFor(vuln, pkg);

    const severity = record?.severity ?? normalizeSeverity(vuln.rating, null);

    out.push({
      id,
      ...(vuln.id !== id ? { osvId: vuln.id } : {}),
      summary: record?.title ?? vuln.summary,
      severity,
      severityFrom: record?.severity ? 'this feed' : vuln.rating ? 'OSV' : 'unrated',
      cvss: record?.score ?? undefined,
      cvssVector: record?.vector ?? vuln.vector ?? undefined,
      epssPercent: record?.epss ?? undefined,
      fixedIn: fixed.length ? fixed : undefined,
      // No fix version in the advisory is itself the answer to "what do I
      // upgrade to", so it is said rather than left blank.
      noFixedVersion: fixed.length ? undefined : true,
      knownExploited: Boolean(record?.exploited || exploitation?.observed),
      exploitation: exploitation
        ? {
            maturity: exploitation.maturity,
            evidence: exploitation.evidence,
            scannedForAtScale: exploitation.scannable || undefined,
            links: exploitation.links?.map((l) => ({ source: l.source, kind: l.kind, url: l.url, name: l.label })),
          }
        : undefined,
      cwes: record?.cwes?.length ? record.cwes : vuln.cwes,
      aiStack: record?.stack ? { categories: record.stack.categories, projects: record.stack.subjects } : undefined,
      inThisFeed: Boolean(record),
      published: record?.published ?? vuln.published,
      advisory: `https://osv.dev/vulnerability/${vuln.id}`,
    });
  }

  // Worst first, by the axis that actually orders remediation work: how
  // reachable an exploit is, then severity, then score.
  out.sort(
    (a, b) =>
      maturityRank(a.exploitation?.maturity) - maturityRank(b.exploitation?.maturity) ||
      severityRank(b.severity) - severityRank(a.severity) ||
      (b.cvss ?? 0) - (a.cvss ?? 0),
  );

  return out.map((v) => JSON.parse(JSON.stringify(v)));
}

/* ---------- the sweep ---------- */

/**
 * Check a list of package coordinates.
 *
 * Always resolves. If OSV is unreachable the result says so explicitly rather
 * than coming back empty, because an empty sweep reads as "you are fine" and
 * that is the one thing it must never say when it does not know.
 */
export async function sweepDependencies({ packages, onlyExploitable = false, includeClean = false } = {}) {
  const coordinates = (packages ?? [])
    .map((p) => ({
      name: String(p?.name ?? '').trim(),
      ecosystem: String(p?.ecosystem ?? '').trim(),
      version: String(p?.version ?? '').trim().replace(/^v/, ''),
      approximate: p?.approximate === true,
    }))
    .filter((p) => p.name && p.ecosystem && p.version)
    .slice(0, config.depsMaxPackages);

  if (!coordinates.length) {
    return { error: 'No usable package coordinates. Each needs a name, an ecosystem and a concrete version.' };
  }

  /* 1. coordinates -> advisory ids, from the database where we have them */

  const keys = coordinates.map(coordinateKey);
  let cachedQueries = null;
  try {
    cachedQueries = await getCachedQueries(keys);
  } catch {
    /* the cache is an optimisation; a sweep still works without it */
  }

  const pending = [];
  const idsByKey = new Map();
  for (let i = 0; i < coordinates.length; i += 1) {
    const hit = cachedQueries?.get(keys[i]);
    if (hit) idsByKey.set(keys[i], hit);
    else pending.push(i);
  }

  let osvOk = true;
  let osvError;
  let queriedUpstream = 0;

  if (pending.length) {
    try {
      const answers = await queryBatch(pending.map((i) => coordinates[i]));
      queriedUpstream = pending.length;
      const toStore = [];
      for (let p = 0; p < pending.length; p += 1) {
        const key = keys[pending[p]];
        idsByKey.set(key, answers[p] ?? []);
        toStore.push([key, answers[p] ?? []]);
      }
      putQueries(toStore).catch(() => {});
    } catch (error) {
      osvOk = false;
      osvError = error.message;
    }
  }

  // Nothing to report and nothing answered: say so, do not imply safety.
  if (!osvOk && !idsByKey.size) {
    return {
      error: `OSV.dev could not be reached, so nothing could be checked: ${osvError}`,
      checked: 0,
      osv: { ok: false, error: osvError },
    };
  }

  /* 2. advisory ids -> advisory details */

  const allIds = [...new Set([...idsByKey.values()].flat())];
  const capped = allIds.slice(0, config.depsMaxAdvisories);

  let details = new Map();
  let detailFailures = [];
  if (capped.length) {
    let stored = null;
    try {
      stored = await getCachedVulns(capped);
    } catch {
      /* as above */
    }
    if (stored) details = stored;

    const missing = capped.filter((id) => !details.has(id));
    if (missing.length) {
      const fetched = await fetchVulnDetails(missing);
      detailFailures = fetched.failed;
      for (const [id, value] of fetched.details) details.set(id, value);
      putVulns([...fetched.details.values()]).catch(() => {});
    }
  }

  /* 3. advisories -> our own severity, score and exploit intelligence */

  const canonicalIds = [...new Set([...details.values()].map(canonicalId))];
  const cveIds = canonicalIds.filter((id) => CVE_ID.test(id));

  let records = new Map();
  try {
    records = (await findRecordsByIds(cveIds)) ?? new Map();
  } catch {
    /* the corpus enriches the answer; OSV alone still answers it */
  }

  // attachSignals is the one path every record in this service goes through
  // for exploit data, so a sweep and the dashboard agree about the same CVE.
  const carriers = cveIds.map((id) => ({ cveId: id, exploited: Boolean(records.get(id)?.exploited) }));
  await attachSignals(carriers);
  const signals = new Map(carriers.filter((c) => c.exploitation).map((c) => [c.cveId, c.exploitation]));

  /* 4. assemble */

  const vulnerable = [];
  const clean = [];

  for (let i = 0; i < coordinates.length; i += 1) {
    const pkg = coordinates[i];
    const osvIds = idsByKey.get(keys[i]);

    // A coordinate we never got an answer for is unknown, not clean.
    if (!osvIds) continue;
    if (!osvIds.length) {
      clean.push(`${pkg.name}@${pkg.version}`);
      continue;
    }

    let found = describe(pkg, osvIds, details, records, signals);
    if (onlyExploitable) found = found.filter((v) => v.exploitation);
    if (!found.length) {
      clean.push(`${pkg.name}@${pkg.version}`);
      continue;
    }

    vulnerable.push({
      package: pkg.name,
      ecosystem: pkg.ecosystem,
      version: pkg.version,
      ...(pkg.approximate
        ? { versionApproximate: true, versionNote: 'Coerced from a range specifier; paste a lockfile for exact versions.' }
        : {}),
      worstMaturity: found[0].exploitation?.maturity,
      vulnerabilities: found,
    });
  }

  vulnerable.sort(
    (a, b) =>
      maturityRank(a.worstMaturity) - maturityRank(b.worstMaturity) ||
      severityRank(b.vulnerabilities[0].severity) - severityRank(a.vulnerabilities[0].severity) ||
      (b.vulnerabilities[0].cvss ?? 0) - (a.vulnerabilities[0].cvss ?? 0),
  );

  const exploitable = vulnerable.filter((p) => p.worstMaturity);

  /* 5. the worklist, which is the point of the whole thing */

  const patchFirst = exploitable.slice(0, 10).map((p) => {
    const worst = p.vulnerabilities[0];
    return {
      package: `${p.package}@${p.version}`,
      upgradeTo: worst.fixedIn?.[0] ?? null,
      because: worst.knownExploited
        ? `${worst.id} is being exploited in the wild (CISA KEV).`
        : `${worst.id} \u2014 exploit signals: ${worst.exploitation.evidence.join(', ')}.`,
    };
  });

  const unknown = coordinates.length - vulnerable.length - clean.length;

  return {
    checked: coordinates.length,
    ecosystems: [...new Set(coordinates.map((c) => c.ecosystem))],
    vulnerablePackages: vulnerable.length,
    advisories: vulnerable.reduce((n, p) => n + p.vulnerabilities.length, 0),
    withKnownExploit: exploitable.length,
    cleanPackages: clean.length,
    ...(unknown > 0 ? { unknownPackages: unknown } : {}),
    // The whole reason to use this instead of `npm audit`: an ordered list of
    // what to do, ordered by what someone could actually run against you.
    ...(patchFirst.length ? { patchFirst } : {}),
    packages: vulnerable,
    ...(includeClean && clean.length ? { clean } : {}),
    osv: {
      ok: osvOk,
      ...(osvError ? { error: osvError } : {}),
      coordinatesFromCache: coordinates.length - queriedUpstream,
      coordinatesQueriedUpstream: queriedUpstream,
      ...(allIds.length > capped.length
        ? { advisoriesNotDetailed: allIds.length - capped.length, note: `Capped at ${config.depsMaxAdvisories} advisory lookups; split the manifest to cover the rest.` }
        : {}),
      ...(detailFailures.length ? { advisoryLookupFailures: detailFailures.length } : {}),
    },
    caveats: [
      'Version matching comes from OSV.dev, which is what the ecosystems themselves publish into.',
      'An empty result means no advisory is known for that exact version, not that the package is safe.',
      'Exploit maturity says whether exploit code exists publicly, not whether you are reachable.',
    ],
  };
}

export default { sweepDependencies };
