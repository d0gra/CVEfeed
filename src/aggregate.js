import config from './config.js';
import { cached, peek } from './lib/cache.js';
import { severityFromScore, severityRank } from './lib/severity.js';
import { enabledSources } from './sources/index.js';

const FEED_KEY = 'feed-merged';

const maxNum = (a, b) => {
  const x = Number.isFinite(Number(a)) ? Number(a) : null;
  const y = Number.isFinite(Number(b)) ? Number(b) : null;
  if (x === null) return y;
  if (y === null) return x;
  return Math.max(x, y);
};

const earliest = (a, b) => (!a ? b : !b ? a : a < b ? a : b);
const latest = (a, b) => (!a ? b : !b ? a : a > b ? a : b);

const isPlaceholderTitle = (title, id) => !title || title === id || /^(CVE|GHSA|EUVD)-/i.test(title);

/** Records describing the same vulnerability share a key; advisories stay distinct. */
function mergeKey(item) {
  if (item.source === 'cisa') return `advisory:${item.advisoryId ?? item.id}`;
  if (item.cveId) return `cve:${item.cveId.toUpperCase()}`;
  if (item.ghsaId) return `ghsa:${item.ghsaId}`;
  if (item.euvdId) return `euvd:${item.euvdId}`;
  return `${item.source}:${item.id}`;
}

function mergeInto(target, item, sourceMeta) {
  target.sources.push(sourceMeta);

  target.score = maxNum(target.score, item.score);
  if (item.score !== null && item.score !== undefined && Number(item.score) === target.score) {
    target.scoreVersion = item.scoreVersion ?? target.scoreVersion;
    target.vector = item.vector ?? target.vector;
  }

  target.epss = maxNum(target.epss, item.epss);
  target.published = earliest(target.published, item.published);
  target.modified = latest(target.modified, item.modified);

  if (isPlaceholderTitle(target.title, target.id) && !isPlaceholderTitle(item.title, item.id)) {
    target.title = item.title;
  }
  if ((item.description?.length ?? 0) > (target.description?.length ?? 0)) {
    target.description = item.description;
  }

  target.cveId ??= item.cveId ?? null;
  target.ghsaId ??= item.ghsaId ?? null;
  target.euvdId ??= item.euvdId ?? null;
  target.vendor ??= item.vendor ?? null;
  target.product ??= item.product ?? null;
  target.status ??= item.status ?? null;
  target.assigner ??= item.assigner ?? null;

  if (item.exploited) target.exploited = true;
  if (item.kev) target.kev = { ...item.kev, ...(target.kev ?? {}) };

  for (const cwe of item.cwes ?? []) target.cweSet.add(cwe);
  for (const tag of item.tags ?? []) target.tagSet.add(tag);
  for (const cve of item.relatedCves ?? []) target.relatedSet.add(cve);
  for (const ref of item.references ?? []) {
    if (ref?.url) target.refMap.set(ref.url, ref);
  }
  // Keep a per-source permalink so the UI can link out to every provider.
  target.links[item.source] = item.url ?? target.links[item.source];
}

function seed(item, sourceMeta) {
  return {
    key: mergeKey(item),
    id: item.id,
    cveId: item.cveId ?? null,
    ghsaId: item.ghsaId ?? null,
    euvdId: item.euvdId ?? null,
    advisoryId: item.advisoryId ?? null,
    kind: item.source === 'cisa' ? 'advisory' : 'cve',
    title: item.title,
    description: item.description ?? '',
    score: Number.isFinite(Number(item.score)) ? Number(item.score) : null,
    scoreVersion: item.scoreVersion ?? null,
    vector: item.vector ?? null,
    epss: Number.isFinite(Number(item.epss)) ? Number(item.epss) : null,
    published: item.published ?? null,
    modified: item.modified ?? null,
    vendor: item.vendor ?? null,
    product: item.product ?? null,
    status: item.status ?? null,
    assigner: item.assigner ?? null,
    exploited: Boolean(item.exploited),
    kev: item.kev ?? null,
    url: item.url ?? null,
    sources: [sourceMeta],
    links: { [item.source]: item.url ?? null },
    cweSet: new Set(item.cwes ?? []),
    tagSet: new Set(item.tags ?? []),
    refMap: new Map((item.references ?? []).filter((r) => r?.url).map((r) => [r.url, r])),
    relatedSet: new Set(item.relatedCves ?? []),
  };
}

function finalize(record) {
  const { cweSet, tagSet, refMap, relatedSet, ...rest } = record;

  // Severity always follows the merged CVSS score; exploitation is a separate signal.
  const severity = severityFromScore(rest.score);

  return {
    ...rest,
    severity,
    severityRank: severityRank(severity),
    cwes: [...cweSet].sort(),
    tags: [...tagSet].sort(),
    references: [...refMap.values()].slice(0, 15),
    relatedCves: [...relatedSet],
    sourceIds: [...new Set(rest.sources.map((s) => s.id))],
    sources: rest.sources.filter(
      (s, i, arr) => arr.findIndex((other) => other.id === s.id) === i,
    ),
  };
}

/** Fetch every enabled source in parallel; one failure never fails the feed. */
async function collect() {
  const sources = enabledSources();

  const results = await Promise.all(
    sources.map(async (source) => {
      const startedAt = Date.now();
      try {
        const items = await source.fetchItems();
        return {
          meta: source.meta,
          items,
          health: {
            ...source.meta,
            ok: true,
            count: items.length,
            durationMs: Date.now() - startedAt,
            error: null,
            fetchedAt: new Date().toISOString(),
          },
        };
      } catch (error) {
        return {
          meta: source.meta,
          items: [],
          health: {
            ...source.meta,
            ok: false,
            count: 0,
            durationMs: Date.now() - startedAt,
            error: error.message,
            fetchedAt: new Date().toISOString(),
          },
        };
      }
    }),
  );

  const merged = new Map();

  for (const { meta, items } of results) {
    const sourceMeta = { id: meta.id, name: meta.name, homepage: meta.homepage };
    for (const item of items) {
      const key = mergeKey(item);
      const existing = merged.get(key);
      if (existing) mergeInto(existing, item, sourceMeta);
      else merged.set(key, seed(item, sourceMeta));
    }
  }

  // Let CISA advisories enrich the CVEs they reference.
  for (const record of merged.values()) {
    if (record.kind !== 'advisory') continue;
    for (const cve of record.relatedSet) {
      const target = merged.get(`cve:${cve.toUpperCase()}`);
      if (!target) continue;
      target.tagSet.add('cisa-advisory');
      target.refMap.set(record.url, { url: record.url, tags: ['CISA advisory'] });
    }
  }

  const items = [...merged.values()].map(finalize).filter(keepRecord);
  items.sort(comparators.priority);

  return {
    items,
    sources: results.map((r) => r.health),
    generatedAt: new Date().toISOString(),
    window: { nvdDays: config.nvdDays },
  };
}

/**
 * The KEV catalog is pulled in full because its value is the exploited flag it
 * contributes when merged onto a CVE. A KEV entry that merged with nothing and
 * was added long ago is history, not feed, so it is dropped past the cutoff.
 */
function keepRecord(record) {
  if (config.kevDays === 0) return true;
  if (record.sourceIds.length !== 1 || record.sourceIds[0] !== 'kev') return true;

  const added = Date.parse(record.kev?.dateAdded ?? record.published ?? '');
  if (!Number.isFinite(added)) return true;
  return added >= Date.now() - config.kevDays * 86_400_000;
}

export const comparators = {
  // Operational triage order: exploited first, then impact, then recency.
  priority: (a, b) =>
    Number(b.exploited) - Number(a.exploited) ||
    (b.score ?? -1) - (a.score ?? -1) ||
    String(b.published ?? '').localeCompare(String(a.published ?? '')),
  newest: (a, b) => String(b.published ?? '').localeCompare(String(a.published ?? '')),
  updated: (a, b) => String(b.modified ?? '').localeCompare(String(a.modified ?? '')),
  score: (a, b) => (b.score ?? -1) - (a.score ?? -1),
  epss: (a, b) => (b.epss ?? -1) - (a.epss ?? -1),
  severity: (a, b) => b.severityRank - a.severityRank || (b.score ?? -1) - (a.score ?? -1),
};

export function getFeed({ force = false } = {}) {
  return cached(FEED_KEY, collect, { force });
}

export const feedCacheStatus = () => peek(FEED_KEY);

export default { getFeed, comparators, feedCacheStatus };
