import config from './config.js';
import { cached, peek } from './lib/cache.js';
import { finalize, mergeAll } from './merge.js';
import { enabledSources } from './sources/index.js';
import { attachSignals } from './exploits.js';

const FEED_KEY = 'feed-merged';

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

  const merged = mergeAll(results);

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

  // Exploit signals are attached here rather than in finalize() because they
  // come from their own slow-moving index, which the feed must never wait on
  // indefinitely. A failure leaves records unsignalled, not wrong.
  const exploitHealth = await attachSignals(items);

  items.sort(comparators.priority);

  return {
    items,
    sources: results.map((r) => r.health),
    exploitSources: exploitHealth,
    generatedAt: new Date().toISOString(),
    window: { nvdDays: config.nvdDays },
  };
}

/** Observed beats weaponized beats a public exploit beats a PoC. */
const maturityOf = (item) => (item.exploitation ? item.exploitation.maturityRank : 99);

export const comparators = {
  // Operational triage order. How reachable an exploit is now outranks the
  // score: a 7.5 with a Metasploit module is a worse afternoon than a 9.8
  // nobody has written anything for.
  priority: (a, b) =>
    maturityOf(a) - maturityOf(b) ||
    (b.score ?? -1) - (a.score ?? -1) ||
    String(b.published ?? '').localeCompare(String(a.published ?? '')),
  newest: (a, b) => String(b.published ?? '').localeCompare(String(a.published ?? '')),
  updated: (a, b) => String(b.modified ?? '').localeCompare(String(a.modified ?? '')),
  score: (a, b) => (b.score ?? -1) - (a.score ?? -1),
  epss: (a, b) => (b.epss ?? -1) - (a.epss ?? -1),
  severity: (a, b) => b.severityRank - a.severityRank || (b.score ?? -1) - (a.score ?? -1),
  exploitability: (a, b) => maturityOf(a) - maturityOf(b) || (b.epss ?? -1) - (a.epss ?? -1),
};

export function getFeed({ force = false } = {}) {
  return cached(FEED_KEY, collect, { force });
}

export const feedCacheStatus = () => peek(FEED_KEY);

export default { getFeed, comparators, feedCacheStatus };
