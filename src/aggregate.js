import config from './config.js';
import { cached, peek } from './lib/cache.js';
import { finalize, mergeAll } from './merge.js';
import { enabledSources } from './sources/index.js';
import { attachSignals } from './exploits.js';
import { mongoConfigured } from './lib/mongo.js';
import { upsertRecords } from './store/cveStore.js';
import { getMeta, putMeta } from './store/metaStore.js';
import { readOnly } from './lib/refreshPolicy.js';

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

  const meta = {
    sources: results.map((r) => r.health),
    exploitSources: exploitHealth,
    generatedAt: new Date().toISOString(),
    window: { nvdDays: config.nvdDays },
  };

  // With a database, a refresh writes and keeps nothing: the cached value is
  // metadata, and the records are queried per request rather than held. The
  // collection also accumulates, so a CVE that falls out of the fetch window
  // keeps its page instead of disappearing.
  if (mongoConfigured()) {
    const written = await upsertRecords(items);
    // Only claim stored mode when the write actually landed. If the database
    // is unreachable - an un-allowlisted IP, a bad credential, an Atlas
    // outage - keep the records in memory and serve from there. A database
    // problem must cost memory, never uptime; the app stays up, just heavier.
    if (written.ok) {
      const summary = { ...meta, items: null, stored: true, fetched: items.length, written: written.written };
      // What every read-only web worker serves its metadata from. Written
      // after the records, so a worker never sees a summary describing
      // records that have not landed yet.
      await putMeta('feed', summary);
      return summary;
    }
    console.warn('[cvefeed] MongoDB is configured but unreachable; serving from memory');
  }

  items.sort(comparators.priority);
  return { ...meta, items };
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

/**
 * Whether this process may build the feed itself.
 *
 * With a database, the answer is no unless WEB_REFRESH says otherwise: the
 * records are already in the store and a worker only needs the summary of the
 * last refresh, which scripts/refresh.js leaves in `meta`. Without a database
 * there is nowhere else for the data to come from, so the process builds it
 * as it always has.
 */
export { readOnly };

/**
 * The last refresh's summary, read from the store.
 *
 * Cached briefly per worker so a busy dashboard is not a findOne per request,
 * and short enough that a new refresh is picked up within a minute. Never
 * builds anything - if no refresh has ever run, it says so rather than
 * starting one.
 */
const META_TTL_MS = 60_000;

async function readFeedSummary() {
  let summary = null;
  try {
    summary = await getMeta('feed');
  } catch {
    /* treated as "no refresh yet" below */
  }
  if (summary) return { ...summary, items: null, stored: true };

  // Nothing has refreshed yet - a fresh deploy before cron's first run. The
  // records already in the store are still served; the empty source list and
  // missing timestamp make the gap visible instead of hiding it.
  return {
    items: null,
    stored: true,
    sources: [],
    exploitSources: [],
    generatedAt: null,
    window: { nvdDays: config.nvdDays },
    neverRefreshed: true,
  };
}

/**
 * Build the feed now. For the refresher - scripts/refresh.js, the refresh
 * endpoint, or the opt-in interval - never for an ordinary request.
 */
export const refreshFeed = () => cached(FEED_KEY, collect, { force: true });

export async function getFeed({ force = false } = {}) {
  // Workers read. Even `force` reads: forcing a rebuild is a refresher's job,
  // and the callers that pass it on a request path only want the newest data
  // there is, which a re-read gives them.
  if (readOnly()) {
    // No stale-while-revalidate. Serving the old summary while re-reading in
    // the background is right for an expensive rebuild and wrong for a 3KB
    // findOne: it meant the first request after expiry - often /healthz on a
    // quiet worker - got the previous refresh's age, so a fresh cron run read
    // as stale. Waiting the few milliseconds is the cheaper mistake to make.
    return cached(FEED_KEY, readFeedSummary, { force, ttlMs: META_TTL_MS, staleWhileRevalidateMs: 0 });
  }

  const feed = await cached(FEED_KEY, collect, { force });

  // A snapshot left by a run with MONGODB_URI set holds only metadata, no
  // records. If Mongo has since been switched off, that snapshot is useless -
  // refetch so the records come back into memory. The reverse direction (a
  // memory snapshot while Mongo is now configured) is deliberately NOT forced
  // here: if the database is unreachable, collect() returns a memory snapshot
  // on purpose, and forcing on every call would refetch endlessly.
  if (!force && feed.value.stored && !mongoConfigured()) {
    return cached(FEED_KEY, collect, { force: true });
  }

  return feed;
}

export const feedCacheStatus = () => peek(FEED_KEY);

export default { getFeed, refreshFeed, readOnly, comparators, feedCacheStatus };
